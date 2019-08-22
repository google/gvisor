// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using absl::StrCat;
using absl::StrSplit;

constexpr char kProcNetTCPHeader[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode                                             "
    "        ";

// Possible values of the "st" field in a /proc/net/tcp entry. Source: Linux
// kernel, include/net/tcp_states.h.
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,
  TCP_NEW_SYN_RECV,

  TCP_MAX_STATES
};

// TCPEntry represents a single entry from /proc/net/tcp.
struct TCPEntry {
  uint32_t local_addr;
  uint16_t local_port;

  uint32_t remote_addr;
  uint16_t remote_port;

  uint64_t state;
  uint64_t uid;
  uint64_t inode;
};

uint32_t IP(const struct sockaddr* addr) {
  auto* in_addr = reinterpret_cast<const struct sockaddr_in*>(addr);
  return in_addr->sin_addr.s_addr;
}

uint16_t Port(const struct sockaddr* addr) {
  auto* in_addr = reinterpret_cast<const struct sockaddr_in*>(addr);
  return ntohs(in_addr->sin_port);
}

// Finds the first entry in 'entries' for which 'predicate' returns true.
// Returns true on match, and sets 'match' to point to the matching entry.
bool FindBy(std::vector<TCPEntry> entries, TCPEntry* match,
            std::function<bool(const TCPEntry&)> predicate) {
  for (int i = 0; i < entries.size(); ++i) {
    if (predicate(entries[i])) {
      *match = entries[i];
      return true;
    }
  }
  return false;
}

bool FindByLocalAddr(std::vector<TCPEntry> entries, TCPEntry* match,
                     const struct sockaddr* addr) {
  uint32_t host = IP(addr);
  uint16_t port = Port(addr);
  return FindBy(entries, match, [host, port](const TCPEntry& e) {
    return (e.local_addr == host && e.local_port == port);
  });
}

bool FindByRemoteAddr(std::vector<TCPEntry> entries, TCPEntry* match,
                      const struct sockaddr* addr) {
  uint32_t host = IP(addr);
  uint16_t port = Port(addr);
  return FindBy(entries, match, [host, port](const TCPEntry& e) {
    return (e.remote_addr == host && e.remote_port == port);
  });
}

// Returns a parsed representation of /proc/net/tcp entries.
PosixErrorOr<std::vector<TCPEntry>> ProcNetTCPEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/net/tcp", &content));

  bool found_header = false;
  std::vector<TCPEntry> entries;
  std::vector<std::string> lines = StrSplit(content, '\n');
  std::cerr << "<contents of /proc/net/tcp>" << std::endl;
  for (std::string line : lines) {
    std::cerr << line << std::endl;

    if (!found_header) {
      EXPECT_EQ(line, kProcNetTCPHeader);
      found_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/net/tcp.
    //
    // Example entries:
    //
    // clang-format off
    //
    //  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    //   0: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1968 1 0000000000000000 100 0 0 10 0
    //   1: 0100007F:7533 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 10684 1 0000000000000000 100 0 0 10 0
    //   ^     ^       ^     ^       ^   ^     ^       ^      ^     ^        ^       ^         ^   ^   ^      ^            ^  ^ ^  ^ ^
    //   0     1       2     3       4   5     6       7      8     9       10       11       12  13  14     15           16 17 18 19 20
    //
    // clang-format on

    TCPEntry entry;
    std::vector<std::string> fields =
        StrSplit(line, absl::ByAnyChar(": "), absl::SkipEmpty());

    ASSIGN_OR_RETURN_ERRNO(entry.local_addr, AtoiBase(fields[1], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.local_port, AtoiBase(fields[2], 16));

    ASSIGN_OR_RETURN_ERRNO(entry.remote_addr, AtoiBase(fields[3], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.remote_port, AtoiBase(fields[4], 16));

    ASSIGN_OR_RETURN_ERRNO(entry.state, AtoiBase(fields[5], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.uid, Atoi<uint64_t>(fields[11]));
    ASSIGN_OR_RETURN_ERRNO(entry.inode, Atoi<uint64_t>(fields[13]));

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/net/tcp>" << std::endl;

  return entries;
}

TEST(ProcNetTCP, Exists) {
  const std::string content =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/tcp"));
  const std::string header_line = StrCat(kProcNetTCPHeader, "\n");
  if (IsRunningOnGvisor()) {
    // Should be just the header since we don't have any tcp sockets yet.
    EXPECT_EQ(content, header_line);
  } else {
    // On a general linux machine, we could have abitrary sockets on the system,
    // so just check the header.
    EXPECT_THAT(content, ::testing::StartsWith(header_line));
  }
}

TEST(ProcNetTCP, EntryUID) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4TCPAcceptBindSocketPair(0).Create());
  std::vector<TCPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());
  TCPEntry e;
  ASSERT_TRUE(FindByLocalAddr(entries, &e, sockets->first_addr()));
  EXPECT_EQ(e.uid, geteuid());
  ASSERT_TRUE(FindByRemoteAddr(entries, &e, sockets->first_addr()));
  EXPECT_EQ(e.uid, geteuid());
}

TEST(ProcNetTCP, BindAcceptConnect) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4TCPAcceptBindSocketPair(0).Create());
  std::vector<TCPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());
  // We can only make assertions about the total number of entries if we control
  // the entire "machine".
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(entries.size(), 2);
  }

  TCPEntry e;
  EXPECT_TRUE(FindByLocalAddr(entries, &e, sockets->first_addr()));
  EXPECT_TRUE(FindByRemoteAddr(entries, &e, sockets->first_addr()));
}

TEST(ProcNetTCP, InodeReasonable) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4TCPAcceptBindSocketPair(0).Create());
  std::vector<TCPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());

  TCPEntry accepted_entry;
  ASSERT_TRUE(FindByLocalAddr(entries, &accepted_entry, sockets->first_addr()));
  EXPECT_NE(accepted_entry.inode, 0);

  TCPEntry client_entry;
  ASSERT_TRUE(FindByRemoteAddr(entries, &client_entry, sockets->first_addr()));
  EXPECT_NE(client_entry.inode, 0);
  EXPECT_NE(accepted_entry.inode, client_entry.inode);
}

TEST(ProcNetTCP, State) {
  std::unique_ptr<FileDescriptor> server =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4TCPUnboundSocket(0).Create());

  auto test_addr = V4Loopback();
  ASSERT_THAT(
      bind(server->get(), reinterpret_cast<struct sockaddr*>(&test_addr.addr),
           test_addr.addr_len),
      SyscallSucceeds());

  struct sockaddr addr;
  socklen_t addrlen = sizeof(struct sockaddr);
  ASSERT_THAT(getsockname(server->get(), &addr, &addrlen), SyscallSucceeds());
  ASSERT_EQ(addrlen, sizeof(struct sockaddr));

  ASSERT_THAT(listen(server->get(), 10), SyscallSucceeds());
  std::vector<TCPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());
  TCPEntry listen_entry;
  ASSERT_TRUE(FindByLocalAddr(entries, &listen_entry, &addr));
  EXPECT_EQ(listen_entry.state, TCP_LISTEN);

  std::unique_ptr<FileDescriptor> client =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4TCPUnboundSocket(0).Create());
  ASSERT_THAT(RetryEINTR(connect)(client->get(), &addr, addrlen),
              SyscallSucceeds());
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());
  ASSERT_TRUE(FindByLocalAddr(entries, &listen_entry, &addr));
  EXPECT_EQ(listen_entry.state, TCP_LISTEN);
  TCPEntry client_entry;
  ASSERT_TRUE(FindByRemoteAddr(entries, &client_entry, &addr));
  EXPECT_EQ(client_entry.state, TCP_ESTABLISHED);

  FileDescriptor accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(server->get(), nullptr, nullptr));

  const uint32_t accepted_local_host = IP(&addr);
  const uint16_t accepted_local_port = Port(&addr);

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCPEntries());
  TCPEntry accepted_entry;
  ASSERT_TRUE(FindBy(entries, &accepted_entry,
                     [client_entry, accepted_local_host,
                      accepted_local_port](const TCPEntry& e) {
                       return e.local_addr == accepted_local_host &&
                              e.local_port == accepted_local_port &&
                              e.remote_addr == client_entry.local_addr &&
                              e.remote_port == client_entry.local_port;
                     }));
  EXPECT_EQ(accepted_entry.state, TCP_ESTABLISHED);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
