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

// Finds the first entry in 'entries' for which 'predicate' returns true.
// Returns true on match, and sets 'match' to a copy of the matching entry. If
// 'match' is null, it's ignored.
bool FindBy(const std::vector<TCPEntry>& entries, TCPEntry* match,
            std::function<bool(const TCPEntry&)> predicate) {
  for (const TCPEntry& entry : entries) {
    if (predicate(entry)) {
      if (match != nullptr) {
        *match = entry;
      }
      return true;
    }
  }
  return false;
}

bool FindByLocalAddr(const std::vector<TCPEntry>& entries, TCPEntry* match,
                     const struct sockaddr* addr) {
  uint32_t host = IPFromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
  return FindBy(entries, match, [host, port](const TCPEntry& e) {
    return (e.local_addr == host && e.local_port == port);
  });
}

bool FindByRemoteAddr(const std::vector<TCPEntry>& entries, TCPEntry* match,
                      const struct sockaddr* addr) {
  uint32_t host = IPFromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
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
  for (const std::string& line : lines) {
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

  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->first_addr()));
  EXPECT_TRUE(FindByRemoteAddr(entries, nullptr, sockets->first_addr()));
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

  const uint32_t accepted_local_host = IPFromInetSockaddr(&addr);
  const uint16_t accepted_local_port = PortFromInetSockaddr(&addr);

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

constexpr char kProcNetTCP6Header[] =
    "  sl  local_address                         remote_address"
    "                        st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode";

// TCP6Entry represents a single entry from /proc/net/tcp6.
struct TCP6Entry {
  struct in6_addr local_addr;
  uint16_t local_port;

  struct in6_addr remote_addr;
  uint16_t remote_port;

  uint64_t state;
  uint64_t uid;
  uint64_t inode;
};

bool IPv6AddrEqual(const struct in6_addr* a1, const struct in6_addr* a2) {
  return memcmp(a1, a2, sizeof(struct in6_addr)) == 0;
}

// Finds the first entry in 'entries' for which 'predicate' returns true.
// Returns true on match, and sets 'match' to a copy of the matching entry. If
// 'match' is null, it's ignored.
bool FindBy6(const std::vector<TCP6Entry>& entries, TCP6Entry* match,
             std::function<bool(const TCP6Entry&)> predicate) {
  for (const TCP6Entry& entry : entries) {
    if (predicate(entry)) {
      if (match != nullptr) {
        *match = entry;
      }
      return true;
    }
  }
  return false;
}

const struct in6_addr* IP6FromInetSockaddr(const struct sockaddr* addr) {
  auto* addr6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
  return &addr6->sin6_addr;
}

bool FindByLocalAddr6(const std::vector<TCP6Entry>& entries, TCP6Entry* match,
                      const struct sockaddr* addr) {
  const struct in6_addr* local = IP6FromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
  return FindBy6(entries, match, [local, port](const TCP6Entry& e) {
    return (IPv6AddrEqual(&e.local_addr, local) && e.local_port == port);
  });
}

bool FindByRemoteAddr6(const std::vector<TCP6Entry>& entries, TCP6Entry* match,
                       const struct sockaddr* addr) {
  const struct in6_addr* remote = IP6FromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
  return FindBy6(entries, match, [remote, port](const TCP6Entry& e) {
    return (IPv6AddrEqual(&e.remote_addr, remote) && e.remote_port == port);
  });
}

void ReadIPv6Address(std::string s, struct in6_addr* addr) {
  uint32_t a0, a1, a2, a3;
  const char* fmt = "%08X%08X%08X%08X";
  EXPECT_EQ(sscanf(s.c_str(), fmt, &a0, &a1, &a2, &a3), 4);

  uint8_t* b = addr->s6_addr;
  *((uint32_t*)&b[0]) = a0;
  *((uint32_t*)&b[4]) = a1;
  *((uint32_t*)&b[8]) = a2;
  *((uint32_t*)&b[12]) = a3;
}

// Returns a parsed representation of /proc/net/tcp6 entries.
PosixErrorOr<std::vector<TCP6Entry>> ProcNetTCP6Entries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/net/tcp6", &content));

  bool found_header = false;
  std::vector<TCP6Entry> entries;
  std::vector<std::string> lines = StrSplit(content, '\n');
  std::cerr << "<contents of /proc/net/tcp6>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (!found_header) {
      EXPECT_EQ(line, kProcNetTCP6Header);
      found_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/net/tcp6.
    //
    // Example entries:
    //
    // clang-format off
    //
    //  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    //   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 876340 1 ffff8803da9c9380 100 0 0 10 0
    //   1: 00000000000000000000000000000000:C350 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 876987 1 ffff8803ec408000 100 0 0 10 0
    //   ^                  ^                  ^                  ^                  ^   ^     ^       ^      ^     ^        ^       ^         ^    ^   ^      ^            ^  ^ ^  ^ ^
    //   0                  1                  2                  3                  4   5     6       7      8     9       10       11       12   13  14     15           16 17 18 19 20
    //
    // clang-format on

    TCP6Entry entry;
    std::vector<std::string> fields =
        StrSplit(line, absl::ByAnyChar(": "), absl::SkipEmpty());

    ReadIPv6Address(fields[1], &entry.local_addr);
    ASSIGN_OR_RETURN_ERRNO(entry.local_port, AtoiBase(fields[2], 16));
    ReadIPv6Address(fields[3], &entry.remote_addr);
    ASSIGN_OR_RETURN_ERRNO(entry.remote_port, AtoiBase(fields[4], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.state, AtoiBase(fields[5], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.uid, Atoi<uint64_t>(fields[11]));
    ASSIGN_OR_RETURN_ERRNO(entry.inode, Atoi<uint64_t>(fields[13]));

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/net/tcp6>" << std::endl;

  return entries;
}

TEST(ProcNetTCP6, Exists) {
  const std::string content =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/tcp6"));
  const std::string header_line = StrCat(kProcNetTCP6Header, "\n");
  if (IsRunningOnGvisor()) {
    // Should be just the header since we don't have any tcp sockets yet.
    EXPECT_EQ(content, header_line);
  } else {
    // On a general linux machine, we could have abitrary sockets on the system,
    // so just check the header.
    EXPECT_THAT(content, ::testing::StartsWith(header_line));
  }
}

TEST(ProcNetTCP6, EntryUID) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv6TCPAcceptBindSocketPair(0).Create());
  std::vector<TCP6Entry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());
  TCP6Entry e;

  ASSERT_TRUE(FindByLocalAddr6(entries, &e, sockets->first_addr()));
  EXPECT_EQ(e.uid, geteuid());
  ASSERT_TRUE(FindByRemoteAddr6(entries, &e, sockets->first_addr()));
  EXPECT_EQ(e.uid, geteuid());
}

TEST(ProcNetTCP6, BindAcceptConnect) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv6TCPAcceptBindSocketPair(0).Create());
  std::vector<TCP6Entry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());
  // We can only make assertions about the total number of entries if we control
  // the entire "machine".
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(entries.size(), 2);
  }

  EXPECT_TRUE(FindByLocalAddr6(entries, nullptr, sockets->first_addr()));
  EXPECT_TRUE(FindByRemoteAddr6(entries, nullptr, sockets->first_addr()));
}

TEST(ProcNetTCP6, InodeReasonable) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv6TCPAcceptBindSocketPair(0).Create());
  std::vector<TCP6Entry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());

  TCP6Entry accepted_entry;

  ASSERT_TRUE(
      FindByLocalAddr6(entries, &accepted_entry, sockets->first_addr()));
  EXPECT_NE(accepted_entry.inode, 0);

  TCP6Entry client_entry;
  ASSERT_TRUE(FindByRemoteAddr6(entries, &client_entry, sockets->first_addr()));
  EXPECT_NE(client_entry.inode, 0);
  EXPECT_NE(accepted_entry.inode, client_entry.inode);
}

TEST(ProcNetTCP6, State) {
  std::unique_ptr<FileDescriptor> server =
      ASSERT_NO_ERRNO_AND_VALUE(IPv6TCPUnboundSocket(0).Create());

  auto test_addr = V6Loopback();
  ASSERT_THAT(
      bind(server->get(), reinterpret_cast<struct sockaddr*>(&test_addr.addr),
           test_addr.addr_len),
      SyscallSucceeds());

  struct sockaddr_in6 addr6;
  socklen_t addrlen = sizeof(struct sockaddr_in6);
  auto* addr = reinterpret_cast<struct sockaddr*>(&addr6);
  ASSERT_THAT(getsockname(server->get(), addr, &addrlen), SyscallSucceeds());
  ASSERT_EQ(addrlen, sizeof(struct sockaddr_in6));

  ASSERT_THAT(listen(server->get(), 10), SyscallSucceeds());
  std::vector<TCP6Entry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());
  TCP6Entry listen_entry;

  ASSERT_TRUE(FindByLocalAddr6(entries, &listen_entry, addr));
  EXPECT_EQ(listen_entry.state, TCP_LISTEN);

  std::unique_ptr<FileDescriptor> client =
      ASSERT_NO_ERRNO_AND_VALUE(IPv6TCPUnboundSocket(0).Create());
  ASSERT_THAT(RetryEINTR(connect)(client->get(), addr, addrlen),
              SyscallSucceeds());
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());
  ASSERT_TRUE(FindByLocalAddr6(entries, &listen_entry, addr));
  EXPECT_EQ(listen_entry.state, TCP_LISTEN);
  TCP6Entry client_entry;
  ASSERT_TRUE(FindByRemoteAddr6(entries, &client_entry, addr));
  EXPECT_EQ(client_entry.state, TCP_ESTABLISHED);

  FileDescriptor accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(server->get(), nullptr, nullptr));

  const struct in6_addr* local = IP6FromInetSockaddr(addr);
  const uint16_t accepted_local_port = PortFromInetSockaddr(addr);

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetTCP6Entries());
  TCP6Entry accepted_entry;
  ASSERT_TRUE(FindBy6(
      entries, &accepted_entry,
      [client_entry, local, accepted_local_port](const TCP6Entry& e) {
        return IPv6AddrEqual(&e.local_addr, local) &&
               e.local_port == accepted_local_port &&
               IPv6AddrEqual(&e.remote_addr, &client_entry.local_addr) &&
               e.remote_port == client_entry.local_port;
      }));
  EXPECT_EQ(accepted_entry.state, TCP_ESTABLISHED);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
