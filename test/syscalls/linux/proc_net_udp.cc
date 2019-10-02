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
using absl::StrFormat;
using absl::StrSplit;

constexpr char kProcNetUDPHeader[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops             ";

// UDPEntry represents a single entry from /proc/net/udp.
struct UDPEntry {
  uint32_t local_addr;
  uint16_t local_port;

  uint32_t remote_addr;
  uint16_t remote_port;

  uint64_t state;
  uint64_t uid;
  uint64_t inode;
};

std::string DescribeFirstInetSocket(const SocketPair& sockets) {
  const struct sockaddr* addr = sockets.first_addr();
  return StrFormat("First test socket: fd:%d %8X:%4X", sockets.first_fd(),
                   IPFromInetSockaddr(addr), PortFromInetSockaddr(addr));
}

std::string DescribeSecondInetSocket(const SocketPair& sockets) {
  const struct sockaddr* addr = sockets.second_addr();
  return StrFormat("Second test socket fd:%d %8X:%4X", sockets.second_fd(),
                   IPFromInetSockaddr(addr), PortFromInetSockaddr(addr));
}

// Finds the first entry in 'entries' for which 'predicate' returns true.
// Returns true on match, and set 'match' to a copy of the matching entry. If
// 'match' is null, it's ignored.
bool FindBy(const std::vector<UDPEntry>& entries, UDPEntry* match,
            std::function<bool(const UDPEntry&)> predicate) {
  for (const UDPEntry& entry : entries) {
    if (predicate(entry)) {
      if (match != nullptr) {
        *match = entry;
      }
      return true;
    }
  }
  return false;
}

bool FindByLocalAddr(const std::vector<UDPEntry>& entries, UDPEntry* match,
                     const struct sockaddr* addr) {
  uint32_t host = IPFromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
  return FindBy(entries, match, [host, port](const UDPEntry& e) {
    return (e.local_addr == host && e.local_port == port);
  });
}

bool FindByRemoteAddr(const std::vector<UDPEntry>& entries, UDPEntry* match,
                      const struct sockaddr* addr) {
  uint32_t host = IPFromInetSockaddr(addr);
  uint16_t port = PortFromInetSockaddr(addr);
  return FindBy(entries, match, [host, port](const UDPEntry& e) {
    return (e.remote_addr == host && e.remote_port == port);
  });
}

PosixErrorOr<uint64_t> InodeFromSocketFD(int fd) {
  ASSIGN_OR_RETURN_ERRNO(struct stat s, Fstat(fd));
  if (!S_ISSOCK(s.st_mode)) {
    return PosixError(EINVAL, StrFormat("FD %d is not a socket", fd));
  }
  return s.st_ino;
}

PosixErrorOr<bool> FindByFD(const std::vector<UDPEntry>& entries,
                            UDPEntry* match, int fd) {
  ASSIGN_OR_RETURN_ERRNO(uint64_t inode, InodeFromSocketFD(fd));
  return FindBy(entries, match,
                [inode](const UDPEntry& e) { return (e.inode == inode); });
}

// Returns a parsed representation of /proc/net/udp entries.
PosixErrorOr<std::vector<UDPEntry>> ProcNetUDPEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/net/udp", &content));

  bool found_header = false;
  std::vector<UDPEntry> entries;
  std::vector<std::string> lines = StrSplit(content, '\n');
  std::cerr << "<contents of /proc/net/udp>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (!found_header) {
      EXPECT_EQ(line, kProcNetUDPHeader);
      found_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/net/udp.
    //
    // Example entries:
    //
    // clang-format off
    //
    //  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
    // 3503: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 33317 2 0000000000000000 0
    // 3518: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 40394 2 0000000000000000 0
    //   ^     ^       ^     ^       ^   ^     ^       ^      ^     ^        ^         ^        ^   ^   ^      ^           ^
    //   0     1       2     3       4   5     6       7      8     9       10        11       12  13  14     15           16
    //
    // clang-format on

    UDPEntry entry;
    std::vector<std::string> fields =
        StrSplit(line, absl::ByAnyChar(": "), absl::SkipEmpty());

    ASSIGN_OR_RETURN_ERRNO(entry.local_addr, AtoiBase(fields[1], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.local_port, AtoiBase(fields[2], 16));

    ASSIGN_OR_RETURN_ERRNO(entry.remote_addr, AtoiBase(fields[3], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.remote_port, AtoiBase(fields[4], 16));

    ASSIGN_OR_RETURN_ERRNO(entry.state, AtoiBase(fields[5], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.uid, Atoi<uint64_t>(fields[11]));
    ASSIGN_OR_RETURN_ERRNO(entry.inode, Atoi<uint64_t>(fields[13]));

    // Linux shares internal data structures between TCP and UDP sockets. The
    // proc entries for UDP sockets share some fields with TCP sockets, but
    // these fields should always be zero as they're not meaningful for UDP
    // sockets.
    EXPECT_EQ(fields[8], "00") << StrFormat("sl:%s, tr", fields[0]);
    EXPECT_EQ(fields[9], "00000000") << StrFormat("sl:%s, tm->when", fields[0]);
    EXPECT_EQ(fields[10], "00000000")
        << StrFormat("sl:%s, retrnsmt", fields[0]);
    EXPECT_EQ(fields[12], "0") << StrFormat("sl:%s, timeout", fields[0]);

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/net/udp>" << std::endl;

  return entries;
}

TEST(ProcNetUDP, Exists) {
  const std::string content =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/udp"));
  const std::string header_line = StrCat(kProcNetUDPHeader, "\n");
  EXPECT_THAT(content, ::testing::StartsWith(header_line));
}

TEST(ProcNetUDP, EntryUID) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4UDPBidirectionalBindSocketPair(0).Create());
  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());
  UDPEntry e;
  ASSERT_TRUE(FindByLocalAddr(entries, &e, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_EQ(e.uid, geteuid());
  ASSERT_TRUE(FindByRemoteAddr(entries, &e, sockets->first_addr()))
      << DescribeSecondInetSocket(*sockets);
  EXPECT_EQ(e.uid, geteuid());
}

TEST(ProcNetUDP, FindMutualEntries) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4UDPBidirectionalBindSocketPair(0).Create());
  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());

  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_TRUE(FindByRemoteAddr(entries, nullptr, sockets->first_addr()))
      << DescribeSecondInetSocket(*sockets);

  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->second_addr()))
      << DescribeSecondInetSocket(*sockets);
  EXPECT_TRUE(FindByRemoteAddr(entries, nullptr, sockets->second_addr()))
      << DescribeFirstInetSocket(*sockets);
}

TEST(ProcNetUDP, EntriesRemovedOnClose) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4UDPBidirectionalBindSocketPair(0).Create());
  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());

  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->second_addr()))
      << DescribeSecondInetSocket(*sockets);

  EXPECT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());
  // First socket's entry should be gone, but the second socket's entry should
  // still exist.
  EXPECT_FALSE(FindByLocalAddr(entries, nullptr, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_TRUE(FindByLocalAddr(entries, nullptr, sockets->second_addr()))
      << DescribeSecondInetSocket(*sockets);

  EXPECT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());
  // Both entries should be gone.
  EXPECT_FALSE(FindByLocalAddr(entries, nullptr, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_FALSE(FindByLocalAddr(entries, nullptr, sockets->second_addr()))
      << DescribeSecondInetSocket(*sockets);
}

PosixErrorOr<std::unique_ptr<FileDescriptor>> BoundUDPSocket() {
  ASSIGN_OR_RETURN_ERRNO(std::unique_ptr<FileDescriptor> socket,
                         IPv4UDPUnboundSocket(0).Create());
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = 0;

  int res = bind(socket->get(), reinterpret_cast<const struct sockaddr*>(&addr),
                 sizeof(addr));
  if (res) {
    return PosixError(errno, "bind()");
  }
  return socket;
}

TEST(ProcNetUDP, BoundEntry) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(BoundUDPSocket());
  struct sockaddr addr;
  socklen_t len = sizeof(addr);
  ASSERT_THAT(getsockname(socket->get(), &addr, &len), SyscallSucceeds());
  uint16_t port = PortFromInetSockaddr(&addr);

  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());
  UDPEntry e;
  ASSERT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(FindByFD(entries, &e, socket->get())));
  EXPECT_EQ(e.local_port, port);
  EXPECT_EQ(e.remote_addr, 0);
  EXPECT_EQ(e.remote_port, 0);
}

TEST(ProcNetUDP, BoundSocketStateClosed) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(BoundUDPSocket());
  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());
  UDPEntry e;
  ASSERT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(FindByFD(entries, &e, socket->get())));
  EXPECT_EQ(e.state, TCP_CLOSE);
}

TEST(ProcNetUDP, ConnectedSocketStateEstablished) {
  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(IPv4UDPBidirectionalBindSocketPair(0).Create());
  std::vector<UDPEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUDPEntries());

  UDPEntry e;
  ASSERT_TRUE(FindByLocalAddr(entries, &e, sockets->first_addr()))
      << DescribeFirstInetSocket(*sockets);
  EXPECT_EQ(e.state, TCP_ESTABLISHED);

  ASSERT_TRUE(FindByLocalAddr(entries, &e, sockets->second_addr()))
      << DescribeSecondInetSocket(*sockets);
  EXPECT_EQ(e.state, TCP_ESTABLISHED);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
