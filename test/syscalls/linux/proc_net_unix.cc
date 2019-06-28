// Copyright 2019 The gVisor Authors.
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

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using absl::StrCat;
using absl::StreamFormat;
using absl::StrFormat;

constexpr char kProcNetUnixHeader[] =
    "Num       RefCount Protocol Flags    Type St Inode Path";

// Possible values of the "st" field in a /proc/net/unix entry. Source: Linux
// kernel, include/uapi/linux/net.h.
enum {
  SS_FREE = 0,      // Not allocated
  SS_UNCONNECTED,   // Unconnected to any socket
  SS_CONNECTING,    // In process of connecting
  SS_CONNECTED,     // Connected to socket
  SS_DISCONNECTING  // In process of disconnecting
};

// UnixEntry represents a single entry from /proc/net/unix.
struct UnixEntry {
  uintptr_t addr;
  uint64_t refs;
  uint64_t protocol;
  uint64_t flags;
  uint64_t type;
  uint64_t state;
  uint64_t inode;
  std::string path;
};

std::string ExtractPath(const struct sockaddr* addr) {
  const char* path =
      reinterpret_cast<const struct sockaddr_un*>(addr)->sun_path;
  // Note: sockaddr_un.sun_path is an embedded character array of length
  // UNIX_PATH_MAX, so we can always safely dereference the first 2 bytes below.
  //
  // The kernel also enforces that the path is always null terminated.
  if (path[0] == 0) {
    // Abstract socket paths are null padded to the end of the struct
    // sockaddr. However, these null bytes may or may not show up in
    // /proc/net/unix depending on the kernel version. Truncate after the first
    // null byte (by treating path as a c-string).
    return StrCat("@", &path[1]);
  }
  return std::string(path);
}

// Returns a parsed representation of /proc/net/unix entries.
PosixErrorOr<std::vector<UnixEntry>> ProcNetUnixEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/net/unix", &content));

  bool skipped_header = false;
  std::vector<UnixEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');
  std::cerr << "<contents of /proc/net/unix>" << std::endl;
  for (std::string line : lines) {
    // Emit the proc entry to the test output to provide context for the test
    // results.
    std::cerr << line << std::endl;

    if (!skipped_header) {
      EXPECT_EQ(line, kProcNetUnixHeader);
      skipped_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Abstract socket paths can have trailing null bytes in them depending on
    // the linux version. Strip off everything after a null byte, including the
    // null byte.
    std::size_t null_pos = line.find('\0');
    if (null_pos != std::string::npos) {
      line.erase(null_pos);
    }

    // Parse a single entry from /proc/net/unix.
    //
    // Sample file:
    //
    // clang-format off
    //
    // Num       RefCount Protocol Flags    Type St Inode Path"
    // ffffa130e7041c00: 00000002 00000000 00010000 0001 01 1299413685 /tmp/control_server/13293772586877554487
    // ffffa14f547dc400: 00000002 00000000 00010000 0001 01  3793 @remote_coredump
    //
    // clang-format on
    //
    // Note that from the second entry, the inode number can be padded using
    // spaces, so we need to handle it separately during parsing. See
    // net/unix/af_unix.c:unix_seq_show() for how these entries are produced. In
    // particular, only the inode field is padded with spaces.
    UnixEntry entry;

    // Process the first 6 fields, up to but not including "Inode".
    std::vector<std::string> fields =
        absl::StrSplit(line, absl::MaxSplits(' ', 6));

    if (fields.size() < 7) {
      return PosixError(EINVAL, StrFormat("Invalid entry: '%s'\n", line));
    }

    // AtoiBase can't handle the ':' in the "Num" field, so strip it out.
    std::vector<std::string> addr = absl::StrSplit(fields[0], ':');
    ASSIGN_OR_RETURN_ERRNO(entry.addr, AtoiBase(addr[0], 16));

    ASSIGN_OR_RETURN_ERRNO(entry.refs, AtoiBase(fields[1], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.protocol, AtoiBase(fields[2], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.flags, AtoiBase(fields[3], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.type, AtoiBase(fields[4], 16));
    ASSIGN_OR_RETURN_ERRNO(entry.state, AtoiBase(fields[5], 16));

    absl::string_view rest = absl::StripAsciiWhitespace(fields[6]);
    fields = absl::StrSplit(rest, absl::MaxSplits(' ', 1));
    if (fields.empty()) {
      return PosixError(
          EINVAL, StrFormat("Invalid entry, missing 'Inode': '%s'\n", line));
    }
    ASSIGN_OR_RETURN_ERRNO(entry.inode, AtoiBase(fields[0], 10));

    entry.path = "";
    if (fields.size() > 1) {
      entry.path = fields[1];
    }

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/net/unix>" << std::endl;

  return entries;
}

// Finds the first entry in 'entries' for which 'predicate' returns true.
// Returns true on match, and sets 'match' to point to the matching entry.
bool FindBy(std::vector<UnixEntry> entries, UnixEntry* match,
            std::function<bool(const UnixEntry&)> predicate) {
  for (int i = 0; i < entries.size(); ++i) {
    if (predicate(entries[i])) {
      *match = entries[i];
      return true;
    }
  }
  return false;
}

bool FindByPath(std::vector<UnixEntry> entries, UnixEntry* match,
                const std::string& path) {
  return FindBy(entries, match,
                [path](const UnixEntry& e) { return e.path == path; });
}

TEST(ProcNetUnix, Exists) {
  const std::string content =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/unix"));
  const std::string header_line = StrCat(kProcNetUnixHeader, "\n");
  if (IsRunningOnGvisor()) {
    // Should be just the header since we don't have any unix domain sockets
    // yet.
    EXPECT_EQ(content, header_line);
  } else {
    // However, on a general linux machine, we could have abitrary sockets on
    // the system, so just check the header.
    EXPECT_THAT(content, ::testing::StartsWith(header_line));
  }
}

TEST(ProcNetUnix, FilesystemBindAcceptConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      FilesystemBoundUnixDomainSocketPair(SOCK_STREAM).Create());

  std::string path1 = ExtractPath(sockets->first_addr());
  std::string path2 = ExtractPath(sockets->second_addr());
  std::cout << StreamFormat("Server socket address: %s\n", path1);
  std::cout << StreamFormat("Client socket address: %s\n", path2);

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(entries.size(), 2);
  }

  // The server-side socket's path is listed in the socket entry...
  UnixEntry s1;
  EXPECT_TRUE(FindByPath(entries, &s1, path1));

  // ... but the client-side socket's path is not.
  UnixEntry s2;
  EXPECT_FALSE(FindByPath(entries, &s2, path2));
}

TEST(ProcNetUnix, AbstractBindAcceptConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractBoundUnixDomainSocketPair(SOCK_STREAM).Create());

  std::string path1 = ExtractPath(sockets->first_addr());
  std::string path2 = ExtractPath(sockets->second_addr());
  std::cout << StreamFormat("Server socket address: '%s'\n", path1);
  std::cout << StreamFormat("Client socket address: '%s'\n", path2);

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(entries.size(), 2);
  }

  // The server-side socket's path is listed in the socket entry...
  UnixEntry s1;
  EXPECT_TRUE(FindByPath(entries, &s1, path1));

  // ... but the client-side socket's path is not.
  UnixEntry s2;
  EXPECT_FALSE(FindByPath(entries, &s2, path2));
}

TEST(ProcNetUnix, SocketPair) {
  // Under gvisor, ensure a socketpair() syscall creates exactly 2 new
  // entries. We have no way to verify this under Linux, as we have no control
  // over socket creation on a general Linux machine.
  SKIP_IF(!IsRunningOnGvisor());

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  ASSERT_EQ(entries.size(), 0);

  auto sockets =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_STREAM).Create());

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  EXPECT_EQ(entries.size(), 2);
}

TEST(ProcNetUnix, StreamSocketStateUnconnectedOnBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractUnboundUnixDomainSocketPair(SOCK_STREAM).Create());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());

  const std::string address = ExtractPath(sockets->first_addr());
  UnixEntry bind_entry;
  ASSERT_TRUE(FindByPath(entries, &bind_entry, address));
  EXPECT_EQ(bind_entry.state, SS_UNCONNECTED);
}

TEST(ProcNetUnix, StreamSocketStateStateUnconnectedOnListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractUnboundUnixDomainSocketPair(SOCK_STREAM).Create());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());

  const std::string address = ExtractPath(sockets->first_addr());
  UnixEntry bind_entry;
  ASSERT_TRUE(FindByPath(entries, &bind_entry, address));
  EXPECT_EQ(bind_entry.state, SS_UNCONNECTED);

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  UnixEntry listen_entry;
  ASSERT_TRUE(
      FindByPath(entries, &listen_entry, ExtractPath(sockets->first_addr())));
  EXPECT_EQ(listen_entry.state, SS_UNCONNECTED);
  // The bind and listen entries should refer to the same socket.
  EXPECT_EQ(listen_entry.inode, bind_entry.inode);
}

TEST(ProcNetUnix, StreamSocketStateStateConnectedOnAccept) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractUnboundUnixDomainSocketPair(SOCK_STREAM).Create());
  const std::string address = ExtractPath(sockets->first_addr());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  UnixEntry listen_entry;
  ASSERT_TRUE(
      FindByPath(entries, &listen_entry, ExtractPath(sockets->first_addr())));

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int clientfd;
  ASSERT_THAT(clientfd = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());

  // Find the entry for the accepted socket. UDS proc entries don't have a
  // remote address, so we distinguish the accepted socket from the listen
  // socket by checking for a different inode.
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  UnixEntry accept_entry;
  ASSERT_TRUE(FindBy(
      entries, &accept_entry, [address, listen_entry](const UnixEntry& e) {
        return e.path == address && e.inode != listen_entry.inode;
      }));
  EXPECT_EQ(accept_entry.state, SS_CONNECTED);
  // Listen entry should still be in SS_UNCONNECTED state.
  ASSERT_TRUE(FindBy(entries, &listen_entry,
                     [&sockets, listen_entry](const UnixEntry& e) {
                       return e.path == ExtractPath(sockets->first_addr()) &&
                              e.inode == listen_entry.inode;
                     }));
  EXPECT_EQ(listen_entry.state, SS_UNCONNECTED);
}

TEST(ProcNetUnix, DgramSocketStateDisconnectingOnBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractUnboundUnixDomainSocketPair(SOCK_DGRAM).Create());

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());

  // On gVisor, the only two UDS on the system are the ones we just created and
  // we rely on this to locate the test socket entries in the remainder of the
  // test. On a generic Linux system, we have no easy way to locate the
  // corresponding entries, as they don't have an address yet.
  if (IsRunningOnGvisor()) {
    ASSERT_EQ(entries.size(), 2);
    for (auto e : entries) {
      ASSERT_EQ(e.state, SS_DISCONNECTING);
    }
  }

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  const std::string address = ExtractPath(sockets->first_addr());
  UnixEntry bind_entry;
  ASSERT_TRUE(FindByPath(entries, &bind_entry, address));
  EXPECT_EQ(bind_entry.state, SS_UNCONNECTED);
}

TEST(ProcNetUnix, DgramSocketStateConnectingOnConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      AbstractUnboundUnixDomainSocketPair(SOCK_DGRAM).Create());

  std::vector<UnixEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());

  // On gVisor, the only two UDS on the system are the ones we just created and
  // we rely on this to locate the test socket entries in the remainder of the
  // test. On a generic Linux system, we have no easy way to locate the
  // corresponding entries, as they don't have an address yet.
  if (IsRunningOnGvisor()) {
    ASSERT_EQ(entries.size(), 2);
    for (auto e : entries) {
      ASSERT_EQ(e.state, SS_DISCONNECTING);
    }
  }

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());
  const std::string address = ExtractPath(sockets->first_addr());
  UnixEntry bind_entry;
  ASSERT_TRUE(FindByPath(entries, &bind_entry, address));

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcNetUnixEntries());

  // Once again, we have no easy way to identify the connecting socket as it has
  // no listed address. We can only identify the entry as the "non-bind socket
  // entry" on gVisor, where we're guaranteed to have only the two entries we
  // create during this test.
  if (IsRunningOnGvisor()) {
    ASSERT_EQ(entries.size(), 2);
    UnixEntry connect_entry;
    ASSERT_TRUE(
        FindBy(entries, &connect_entry, [bind_entry](const UnixEntry& e) {
          return e.inode != bind_entry.inode;
        }));
    EXPECT_EQ(connect_entry.state, SS_CONNECTING);
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
