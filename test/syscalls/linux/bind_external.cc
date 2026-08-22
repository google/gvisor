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

#ifdef __linux__
#include <sys/epoll.h>
#endif  // __linux__
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// This file contains tests specific to binding to host UDS that will be
// connected to from outside the sandbox / test.
//
// A set of ultity sockets will be created externally in $TEST_UDS_TREE and
// $TEST_UDS_ATTACH_TREE for these tests to interact with.

namespace gvisor {
namespace testing {

namespace {

struct ProtocolSocket {
  int protocol;
  std::string name;
};

// Parameter is (socket root dir, ProtocolSocket).
using GoferStreamSeqpacketTest =
    ::testing::TestWithParam<std::tuple<std::string, ProtocolSocket>>;

// Bind to a socket, then Listen and Accept.
TEST_P(GoferStreamSeqpacketTest, BindListenAccept) {
  std::string env;
  ProtocolSocket proto;
  std::tie(env, proto) = GetParam();

  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, proto.protocol, 0));

  std::string socket_path = JoinPath(root, proto.name, "created-in-sandbox");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(sock.get(), 1), SyscallSucceeds());

  // Bind again on that socket with a diff address should fail.
  std::string socket_path2 = socket_path + "-fail";
  struct sockaddr_un addr2 = {};
  addr2.sun_family = AF_UNIX;
  memcpy(addr2.sun_path, socket_path2.c_str(), socket_path2.length());
  ASSERT_THAT(bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr2),
                   sizeof(addr2)),
              SyscallFailsWithErrno(EINVAL));

  FileDescriptor accSock =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(sock.get(), NULL, NULL));

  // Other socket should be echo client.
  constexpr int kBufferSize = 64;
  char send_buffer[kBufferSize];
  memset(send_buffer, 'a', sizeof(send_buffer));

  ASSERT_THAT(WriteFd(accSock.get(), send_buffer, sizeof(send_buffer)),
              SyscallSucceedsWithValue(sizeof(send_buffer)));

  char recv_buffer[kBufferSize];
  ASSERT_THAT(ReadFd(accSock.get(), recv_buffer, sizeof(recv_buffer)),
              SyscallSucceedsWithValue(sizeof(recv_buffer)));
  ASSERT_EQ(0, memcmp(send_buffer, recv_buffer, sizeof(send_buffer)));
}

// Create socket, register with epoll, bind to socket, Listen, wait for socket
// to become ready using epoll and then Accept.
TEST_P(GoferStreamSeqpacketTest, EpollBindListenWaitAccept) {
  std::string env;
  ProtocolSocket proto;
  std::tie(env, proto) = GetParam();

  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, proto.protocol, 0));

  // Epoll on sockfd.
  int efd;
  ASSERT_THAT(efd = epoll_create(1), SyscallSucceeds());
  FileDescriptor epollfd(efd);
  struct epoll_event event = {};
  event.events = EPOLLIN;
  ASSERT_THAT(epoll_ctl(epollfd.get(), EPOLL_CTL_ADD, sock.get(), &event),
              SyscallSucceeds());

  std::string socket_path =
      JoinPath(root, proto.name, "created-in-sandbox-epoll");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(sock.get(), 1), SyscallSucceeds());

  struct epoll_event results = {};
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), &results, 1, -1),
              SyscallSucceeds());

  FileDescriptor accSock =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(sock.get(), NULL, NULL));

  // Other socket should be echo client.
  constexpr int kBufferSize = 64;
  char send_buffer[kBufferSize];
  memset(send_buffer, 'a', sizeof(send_buffer));

  ASSERT_THAT(WriteFd(accSock.get(), send_buffer, sizeof(send_buffer)),
              SyscallSucceedsWithValue(sizeof(send_buffer)));

  char recv_buffer[kBufferSize];
  ASSERT_THAT(ReadFd(accSock.get(), recv_buffer, sizeof(recv_buffer)),
              SyscallSucceedsWithValue(sizeof(recv_buffer)));
  ASSERT_EQ(0, memcmp(send_buffer, recv_buffer, sizeof(send_buffer)));
}

INSTANTIATE_TEST_SUITE_P(
    StreamSeqpacket, GoferStreamSeqpacketTest,
    ::testing::Combine(::testing::Values("TEST_CONNECTOR_TREE"),
                       ::testing::Values(ProtocolSocket{SOCK_STREAM, "stream"},
                                         ProtocolSocket{SOCK_SEQPACKET,
                                                        "seqpacket"})));

// Parameter is the unix socket type.
using BindHardLinkTest = ::testing::TestWithParam<int>;

// Regression test for a gofer-client dentry reference-counting bug. A bound
// socket's endpoint is stored on the inode, which is shared across hard links
// via the gofer inode cache. The compensating dentry reference that keeps an
// endpoint-bearing dentry alive used to be taken only by bind(2), so a second
// name hard-linked to the same socket got a dentry born without that reference;
// dropping the second name (or tearing the filesystem down) then underflowed
// the dentry refcount and panicked the sentry.
//
// Only connection-oriented socket types are exercised: a bound SOCK_DGRAM unix
// socket is realized as a synthetic file that cannot be hard-linked.
TEST_P(BindHardLinkTest, HardLinkThenUnlink) {
  char* val = getenv("TEST_CONNECTOR_TREE");
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string orig_path =
      JoinPath(root, absl::StrCat("bind_hardlink_", GetParam()));
  const std::string link_path = absl::StrCat(orig_path, ".hardlink");

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, GetParam(), 0));

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  ASSERT_LT(orig_path.length(), sizeof(addr.sun_path));
  memcpy(addr.sun_path, orig_path.c_str(), orig_path.length());
  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());

  // Create a second name for the bound socket. In the sentry this materializes
  // a second dentry sharing the socket's inode (and its endpoint).
  ASSERT_THAT(link(orig_path.c_str(), link_path.c_str()), SyscallSucceeds());

  struct stat orig_st = {};
  struct stat link_st = {};
  ASSERT_THAT(stat(orig_path.c_str(), &orig_st), SyscallSucceeds());
  ASSERT_THAT(stat(link_path.c_str(), &link_st), SyscallSucceeds());
  EXPECT_TRUE(S_ISSOCK(link_st.st_mode));
  EXPECT_EQ(orig_st.st_ino, link_st.st_ino);
  EXPECT_EQ(orig_st.st_nlink, 2);

  // Dropping the second name is what used to panic the sentry.
  ASSERT_THAT(unlink(link_path.c_str()), SyscallSucceeds());

  struct stat after_st = {};
  ASSERT_THAT(stat(orig_path.c_str(), &after_st), SyscallSucceeds());
  EXPECT_TRUE(S_ISSOCK(after_st.st_mode));
  EXPECT_EQ(after_st.st_nlink, 1);

  // Clean up, exercising the primary (bind-created) endpoint dentry's drop
  // path.
  ASSERT_THAT(unlink(orig_path.c_str()), SyscallSucceeds());
}

// Unlinking the original name first (leaving only the hard link) must also
// work: the endpoint outlives the bind-created dentry, and dropping the
// surviving link afterward must not underflow either.
TEST_P(BindHardLinkTest, UnlinkOriginalFirst) {
  char* val = getenv("TEST_CONNECTOR_TREE");
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string orig_path =
      JoinPath(root, absl::StrCat("bind_hardlink_orig1st_", GetParam()));
  const std::string link_path = absl::StrCat(orig_path, ".hardlink");

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, GetParam(), 0));

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  ASSERT_LT(orig_path.length(), sizeof(addr.sun_path));
  memcpy(addr.sun_path, orig_path.c_str(), orig_path.length());
  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());

  ASSERT_THAT(link(orig_path.c_str(), link_path.c_str()), SyscallSucceeds());

  // Drop the bind-created name first.
  ASSERT_THAT(unlink(orig_path.c_str()), SyscallSucceeds());

  struct stat link_st = {};
  ASSERT_THAT(stat(link_path.c_str(), &link_st), SyscallSucceeds());
  EXPECT_TRUE(S_ISSOCK(link_st.st_mode));
  EXPECT_EQ(link_st.st_nlink, 1);

  // Dropping the surviving link must not underflow.
  ASSERT_THAT(unlink(link_path.c_str()), SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(AllUnixDomainSockets, BindHardLinkTest,
                         ::testing::Values(SOCK_STREAM, SOCK_SEQPACKET));

}  // namespace

}  // namespace testing
}  // namespace gvisor
