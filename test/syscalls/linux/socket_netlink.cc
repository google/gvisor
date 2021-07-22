// Copyright 2018 The gVisor Authors.
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

#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Tests for all netlink socket protocols.

namespace gvisor {
namespace testing {

namespace {

// NetlinkTest parameter is the protocol to test.
using NetlinkTest = ::testing::TestWithParam<int>;

// Netlink sockets must be SOCK_DGRAM or SOCK_RAW.
TEST_P(NetlinkTest, Types) {
  const int protocol = GetParam();

  EXPECT_THAT(socket(AF_NETLINK, SOCK_STREAM, protocol),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_SEQPACKET, protocol),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_RDM, protocol),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_DCCP, protocol),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_PACKET, protocol),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));

  int fd;
  EXPECT_THAT(fd = socket(AF_NETLINK, SOCK_DGRAM, protocol), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(fd = socket(AF_NETLINK, SOCK_RAW, protocol), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_P(NetlinkTest, AutomaticPort) {
  const int protocol = GetParam();

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, protocol));

  struct sockaddr_nl addr = {};
  addr.nl_family = AF_NETLINK;

  EXPECT_THAT(
      bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());

  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));
  // This is the only netlink socket in the process, so it should get the PID as
  // the port id.
  //
  // N.B. Another process could theoretically have explicitly reserved our pid
  // as a port ID, but that is very unlikely.
  EXPECT_EQ(addr.nl_pid, getpid());
}

// Calling connect automatically binds to an automatic port.
TEST_P(NetlinkTest, ConnectBinds) {
  const int protocol = GetParam();

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, protocol));

  struct sockaddr_nl addr = {};
  addr.nl_family = AF_NETLINK;

  EXPECT_THAT(connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));

  // Each test is running in a pid namespace, so another process can explicitly
  // reserve our pid as a port ID. In this case, a negative portid value will be
  // set.
  if (static_cast<pid_t>(addr.nl_pid) > 0) {
    EXPECT_EQ(addr.nl_pid, getpid());
  }

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;

  // Connecting again is allowed, but keeps the same port.
  EXPECT_THAT(connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));
  EXPECT_EQ(addr.nl_pid, getpid());
}

TEST_P(NetlinkTest, GetPeerName) {
  const int protocol = GetParam();

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, protocol));

  struct sockaddr_nl addr = {};
  socklen_t addrlen = sizeof(addr);

  EXPECT_THAT(getpeername(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, sizeof(addr));
  EXPECT_EQ(addr.nl_family, AF_NETLINK);
  // Peer is the kernel if we didn't connect elsewhere.
  EXPECT_EQ(addr.nl_pid, 0);
}

INSTANTIATE_TEST_SUITE_P(ProtocolTest, NetlinkTest,
                         ::testing::Values(NETLINK_ROUTE,
                                           NETLINK_KOBJECT_UEVENT));

}  // namespace

}  // namespace testing
}  // namespace gvisor
