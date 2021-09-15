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

#include "test/syscalls/linux/socket_ipv4_datagram_based_socket_unbound.h"

#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/capability_util.h"

namespace gvisor {
namespace testing {

void IPv4DatagramBasedUnboundSocketTest::SetUp() {
  if (GetParam().type & SOCK_RAW) {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));
  }
}

// Check that dropping a group membership that does not exist fails.
TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastInvalidDrop) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Unregister from a membership that we didn't have.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfZero) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn iface = {};
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfInvalidNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn iface = {};
  iface.imr_ifindex = -1;
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfInvalidAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreq iface = {};
  iface.imr_interface.s_addr = inet_addr("255.255.255");
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetShort) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Create a valid full-sized request.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());

  // Send an optlen of 1 to check that optlen is enforced.
  EXPECT_THAT(
      setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface, 1),
      SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfDefault) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfDefaultReqn) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  // getsockopt(IP_MULTICAST_IF) can only return an in_addr, so it treats the
  // first sizeof(struct in_addr) bytes of struct ip_mreqn as a struct in_addr.
  // Conveniently, this corresponds to the field ip_mreqn::imr_multiaddr.
  EXPECT_EQ(size, sizeof(in_addr));

  // getsockopt(IP_MULTICAST_IF) will only return the interface address which
  // hasn't been set.
  EXPECT_EQ(get.imr_multiaddr.s_addr, 0);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetAddrGetReqn) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  in_addr set = {};
  set.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  // getsockopt(IP_MULTICAST_IF) can only return an in_addr, so it treats the
  // first sizeof(struct in_addr) bytes of struct ip_mreqn as a struct in_addr.
  // Conveniently, this corresponds to the field ip_mreqn::imr_multiaddr.
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, set.s_addr);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetReqAddrGetReqn) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreq set = {};
  set.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  // getsockopt(IP_MULTICAST_IF) can only return an in_addr, so it treats the
  // first sizeof(struct in_addr) bytes of struct ip_mreqn as a struct in_addr.
  // Conveniently, this corresponds to the field ip_mreqn::imr_multiaddr.
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, set.imr_interface.s_addr);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetNicGetReqn) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, 0);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  in_addr set = {};
  set.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, set.s_addr);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetReqAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreq set = {};
  set.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, set.imr_interface.s_addr);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, IpMulticastIfSetNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, 0);
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, TestJoinGroupNoIf) {
  // TODO(b/185517803): Fix for native test.
  SKIP_IF(!IsRunningOnGvisor());
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(ENODEV));
}

TEST_P(IPv4DatagramBasedUnboundSocketTest, TestJoinGroupInvalidIf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn group = {};
  group.imr_address.s_addr = inet_addr("255.255.255");
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(ENODEV));
}

// Check that multiple memberships are not allowed on the same socket.
TEST_P(IPv4DatagramBasedUnboundSocketTest, TestMultipleJoinsOnSingleSocket) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto fd = socket1->get();
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());

  EXPECT_THAT(
      setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)),
      SyscallSucceeds());

  EXPECT_THAT(
      setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)),
      SyscallFailsWithErrno(EADDRINUSE));
}

}  // namespace testing
}  // namespace gvisor
