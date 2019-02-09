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

#include "test/syscalls/linux/socket_ipv4_udp_unbound.h"

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

constexpr char kMulticastAddress[] = "224.0.2.1";

TestAddress V4Multicast() {
  TestAddress t("V4Multicast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      inet_addr(kMulticastAddress);
  return t;
}

// Check that packets are not received without a group memebership. Default send
// interface configured by bind.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNoGroup) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address. If multicast worked like unicast,
  // this would ensure that we get the packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Send the multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that not setting a default send interface prevents multicast packets
// from being sent. Group membership interface configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackAddrNoDefaultSendIf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the second FD to the v4 any address to ensure that we can receive any
  // unicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallFailsWithErrno(ENETUNREACH));
}

// Check that not setting a default send interface prevents multicast packets
// from being sent. Group membership interface configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNicNoDefaultSendIf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the second FD to the v4 any address to ensure that we can receive any
  // unicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallFailsWithErrno(ENETUNREACH));
}

// Check that multicast works when the default send interface is configured by
// bind and the group membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is confgured by
// bind and the group membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that dropping a group membership that does not exist fails.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastInvalidDrop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Unregister from a membership that we didn't have.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Check that dropping a group membership prevents multicast packets from being
// delivered. Default send address configured by bind and group membership
// interface configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastDropAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register and unregister to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that dropping a group membership prevents multicast packets from being
// delivered. Default send address configured by bind and group membership
// interface configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastDropNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  EXPECT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register and unregister to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

}  // namespace testing
}  // namespace gvisor
