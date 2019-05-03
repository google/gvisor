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
  ASSERT_THAT(getsockname(sockets->second_fd(),
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
  ASSERT_THAT(getsockname(sockets->second_fd(),
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
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
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
  ASSERT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
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

// Check that multicast works when the default send interface is configured by
// bind and the group membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  ASSERT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
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

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
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

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
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

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfAddrConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), send_buf, sizeof(send_buf), 0),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfNicConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->second_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), send_buf, sizeof(send_buf), 0),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfAddrSelf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfNicSelf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfAddrSelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  EXPECT_THAT(
      RetryEINTR(connect)(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), send_buf, sizeof(send_buf), 0),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfNicSelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), send_buf, sizeof(send_buf), 0),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfAddrSelfNoLoop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf), 0),
      SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackIfNicSelfNoLoop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(sockets->first_fd(), recv_buf, sizeof(recv_buf), 0),
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
  ASSERT_THAT(getsockname(sockets->second_fd(),
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
  ASSERT_THAT(getsockname(sockets->second_fd(),
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

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfZero) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn iface = {};
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallSucceeds());
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfInvalidNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn iface = {};
  iface.imr_ifindex = -1;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfInvalidAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreq iface = {};
  iface.imr_interface.s_addr = inet_addr("255.255.255");
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                         &iface, sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetShort) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Create a valid full-sized request.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));

  // Send an optlen of 1 to check that optlen is enforced.
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &iface, 1),
      SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, 0);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfDefaultReqn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
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

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetAddrGetReqn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  in_addr set = {};
  set.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  // getsockopt(IP_MULTICAST_IF) can only return an in_addr, so it treats the
  // first sizeof(struct in_addr) bytes of struct ip_mreqn as a struct in_addr.
  // Conveniently, this corresponds to the field ip_mreqn::imr_multiaddr.
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, set.s_addr);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetReqAddrGetReqn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreq set = {};
  set.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  // getsockopt(IP_MULTICAST_IF) can only return an in_addr, so it treats the
  // first sizeof(struct in_addr) bytes of struct ip_mreqn as a struct in_addr.
  // Conveniently, this corresponds to the field ip_mreqn::imr_multiaddr.
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, set.imr_interface.s_addr);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetNicGetReqn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  ip_mreqn get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(in_addr));
  EXPECT_EQ(get.imr_multiaddr.s_addr, 0);
  EXPECT_EQ(get.imr_address.s_addr, 0);
  EXPECT_EQ(get.imr_ifindex, 0);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  in_addr set = {};
  set.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, set.s_addr);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetReqAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreq set = {};
  set.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());

  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, set.imr_interface.s_addr);
}

TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastIfSetNic) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &set,
                         sizeof(set)),
              SyscallSucceeds());

  in_addr get = {};
  socklen_t size = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF, &get, &size),
      SyscallSucceeds());
  EXPECT_EQ(size, sizeof(get));
  EXPECT_EQ(get.s_addr, 0);
}

TEST_P(IPv4UDPUnboundSocketPairTest, TestJoinGroupNoIf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallFailsWithErrno(ENODEV));
}

TEST_P(IPv4UDPUnboundSocketPairTest, TestJoinGroupInvalidIf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn group = {};
  group.imr_address.s_addr = inet_addr("255.255.255");
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallFailsWithErrno(ENODEV));
}

// Check that multiple memberships are not allowed on the same socket.
TEST_P(IPv4UDPUnboundSocketPairTest, TestMultipleJoinsOnSingleSocket) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  auto fd = sockets->first_fd();
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));

  EXPECT_THAT(
      setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)),
      SyscallSucceeds());

  EXPECT_THAT(
      setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)),
      SyscallFailsWithErrno(EADDRINUSE));
}

// Check that two sockets can join the same multicast group at the same time.
TEST_P(IPv4UDPUnboundSocketPairTest, TestTwoSocketsJoinSameMulticastGroup) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Drop the membership twice on each socket, the second call for each socket
  // should fail.
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Check that two sockets can join the same multicast group at the same time,
// and both will receive data on it.
TEST_P(IPv4UDPUnboundSocketPairTest, TestMcastReceptionOnTwoSockets) {
  std::unique_ptr<SocketPair> socket_pairs[2] = {
      ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair()),
      ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair())};

  ip_mreq iface = {}, group = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  auto receiver_addr = V4Any();
  int bound_port = 0;

  // Create two socketpairs with the exact same configuration.
  for (auto& sockets : socket_pairs) {
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                           &iface, sizeof(iface)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_REUSEPORT,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &group, sizeof(group)),
                SyscallSucceeds());
    ASSERT_THAT(bind(sockets->second_fd(),
                     reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                     receiver_addr.addr_len),
                SyscallSucceeds());
    // Get the port assigned.
    socklen_t receiver_addr_len = receiver_addr.addr_len;
    ASSERT_THAT(getsockname(sockets->second_fd(),
                            reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                            &receiver_addr_len),
                SyscallSucceeds());
    EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
    // On the first iteration, save the port we are bound to. On the second
    // iteration, verify the port is the same as the one from the first
    // iteration. In other words, both sockets listen on the same port.
    if (bound_port == 0) {
      bound_port =
          reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
    } else {
      EXPECT_EQ(bound_port,
                reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port);
    }
  }

  // Send a multicast packet to the group from two different sockets and verify
  // it is received by both sockets that joined that group.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port = bound_port;
  for (auto& sockets : socket_pairs) {
    char send_buf[200];
    RandomizeBuffer(send_buf, sizeof(send_buf));
    ASSERT_THAT(
        RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                           reinterpret_cast<sockaddr*>(&send_addr.addr),
                           send_addr.addr_len),
        SyscallSucceedsWithValue(sizeof(send_buf)));

    // Check that we received the multicast packet on both sockets.
    for (auto& sockets : socket_pairs) {
      char recv_buf[sizeof(send_buf)] = {};
      ASSERT_THAT(
          RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
          SyscallSucceedsWithValue(sizeof(recv_buf)));
      EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
    }
  }
}

// Check that on two sockets that joined a group and listen on ANY, dropping
// memberships one by one will continue to deliver packets to both sockets until
// both memberships have been dropped.
TEST_P(IPv4UDPUnboundSocketPairTest,
       TestMcastReceptionWhenDroppingMemberships) {
  std::unique_ptr<SocketPair> socket_pairs[2] = {
      ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair()),
      ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair())};

  ip_mreq iface = {}, group = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  auto receiver_addr = V4Any();
  int bound_port = 0;

  // Create two socketpairs with the exact same configuration.
  for (auto& sockets : socket_pairs) {
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_IF,
                           &iface, sizeof(iface)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_REUSEPORT,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &group, sizeof(group)),
                SyscallSucceeds());
    ASSERT_THAT(bind(sockets->second_fd(),
                     reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                     receiver_addr.addr_len),
                SyscallSucceeds());
    // Get the port assigned.
    socklen_t receiver_addr_len = receiver_addr.addr_len;
    ASSERT_THAT(getsockname(sockets->second_fd(),
                            reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                            &receiver_addr_len),
                SyscallSucceeds());
    EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
    // On the first iteration, save the port we are bound to. On the second
    // iteration, verify the port is the same as the one from the first
    // iteration. In other words, both sockets listen on the same port.
    if (bound_port == 0) {
      bound_port =
          reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
    } else {
      EXPECT_EQ(bound_port,
                reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port);
    }
  }

  // Drop the membership of the first socket pair and verify data is still
  // received.
  ASSERT_THAT(setsockopt(socket_pairs[0]->second_fd(), IPPROTO_IP,
                         IP_DROP_MEMBERSHIP, &group, sizeof(group)),
              SyscallSucceeds());
  // Send a packet from each socket_pair.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port = bound_port;
  for (auto& sockets : socket_pairs) {
    char send_buf[200];
    RandomizeBuffer(send_buf, sizeof(send_buf));
    ASSERT_THAT(
        RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                           reinterpret_cast<sockaddr*>(&send_addr.addr),
                           send_addr.addr_len),
        SyscallSucceedsWithValue(sizeof(send_buf)));

    // Check that we received the multicast packet on both sockets.
    for (auto& sockets : socket_pairs) {
      char recv_buf[sizeof(send_buf)] = {};
      ASSERT_THAT(
          RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf), 0),
          SyscallSucceedsWithValue(sizeof(recv_buf)));
      EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
    }
  }

  // Drop the membership of the second socket pair and verify data stops being
  // received.
  ASSERT_THAT(setsockopt(socket_pairs[1]->second_fd(), IPPROTO_IP,
                         IP_DROP_MEMBERSHIP, &group, sizeof(group)),
              SyscallSucceeds());
  // Send a packet from each socket_pair.
  for (auto& sockets : socket_pairs) {
    char send_buf[200];
    ASSERT_THAT(
        RetryEINTR(sendto)(sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                           reinterpret_cast<sockaddr*>(&send_addr.addr),
                           send_addr.addr_len),
        SyscallSucceedsWithValue(sizeof(send_buf)));

    char recv_buf[sizeof(send_buf)] = {};
    for (auto& sockets : socket_pairs) {
      ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), recv_buf,
                                   sizeof(recv_buf), MSG_DONTWAIT),
                  SyscallFailsWithErrno(EAGAIN));
    }
  }
}

}  // namespace testing
}  // namespace gvisor
