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
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

constexpr char kMulticastAddress[] = "224.0.2.1";
constexpr char kBroadcastAddress[] = "255.255.255.255";

TestAddress V4Multicast() {
  TestAddress t("V4Multicast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      inet_addr(kMulticastAddress);
  return t;
}

TestAddress V4Broadcast() {
  TestAddress t("V4Broadcast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      inet_addr(kBroadcastAddress);
  return t;
}

// Check that packets are not received without a group membership. Default send
// interface configured by bind.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackNoGroup) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address. If multicast worked like unicast,
  // this would ensure that we get the packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
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
  EXPECT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that not setting a default send interface prevents multicast packets
// from being sent. Group membership interface configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackAddrNoDefaultSendIf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive any
  // unicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallFailsWithErrno(ENETUNREACH));
}

// Check that not setting a default send interface prevents multicast packets
// from being sent. Group membership interface configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackNicNoDefaultSendIf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive any
  // unicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallFailsWithErrno(ENETUNREACH));
}

// Check that multicast works when the default send interface is configured by
// bind and the group membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// bind and the group membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfAddrConnect) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(socket1->get(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(send)(socket1->get(), send_buf, sizeof(send_buf), 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfNicConnect) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(socket1->get(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(send)(socket1->get(), send_buf, sizeof(send_buf), 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfAddrSelf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfNicSelf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfAddrSelfConnect) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  EXPECT_THAT(
      RetryEINTR(connect)(socket1->get(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(send)(socket1->get(), send_buf, sizeof(send_buf), 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in connect, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfNicSelfConnect) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto connect_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&connect_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(socket1->get(),
                          reinterpret_cast<sockaddr*>(&connect_addr.addr),
                          connect_addr.addr_len),
      SyscallSucceeds());

  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(send)(socket1->get(), send_buf, sizeof(send_buf), 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfAddrSelfNoLoop) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Bind the first FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast works when the default send interface is configured by
// IP_MULTICAST_IF, the send address is specified in sendto, and the group
// membership is configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastLoopbackIfNicSelfNoLoop) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Set the default send interface.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket1->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that dropping a group membership that does not exist fails.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastInvalidDrop) {
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

// Check that dropping a group membership prevents multicast packets from being
// delivered. Default send address configured by bind and group membership
// interface configured by address.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastDropAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register and unregister to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that dropping a group membership prevents multicast packets from being
// delivered. Default send address configured by bind and group membership
// interface configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketTest, IpMulticastDropNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  EXPECT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  EXPECT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register and unregister to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfZero) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn iface = {};
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfInvalidNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn iface = {};
  iface.imr_ifindex = -1;
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfInvalidAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreq iface = {};
  iface.imr_interface.s_addr = inet_addr("255.255.255");
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetShort) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Create a valid full-sized request.
  ip_mreqn iface = {};
  iface.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));

  // Send an optlen of 1 to check that optlen is enforced.
  EXPECT_THAT(
      setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface, 1),
      SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfDefault) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfDefaultReqn) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetAddrGetReqn) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetReqAddrGetReqn) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetNicGetReqn) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetAddr) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetReqAddr) {
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

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIfSetNic) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn set = {};
  set.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
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

TEST_P(IPv4UDPUnboundSocketTest, TestJoinGroupNoIf) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(ENODEV));
}

TEST_P(IPv4UDPUnboundSocketTest, TestJoinGroupInvalidIf) {
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
TEST_P(IPv4UDPUnboundSocketTest, TestMultipleJoinsOnSingleSocket) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto fd = socket1->get();
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
TEST_P(IPv4UDPUnboundSocketTest, TestTwoSocketsJoinSameMulticastGroup) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Drop the membership twice on each socket, the second call for each socket
  // should fail.
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Check that two sockets can join the same multicast group at the same time,
// and both will receive data on it.
TEST_P(IPv4UDPUnboundSocketTest, TestMcastReceptionOnTwoSockets) {
  std::unique_ptr<SocketPair> socket_pairs[2] = {
      absl::make_unique<FDSocketPair>(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()),
                                      ASSERT_NO_ERRNO_AND_VALUE(NewSocket())),
      absl::make_unique<FDSocketPair>(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()),
                                      ASSERT_NO_ERRNO_AND_VALUE(NewSocket()))};

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
TEST_P(IPv4UDPUnboundSocketTest, TestMcastReceptionWhenDroppingMemberships) {
  std::unique_ptr<SocketPair> socket_pairs[2] = {
      absl::make_unique<FDSocketPair>(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()),
                                      ASSERT_NO_ERRNO_AND_VALUE(NewSocket())),
      absl::make_unique<FDSocketPair>(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()),
                                      ASSERT_NO_ERRNO_AND_VALUE(NewSocket()))};

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

// Check that a receiving socket can bind to the multicast address before
// joining the group and receive data once the group has been joined.
TEST_P(IPv4UDPUnboundSocketTest, TestBindToMcastThenJoinThenReceive) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind second socket (receiver) to the multicast address.
  auto receiver_addr = V4Multicast();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  // Update receiver_addr with the correct port number.
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(socket2->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet on the first socket out the loopback interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());
  auto sendto_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that a receiving socket can bind to the multicast address and won't
// receive multicast data if it hasn't joined the group.
TEST_P(IPv4UDPUnboundSocketTest, TestBindToMcastThenNoJoinThenNoReceive) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind second socket (receiver) to the multicast address.
  auto receiver_addr = V4Multicast();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  // Update receiver_addr with the correct port number.
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Send a multicast packet on the first socket out the loopback interface.
  ip_mreq iface = {};
  iface.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(setsockopt(socket1->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());
  auto sendto_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we don't receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that a socket can bind to a multicast address and still send out
// packets.
TEST_P(IPv4UDPUnboundSocketTest, TestBindToMcastThenSend) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind second socket (receiver) to the ANY address.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Bind the first socket (sender) to the multicast address.
  auto sender_addr = V4Multicast();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());
  socklen_t sender_addr_len = sender_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&sender_addr.addr),
                          &sender_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(sender_addr_len, sender_addr.addr_len);

  // Send a packet on the first socket to the loopback address.
  auto sendto_addr = V4Loopback();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that a receiving socket can bind to the broadcast address and receive
// broadcast packets.
TEST_P(IPv4UDPUnboundSocketTest, TestBindToBcastThenReceive) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind second socket (receiver) to the broadcast address.
  auto receiver_addr = V4Broadcast();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Send a broadcast packet on the first socket out the loopback interface.
  EXPECT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));
  // Note: Binding to the loopback interface makes the broadcast go out of it.
  auto sender_bind_addr = V4Loopback();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_bind_addr.addr),
           sender_bind_addr.addr_len),
      SyscallSucceeds());
  auto sendto_addr = V4Broadcast();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that a socket can bind to the broadcast address and still send out
// packets.
TEST_P(IPv4UDPUnboundSocketTest, TestBindToBcastThenSend) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind second socket (receiver) to the ANY address.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(socket2->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(socket2->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Bind the first socket (sender) to the broadcast address.
  auto sender_addr = V4Broadcast();
  ASSERT_THAT(
      bind(socket1->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());
  socklen_t sender_addr_len = sender_addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&sender_addr.addr),
                          &sender_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(sender_addr_len, sender_addr.addr_len);

  // Send a packet on the first socket to the loopback address.
  auto sendto_addr = V4Loopback();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket1->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that SO_REUSEADDR always delivers to the most recently bound socket.
TEST_P(IPv4UDPUnboundSocketTest, ReuseAddrDistribution) {
  // FIXME(b/129164367): Support SO_REUSEADDR on UDP sockets.
  SKIP_IF(IsRunningOnGvisor());

  std::vector<std::unique_ptr<FileDescriptor>> sockets;
  sockets.emplace_back(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()));

  ASSERT_THAT(setsockopt(sockets[0]->get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(sockets[0]->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(sockets[0]->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  constexpr int kMessageSize = 200;

  for (int i = 0; i < 10; i++) {
    // Add a new receiver.
    sockets.emplace_back(ASSERT_NO_ERRNO_AND_VALUE(NewSocket()));
    auto& last = sockets.back();
    ASSERT_THAT(setsockopt(last->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(bind(last->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                     addr.addr_len),
                SyscallSucceeds());

    // Send a new message to the SO_REUSEADDR group. We use a new socket each
    // time so that a new ephemeral port will be used each time. This ensures
    // that we aren't doing REUSEPORT-like hash load blancing.
    auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
    char send_buf[kMessageSize];
    RandomizeBuffer(send_buf, sizeof(send_buf));
    EXPECT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                   reinterpret_cast<sockaddr*>(&addr.addr),
                                   addr.addr_len),
                SyscallSucceedsWithValue(sizeof(send_buf)));

    // Verify that the most recent socket got the message. We don't expect any
    // of the other sockets to have received it, but we will check that later.
    char recv_buf[sizeof(send_buf)] = {};
    EXPECT_THAT(
        RetryEINTR(recv)(last->get(), recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
        SyscallSucceedsWithValue(sizeof(send_buf)));
    EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
  }

  // Verify that no other messages were received.
  for (auto& socket : sockets) {
    char recv_buf[kMessageSize] = {};
    EXPECT_THAT(RetryEINTR(recv)(socket->get(), recv_buf, sizeof(recv_buf),
                                 MSG_DONTWAIT),
                SyscallFailsWithErrno(EAGAIN));
  }
}

TEST_P(IPv4UDPUnboundSocketTest, BindReuseAddrThenReusePort) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(IPv4UDPUnboundSocketTest, BindReusePortThenReuseAddr) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(IPv4UDPUnboundSocketTest, BindReuseAddrReusePortConvertibleToReusePort) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Bind socket3 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(IPv4UDPUnboundSocketTest, BindReuseAddrReusePortConvertibleToReuseAddr) {
  // FIXME(b/129164367): Support SO_REUSEADDR on UDP sockets.
  SKIP_IF(IsRunningOnGvisor());

  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Bind socket3 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(IPv4UDPUnboundSocketTest, BindReuseAddrReusePortConversionReversable1) {
  // FIXME(b/129164367): Support SO_REUSEADDR on UDP sockets.
  SKIP_IF(IsRunningOnGvisor());

  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Close socket2 to revert to just socket1 with REUSEADDR and REUSEPORT.
  socket2->reset();

  // Bind socket3 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
}

TEST_P(IPv4UDPUnboundSocketTest, BindReuseAddrReusePortConversionReversable2) {
  // FIXME(b/129164367): Support SO_REUSEADDR on UDP sockets.
  SKIP_IF(IsRunningOnGvisor());

  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Close socket2 to revert to just socket1 with REUSEADDR and REUSEPORT.
  socket2->reset();

  // Bind socket3 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
}

TEST_P(IPv4UDPUnboundSocketTest, BindDoubleReuseAddrReusePortThenReusePort) {
  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, also with REUSEADDR and
  // REUSEPORT.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Bind socket3 to the same address as socket1, only with REUSEPORT.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
}

TEST_P(IPv4UDPUnboundSocketTest, BindDoubleReuseAddrReusePortThenReuseAddr) {
  // FIXME(b/129164367): Support SO_REUSEADDR on UDP sockets.
  SKIP_IF(IsRunningOnGvisor());

  auto socket1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto socket3 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind socket1 with REUSEADDR and REUSEPORT.
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(socket1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(socket1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind socket2 to the same address as socket1, also with REUSEADDR and
  // REUSEPORT.
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(socket2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(bind(socket2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  // Bind socket3 to the same address as socket1, only with REUSEADDR.
  ASSERT_THAT(setsockopt(socket3->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(socket3->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
}

// Check that REUSEPORT takes precedence over REUSEADDR.
TEST_P(IPv4UDPUnboundSocketTest, ReuseAddrReusePortDistribution) {
  auto receiver1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ASSERT_THAT(setsockopt(receiver1->get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(receiver1->get(), SOL_SOCKET, SO_REUSEPORT,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(receiver1->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(receiver1->get(),
                          reinterpret_cast<sockaddr*>(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Bind receiver2 to the same address as socket1, also with REUSEADDR and
  // REUSEPORT.
  ASSERT_THAT(setsockopt(receiver2->get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(receiver2->get(), SOL_SOCKET, SO_REUSEPORT,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(receiver2->get(), reinterpret_cast<sockaddr*>(&addr.addr),
                   addr.addr_len),
              SyscallSucceeds());

  constexpr int kMessageSize = 10;

  for (int i = 0; i < 100; ++i) {
    // Send a new message to the REUSEADDR/REUSEPORT group. We use a new socket
    // each time so that a new ephemerial port will be used each time. This
    // ensures that we cycle through hashes.
    auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
    char send_buf[kMessageSize] = {};
    EXPECT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                   reinterpret_cast<sockaddr*>(&addr.addr),
                                   addr.addr_len),
                SyscallSucceedsWithValue(sizeof(send_buf)));
  }

  // Check that both receivers got messages. This checks that we are using load
  // balancing (REUSEPORT) instead of the most recently bound socket
  // (REUSEADDR).
  char recv_buf[kMessageSize] = {};
  EXPECT_THAT(RetryEINTR(recv)(receiver1->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(kMessageSize));
  EXPECT_THAT(RetryEINTR(recv)(receiver2->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallSucceedsWithValue(kMessageSize));
}

}  // namespace testing
}  // namespace gvisor
