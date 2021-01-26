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
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

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
  EXPECT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  EXPECT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
  EXPECT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
  ASSERT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  ASSERT_THAT(
      RecvTimeout(socket1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

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
  EXPECT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
  EXPECT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
      ASSERT_THAT(RecvTimeout(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                              1 /*timeout*/),
                  IsPosixErrorOkAndHolds(sizeof(recv_buf)));
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
      ASSERT_THAT(RecvTimeout(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                              1 /*timeout*/),
                  IsPosixErrorOkAndHolds(sizeof(recv_buf)));
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
      ASSERT_THAT(RecvTimeout(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                              1 /*timeout*/),
                  PosixErrorIs(EAGAIN, ::testing::_));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      PosixErrorIs(EAGAIN, ::testing::_));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
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
  ASSERT_THAT(
      RecvTimeout(socket2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that SO_REUSEADDR always delivers to the most recently bound socket.
//
// FIXME(gvisor.dev/issue/873): Endpoint order is not restored correctly. Enable
// random and co-op save (below) once that is fixed.
TEST_P(IPv4UDPUnboundSocketTest, ReuseAddrDistribution_NoRandomSave) {
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

  // FIXME(gvisor.dev/issue/873): Endpoint order is not restored correctly.
  const DisableSave ds;

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
        RecvTimeout(last->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
        IsPosixErrorOkAndHolds(sizeof(send_buf)));
    EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
  }

  // Verify that no other messages were received.
  for (auto& socket : sockets) {
    char recv_buf[kMessageSize] = {};
    EXPECT_THAT(
        RecvTimeout(socket->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
        PosixErrorIs(EAGAIN, ::testing::_));
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

  // Saving during each iteration of the following loop is too expensive.
  DisableSave ds;

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

  ds.reset();

  // Check that both receivers got messages. This checks that we are using load
  // balancing (REUSEPORT) instead of the most recently bound socket
  // (REUSEADDR).
  char recv_buf[kMessageSize] = {};
  EXPECT_THAT(
      RecvTimeout(receiver1->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(kMessageSize));
  EXPECT_THAT(
      RecvTimeout(receiver2->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(kMessageSize));
}

// Test that socket will receive packet info control message.
TEST_P(IPv4UDPUnboundSocketTest, SetAndReceiveIPPKTINFO) {
  // TODO(gvisor.dev/issue/1202): ioctl() is not supported by hostinet.
  SKIP_IF((IsRunningWithHostinet()));

  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto sender_addr = V4Loopback();
  int level = SOL_IP;
  int type = IP_PKTINFO;

  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());
  socklen_t sender_addr_len = sender_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&sender_addr.addr),
                          &sender_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(sender_addr_len, sender_addr.addr_len);

  auto receiver_addr = V4Loopback();
  reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&sender_addr.addr)->sin_port;
  ASSERT_THAT(
      connect(sender->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
              receiver_addr.addr_len),
      SyscallSucceeds());

  // Allow socket to receive control message.
  ASSERT_THAT(
      setsockopt(receiver->get(), level, type, &kSockOptOn, sizeof(kSockOptOn)),
      SyscallSucceeds());

  // Prepare message to send.
  constexpr size_t kDataLength = 1024;
  msghdr sent_msg = {};
  iovec sent_iov = {};
  char sent_data[kDataLength];
  sent_iov.iov_base = sent_data;
  sent_iov.iov_len = kDataLength;
  sent_msg.msg_iov = &sent_iov;
  sent_msg.msg_iovlen = 1;
  sent_msg.msg_flags = 0;

  ASSERT_THAT(RetryEINTR(sendmsg)(sender->get(), &sent_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  msghdr received_msg = {};
  iovec received_iov = {};
  char received_data[kDataLength];
  char received_cmsg_buf[CMSG_SPACE(sizeof(in_pktinfo))] = {};
  size_t cmsg_data_len = sizeof(in_pktinfo);
  received_iov.iov_base = received_data;
  received_iov.iov_len = kDataLength;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;
  received_msg.msg_controllen = CMSG_LEN(cmsg_data_len);
  received_msg.msg_control = received_cmsg_buf;

  ASSERT_THAT(RecvMsgTimeout(receiver->get(), &received_msg, 1 /*timeout*/),
              IsPosixErrorOkAndHolds(kDataLength));

  cmsghdr* cmsg = CMSG_FIRSTHDR(&received_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, level);
  EXPECT_EQ(cmsg->cmsg_type, type);

  // Get loopback index.
  ifreq ifr = {};
  absl::SNPrintF(ifr.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(sender->get(), SIOCGIFINDEX, &ifr), SyscallSucceeds());
  ASSERT_NE(ifr.ifr_ifindex, 0);

  // Check the data
  in_pktinfo received_pktinfo = {};
  memcpy(&received_pktinfo, CMSG_DATA(cmsg), sizeof(in_pktinfo));
  EXPECT_EQ(received_pktinfo.ipi_ifindex, ifr.ifr_ifindex);
  EXPECT_EQ(received_pktinfo.ipi_spec_dst.s_addr, htonl(INADDR_LOOPBACK));
  EXPECT_EQ(received_pktinfo.ipi_addr.s_addr, htonl(INADDR_LOOPBACK));
}

// Test that socket will receive IP_RECVORIGDSTADDR control message.
TEST_P(IPv4UDPUnboundSocketTest, SetAndReceiveIPReceiveOrigDstAddr) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver_addr = V4Loopback();
  int level = SOL_IP;
  int type = IP_RECVORIGDSTADDR;

  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());

  // Retrieve the port bound by the receiver.
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  ASSERT_THAT(
      connect(sender->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
              receiver_addr.addr_len),
      SyscallSucceeds());

  // Get address and port bound by the sender.
  sockaddr_storage sender_addr_storage;
  socklen_t sender_addr_len = sizeof(sender_addr_storage);
  ASSERT_THAT(getsockname(sender->get(),
                          reinterpret_cast<sockaddr*>(&sender_addr_storage),
                          &sender_addr_len),
              SyscallSucceeds());
  ASSERT_EQ(sender_addr_len, sizeof(struct sockaddr_in));

  // Enable IP_RECVORIGDSTADDR on socket so that we get the original destination
  // address of the datagram as auxiliary information in the control message.
  ASSERT_THAT(
      setsockopt(receiver->get(), level, type, &kSockOptOn, sizeof(kSockOptOn)),
      SyscallSucceeds());

  // Prepare message to send.
  constexpr size_t kDataLength = 1024;
  msghdr sent_msg = {};
  iovec sent_iov = {};
  char sent_data[kDataLength];
  sent_iov.iov_base = sent_data;
  sent_iov.iov_len = kDataLength;
  sent_msg.msg_iov = &sent_iov;
  sent_msg.msg_iovlen = 1;
  sent_msg.msg_flags = 0;

  ASSERT_THAT(RetryEINTR(sendmsg)(sender->get(), &sent_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  msghdr received_msg = {};
  iovec received_iov = {};
  char received_data[kDataLength];
  char received_cmsg_buf[CMSG_SPACE(sizeof(sockaddr_in))] = {};
  size_t cmsg_data_len = sizeof(sockaddr_in);
  received_iov.iov_base = received_data;
  received_iov.iov_len = kDataLength;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;
  received_msg.msg_controllen = CMSG_LEN(cmsg_data_len);
  received_msg.msg_control = received_cmsg_buf;

  ASSERT_THAT(RecvMsgTimeout(receiver->get(), &received_msg, 1 /*timeout*/),
              IsPosixErrorOkAndHolds(kDataLength));

  cmsghdr* cmsg = CMSG_FIRSTHDR(&received_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, level);
  EXPECT_EQ(cmsg->cmsg_type, type);

  // Check the data
  sockaddr_in received_addr = {};
  memcpy(&received_addr, CMSG_DATA(cmsg), sizeof(received_addr));
  auto orig_receiver_addr = reinterpret_cast<sockaddr_in*>(&receiver_addr.addr);
  EXPECT_EQ(received_addr.sin_addr.s_addr, orig_receiver_addr->sin_addr.s_addr);
  EXPECT_EQ(received_addr.sin_port, orig_receiver_addr->sin_port);
}

// Check that setting SO_RCVBUF below min is clamped to the minimum
// receive buffer size.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketRecvBufBelowMin) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Discover minimum buffer size by setting it to zero.
  constexpr int kRcvBufSz = 0;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                         sizeof(kRcvBufSz)),
              SyscallSucceeds());

  int min = 0;
  socklen_t min_len = sizeof(min);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &min, &min_len),
              SyscallSucceeds());

  // Linux doubles the value so let's use a value that when doubled will still
  // be smaller than min.
  int below_min = min / 2 - 1;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &below_min,
                         sizeof(below_min)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());

  ASSERT_EQ(min, val);
}

// Check that setting SO_RCVBUF above max is clamped to the maximum
// receive buffer size.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketRecvBufAboveMax) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Discover maxmimum buffer size by setting to a really large value.
  constexpr int kRcvBufSz = 0xffffffff;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                         sizeof(kRcvBufSz)),
              SyscallSucceeds());

  int max = 0;
  socklen_t max_len = sizeof(max);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &max, &max_len),
              SyscallSucceeds());

  int above_max = max + 1;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &above_max,
                         sizeof(above_max)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());
  ASSERT_EQ(max, val);
}

// Check that setting SO_RCVBUF min <= rcvBufSz <= max is honored.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketRecvBuf) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int max = 0;
  int min = 0;
  {
    // Discover maxmimum buffer size by setting to a really large value.
    constexpr int kRcvBufSz = 0xffffffff;
    ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                           sizeof(kRcvBufSz)),
                SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by setting it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                           sizeof(kRcvBufSz)),
                SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &quarter_sz,
                         sizeof(quarter_sz)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());

  // Linux doubles the value set by SO_SNDBUF/SO_RCVBUF.
  if (!IsRunningOnGvisor()) {
    quarter_sz *= 2;
  }
  ASSERT_EQ(quarter_sz, val);
}

// Check that setting SO_SNDBUF below min is clamped to the minimum
// send buffer size.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketSendBufBelowMin) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Discover minimum buffer size by setting it to zero.
  constexpr int kSndBufSz = 0;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &kSndBufSz,
                         sizeof(kSndBufSz)),
              SyscallSucceeds());

  int min = 0;
  socklen_t min_len = sizeof(min);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &min, &min_len),
              SyscallSucceeds());

  // Linux doubles the value so let's use a value that when doubled will still
  // be smaller than min.
  int below_min = min / 2 - 1;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &below_min,
                         sizeof(below_min)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  ASSERT_EQ(min, val);
}

// Check that setting SO_SNDBUF above max is clamped to the maximum
// send buffer size.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketSendBufAboveMax) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Discover maxmimum buffer size by setting to a really large value.
  constexpr int kSndBufSz = 0xffffffff;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &kSndBufSz,
                         sizeof(kSndBufSz)),
              SyscallSucceeds());

  int max = 0;
  socklen_t max_len = sizeof(max);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &max, &max_len),
              SyscallSucceeds());

  int above_max = max + 1;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &above_max,
                         sizeof(above_max)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());
  ASSERT_EQ(max, val);
}

// Check that setting SO_SNDBUF min <= kSndBufSz <= max is honored.
TEST_P(IPv4UDPUnboundSocketTest, SetSocketSendBuf) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int max = 0;
  int min = 0;
  {
    // Discover maxmimum buffer size by setting to a really large value.
    constexpr int kSndBufSz = 0xffffffff;
    ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &kSndBufSz,
                           sizeof(kSndBufSz)),
                SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by setting it to zero.
    constexpr int kSndBufSz = 0;
    ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &kSndBufSz,
                           sizeof(kSndBufSz)),
                SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(setsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &quarter_sz,
                         sizeof(quarter_sz)),
              SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s->get(), SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  quarter_sz *= 2;
  ASSERT_EQ(quarter_sz, val);
}

TEST_P(IPv4UDPUnboundSocketTest, IpMulticastIPPacketInfo) {
  auto sender_socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver_socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  auto sender_addr = V4Loopback();
  ASSERT_THAT(
      bind(sender_socket->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(bind(receiver_socket->get(),
                   reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver_socket->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  ASSERT_THAT(setsockopt(receiver_socket->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Register to receive IP packet info.
  const int one = 1;
  ASSERT_THAT(setsockopt(receiver_socket->get(), IPPROTO_IP, IP_PKTINFO, &one,
                         sizeof(one)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sender_socket->get(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&send_addr.addr),
                         send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  msghdr recv_msg = {};
  iovec recv_iov = {};
  char recv_buf[sizeof(send_buf)];
  char recv_cmsg_buf[CMSG_SPACE(sizeof(in_pktinfo))] = {};
  size_t cmsg_data_len = sizeof(in_pktinfo);
  recv_iov.iov_base = recv_buf;
  recv_iov.iov_len = sizeof(recv_buf);
  recv_msg.msg_iov = &recv_iov;
  recv_msg.msg_iovlen = 1;
  recv_msg.msg_controllen = CMSG_LEN(cmsg_data_len);
  recv_msg.msg_control = recv_cmsg_buf;
  ASSERT_THAT(RetryEINTR(recvmsg)(receiver_socket->get(), &recv_msg, 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));

  // Check the IP_PKTINFO control message.
  cmsghdr* cmsg = CMSG_FIRSTHDR(&recv_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, IPPROTO_IP);
  EXPECT_EQ(cmsg->cmsg_type, IP_PKTINFO);

  // Get loopback index.
  ifreq ifr = {};
  absl::SNPrintF(ifr.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(receiver_socket->get(), SIOCGIFINDEX, &ifr),
              SyscallSucceeds());
  ASSERT_NE(ifr.ifr_ifindex, 0);

  in_pktinfo received_pktinfo = {};
  memcpy(&received_pktinfo, CMSG_DATA(cmsg), sizeof(in_pktinfo));
  EXPECT_EQ(received_pktinfo.ipi_ifindex, ifr.ifr_ifindex);
  if (IsRunningOnGvisor()) {
    // This should actually be a unicast address assigned to the interface.
    //
    // TODO(gvisor.dev/issue/3556): This check is validating incorrect
    // behaviour. We still include the test so that once the bug is
    // resolved, this test will start to fail and the individual tasked
    // with fixing this bug knows to also fix this test :).
    EXPECT_EQ(received_pktinfo.ipi_spec_dst.s_addr, group.imr_multiaddr.s_addr);
  } else {
    EXPECT_EQ(received_pktinfo.ipi_spec_dst.s_addr, htonl(INADDR_LOOPBACK));
  }
  EXPECT_EQ(received_pktinfo.ipi_addr.s_addr, group.imr_multiaddr.s_addr);
}

}  // namespace testing
}  // namespace gvisor
