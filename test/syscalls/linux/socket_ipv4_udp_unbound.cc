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

// Check that packets are not received without a group memebership. Default send
// interface configured by bind.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNoGroup) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  sockaddr_in senderAddr = {};
  senderAddr.sin_family = AF_INET;
  senderAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&senderAddr),
           sizeof(senderAddr)),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address. If multicast worked like unicast,
  // this would ensure that we get the packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Send the multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
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
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
              SyscallFailsWithErrno(ENETUNREACH));
}

// Check that not setting a default send interface prevents multicast packets
// from being sent. Group membership interface configured by NIC ID.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackNicNoDefaultSendIf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the second FD to the v4 any address to ensure that we can receive any
  // unicast packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
              SyscallFailsWithErrno(ENETUNREACH));
}

// Check that multicast works when the default send interface is configured by
// bind and the group membership is configured by address.
TEST_P(IPv4UDPUnboundSocketPairTest, IpMulticastLoopbackAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Bind the first FD to the loopback. This is an alternative to
  // IP_MULTICAST_IF for setting the default send interface.
  sockaddr_in senderAddr = {};
  senderAddr.sin_family = AF_INET;
  senderAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&senderAddr),
           sizeof(senderAddr)),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
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
  sockaddr_in senderAddr = {};
  senderAddr.sin_family = AF_INET;
  senderAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&senderAddr),
           sizeof(senderAddr)),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
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
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
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
  sockaddr_in senderAddr = {};
  senderAddr.sin_family = AF_INET;
  senderAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&senderAddr),
           sizeof(senderAddr)),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register and unregister to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
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
  sockaddr_in senderAddr = {};
  senderAddr.sin_family = AF_INET;
  senderAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_THAT(
      bind(sockets->first_fd(), reinterpret_cast<sockaddr*>(&senderAddr),
           sizeof(senderAddr)),
      SyscallSucceeds());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  sockaddr_in receiverAddr = {};
  receiverAddr.sin_family = AF_INET;
  receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sockets->second_fd(), reinterpret_cast<sockaddr*>(&receiverAddr),
           sizeof(receiverAddr)),
      SyscallSucceeds());
  socklen_t receiverAddrLen = sizeof(receiverAddr);
  EXPECT_THAT(
      getsockname(sockets->second_fd(),
                  reinterpret_cast<sockaddr*>(&receiverAddr), &receiverAddrLen),
      SyscallSucceeds());
  EXPECT_EQ(receiverAddrLen, sizeof(receiverAddr));

  // Register and unregister to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr("224.0.2.1");
  group.imr_ifindex = ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex("lo"));
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                         &group, sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  sockaddr_in sendAddr = {};
  sendAddr.sin_family = AF_INET;
  sendAddr.sin_port = receiverAddr.sin_port;
  sendAddr.sin_addr.s_addr = inet_addr("224.0.2.1");
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(RetryEINTR(sendto)(
                  sockets->first_fd(), send_buf, sizeof(send_buf), 0,
                  reinterpret_cast<sockaddr*>(&sendAddr), sizeof(sendAddr)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->second_fd(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

}  // namespace testing
}  // namespace gvisor
