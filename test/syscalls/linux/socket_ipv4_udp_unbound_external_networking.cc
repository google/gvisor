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

#include "test/syscalls/linux/socket_ipv4_udp_unbound_external_networking.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TestAddress V4EmptyAddress() {
  TestAddress t("V4Empty");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  return t;
}

void IPv4UDPUnboundExternalNetworkingSocketTest::SetUp() {
  got_if_infos_ = false;

  // Get interface list.
  std::vector<std::string> if_names;
  ASSERT_NO_ERRNO(if_helper_.Load());
  if_names = if_helper_.InterfaceList(AF_INET);
  if (if_names.size() != 2) {
    return;
  }

  // Figure out which interface is where.
  int lo = 0, eth = 1;
  if (if_names[lo] != "lo") {
    lo = 1;
    eth = 0;
  }

  if (if_names[lo] != "lo") {
    return;
  }

  lo_if_idx_ = ASSERT_NO_ERRNO_AND_VALUE(if_helper_.GetIndex(if_names[lo]));
  lo_if_addr_ = if_helper_.GetAddr(AF_INET, if_names[lo]);
  if (lo_if_addr_ == nullptr) {
    return;
  }
  lo_if_sin_addr_ = reinterpret_cast<sockaddr_in*>(lo_if_addr_)->sin_addr;

  eth_if_idx_ = ASSERT_NO_ERRNO_AND_VALUE(if_helper_.GetIndex(if_names[eth]));
  eth_if_addr_ = if_helper_.GetAddr(AF_INET, if_names[eth]);
  if (eth_if_addr_ == nullptr) {
    return;
  }
  eth_if_sin_addr_ = reinterpret_cast<sockaddr_in*>(eth_if_addr_)->sin_addr;

  got_if_infos_ = true;
}

// Verifies that a newly instantiated UDP socket does not have the
// broadcast socket option enabled.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, UDPBroadcastDefault) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get = -1;
  socklen_t get_sz = sizeof(get);
  EXPECT_THAT(
      getsockopt(socket->get(), SOL_SOCKET, SO_BROADCAST, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOff);
  EXPECT_EQ(get_sz, sizeof(get));
}

// Verifies that a newly instantiated UDP socket returns true after enabling
// the broadcast socket option.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, SetUDPBroadcast) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  EXPECT_THAT(setsockopt(socket->get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_sz = sizeof(get);
  EXPECT_THAT(
      getsockopt(socket->get(), SOL_SOCKET, SO_BROADCAST, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOn);
  EXPECT_EQ(get_sz, sizeof(get));
}

// Verifies that a broadcast UDP packet will arrive at all UDP sockets with
// the destination port number.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       UDPBroadcastReceivedOnAllExpectedEndpoints) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcvr1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcvr2 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto norcv = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Enable SO_BROADCAST on the sending socket.
  ASSERT_THAT(setsockopt(sender->get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  // Enable SO_REUSEPORT on the receiving sockets so that they may both be bound
  // to the broadcast messages destination port.
  ASSERT_THAT(setsockopt(rcvr1->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(setsockopt(rcvr2->get(), SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  sockaddr_in rcv_addr = {};
  socklen_t rcv_addr_sz = sizeof(rcv_addr);
  rcv_addr.sin_family = AF_INET;
  rcv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ASSERT_THAT(bind(rcvr1->get(), reinterpret_cast<struct sockaddr*>(&rcv_addr),
                   rcv_addr_sz),
              SyscallSucceedsWithValue(0));
  // Retrieve port number from first socket so that it can be bound to the
  // second socket.
  rcv_addr = {};
  ASSERT_THAT(
      getsockname(rcvr1->get(), reinterpret_cast<struct sockaddr*>(&rcv_addr),
                  &rcv_addr_sz),
      SyscallSucceedsWithValue(0));
  ASSERT_THAT(bind(rcvr2->get(), reinterpret_cast<struct sockaddr*>(&rcv_addr),
                   rcv_addr_sz),
              SyscallSucceedsWithValue(0));

  // Bind the non-receiving socket to an ephemeral port.
  sockaddr_in norcv_addr = {};
  norcv_addr.sin_family = AF_INET;
  norcv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ASSERT_THAT(
      bind(norcv->get(), reinterpret_cast<struct sockaddr*>(&norcv_addr),
           sizeof(norcv_addr)),
      SyscallSucceedsWithValue(0));

  // Broadcast a test message.
  sockaddr_in dst_addr = {};
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
  dst_addr.sin_port = rcv_addr.sin_port;
  constexpr char kTestMsg[] = "hello, world";
  EXPECT_THAT(
      sendto(sender->get(), kTestMsg, sizeof(kTestMsg), 0,
             reinterpret_cast<struct sockaddr*>(&dst_addr), sizeof(dst_addr)),
      SyscallSucceedsWithValue(sizeof(kTestMsg)));

  // Verify that the receiving sockets received the test message.
  char buf[sizeof(kTestMsg)] = {};
  EXPECT_THAT(read(rcvr1->get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(kTestMsg)));
  EXPECT_EQ(0, memcmp(buf, kTestMsg, sizeof(kTestMsg)));
  memset(buf, 0, sizeof(buf));
  EXPECT_THAT(read(rcvr2->get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(kTestMsg)));
  EXPECT_EQ(0, memcmp(buf, kTestMsg, sizeof(kTestMsg)));

  // Verify that the non-receiving socket did not receive the test message.
  memset(buf, 0, sizeof(buf));
  EXPECT_THAT(RetryEINTR(recv)(norcv->get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Verifies that a UDP broadcast sent via the loopback interface is not received
// by the sender.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       UDPBroadcastViaLoopbackFails) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Enable SO_BROADCAST.
  ASSERT_THAT(setsockopt(sender->get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  // Bind the sender to the loopback interface.
  sockaddr_in src = {};
  socklen_t src_sz = sizeof(src);
  src.sin_family = AF_INET;
  src.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_THAT(
      bind(sender->get(), reinterpret_cast<struct sockaddr*>(&src), src_sz),
      SyscallSucceedsWithValue(0));
  ASSERT_THAT(getsockname(sender->get(),
                          reinterpret_cast<struct sockaddr*>(&src), &src_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(src.sin_addr.s_addr, htonl(INADDR_LOOPBACK));

  // Send the message.
  sockaddr_in dst = {};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
  dst.sin_port = src.sin_port;
  constexpr char kTestMsg[] = "hello, world";
  EXPECT_THAT(sendto(sender->get(), kTestMsg, sizeof(kTestMsg), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)),
              SyscallSucceedsWithValue(sizeof(kTestMsg)));

  // Verify that the message was not received by the sender (loopback).
  char buf[sizeof(kTestMsg)] = {};
  EXPECT_THAT(RetryEINTR(recv)(sender->get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Verifies that a UDP broadcast fails to send on a socket with SO_BROADCAST
// disabled.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendBroadcast) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Broadcast a test message without having enabled SO_BROADCAST on the sending
  // socket.
  sockaddr_in addr = {};
  socklen_t addr_sz = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(12345);
  addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
  constexpr char kTestMsg[] = "hello, world";

  EXPECT_THAT(sendto(sender->get(), kTestMsg, sizeof(kTestMsg), 0,
                     reinterpret_cast<struct sockaddr*>(&addr), addr_sz),
              SyscallFailsWithErrno(EACCES));
}

// Verifies that a UDP unicast on an unbound socket reaches its destination.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendUnicastOnUnbound) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcvr = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the receiver and retrieve its address and port number.
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(0);
  ASSERT_THAT(bind(rcvr->get(), reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceedsWithValue(0));
  memset(&addr, 0, sizeof(addr));
  socklen_t addr_sz = sizeof(addr);
  ASSERT_THAT(getsockname(rcvr->get(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addr_sz),
              SyscallSucceedsWithValue(0));

  // Send a test message to the receiver.
  constexpr char kTestMsg[] = "hello, world";
  ASSERT_THAT(sendto(sender->get(), kTestMsg, sizeof(kTestMsg), 0,
                     reinterpret_cast<struct sockaddr*>(&addr), addr_sz),
              SyscallSucceedsWithValue(sizeof(kTestMsg)));
  char buf[sizeof(kTestMsg)] = {};
  ASSERT_THAT(read(rcvr->get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(kTestMsg)));
}

constexpr char kMulticastAddress[] = "224.0.2.1";

TestAddress V4Multicast() {
  TestAddress t("V4Multicast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      inet_addr(kMulticastAddress);
  return t;
}

// Check that multicast packets won't be delivered to the sending socket with no
// set interface or group membership.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       TestSendMulticastSelfNoGroup) {
  // FIXME(b/125485338): A group membership is not required for external
  // multicast on gVisor.
  SKIP_IF(IsRunningOnGvisor());

  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto bind_addr = V4Any();
  ASSERT_THAT(bind(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                   bind_addr.addr_len),
              SyscallSucceeds());
  socklen_t bind_addr_len = bind_addr.addr_len;
  ASSERT_THAT(
      getsockname(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                  &bind_addr_len),
      SyscallSucceeds());
  EXPECT_EQ(bind_addr_len, bind_addr.addr_len);

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&bind_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(socket->get(), recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
      SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast packets will be delivered to the sending socket without
// setting an interface.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendMulticastSelf) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto bind_addr = V4Any();
  ASSERT_THAT(bind(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                   bind_addr.addr_len),
              SyscallSucceeds());
  socklen_t bind_addr_len = bind_addr.addr_len;
  ASSERT_THAT(
      getsockname(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                  &bind_addr_len),
      SyscallSucceeds());
  EXPECT_EQ(bind_addr_len, bind_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&bind_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(socket->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast packets won't be delivered to the sending socket with no
// set interface and IP_MULTICAST_LOOP disabled.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       TestSendMulticastSelfLoopOff) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto bind_addr = V4Any();
  ASSERT_THAT(bind(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                   bind_addr.addr_len),
              SyscallSucceeds());
  socklen_t bind_addr_len = bind_addr.addr_len;
  ASSERT_THAT(
      getsockname(socket->get(), reinterpret_cast<sockaddr*>(&bind_addr.addr),
                  &bind_addr_len),
      SyscallSucceeds());
  EXPECT_EQ(bind_addr_len, bind_addr.addr_len);

  // Disable multicast looping.
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Register to receive multicast packets.
  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&bind_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(socket->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(
      RetryEINTR(recv)(socket->get(), recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
      SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast packets won't be delivered to another socket with no
// set interface or group membership.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendMulticastNoGroup) {
  // FIXME(b/125485338): A group membership is not required for external
  // multicast on gVisor.
  SKIP_IF(IsRunningOnGvisor());

  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast packets will be delivered to another socket without
// setting an interface.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendMulticast) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that multicast packets won't be delivered to another socket with no
// set interface and IP_MULTICAST_LOOP disabled on the sending socket.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       TestSendMulticastSenderNoLoop) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Disable multicast looping on the sender.
  EXPECT_THAT(setsockopt(sender->get(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  EXPECT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we did not receive the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Check that multicast packets will be delivered to the sending socket without
// setting an interface and IP_MULTICAST_LOOP disabled on the receiving socket.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       TestSendMulticastReceiverNoLoop) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind the second FD to the v4 any address to ensure that we can receive the
  // multicast packet.
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Disable multicast looping on the receiver.
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Register to receive multicast packets.
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

// Check that two sockets can join the same multicast group at the same time,
// and both will receive data on it.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest, TestSendMulticastToTwo) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  std::unique_ptr<FileDescriptor> receivers[2] = {
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket()),
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket())};

  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  auto receiver_addr = V4Any();
  int bound_port = 0;
  for (auto& receiver : receivers) {
    ASSERT_THAT(setsockopt(receiver->get(), SOL_SOCKET, SO_REUSEPORT,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
    // Bind the receiver to the v4 any address to ensure that we can receive the
    // multicast packet.
    ASSERT_THAT(
        bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
             receiver_addr.addr_len),
        SyscallSucceeds());
    socklen_t receiver_addr_len = receiver_addr.addr_len;
    ASSERT_THAT(getsockname(receiver->get(),
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

    // Register to receive multicast packets.
    ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &group, sizeof(group)),
                SyscallSucceeds());
  }

  // Send a multicast packet to the group and verify both receivers get it.
  auto send_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&send_addr.addr)->sin_port = bound_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&send_addr.addr),
                                 send_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));
  for (auto& receiver : receivers) {
    char recv_buf[sizeof(send_buf)] = {};
    ASSERT_THAT(
        RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf), 0),
        SyscallSucceedsWithValue(sizeof(recv_buf)));
    EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
  }
}

// Check that when receiving a looped-back multicast packet, its source address
// is not a multicast address.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       IpMulticastLoopbackFromAddr) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
  int receiver_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;

  ip_mreq group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Connect to the multicast address. This binds us to the outgoing interface
  // and allows us to get its IP (to be compared against the src-IP on the
  // receiver side).
  auto sendto_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port = receiver_port;
  ASSERT_THAT(RetryEINTR(connect)(
                  sender->get(), reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                  sendto_addr.addr_len),
              SyscallSucceeds());
  auto sender_addr = V4EmptyAddress();
  ASSERT_THAT(
      getsockname(sender->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
                  &sender_addr.addr_len),
      SyscallSucceeds());
  ASSERT_EQ(sizeof(struct sockaddr_in), sender_addr.addr_len);
  sockaddr_in* sender_addr_in =
      reinterpret_cast<sockaddr_in*>(&sender_addr.addr);

  // Send a multicast packet.
  char send_buf[4] = {};
  ASSERT_THAT(RetryEINTR(send)(sender->get(), send_buf, sizeof(send_buf), 0),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Receive a multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  auto src_addr = V4EmptyAddress();
  ASSERT_THAT(
      RetryEINTR(recvfrom)(receiver->get(), recv_buf, sizeof(recv_buf), 0,
                           reinterpret_cast<sockaddr*>(&src_addr.addr),
                           &src_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(recv_buf)));
  ASSERT_EQ(sizeof(struct sockaddr_in), src_addr.addr_len);
  sockaddr_in* src_addr_in = reinterpret_cast<sockaddr_in*>(&src_addr.addr);

  // Verify that the received source IP:port matches the sender one.
  EXPECT_EQ(sender_addr_in->sin_port, src_addr_in->sin_port);
  EXPECT_EQ(sender_addr_in->sin_addr.s_addr, src_addr_in->sin_addr.s_addr);
}

// Check that when setting the IP_MULTICAST_IF option to both an index pointing
// to the loopback interface and an address pointing to the non-loopback
// interface, a multicast packet sent out uses the latter as its source address.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       IpMulticastLoopbackIfNicAndAddr) {
  // FIXME(b/137899561): Linux instance for syscall tests sometimes misses its
  // IPv4 address on eth0.
  SKIP_IF(!got_if_infos_);

  // Create receiver, bind to ANY and join the multicast group.
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
  int receiver_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  ip_mreqn group = {};
  group.imr_multiaddr.s_addr = inet_addr(kMulticastAddress);
  group.imr_ifindex = lo_if_idx_;
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &group,
                         sizeof(group)),
              SyscallSucceeds());

  // Set outgoing multicast interface config, with NIC and addr pointing to
  // different interfaces.
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  ip_mreqn iface = {};
  iface.imr_ifindex = lo_if_idx_;
  iface.imr_address = eth_if_sin_addr_;
  ASSERT_THAT(setsockopt(sender->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                         sizeof(iface)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto sendto_addr = V4Multicast();
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port = receiver_port;
  char send_buf[4] = {};
  ASSERT_THAT(RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Receive a multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  auto src_addr = V4EmptyAddress();
  ASSERT_THAT(
      RetryEINTR(recvfrom)(receiver->get(), recv_buf, sizeof(recv_buf), 0,
                           reinterpret_cast<sockaddr*>(&src_addr.addr),
                           &src_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(recv_buf)));
  ASSERT_EQ(sizeof(struct sockaddr_in), src_addr.addr_len);
  sockaddr_in* src_addr_in = reinterpret_cast<sockaddr_in*>(&src_addr.addr);

  // FIXME (b/137781162): When sending a multicast packet use the proper logic
  // to determine the packet's src-IP.
  SKIP_IF(IsRunningOnGvisor());

  // Verify the received source address.
  EXPECT_EQ(eth_if_sin_addr_.s_addr, src_addr_in->sin_addr.s_addr);
}

// Check that when we are bound to one interface we can set IP_MULTICAST_IF to
// another interface.
TEST_P(IPv4UDPUnboundExternalNetworkingSocketTest,
       IpMulticastLoopbackBindToOneIfSetMcastIfToAnother) {
  // FIXME(b/137899561): Linux instance for syscall tests sometimes misses its
  // IPv4 address on eth0.
  SKIP_IF(!got_if_infos_);

  // FIXME (b/137790511): When bound to one interface it is not possible to set
  // IP_MULTICAST_IF to a different interface.
  SKIP_IF(IsRunningOnGvisor());

  // Create sender and bind to eth interface.
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  ASSERT_THAT(bind(sender->get(), eth_if_addr_, sizeof(sockaddr_in)),
              SyscallSucceeds());

  // Run through all possible combinations of index and address for
  // IP_MULTICAST_IF that selects the loopback interface.
  struct {
    int imr_ifindex;
    struct in_addr imr_address;
  } test_data[] = {
      {lo_if_idx_, {}},
      {0, lo_if_sin_addr_},
      {lo_if_idx_, lo_if_sin_addr_},
      {lo_if_idx_, eth_if_sin_addr_},
  };
  for (auto t : test_data) {
    ip_mreqn iface = {};
    iface.imr_ifindex = t.imr_ifindex;
    iface.imr_address = t.imr_address;
    EXPECT_THAT(setsockopt(sender->get(), IPPROTO_IP, IP_MULTICAST_IF, &iface,
                           sizeof(iface)),
                SyscallSucceeds())
        << "imr_index=" << iface.imr_ifindex
        << " imr_address=" << GetAddr4Str(&iface.imr_address);
  }
}
}  // namespace testing
}  // namespace gvisor
