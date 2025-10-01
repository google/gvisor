// Copyright 2020 The gVisor Authors.
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

#include "test/syscalls/linux/socket_ipv6_udp_unbound_external_networking.h"

#include <net/if.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void IPv6UDPUnboundExternalNetworkingSocketTest::SetUp() {
#ifdef ANDROID
  GTEST_SKIP() << "Android does not support getifaddrs in r22";
#endif

  ifaddrs* ifaddr;
  ASSERT_THAT(getifaddrs(&ifaddr), SyscallSucceeds());
  auto cleanup = absl::MakeCleanup([ifaddr] { freeifaddrs(ifaddr); });

  for (const ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    ASSERT_NE(ifa->ifa_name, nullptr);
    ASSERT_NE(ifa->ifa_addr, nullptr);

    if (ifa->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    std::optional<std::pair<int, sockaddr_in6>>& if_pair = *[this, ifa]() {
      if (strcmp(ifa->ifa_name, "lo") == 0) {
        return &lo_if_;
      }
      return &eth_if_;
    }();

    const int if_index =
        ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex(ifa->ifa_name));

    std::cout << " name=" << ifa->ifa_name
              << " addr=" << GetAddrStr(ifa->ifa_addr) << " index=" << if_index
              << " has_value=" << if_pair.has_value() << std::endl;

    if (if_pair.has_value()) {
      continue;
    }

    if_pair = std::make_pair(
        if_index, *reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr));
  }

  if (!(eth_if_.has_value() && lo_if_.has_value())) {
    GTEST_SKIP() << " eth_if_.has_value()=" << eth_if_.has_value()
                 << " lo_if_.has_value()=" << lo_if_.has_value();
  }
}

TEST_P(IPv6UDPUnboundExternalNetworkingSocketTest, TestJoinLeaveMulticast) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  auto receiver_addr = V6Any();
  ASSERT_THAT(bind(receiver->get(), AsSockAddr(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(), AsSockAddr(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  // Register to receive multicast packets.
  auto multicast_addr = V6Multicast();
  ipv6_mreq group_req = {
      .ipv6mr_multiaddr =
          reinterpret_cast<sockaddr_in6*>(&multicast_addr.addr)->sin6_addr,
      .ipv6mr_interface = static_cast<decltype(ipv6_mreq::ipv6mr_interface)>(
          ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex())),
  };
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                         &group_req, sizeof(group_req)),
              SyscallSucceeds());

  // Set the sender to the loopback interface.
  auto sender_addr = V6Loopback();
  ASSERT_THAT(
      bind(sender->get(), AsSockAddr(&sender_addr.addr), sender_addr.addr_len),
      SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = multicast_addr;
  reinterpret_cast<sockaddr_in6*>(&send_addr.addr)->sin6_port =
      reinterpret_cast<sockaddr_in6*>(&receiver_addr.addr)->sin6_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                         AsSockAddr(&send_addr.addr), send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(
      RecvTimeout(receiver->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));

  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));

  // Leave the group and make sure we don't receive its multicast traffic.
  ASSERT_THAT(setsockopt(receiver->get(), IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                         &group_req, sizeof(group_req)),
              SyscallSucceeds());
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(sender->get(), send_buf, sizeof(send_buf), 0,
                         AsSockAddr(&send_addr.addr), send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));
  ASSERT_THAT(RetryEINTR(recv)(receiver->get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that an AF_INET6 socket can set the IP_ADD_MEMBERSHIP socket option.
TEST_P(IPv6UDPUnboundExternalNetworkingSocketTest, AddV4MembershipToV6Socket) {
  TestAddress send_addr = V4Multicast();
  sockaddr_in* send_addr_in = reinterpret_cast<sockaddr_in*>(&send_addr.addr);

  // recv is an AF_INET6 socket while send is an AF_INET socket.
  auto recv = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  FileDescriptor send =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

  // Make recv join the multicast group with address `send_addr`.
  // Note that IP_ADD_MEMBERSHIP is used instead of IPV6_ADD_MEMBERSHIP, and
  // the group address is an IPv4 address.
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = send_addr_in->sin_addr.s_addr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  ASSERT_THAT(
      setsockopt(recv->get(), SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)),
      SyscallSucceeds());

  // Bind recv to ::.
  auto recv_addr = V6Any();
  ASSERT_THAT(
      bind(recv->get(), AsSockAddr(&recv_addr.addr), recv_addr.addr_len),
      SyscallSucceeds());
  socklen_t recv_addr_len = recv_addr.addr_len;
  ASSERT_THAT(
      getsockname(recv->get(), AsSockAddr(&recv_addr.addr), &recv_addr_len),
      SyscallSucceeds());
  EXPECT_EQ(recv_addr_len, recv_addr.addr_len);

  // Send a multicast packet...
  send_addr_in->sin_port =
      reinterpret_cast<sockaddr_in*>(&recv_addr.addr)->sin_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(send.get(), send_buf, sizeof(send_buf), 0,
                         AsSockAddr(&send_addr.addr), send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // ...and check that it was received.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RecvTimeout(recv->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));

  EXPECT_THAT(
      setsockopt(recv->get(), SOL_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)),
      SyscallSucceeds());

  // The same does not apply in reverse: it is not possible to setsockopt
  // IPV6_ADD_MEMBERSHIP on an AF_INET socket.
  auto multicast_addr = V6Multicast();
  ipv6_mreq group_req = {
      .ipv6mr_multiaddr =
          reinterpret_cast<sockaddr_in6*>(&multicast_addr.addr)->sin6_addr,
      .ipv6mr_interface =
          static_cast<decltype(ipv6_mreq::ipv6mr_interface)>(lo_if_idx()),
  };
  EXPECT_THAT(setsockopt(send.get(), IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                         &group_req, sizeof(group_req)),
              SyscallFailsWithErrno(ENOPROTOOPT));
}

TEST_P(IPv6UDPUnboundExternalNetworkingSocketTest, TestIPv6MulticastIf) {
  auto sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind sock to the ethernet interface.
  struct sockaddr_in6 bind_addr = eth_if_addr();
  ASSERT_THAT(bind(sock->get(), AsSockAddr(&bind_addr), sizeof(bind_addr)),
              SyscallSucceeds());

  int mcast_idx;
  socklen_t slen = sizeof(mcast_idx);
  ASSERT_THAT(getsockopt(sock->get(), IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &mcast_idx, &slen),
              SyscallSucceeds());
  EXPECT_EQ(mcast_idx, 0);  // Default is 0.

  // Setting its multicast interface to the loopback interface should fail.
  mcast_idx = lo_if_idx();
  EXPECT_THAT(setsockopt(sock->get(), IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &mcast_idx, slen),
              SyscallFailsWithErrno(EINVAL));

  // But setting it to the ethernet interface should succeed.
  mcast_idx = eth_if_idx();
  EXPECT_THAT(setsockopt(sock->get(), IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &mcast_idx, slen),
              SyscallSucceeds());
  ASSERT_THAT(getsockopt(sock->get(), IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &mcast_idx, &slen),
              SyscallSucceeds());
  EXPECT_EQ(mcast_idx, eth_if_idx());
}

TEST_P(IPv6UDPUnboundExternalNetworkingSocketTest,
       TestIPv6MulticastIfSendAndRecv) {
  auto recv = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto send = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Bind recv to ::.
  TestAddress recv_addr = V6Any();
  ASSERT_THAT(
      bind(recv->get(), AsSockAddr(&recv_addr.addr), recv_addr.addr_len),
      SyscallSucceeds());
  socklen_t recv_addr_len = recv_addr.addr_len;
  // Retrieve its assigned port.
  ASSERT_THAT(
      getsockname(recv->get(), AsSockAddr(&recv_addr.addr), &recv_addr_len),
      SyscallSucceeds());

  // And have it join a multicast group on the loopback interface.
  TestAddress multicast_addr = V6Multicast();
  ipv6_mreq group_req = {
      .ipv6mr_multiaddr =
          reinterpret_cast<sockaddr_in6*>(&multicast_addr.addr)->sin6_addr,
      .ipv6mr_interface =
          static_cast<decltype(ipv6_mreq::ipv6mr_interface)>(lo_if_idx()),
  };
  ASSERT_THAT(setsockopt(recv->get(), IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                         &group_req, sizeof(group_req)),
              SyscallSucceeds());

  // Set send's multicast interface to the loopback interface. It is still
  // unbound.
  int mcast_idx = lo_if_idx();
  ASSERT_THAT(setsockopt(send->get(), IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &mcast_idx, sizeof(mcast_idx)),
              SyscallSucceeds());

  // Send a multicast packet.
  auto send_addr = multicast_addr;
  reinterpret_cast<sockaddr_in6*>(&send_addr.addr)->sin6_port =
      reinterpret_cast<sockaddr_in6*>(&recv_addr.addr)->sin6_port;
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  ASSERT_THAT(
      RetryEINTR(sendto)(send->get(), send_buf, sizeof(send_buf), 0,
                         AsSockAddr(&send_addr.addr), send_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the multicast packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(
      RecvTimeout(recv->get(), recv_buf, sizeof(recv_buf), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));

  // Drop recv from the multicast group.
  ASSERT_THAT(setsockopt(recv->get(), IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                         &group_req, sizeof(group_req)),
              SyscallSucceeds());
}

}  // namespace testing
}  // namespace gvisor
