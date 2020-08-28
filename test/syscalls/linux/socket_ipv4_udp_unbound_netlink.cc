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

#include "test/syscalls/linux/socket_ipv4_udp_unbound_netlink.h"

#include <arpa/inet.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"

namespace gvisor {
namespace testing {

constexpr size_t kSendBufSize = 200;

// Checks that the loopback interface considers itself bound to all IPs in an
// associated subnet.
TEST_P(IPv4UDPUnboundSocketNetlinkTest, JoinSubnet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Add an IP address to the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  struct in_addr addr;
  EXPECT_EQ(1, inet_pton(AF_INET, "192.0.2.1", &addr));
  EXPECT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET,
                                   /*prefixlen=*/24, &addr, sizeof(addr)));

  auto snd_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcv_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Send from an unassigned address but an address that is in the subnet
  // associated with the loopback interface.
  TestAddress sender_addr("V4NotAssignd1");
  sender_addr.addr.ss_family = AF_INET;
  sender_addr.addr_len = sizeof(sockaddr_in);
  EXPECT_EQ(1, inet_pton(AF_INET, "192.0.2.2",
                         &(reinterpret_cast<sockaddr_in*>(&sender_addr.addr)
                               ->sin_addr.s_addr)));
  EXPECT_THAT(
      bind(snd_sock->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Send the packet to an unassigned address but an address that is in the
  // subnet associated with the loopback interface.
  TestAddress receiver_addr("V4NotAssigned2");
  receiver_addr.addr.ss_family = AF_INET;
  receiver_addr.addr_len = sizeof(sockaddr_in);
  EXPECT_EQ(1, inet_pton(AF_INET, "192.0.2.254",
                         &(reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)
                               ->sin_addr.s_addr)));
  EXPECT_THAT(
      bind(rcv_sock->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(rcv_sock->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
  char send_buf[kSendBufSize];
  RandomizeBuffer(send_buf, kSendBufSize);
  EXPECT_THAT(
      RetryEINTR(sendto)(snd_sock->get(), send_buf, kSendBufSize, 0,
                         reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                         receiver_addr.addr_len),
      SyscallSucceedsWithValue(kSendBufSize));

  // Check that we received the packet.
  char recv_buf[kSendBufSize] = {};
  ASSERT_THAT(RetryEINTR(recv)(rcv_sock->get(), recv_buf, kSendBufSize, 0),
              SyscallSucceedsWithValue(kSendBufSize));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, kSendBufSize));
}

}  // namespace testing
}  // namespace gvisor
