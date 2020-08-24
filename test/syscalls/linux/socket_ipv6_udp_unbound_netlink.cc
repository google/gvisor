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

#include "test/syscalls/linux/socket_ipv6_udp_unbound_netlink.h"

#include <arpa/inet.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"

namespace gvisor {
namespace testing {

// Checks that the loopback interface considers itself bound to all IPs in an
// associated subnet.
TEST_P(IPv6UDPUnboundSocketNetlinkTest, JoinSubnet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Add an IP address to the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  struct in6_addr addr;
  EXPECT_EQ(1, inet_pton(AF_INET6, "2001:db8::1", &addr));
  EXPECT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET6,
                                   /*prefixlen=*/64, &addr, sizeof(addr)));

  // Send from an unassigned address but an address that is in the subnet
  // associated with the loopback interface.
  TestAddress sender_addr("V6NotAssignd1");
  sender_addr.addr.ss_family = AF_INET6;
  sender_addr.addr_len = sizeof(sockaddr_in6);
  EXPECT_EQ(1, inet_pton(AF_INET6, "2001:db8::2",
                         reinterpret_cast<sockaddr_in6*>(&sender_addr.addr)
                             ->sin6_addr.s6_addr));

  // Send the packet to an unassigned address but an address that is in the
  // subnet associated with the loopback interface.
  TestAddress receiver_addr("V6NotAssigned2");
  receiver_addr.addr.ss_family = AF_INET6;
  receiver_addr.addr_len = sizeof(sockaddr_in6);
  EXPECT_EQ(1, inet_pton(AF_INET6, "2001:db8::ffff:ffff:ffff:ffff",
                         reinterpret_cast<sockaddr_in6*>(&receiver_addr.addr)
                             ->sin6_addr.s6_addr));

  TestSendRecv(sender_addr, receiver_addr);
}

}  // namespace testing
}  // namespace gvisor
