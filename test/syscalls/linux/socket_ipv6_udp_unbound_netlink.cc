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
#include <linux/capability.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Checks that the loopback interface does not consider itself bound to all IPs
// in an associated subnet.
TEST_P(IPv6UDPUnboundSocketNetlinkTest, JoinSubnet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor nlsk =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  auto sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  {
    // Restore recreates network configuration from the host. Keep this
    // temporary address alive through the bind assertion and remove it before
    // saving.
    const DisableSave ds;

    // Add an IP address to the loopback interface.
    Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
    struct in6_addr addr;
    ASSERT_EQ(1, inet_pton(AF_INET6, "2001:db8::1", &addr));
    ASSERT_NO_ERRNO(LinkAddLocalAddr(nlsk, loopback_link.index, AF_INET6,
                                     /*prefixlen=*/64, &addr, sizeof(addr)));
    Cleanup defer_addr_removal([&] {
      EXPECT_NO_ERRNO(LinkDelLocalAddr(nlsk, loopback_link.index, AF_INET6,
                                       /*prefixlen=*/64, &addr, sizeof(addr)));
    });

    // Binding to an unassigned address but an address that is in the subnet
    // associated with the loopback interface should fail.
    TestAddress sender_addr("V6NotAssignd1");
    sender_addr.addr.ss_family = AF_INET6;
    sender_addr.addr_len = sizeof(sockaddr_in6);
    ASSERT_EQ(1, inet_pton(AF_INET6, "2001:db8::2",
                           reinterpret_cast<sockaddr_in6*>(&sender_addr.addr)
                               ->sin6_addr.s6_addr));
    EXPECT_THAT(
        bind(sock->get(), AsSockAddr(&sender_addr.addr), sender_addr.addr_len),
        SyscallFailsWithErrno(EADDRNOTAVAIL));
  }
  MaybeSave();  // Checkpoint the still-open socket after removing the address.
}

}  // namespace testing
}  // namespace gvisor
