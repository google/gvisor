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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to pairs of IP sockets.
using IPv6UnboundSocketTest = SimpleSocketTest;

TEST_P(IPv6UnboundSocketTest, ConnectToBadLocalAddress) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // TODO(gvisor.dev/issue/4595): Addresses on net devices are not saved
  // across save/restore.
  DisableSave ds;

  // Delete the loopback address from the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  EXPECT_NO_ERRNO(LinkDelLocalAddr(loopback_link.index, AF_INET6,
                                   /*prefixlen=*/128, &in6addr_loopback,
                                   sizeof(in6addr_loopback)));
  Cleanup defer_addr_removal =
      Cleanup([loopback_link = std::move(loopback_link)] {
        EXPECT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET6,
                                         /*prefixlen=*/128, &in6addr_loopback,
                                         sizeof(in6addr_loopback)));
      });

  TestAddress addr = V6Loopback();
  reinterpret_cast<sockaddr_in6*>(&addr.addr)->sin6_port = 65535;
  auto sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  EXPECT_THAT(connect(sock->get(), AsSockAddr(&addr.addr), addr.addr_len),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

INSTANTIATE_TEST_SUITE_P(IPUnboundSockets, IPv6UnboundSocketTest,
                         ::testing::ValuesIn(std::vector<SocketKind>{
                             IPv6UDPUnboundSocket(0),
                             IPv6TCPUnboundSocket(0)}));

using IPv4UnboundSocketTest = SimpleSocketTest;

TEST_P(IPv4UnboundSocketTest, ConnectToBadLocalAddress) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // TODO(gvisor.dev/issue/4595): Addresses on net devices are not saved
  // across save/restore.
  DisableSave ds;

  // Delete the loopback address from the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  struct in_addr laddr;
  laddr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_NO_ERRNO(LinkDelLocalAddr(loopback_link.index, AF_INET,
                                   /*prefixlen=*/8, &laddr, sizeof(laddr)));
  Cleanup defer_addr_removal = Cleanup(
      [loopback_link = std::move(loopback_link), addr = std::move(laddr)] {
        EXPECT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET,
                                         /*prefixlen=*/8, &addr, sizeof(addr)));
      });
  TestAddress addr = V4Loopback();
  reinterpret_cast<sockaddr_in*>(&addr.addr)->sin_port = 65535;
  auto sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  EXPECT_THAT(connect(sock->get(), AsSockAddr(&addr.addr), addr.addr_len),
              SyscallFailsWithErrno(ENETUNREACH));
}

INSTANTIATE_TEST_SUITE_P(IPUnboundSockets, IPv4UnboundSocketTest,
                         ::testing::ValuesIn(std::vector<SocketKind>{
                             IPv4UDPUnboundSocket(0),
                             IPv4TCPUnboundSocket(0)}));

}  // namespace testing
}  // namespace gvisor
