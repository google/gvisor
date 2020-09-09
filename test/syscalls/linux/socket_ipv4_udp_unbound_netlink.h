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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_NETLINK_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_NETLINK_UTIL_H_

#include "test/syscalls/linux/socket_ip_udp_unbound_netlink_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to IPv4 UDP sockets.
using IPv4UDPUnboundSocketNetlinkTest = IPUDPUnboundSocketNetlinkTest;

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_NETLINK_UTIL_H_
