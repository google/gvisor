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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_ROUTE_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_ROUTE_UTIL_H_

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vector>

#include "test/syscalls/linux/socket_netlink_util.h"

namespace gvisor {
namespace testing {

struct Link {
  int index;
  int16_t type;
  std::string name;
};

PosixError DumpLinks(const FileDescriptor& fd, uint32_t seq,
                     const std::function<void(const struct nlmsghdr* hdr)>& fn);

PosixErrorOr<std::vector<Link>> DumpLinks();

// Returns the loopback link on the system. ENOENT if not found.
PosixErrorOr<Link> LoopbackLink();

// LinkAddLocalAddr sets IFA_LOCAL attribute on the interface.
PosixError LinkAddLocalAddr(int index, int family, int prefixlen,
                            const void* addr, int addrlen);

// LinkChangeFlags changes interface flags. E.g. IFF_UP.
PosixError LinkChangeFlags(int index, unsigned int flags, unsigned int change);

// LinkSetMacAddr sets IFLA_ADDRESS attribute of the interface.
PosixError LinkSetMacAddr(int index, const void* addr, int addrlen);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_ROUTE_UTIL_H_
