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
  uint32_t mtu;
  std::string address;
  unsigned int flags;
};

PosixError DumpLinks(const FileDescriptor& fd, uint32_t seq,
                     const std::function<void(const struct nlmsghdr* hdr)>& fn);

PosixErrorOr<std::vector<Link>> DumpLinks();

// Returns the loopback link on the system. ENOENT if not found.
PosixErrorOr<Link> LoopbackLink();

// LinkAddLocalAddr adds a new IFA_LOCAL address to the interface.
PosixError LinkAddLocalAddr(FileDescriptor& fd, int index, int family,
                            int prefixlen, const void* addr, int addrlen);

// LinkAddExclusiveLocalAddr adds a new IFA_LOCAL address with NLM_F_EXCL flag
// to the interface.
PosixError LinkAddExclusiveLocalAddr(FileDescriptor& fd, int index, int family,
                                     int prefixlen, const void* addr,
                                     int addrlen);

// LinkReplaceLocalAddr replaces an IFA_LOCAL address on the interface.
PosixError LinkReplaceLocalAddr(FileDescriptor& fd, int index, int family,
                                int prefixlen, const void* addr, int addrlen);

// LinkDelLocalAddr removes IFA_LOCAL attribute on the interface.
PosixError LinkDelLocalAddr(FileDescriptor& fd, int index, int family,
                            int prefixlen, const void* addr, int addrlen);

// LinkChangeFlags changes interface flags. E.g. IFF_UP.
PosixError LinkChangeFlags(int index, unsigned int flags, unsigned int change);

// LinkSetMacAddr sets IFLA_ADDRESS attribute of the interface.
PosixError LinkSetMacAddr(int index, const void* addr, int addrlen);

// AddRoute adds a route to the given dst subnet via the given interface.
PosixError AddUnicastRoute(int interface, int family, int prefixlen,
                           const void* dst, int dstlen);

// DelRoute removes a route to the given dst subnet via the given interface.
PosixError DelUnicastRoute(int interface, int family, int prefixlen,
                           const void* dst, int dstlen);

// AddExclusiveLookupInTableRule adds a PBR rule that performs a route lookup
// against the given table, for all packets destined to the given subnet.
PosixError AddExclusiveLookupInTableRule(int family, int table, int priority,
                                         int prefixlen, const void* dst,
                                         int dstlen);

// DelLookupInTableRule deletes a PBR rule that performs a route lookup against
// given table, for all packets destined to the given subnet.
PosixError DelLookupInTableRule(int family, int table, int priority,
                                int prefixlen, const void* dst, int dstlen);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_ROUTE_UTIL_H_
