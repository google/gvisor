// Copyright 2025 The gVisor Authors.
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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_

#include <linux/capability.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_compat.h>
#include <linux/netlink.h>

#include <cstdint>

namespace gvisor {
namespace testing {

void InitNetfilterGenmsg(struct nfgenmsg* genmsg, uint8_t family,
                         uint8_t version, uint16_t res_id);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_
