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

#include "test/syscalls/linux/socket_ip_udp_unbound_external_networking.h"

#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void IPUDPUnboundExternalNetworkingSocketTest::SetUp() {
  // FIXME(b/137899561): Linux instance for syscall tests sometimes misses its
  // IPv4 address on eth0.
  found_net_interfaces_ = false;

  // Get interface list.
  ASSERT_NO_ERRNO(if_helper_.Load());
  std::vector<std::string> if_names = if_helper_.InterfaceList(AF_INET);
  if (if_names.size() != 2) {
    return;
  }

  // Figure out which interface is where.
  std::string lo = if_names[0];
  std::string eth = if_names[1];
  if (lo != "lo") std::swap(lo, eth);
  if (lo != "lo") return;

  lo_if_idx_ = ASSERT_NO_ERRNO_AND_VALUE(if_helper_.GetIndex(lo));
  auto lo_if_addr = if_helper_.GetAddr(AF_INET, lo);
  if (lo_if_addr == nullptr) {
    return;
  }
  lo_if_addr_ = *reinterpret_cast<const sockaddr_in*>(lo_if_addr);

  eth_if_idx_ = ASSERT_NO_ERRNO_AND_VALUE(if_helper_.GetIndex(eth));
  auto eth_if_addr = if_helper_.GetAddr(AF_INET, eth);
  if (eth_if_addr == nullptr) {
    return;
  }
  eth_if_addr_ = *reinterpret_cast<const sockaddr_in*>(eth_if_addr);

  found_net_interfaces_ = true;
}

}  // namespace testing
}  // namespace gvisor
