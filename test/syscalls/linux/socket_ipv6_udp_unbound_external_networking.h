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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV6_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV6_UDP_UNBOUND_EXTERNAL_NETWORKING_H_

#include <optional>
#include <utility>

#include "test/syscalls/linux/socket_ip_udp_unbound_external_networking.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to unbound IPv6 UDP sockets in a sandbox
// with external networking support.
class IPv6UDPUnboundExternalNetworkingSocketTest
    : public IPUDPUnboundExternalNetworkingSocketTest {
 protected:
  void SetUp() override;

  int lo_if_idx() const { return std::get<0>(lo_if_.value()); }
  int eth_if_idx() const { return std::get<0>(eth_if_.value()); }

  const sockaddr_in6& lo_if_addr() const { return std::get<1>(lo_if_.value()); }
  const sockaddr_in6& eth_if_addr() const {
    return std::get<1>(eth_if_.value());
  }

 private:
  // SetUp() will skip the tests if either of these does not have a value,
  // making it safe to access these without checking has_value().
  std::optional<std::pair<int, sockaddr_in6>> lo_if_, eth_if_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV6yy_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
