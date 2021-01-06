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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IP_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IP_UDP_UNBOUND_EXTERNAL_NETWORKING_H_

#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to unbound IP UDP sockets in a sandbox
// with external networking support.
class IPUDPUnboundExternalNetworkingSocketTest : public SimpleSocketTest {
 protected:
  void SetUp() override;

  IfAddrHelper if_helper_;

  // found_net_interfaces_ is set to false if SetUp() could not obtain
  // all interface infos that we need.
  bool found_net_interfaces_;

  // Interface infos.
  int lo_if_idx_;
  int eth_if_idx_;
  sockaddr_in lo_if_addr_;
  sockaddr_in eth_if_addr_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IP_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
