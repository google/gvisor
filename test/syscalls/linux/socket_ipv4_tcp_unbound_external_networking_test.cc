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

#include "test/syscalls/linux/socket_ipv4_tcp_unbound_external_networking.h"

#include <vector>

#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

std::vector<SocketKind> GetSockets() {
  return ApplyVec<SocketKind>(
      IPv4TCPUnboundSocket,
      AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK}));
}

INSTANTIATE_TEST_SUITE_P(IPv4TCPUnboundSockets,
                         IPv4TCPUnboundExternalNetworkingSocketTest,
                         ::testing::ValuesIn(GetSockets()));
}  // namespace testing
}  // namespace gvisor
