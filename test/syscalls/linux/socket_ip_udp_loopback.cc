// Copyright 2018 The gVisor Authors.
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

#include <vector>

#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_generic.h"
#include "test/syscalls/linux/socket_ip_udp_generic.h"
#include "test/syscalls/linux/socket_non_stream.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

std::vector<SocketPairKind> GetSocketPairs() {
  return {
      IPv6UDPBidirectionalBindSocketPair(0),
      IPv4UDPBidirectionalBindSocketPair(0),
      DualStackUDPBidirectionalBindSocketPair(0),
  };
}

INSTANTIATE_TEST_SUITE_P(
    AllUDPSockets, AllSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

INSTANTIATE_TEST_SUITE_P(
    AllUDPSockets, NonStreamSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

INSTANTIATE_TEST_SUITE_P(
    AllUDPSockets, UDPSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

}  // namespace
}  // namespace testing
}  // namespace gvisor
