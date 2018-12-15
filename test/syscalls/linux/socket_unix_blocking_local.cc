// Copyright 2018 Google LLC
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

#include "test/syscalls/linux/socket_blocking.h"

#include <vector>

#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

std::vector<SocketPairKind> GetSocketPairs() {
  return VecCat<SocketPairKind>(
      ApplyVec<SocketPairKind>(
          UnixDomainSocketPair,
          AllBitwiseCombinations(
              List<int>{SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM},
              List<int>{0, SOCK_CLOEXEC})),
      ApplyVec<SocketPairKind>(
          FilesystemBoundUnixDomainSocketPair,
          AllBitwiseCombinations(
              // FIXME: Add SOCK_DGRAM once blocking is fixed.
              List<int>{SOCK_STREAM, SOCK_SEQPACKET},
              List<int>{0, SOCK_CLOEXEC})),
      ApplyVec<SocketPairKind>(
          AbstractBoundUnixDomainSocketPair,
          AllBitwiseCombinations(
              // FIXME: Add SOCK_DGRAM once blocking is fixed.
              List<int>{SOCK_STREAM, SOCK_SEQPACKET},
              List<int>{0, SOCK_CLOEXEC})));
}

INSTANTIATE_TEST_CASE_P(
    AllUnixDomainSockets, BlockingSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

}  // namespace testing
}  // namespace gvisor
