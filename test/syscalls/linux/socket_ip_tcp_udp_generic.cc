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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of TCP and UDP sockets.
using TcpUdpSocketPairTest = SocketPairTest;

TEST_P(TcpUdpSocketPairTest, ShutdownWrFollowedBySendIsError) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Now shutdown the write end of the first.
  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_WR), SyscallSucceeds());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(send)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EPIPE));
}

std::vector<SocketPairKind> GetSocketPairs() {
  return VecCat<SocketPairKind>(
      ApplyVec<SocketPairKind>(
          IPv6UDPBidirectionalBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})),
      ApplyVec<SocketPairKind>(
          IPv4UDPBidirectionalBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})),
      ApplyVec<SocketPairKind>(
          DualStackUDPBidirectionalBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})),
      ApplyVec<SocketPairKind>(
          IPv6TCPAcceptBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})),
      ApplyVec<SocketPairKind>(
          IPv4TCPAcceptBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})),
      ApplyVec<SocketPairKind>(
          DualStackTCPAcceptBindSocketPair,
          AllBitwiseCombinations(List<int>{0, SOCK_NONBLOCK})));
}

INSTANTIATE_TEST_SUITE_P(
    AllTCPSockets, TcpUdpSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

}  // namespace

}  // namespace testing
}  // namespace gvisor
