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

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to pairs of connected sockets.
using ConnectStressTest = SocketPairTest;

TEST_P(ConnectStressTest, Reset65kTimes) {
  for (int i = 0; i < 1 << 16; ++i) {
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

    // Send some data to ensure that the connection gets reset and the port gets
    // released immediately. This avoids either end entering TIME-WAIT.
    char sent_data[100] = {};
    ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
                SyscallSucceedsWithValue(sizeof(sent_data)));
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllConnectedSockets, ConnectStressTest,
    ::testing::Values(IPv6UDPBidirectionalBindSocketPair(0),
                      IPv4UDPBidirectionalBindSocketPair(0),
                      DualStackUDPBidirectionalBindSocketPair(0),

                      // Without REUSEADDR, we get port exhaustion on Linux.
                      SetSockOpt(SOL_SOCKET, SO_REUSEADDR,
                                 &kSockOptOn)(IPv6TCPAcceptBindSocketPair(0)),
                      SetSockOpt(SOL_SOCKET, SO_REUSEADDR,
                                 &kSockOptOn)(IPv4TCPAcceptBindSocketPair(0)),
                      SetSockOpt(SOL_SOCKET, SO_REUSEADDR, &kSockOptOn)(
                          DualStackTCPAcceptBindSocketPair(0))));

// Test fixture for tests that apply to pairs of connected sockets created with
// a persistent listener (if applicable).
using PersistentListenerConnectStressTest = SocketPairTest;

TEST_P(PersistentListenerConnectStressTest, 65kTimes) {
  for (int i = 0; i < 1 << 16; ++i) {
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllConnectedSockets, PersistentListenerConnectStressTest,
    ::testing::Values(
        IPv6UDPBidirectionalBindSocketPair(0),
        IPv4UDPBidirectionalBindSocketPair(0),
        DualStackUDPBidirectionalBindSocketPair(0),

        // Without REUSEADDR, we get port exhaustion on Linux.
        SetSockOpt(SOL_SOCKET, SO_REUSEADDR, &kSockOptOn)(
            IPv6TCPAcceptBindPersistentListenerSocketPair(0)),
        SetSockOpt(SOL_SOCKET, SO_REUSEADDR, &kSockOptOn)(
            IPv4TCPAcceptBindPersistentListenerSocketPair(0)),
        SetSockOpt(SOL_SOCKET, SO_REUSEADDR, &kSockOptOn)(
            DualStackTCPAcceptBindPersistentListenerSocketPair(0))));

}  // namespace testing
}  // namespace gvisor
