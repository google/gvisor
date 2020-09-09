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

#include <poll.h>
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
  // TODO(b/165912341): These are too slow on KVM platform with nested virt.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  for (int i = 0; i < 1 << 16; ++i) {
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

    // Send some data to ensure that the connection gets reset and the port gets
    // released immediately. This avoids either end entering TIME-WAIT.
    char sent_data[100] = {};
    ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
                SyscallSucceedsWithValue(sizeof(sent_data)));
    // Poll the other FD to make sure that the data is in the receive buffer
    // before closing it to ensure a RST is triggered.
    const int kTimeout = 10000;
    struct pollfd pfd = {
        .fd = sockets->second_fd(),
        .events = POLL_IN,
    };
    ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
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

TEST_P(PersistentListenerConnectStressTest, 65kTimesShutdownCloseFirst) {
  // TODO(b/165912341): These are too slow on KVM platform with nested virt.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  for (int i = 0; i < 1 << 16; ++i) {
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
    ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());
    if (GetParam().type == SOCK_STREAM) {
      // Poll the other FD to make sure that we see the FIN from the other
      // side before closing the second_fd. This ensures that the first_fd
      // enters TIME-WAIT and not second_fd.
      const int kTimeout = 10000;
      struct pollfd pfd = {
          .fd = sockets->second_fd(),
          .events = POLL_IN,
      };
      ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
    }
    ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RDWR), SyscallSucceeds());
  }
}

TEST_P(PersistentListenerConnectStressTest, 65kTimesShutdownCloseSecond) {
  // TODO(b/165912341): These are too slow on KVM platform with nested virt.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  for (int i = 0; i < 1 << 16; ++i) {
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
    ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RDWR), SyscallSucceeds());
    if (GetParam().type == SOCK_STREAM) {
      // Poll the other FD to make sure that we see the FIN from the other
      // side before closing the first_fd. This ensures that the second_fd
      // enters TIME-WAIT and not first_fd.
      const int kTimeout = 10000;
      struct pollfd pfd = {
          .fd = sockets->first_fd(),
          .events = POLL_IN,
      };
      ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
    }
    ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());
  }
}

TEST_P(PersistentListenerConnectStressTest, 65kTimesClose) {
  // TODO(b/165912341): These are too slow on KVM platform with nested virt.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

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
