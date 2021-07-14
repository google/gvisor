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

#include <sys/socket.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to IPv4 UDP sockets.
using IPv4UDPUnboundSocketNogotsanTest = SimpleSocketTest;

// Check that connect returns EAGAIN when out of local ephemeral ports.
// We disable S/R because this test creates a large number of sockets.
TEST_P(IPv4UDPUnboundSocketNogotsanTest, UDPConnectPortExhaustion) {
  auto receiver1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  const int kClients = ASSERT_NO_ERRNO_AND_VALUE(MaybeLimitEphemeralPorts());
  // Bind the first socket to the loopback and take note of the selected port.
  auto addr = V4Loopback();
  ASSERT_THAT(bind(receiver1->get(), AsSockAddr(&addr.addr), addr.addr_len),
              SyscallSucceeds());
  socklen_t addr_len = addr.addr_len;
  ASSERT_THAT(getsockname(receiver1->get(), AsSockAddr(&addr.addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, addr.addr_len);

  // Disable cooperative S/R as we are making too many syscalls.
  DisableSave ds;
  std::vector<std::unique_ptr<FileDescriptor>> sockets;
  for (int i = 0; i < kClients; i++) {
    auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

    int ret = connect(s->get(), AsSockAddr(&addr.addr), addr.addr_len);
    if (ret == 0) {
      sockets.push_back(std::move(s));
      continue;
    }
    ASSERT_THAT(ret, SyscallFailsWithErrno(EAGAIN));
    break;
  }
}

// Check that bind returns EADDRINUSE when out of local ephemeral ports.
// We disable S/R because this test creates a large number of sockets.
TEST_P(IPv4UDPUnboundSocketNogotsanTest, UDPBindPortExhaustion) {
  auto receiver1 = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  const int kClients = ASSERT_NO_ERRNO_AND_VALUE(MaybeLimitEphemeralPorts());
  auto addr = V4Loopback();
  // Disable cooperative S/R as we are making too many syscalls.
  DisableSave ds;
  std::vector<std::unique_ptr<FileDescriptor>> sockets;
  for (int i = 0; i < kClients; i++) {
    auto s = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

    int ret = bind(s->get(), AsSockAddr(&addr.addr), addr.addr_len);
    if (ret == 0) {
      sockets.push_back(std::move(s));
      continue;
    }
    ASSERT_THAT(ret, SyscallFailsWithErrno(EADDRINUSE));
    break;
  }
}

INSTANTIATE_TEST_SUITE_P(
    IPv4UDPSockets, IPv4UDPUnboundSocketNogotsanTest,
    ::testing::ValuesIn(ApplyVec<SocketKind>(IPv4UDPUnboundSocket,
                                             AllBitwiseCombinations(List<int>{
                                                 0, SOCK_NONBLOCK}))));

}  // namespace testing
}  // namespace gvisor
