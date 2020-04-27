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

#ifndef THIRD_PARTY_GOLANG_GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_H_
#define THIRD_PARTY_GOLANG_GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_H_

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"

namespace gvisor {
namespace testing {

// The initial port to be be used on gvisor.
constexpr int TestPort = 40000;

// Fixture for tests parameterized by the address family to use (AF_INET and
// AF_INET6) when creating sockets.
class UdpSocketTest
    : public ::testing::TestWithParam<gvisor::testing::AddressFamily> {
 protected:
  // Creates two sockets that will be used by test cases.
  void SetUp() override;

  // Closes the sockets created by SetUp().
  void TearDown() override {
    EXPECT_THAT(close(s_), SyscallSucceeds());
    EXPECT_THAT(close(t_), SyscallSucceeds());

    for (size_t i = 0; i < ABSL_ARRAYSIZE(ports_); ++i) {
      ASSERT_NO_ERRNO(FreeAvailablePort(ports_[i]));
    }
  }

  // First UDP socket.
  int s_;

  // Second UDP socket.
  int t_;

  // The length of the socket address.
  socklen_t addrlen_;

  // Initialized address pointing to loopback and port TestPort+i.
  struct sockaddr* addr_[3];

  // Initialize "any" address.
  struct sockaddr* anyaddr_;

  // Used ports.
  int ports_[3];

 private:
  // Storage for the loopback addresses.
  struct sockaddr_storage addr_storage_[3];

  // Storage for the "any" address.
  struct sockaddr_storage anyaddr_storage_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // THIRD_PARTY_GOLANG_GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_H_
