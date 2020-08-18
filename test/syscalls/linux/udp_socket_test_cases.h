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

#include <sys/socket.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

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

  // Binds the socket bind_ to the loopback and updates bind_addr_.
  PosixError BindLoopback();

  // Binds the socket bind_ to Any and updates bind_addr_.
  PosixError BindAny();

  // Binds given socket to address addr and updates.
  PosixError BindSocket(int socket, struct sockaddr* addr);

  // Return initialized Any address to port 0.
  struct sockaddr_storage InetAnyAddr();

  // Return initialized Loopback address to port 0.
  struct sockaddr_storage InetLoopbackAddr();

  // Disconnects socket sockfd.
  void Disconnect(int sockfd);

  // Get family for the test.
  int GetFamily();

  // Socket used by Bind methods
  FileDescriptor bind_;

  // Second socket used for tests.
  FileDescriptor sock_;

  // Address for bind_ socket.
  struct sockaddr* bind_addr_;

  // Initialized to the length based on GetFamily().
  socklen_t addrlen_;

  // Storage for bind_addr_.
  struct sockaddr_storage bind_addr_storage_;

 private:
  // Helper to initialize addrlen_ for the test case.
  socklen_t GetAddrLength();
};
}  // namespace testing
}  // namespace gvisor

#endif  // THIRD_PARTY_GOLANG_GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_H_
