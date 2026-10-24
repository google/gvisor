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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_EXTERNAL_NETWORKING_H_

#include <cstdio>
#include <memory>
#include <optional>
#include <tuple>
#include <utility>

#include "test/syscalls/linux/socket_ip_udp_unbound_external_networking.h"

namespace gvisor {
namespace testing {

// Base class for IPv4 UDP tests that need host interface information.
class IPv4UDPUnboundExternalNetworkingTestBase {
 protected:
  void SetUpInterfaces();

  int lo_if_idx() const { return std::get<0>(lo_if_.value()); }
  int eth_if_idx() const { return std::get<0>(eth_if_.value()); }

  const sockaddr_in& lo_if_addr() const { return std::get<1>(lo_if_.value()); }
  const sockaddr_in& eth_if_addr() const {
    return std::get<1>(eth_if_.value());
  }

 private:
  std::optional<std::pair<int, sockaddr_in>> lo_if_, eth_if_;
};

// Test fixture for tests that apply to unbound IPv4 UDP sockets in a sandbox
// with external networking support.
class IPv4UDPUnboundExternalNetworkingSocketTest
    : public IPUDPUnboundExternalNetworkingSocketTest,
      public IPv4UDPUnboundExternalNetworkingTestBase {
 protected:
  void SetUp() override { SetUpInterfaces(); }
};

using IPv4UDPUnboundExternalNetworkingSocketAddressParam =
    std::tuple<SocketKind, TestAddress>;

// Test fixture for tests that apply to unbound IPv4 UDP sockets and also need
// an address parameter.
class IPv4UDPUnboundExternalNetworkingSocketAddressTest
    : public ::testing::TestWithParam<
          IPv4UDPUnboundExternalNetworkingSocketAddressParam>,
      public IPv4UDPUnboundExternalNetworkingTestBase {
 protected:
  IPv4UDPUnboundExternalNetworkingSocketAddressTest() {
    printf("Testing with %s, %s\n", socket_kind().description.c_str(),
           address().description.c_str());
    fflush(stdout);
  }

  void SetUp() override { SetUpInterfaces(); }

  PosixErrorOr<std::unique_ptr<FileDescriptor>> NewSocket() const {
    return socket_kind().Create();
  }

  TestAddress address() const { return std::get<1>(GetParam()); }

 private:
  const SocketKind& socket_kind() const { return std::get<0>(GetParam()); }
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_IPV4_UDP_UNBOUND_EXTERNAL_NETWORKING_H_
