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

#include "test/syscalls/linux/socket_ip_udp_unbound_external_networking.h"

#include "absl/cleanup/cleanup.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void IPUDPUnboundExternalNetworkingSocketTest::SetUp() {
#ifdef ANDROID
  GTEST_SKIP() << "Android does not support getifaddrs in r22";
#endif

  ifaddrs* ifaddr;
  ASSERT_THAT(getifaddrs(&ifaddr), SyscallSucceeds());
  auto cleanup = absl::MakeCleanup([ifaddr] { freeifaddrs(ifaddr); });

  for (const ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    ASSERT_NE(ifa->ifa_name, nullptr);
    ASSERT_NE(ifa->ifa_addr, nullptr);

    if (ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    std::optional<std::pair<int, sockaddr_in>>& if_pair = *[this, ifa]() {
      if (strcmp(ifa->ifa_name, "lo") == 0) {
        return &lo_if_;
      }
      return &eth_if_;
    }();

    const int if_index =
        ASSERT_NO_ERRNO_AND_VALUE(InterfaceIndex(ifa->ifa_name));

    std::cout << " name=" << ifa->ifa_name
              << " addr=" << GetAddrStr(ifa->ifa_addr) << " index=" << if_index
              << " has_value=" << if_pair.has_value() << std::endl;

    if (if_pair.has_value()) {
      continue;
    }

    if_pair = std::make_pair(
        if_index, *reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr));
  }

  if (!(eth_if_.has_value() && lo_if_.has_value())) {
    // FIXME(b/137899561): Linux instance for syscall tests sometimes misses its
    // IPv4 address on eth0.
    GTEST_SKIP() << " eth_if_.has_value()=" << eth_if_.has_value()
                 << " lo_if_.has_value()=" << lo_if_.has_value();
  }
}

}  // namespace testing
}  // namespace gvisor
