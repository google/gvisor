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

#include "test/syscalls/linux/socket_inet_loopback_util.h"

namespace gvisor {
namespace testing {

std::string DescribeTestParam(::testing::TestParamInfo<TestParam> const& info) {
  return absl::StrCat("Listen", info.param.listener.description, "_Connect",
                      info.param.connector.description);
}

PosixErrorOr<uint16_t> AddrPort(int family, sockaddr_storage const& addr) {
  switch (family) {
    case AF_INET:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in const*>(&addr)->sin_port);
    case AF_INET6:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in6 const*>(&addr)->sin6_port);
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

PosixError SetAddrPort(int family, sockaddr_storage* addr, uint16_t port) {
  switch (family) {
    case AF_INET:
      reinterpret_cast<sockaddr_in*>(addr)->sin_port = port;
      return NoError();
    case AF_INET6:
      reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = port;
      return NoError();
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}  // namespace

}  // namespace testing
}  // namespace gvisor
