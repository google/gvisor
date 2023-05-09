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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_TEST_PARAMS_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_TEST_PARAMS_H_

#include "gtest/gtest.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

struct SocketInetTestParam {
  TestAddress listener;
  TestAddress connector;
};

inline std::string DescribeSocketInetTestParam(
    ::testing::TestParamInfo<SocketInetTestParam> const& info) {
  return absl::StrCat("Listen", info.param.listener.description, "_Connect",
                      info.param.connector.description);
}

inline auto SocketInetLoopbackTestValues() {
  return ::testing::Values(
      // Listeners bound to IPv4 addresses refuse connections using IPv6
      // addresses.
      SocketInetTestParam{V4Any(), V4Any()},
      SocketInetTestParam{V4Any(), V4Loopback()},
      SocketInetTestParam{V4Any(), V4MappedAny()},
      SocketInetTestParam{V4Any(), V4MappedLoopback()},
      SocketInetTestParam{V4Loopback(), V4Any()},
      SocketInetTestParam{V4Loopback(), V4Loopback()},
      SocketInetTestParam{V4Loopback(), V4MappedLoopback()},
      SocketInetTestParam{V4MappedAny(), V4Any()},
      SocketInetTestParam{V4MappedAny(), V4Loopback()},
      SocketInetTestParam{V4MappedAny(), V4MappedAny()},
      SocketInetTestParam{V4MappedAny(), V4MappedLoopback()},
      SocketInetTestParam{V4MappedLoopback(), V4Any()},
      SocketInetTestParam{V4MappedLoopback(), V4Loopback()},
      SocketInetTestParam{V4MappedLoopback(), V4MappedLoopback()},

      // Listeners bound to IN6ADDR_ANY accept all connections.
      SocketInetTestParam{V6Any(), V4Any()},
      SocketInetTestParam{V6Any(), V4Loopback()},
      SocketInetTestParam{V6Any(), V4MappedAny()},
      SocketInetTestParam{V6Any(), V4MappedLoopback()},
      SocketInetTestParam{V6Any(), V6Any()},
      SocketInetTestParam{V6Any(), V6Loopback()},

      // Listeners bound to IN6ADDR_LOOPBACK refuse connections using IPv4
      // addresses.
      SocketInetTestParam{V6Loopback(), V6Any()},
      SocketInetTestParam{V6Loopback(), V6Loopback()});
}

struct ProtocolTestParam {
  std::string description;
  int type;
};

inline std::string DescribeProtocolTestParam(
    ::testing::TestParamInfo<ProtocolTestParam> const& info) {
  return info.param.description;
}

inline auto ProtocolTestValues() {
  return ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                           ProtocolTestParam{"UDP", SOCK_DGRAM});
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_TEST_PARAMS_H_
