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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_H_

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <memory>

#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

struct TestParam {
  TestAddress listener;
  TestAddress connector;
};

struct ProtocolTestParam {
  std::string description;
  int type;
};

inline std::string DescribeProtocolTestParam(
    ::testing::TestParamInfo<ProtocolTestParam> const& info) {
  return info.param.description;
}

using SocketInetLoopbackTest = ::testing::TestWithParam<TestParam>;
using SocketMultiProtocolInetLoopbackTest =
    ::testing::TestWithParam<ProtocolTestParam>;

std::string DescribeTestParam(::testing::TestParamInfo<TestParam> const& info);
PosixErrorOr<uint16_t> AddrPort(int family, sockaddr_storage const& addr);
PosixError SetAddrPort(int family, sockaddr_storage* addr, uint16_t port);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_INET_LOOPBACK_H_
