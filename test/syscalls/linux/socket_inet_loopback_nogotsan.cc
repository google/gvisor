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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::Gt;

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
}

struct TestParam {
  TestAddress listener;
  TestAddress connector;
};

std::string DescribeTestParam(::testing::TestParamInfo<TestParam> const& info) {
  return absl::StrCat("Listen", info.param.listener.description, "_Connect",
                      info.param.connector.description);
}

using SocketInetLoopbackTest = ::testing::TestWithParam<TestParam>;

// This test verifies that connect returns EADDRNOTAVAIL if all local ephemeral
// ports are already in use for a given destination ip/port.
//
// We disable S/R because this test creates a large number of sockets.
TEST_P(SocketInetLoopbackTest, TestTCPPortExhaustion_NoRandomSave) {
  auto const& param = GetParam();
  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  constexpr int kBacklog = 10;
  constexpr int kClients = 65536;

  // Create the listening socket.
  auto listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   listener.addr_len),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), kBacklog), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  // Disable cooperative S/R as we are making too many syscalls.
  DisableSave ds;

  // Now we keep opening connections till we run out of local ephemeral ports.
  // and assert the error we get back.
  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  std::vector<FileDescriptor> clients;
  std::vector<FileDescriptor> servers;

  for (int i = 0; i < kClients; i++) {
    FileDescriptor client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    int ret = connect(client.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                      connector.addr_len);
    if (ret == 0) {
      clients.push_back(std::move(client));
      FileDescriptor server =
          ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
      servers.push_back(std::move(server));
      continue;
    }
    ASSERT_THAT(ret, SyscallFailsWithErrno(EADDRNOTAVAIL));
    break;
  }
}

INSTANTIATE_TEST_SUITE_P(
    All, SocketInetLoopbackTest,
    ::testing::Values(
        // Listeners bound to IPv4 addresses refuse connections using IPv6
        // addresses.
        TestParam{V4Any(), V4Any()}, TestParam{V4Any(), V4Loopback()},
        TestParam{V4Any(), V4MappedAny()},
        TestParam{V4Any(), V4MappedLoopback()},
        TestParam{V4Loopback(), V4Any()}, TestParam{V4Loopback(), V4Loopback()},
        TestParam{V4Loopback(), V4MappedLoopback()},
        TestParam{V4MappedAny(), V4Any()},
        TestParam{V4MappedAny(), V4Loopback()},
        TestParam{V4MappedAny(), V4MappedAny()},
        TestParam{V4MappedAny(), V4MappedLoopback()},
        TestParam{V4MappedLoopback(), V4Any()},
        TestParam{V4MappedLoopback(), V4Loopback()},
        TestParam{V4MappedLoopback(), V4MappedLoopback()},

        // Listeners bound to IN6ADDR_ANY accept all connections.
        TestParam{V6Any(), V4Any()}, TestParam{V6Any(), V4Loopback()},
        TestParam{V6Any(), V4MappedAny()},
        TestParam{V6Any(), V4MappedLoopback()}, TestParam{V6Any(), V6Any()},
        TestParam{V6Any(), V6Loopback()},

        // Listeners bound to IN6ADDR_LOOPBACK refuse connections using IPv4
        // addresses.
        TestParam{V6Loopback(), V6Any()},
        TestParam{V6Loopback(), V6Loopback()}),
    DescribeTestParam);

struct ProtocolTestParam {
  std::string description;
  int type;
};

std::string DescribeProtocolTestParam(
    ::testing::TestParamInfo<ProtocolTestParam> const& info) {
  return info.param.description;
}

using SocketMultiProtocolInetLoopbackTest =
    ::testing::TestWithParam<ProtocolTestParam>;

TEST_P(SocketMultiProtocolInetLoopbackTest,
       BindAvoidsListeningPortsReuseAddr_NoRandomSave) {
  const auto& param = GetParam();
  // UDP sockets are allowed to bind/listen on the port w/ SO_REUSEADDR, for TCP
  // this is only permitted if there is no other listening socket.
  SKIP_IF(param.type != SOCK_STREAM);

  DisableSave ds;  // Too many syscalls.

  // A map of port to file descriptor binding the port.
  std::map<uint16_t, FileDescriptor> listen_sockets;

  // Exhaust all ephemeral ports.
  while (true) {
    // Bind the v4 loopback on a v4 socket.
    TestAddress const& test_addr = V4Loopback();
    sockaddr_storage bound_addr = test_addr.addr;
    FileDescriptor bound_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));

    ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());

    int ret = bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                   test_addr.addr_len);
    if (ret != 0) {
      ASSERT_EQ(errno, EADDRINUSE);
      break;
    }
    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                    &bound_addr_len),
        SyscallSucceeds());
    uint16_t port = reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port;

    // Newly bound port should not already be in use by a listening socket.
    ASSERT_EQ(listen_sockets.find(port), listen_sockets.end());
    auto fd = bound_fd.get();
    listen_sockets.insert(std::make_pair(port, std::move(bound_fd)));
    ASSERT_THAT(listen(fd, SOMAXCONN), SyscallSucceeds());
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllFamilies, SocketMultiProtocolInetLoopbackTest,
    ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                      ProtocolTestParam{"UDP", SOCK_DGRAM}),
    DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
