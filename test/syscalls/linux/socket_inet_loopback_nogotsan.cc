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
#include "test/syscalls/linux/socket_inet_loopback_test_params.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using SocketInetLoopbackTest = ::testing::TestWithParam<SocketInetTestParam>;

// This test verifies that connect returns EADDRNOTAVAIL if all local ephemeral
// ports are already in use for a given destination ip/port.
//
// We disable S/R because this test creates a large number of sockets.
//
// FIXME(b/162475855): This test is failing reliably.
TEST_P(SocketInetLoopbackTest, DISABLED_TestTCPPortExhaustion) {
  SocketInetTestParam const& param = GetParam();
  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  constexpr int kBacklog = 10;
  constexpr int kClients = 65536;

  // Create the listening socket.
  auto listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  ASSERT_THAT(
      bind(listen_fd.get(), AsSockAddr(&listen_addr), listener.addr_len),
      SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), kBacklog), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(), AsSockAddr(&listen_addr), &addrlen),
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
    int ret = connect(client.get(), AsSockAddr(&conn_addr), connector.addr_len);
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

INSTANTIATE_TEST_SUITE_P(All, SocketInetLoopbackTest,
                         SocketInetLoopbackTestValues(),
                         DescribeSocketInetTestParam);

using SocketMultiProtocolInetLoopbackTest =
    ::testing::TestWithParam<ProtocolTestParam>;

TEST_P(SocketMultiProtocolInetLoopbackTest,
       TCPBindAvoidsOtherBoundPortsReuseAddr) {
  ProtocolTestParam const& param = GetParam();
  // UDP sockets are allowed to bind/listen on an already bound port w/
  // SO_REUSEADDR even when requesting a port from the kernel. In case of TCP
  // rebinding is only permitted when SO_REUSEADDR is set and an explicit port
  // is specified. When a zero port is specified to the bind() call then an
  // already bound port will not be picked.
  SKIP_IF(param.type != SOCK_STREAM);

  DisableSave ds;  // Too many syscalls.

  // A map of port to file descriptor binding the port.
  std::map<uint16_t, FileDescriptor> bound_sockets;

  // Reduce number of ephemeral ports if permitted to reduce running time of
  // the test.
  [[maybe_unused]] const int nports =
      ASSERT_NO_ERRNO_AND_VALUE(MaybeLimitEphemeralPorts());

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

    int ret = bind(bound_fd.get(), AsSockAddr(&bound_addr), test_addr.addr_len);
    if (ret != 0) {
      ASSERT_EQ(errno, EADDRINUSE);
      break;
    }
    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), AsSockAddr(&bound_addr), &bound_addr_len),
        SyscallSucceeds());
    uint16_t port = reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port;

    auto [iter, inserted] = bound_sockets.emplace(port, std::move(bound_fd));
    ASSERT_TRUE(inserted);
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest,
       UDPBindMayBindOtherBoundPortsReuseAddr) {
  ProtocolTestParam const& param = GetParam();
  // UDP sockets are allowed to bind/listen on an already bound port w/
  // SO_REUSEADDR even when requesting a port from the kernel.
  SKIP_IF(param.type != SOCK_DGRAM);

  DisableSave ds;  // Too many syscalls.

  // A map of port to file descriptor binding the port.
  std::map<uint16_t, FileDescriptor> bound_sockets;

  // Reduce number of ephemeral ports if permitted to reduce running time of
  // the test.
  [[maybe_unused]] const int nports =
      ASSERT_NO_ERRNO_AND_VALUE(MaybeLimitEphemeralPorts());

  // Exhaust all ephemeral ports.
  bool duplicate_binding = false;
  while (true) {
    // Bind the v4 loopback on a v4 socket.
    TestAddress const& test_addr = V4Loopback();
    sockaddr_storage bound_addr = test_addr.addr;
    FileDescriptor bound_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));

    ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());

    ASSERT_THAT(
        bind(bound_fd.get(), AsSockAddr(&bound_addr), test_addr.addr_len),
        SyscallSucceeds());

    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), AsSockAddr(&bound_addr), &bound_addr_len),
        SyscallSucceeds());
    uint16_t port = reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port;

    auto [iter, inserted] = bound_sockets.emplace(port, std::move(bound_fd));
    if (!inserted) {
      duplicate_binding = true;
      break;
    }
  }
  ASSERT_TRUE(duplicate_binding);
}

INSTANTIATE_TEST_SUITE_P(AllFamilies, SocketMultiProtocolInetLoopbackTest,
                         ProtocolTestValues(), DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
