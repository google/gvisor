// Copyright 2018 Google LLC
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
#include <string.h>
#include <sys/socket.h>

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

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

struct TestAddress {
  std::string description;
  sockaddr_storage addr;
  socklen_t addr_len;

  int family() const { return addr.ss_family; }
  explicit TestAddress(std::string description = "")
      : description(std::move(description)), addr(), addr_len() {}
};

TestAddress V4Any() {
  TestAddress t("V4Any");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr = htonl(INADDR_ANY);
  return t;
}

TestAddress V4Loopback() {
  TestAddress t("V4Loopback");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      htonl(INADDR_LOOPBACK);
  return t;
}

TestAddress V4MappedAny() {
  TestAddress t("V4MappedAny");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  inet_pton(AF_INET6, "::ffff:0.0.0.0",
            reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr.s6_addr);
  return t;
}

TestAddress V4MappedLoopback() {
  TestAddress t("V4MappedLoopback");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  inet_pton(AF_INET6, "::ffff:127.0.0.1",
            reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr.s6_addr);
  return t;
}

TestAddress V6Any() {
  TestAddress t("V6Any");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr = in6addr_any;
  return t;
}

TestAddress V6Loopback() {
  TestAddress t("V6Loopback");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr = in6addr_loopback;
  return t;
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

TEST(BadSocketPairArgs, ValidateErrForBadCallsToSocketPair) {
  int fd[2] = {};

  // Valid AF but invalid for socketpair(2) return ESOCKTNOSUPPORT.
  ASSERT_THAT(socketpair(AF_INET, 0, 0, fd),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  ASSERT_THAT(socketpair(AF_INET6, 0, 0, fd),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));

  // Invalid AF will return ENOAFSUPPORT.
  ASSERT_THAT(socketpair(AF_MAX, 0, 0, fd),
              SyscallFailsWithErrno(EAFNOSUPPORT));
  ASSERT_THAT(socketpair(8675309, 0, 0, fd),
              SyscallFailsWithErrno(EAFNOSUPPORT));
}

TEST_P(SocketInetLoopbackTest, TCP) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  // Create the listening socket.
  const FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   listener.addr_len),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), SOMAXCONN), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  // Connect to the listening socket.
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Accept the connection.
  //
  // We have to assign a name to the accepted socket, as unamed temporary
  // objects are destructed upon full evaluation of the expression it is in,
  // potentially causing the connecting socket to fail to shutdown properly.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  ASSERT_THAT(shutdown(listen_fd.get(), SHUT_RDWR), SyscallSucceeds());

  ASSERT_THAT(shutdown(conn_fd.get(), SHUT_RDWR), SyscallSucceeds());
}

INSTANTIATE_TEST_CASE_P(
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

TEST_P(SocketMultiProtocolInetLoopbackTest, V4MappedLoopbackOnlyReservesV4) {
  auto const& param = GetParam();

  for (int i = 0; true; i++) {
    // Bind the v4 loopback on a dual stack socket.
    TestAddress const& test_addr_dual = V4MappedLoopback();
    sockaddr_storage addr_dual = test_addr_dual.addr;
    const FileDescriptor fd_dual = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_dual.family(), param.type, 0));
    ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                     test_addr_dual.addr_len),
                SyscallSucceeds());

    // Get the port that we bound.
    socklen_t addrlen = test_addr_dual.addr_len;
    ASSERT_THAT(getsockname(fd_dual.get(),
                            reinterpret_cast<sockaddr*>(&addr_dual), &addrlen),
                SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr_dual.family(), addr_dual));

    // Verify that we can still bind the v6 loopback on the same port.
    TestAddress const& test_addr_v6 = V6Loopback();
    sockaddr_storage addr_v6 = test_addr_v6.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v6.family(), &addr_v6, port));
    const FileDescriptor fd_v6 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v6.family(), param.type, 0));
    int ret = bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                   test_addr_v6.addr_len);
    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    ASSERT_THAT(ret, SyscallSucceeds());

    // Verify that binding the v4 loopback with the same port on a v4 socket
    // fails.
    TestAddress const& test_addr_v4 = V4Loopback();
    sockaddr_storage addr_v4 = test_addr_v4.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4.family(), &addr_v4, port));
    const FileDescriptor fd_v4 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v4.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v4.get(), reinterpret_cast<sockaddr*>(&addr_v4),
                     test_addr_v4.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // No need to try again.
    break;
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V4MappedAnyOnlyReservesV4) {
  auto const& param = GetParam();

  for (int i = 0; true; i++) {
    // Bind the v4 any on a dual stack socket.
    TestAddress const& test_addr_dual = V4MappedAny();
    sockaddr_storage addr_dual = test_addr_dual.addr;
    const FileDescriptor fd_dual = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_dual.family(), param.type, 0));
    ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                     test_addr_dual.addr_len),
                SyscallSucceeds());

    // Get the port that we bound.
    socklen_t addrlen = test_addr_dual.addr_len;
    ASSERT_THAT(getsockname(fd_dual.get(),
                            reinterpret_cast<sockaddr*>(&addr_dual), &addrlen),
                SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr_dual.family(), addr_dual));

    // Verify that we can still bind the v6 loopback on the same port.
    TestAddress const& test_addr_v6 = V6Loopback();
    sockaddr_storage addr_v6 = test_addr_v6.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v6.family(), &addr_v6, port));
    const FileDescriptor fd_v6 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v6.family(), param.type, 0));
    int ret = bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                   test_addr_v6.addr_len);
    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    ASSERT_THAT(ret, SyscallSucceeds());

    // Verify that binding the v4 loopback with the same port on a v4 socket
    // fails.
    TestAddress const& test_addr_v4 = V4Loopback();
    sockaddr_storage addr_v4 = test_addr_v4.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4.family(), &addr_v4, port));
    const FileDescriptor fd_v4 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v4.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v4.get(), reinterpret_cast<sockaddr*>(&addr_v4),
                     test_addr_v4.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // No need to try again.
    break;
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest, DualStackV6AnyReservesEverything) {
  auto const& param = GetParam();

  // Bind the v6 any on a dual stack socket.
  TestAddress const& test_addr_dual = V6Any();
  sockaddr_storage addr_dual = test_addr_dual.addr;
  const FileDescriptor fd_dual =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_dual.family(), param.type, 0));
  ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                   test_addr_dual.addr_len),
              SyscallSucceeds());

  // Get the port that we bound.
  socklen_t addrlen = test_addr_dual.addr_len;
  ASSERT_THAT(getsockname(fd_dual.get(),
                          reinterpret_cast<sockaddr*>(&addr_dual), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr_dual.family(), addr_dual));

  // Verify that binding the v6 loopback with the same port fails.
  TestAddress const& test_addr_v6 = V6Loopback();
  sockaddr_storage addr_v6 = test_addr_v6.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v6.family(), &addr_v6, port));
  const FileDescriptor fd_v6 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v6.family(), param.type, 0));
  ASSERT_THAT(bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                   test_addr_v6.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));

  // Verify that binding the v4 loopback on the same port with a v6 socket
  // fails.
  TestAddress const& test_addr_v4_mapped = V4MappedLoopback();
  sockaddr_storage addr_v4_mapped = test_addr_v4_mapped.addr;
  ASSERT_NO_ERRNO(
      SetAddrPort(test_addr_v4_mapped.family(), &addr_v4_mapped, port));
  const FileDescriptor fd_v4_mapped = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(test_addr_v4_mapped.family(), param.type, 0));
  ASSERT_THAT(
      bind(fd_v4_mapped.get(), reinterpret_cast<sockaddr*>(&addr_v4_mapped),
           test_addr_v4_mapped.addr_len),
      SyscallFailsWithErrno(EADDRINUSE));

  // Verify that binding the v4 loopback on the same port with a v4 socket
  // fails.
  TestAddress const& test_addr_v4 = V4Loopback();
  sockaddr_storage addr_v4 = test_addr_v4.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4.family(), &addr_v4, port));
  const FileDescriptor fd_v4 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v4.family(), param.type, 0));
  ASSERT_THAT(bind(fd_v4.get(), reinterpret_cast<sockaddr*>(&addr_v4),
                   test_addr_v4.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V6OnlyV6AnyReservesV6) {
  auto const& param = GetParam();

  for (int i = 0; true; i++) {
    // Bind the v6 any on a v6-only socket.
    TestAddress const& test_addr_dual = V6Any();
    sockaddr_storage addr_dual = test_addr_dual.addr;
    const FileDescriptor fd_dual = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_dual.family(), param.type, 0));
    int one = 1;
    EXPECT_THAT(
        setsockopt(fd_dual.get(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)),
        SyscallSucceeds());
    ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                     test_addr_dual.addr_len),
                SyscallSucceeds());

    // Get the port that we bound.
    socklen_t addrlen = test_addr_dual.addr_len;
    ASSERT_THAT(getsockname(fd_dual.get(),
                            reinterpret_cast<sockaddr*>(&addr_dual), &addrlen),
                SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr_dual.family(), addr_dual));

    // Verify that binding the v6 loopback with the same port fails.
    TestAddress const& test_addr_v6 = V6Loopback();
    sockaddr_storage addr_v6 = test_addr_v6.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v6.family(), &addr_v6, port));
    const FileDescriptor fd_v6 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v6.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                     test_addr_v6.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // Verify that we can still bind the v4 loopback on the same port.
    TestAddress const& test_addr_v4_mapped = V4MappedLoopback();
    sockaddr_storage addr_v4_mapped = test_addr_v4_mapped.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v4_mapped.family(), &addr_v4_mapped, port));
    const FileDescriptor fd_v4_mapped = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v4_mapped.family(), param.type, 0));
    int ret =
        bind(fd_v4_mapped.get(), reinterpret_cast<sockaddr*>(&addr_v4_mapped),
             test_addr_v4_mapped.addr_len);
    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    ASSERT_THAT(ret, SyscallSucceeds());

    // No need to try again.
    break;
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V6EphemeralPortReserved) {
  auto const& param = GetParam();

  // FIXME
  SKIP_IF(IsRunningOnGvisor() && param.type == SOCK_STREAM);

  for (int i = 0; true; i++) {
    // Bind the v6 loopback on a dual stack socket.
    TestAddress const& test_addr = V6Loopback();
    sockaddr_storage bound_addr = test_addr.addr;
    const FileDescriptor bound_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                     test_addr.addr_len),
                SyscallSucceeds());

    // Listen iff TCP.
    if (param.type == SOCK_STREAM) {
      ASSERT_THAT(listen(bound_fd.get(), SOMAXCONN), SyscallSucceeds());
    }

    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                    &bound_addr_len),
        SyscallSucceeds());

    // Connect to bind an ephemeral port.
    const FileDescriptor connected_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(
        connect(connected_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                bound_addr_len),
        SyscallSucceeds());

    // Get the ephemeral port.
    sockaddr_storage connected_addr = {};
    socklen_t connected_addr_len = sizeof(connected_addr);
    ASSERT_THAT(getsockname(connected_fd.get(),
                            reinterpret_cast<sockaddr*>(&connected_addr),
                            &connected_addr_len),
                SyscallSucceeds());
    uint16_t const ephemeral_port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr.family(), connected_addr));

    // Verify that we actually got an ephemeral port.
    ASSERT_NE(ephemeral_port, 0);

    // Verify that the ephemeral port is reserved.
    const FileDescriptor checking_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    EXPECT_THAT(
        bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
             connected_addr_len),
        SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v6 loopback with the same port fails.
    TestAddress const& test_addr_v6 = V6Loopback();
    sockaddr_storage addr_v6 = test_addr_v6.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v6.family(), &addr_v6, ephemeral_port));
    const FileDescriptor fd_v6 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v6.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                     test_addr_v6.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v4 any with the same port fails.
    TestAddress const& test_addr_v4_any = V4Any();
    sockaddr_storage addr_v4_any = test_addr_v4_any.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v4_any.family(), &addr_v4_any, ephemeral_port));
    const FileDescriptor fd_v4_any = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v4_any.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v4_any.get(), reinterpret_cast<sockaddr*>(&addr_v4_any),
                     test_addr_v4_any.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // Verify that we can still bind the v4 loopback on the same port.
    TestAddress const& test_addr_v4_mapped = V4MappedLoopback();
    sockaddr_storage addr_v4_mapped = test_addr_v4_mapped.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_mapped.family(), &addr_v4_mapped,
                                ephemeral_port));
    const FileDescriptor fd_v4_mapped = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v4_mapped.family(), param.type, 0));
    int ret =
        bind(fd_v4_mapped.get(), reinterpret_cast<sockaddr*>(&addr_v4_mapped),
             test_addr_v4_mapped.addr_len);
    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    EXPECT_THAT(ret, SyscallSucceeds());

    // No need to try again.
    break;
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V4MappedEphemeralPortReserved) {
  auto const& param = GetParam();

  // FIXME
  SKIP_IF(IsRunningOnGvisor() && param.type == SOCK_STREAM);

  for (int i = 0; true; i++) {
    // Bind the v4 loopback on a dual stack socket.
    TestAddress const& test_addr = V4MappedLoopback();
    sockaddr_storage bound_addr = test_addr.addr;
    const FileDescriptor bound_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                     test_addr.addr_len),
                SyscallSucceeds());

    // Listen iff TCP.
    if (param.type == SOCK_STREAM) {
      ASSERT_THAT(listen(bound_fd.get(), SOMAXCONN), SyscallSucceeds());
    }

    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                    &bound_addr_len),
        SyscallSucceeds());

    // Connect to bind an ephemeral port.
    const FileDescriptor connected_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(
        connect(connected_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                bound_addr_len),
        SyscallSucceeds());

    // Get the ephemeral port.
    sockaddr_storage connected_addr = {};
    socklen_t connected_addr_len = sizeof(connected_addr);
    ASSERT_THAT(getsockname(connected_fd.get(),
                            reinterpret_cast<sockaddr*>(&connected_addr),
                            &connected_addr_len),
                SyscallSucceeds());
    uint16_t const ephemeral_port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr.family(), connected_addr));

    // Verify that we actually got an ephemeral port.
    ASSERT_NE(ephemeral_port, 0);

    // Verify that the ephemeral port is reserved.
    const FileDescriptor checking_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    EXPECT_THAT(
        bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
             connected_addr_len),
        SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v4 loopback on the same port with a v4 socket
    // fails.
    TestAddress const& test_addr_v4 = V4Loopback();
    sockaddr_storage addr_v4 = test_addr_v4.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v4.family(), &addr_v4, ephemeral_port));
    const FileDescriptor fd_v4 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_v4.family(), param.type, 0));
    EXPECT_THAT(bind(fd_v4.get(), reinterpret_cast<sockaddr*>(&addr_v4),
                     test_addr_v4.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v6 any on the same port with a dual-stack socket
    // fails.
    TestAddress const& test_addr_v6_any = V6Any();
    sockaddr_storage addr_v6_any = test_addr_v6_any.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v6_any.family(), &addr_v6_any, ephemeral_port));
    const FileDescriptor fd_v6_any = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v6_any.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v6_any.get(), reinterpret_cast<sockaddr*>(&addr_v6_any),
                     test_addr_v6_any.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // For some reason, binding the TCP v6-only any is flaky on Linux. Maybe we
    // tend to run out of ephemeral ports? Regardless, binding the v6 loopback
    // seems pretty reliable. Only try to bind the v6-only any on UDP and
    // gVisor.

    int ret = -1;

    if (!IsRunningOnGvisor() && param.type == SOCK_STREAM) {
      // Verify that we can still bind the v6 loopback on the same port.
      TestAddress const& test_addr_v6 = V6Loopback();
      sockaddr_storage addr_v6 = test_addr_v6.addr;
      ASSERT_NO_ERRNO(
          SetAddrPort(test_addr_v6.family(), &addr_v6, ephemeral_port));
      const FileDescriptor fd_v6 = ASSERT_NO_ERRNO_AND_VALUE(
          Socket(test_addr_v6.family(), param.type, 0));
      ret = bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                 test_addr_v6.addr_len);
    } else {
      // Verify that we can still bind the v6 any on the same port with a
      // v6-only socket.
      const FileDescriptor fd_v6_only_any = ASSERT_NO_ERRNO_AND_VALUE(
          Socket(test_addr_v6_any.family(), param.type, 0));
      int one = 1;
      EXPECT_THAT(setsockopt(fd_v6_only_any.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                             &one, sizeof(one)),
                  SyscallSucceeds());
      ret =
          bind(fd_v6_only_any.get(), reinterpret_cast<sockaddr*>(&addr_v6_any),
               test_addr_v6_any.addr_len);
    }

    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    EXPECT_THAT(ret, SyscallSucceeds());

    // No need to try again.
    break;
  }
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V4EphemeralPortReserved) {
  auto const& param = GetParam();

  // FIXME
  SKIP_IF(IsRunningOnGvisor() && param.type == SOCK_STREAM);

  for (int i = 0; true; i++) {
    // Bind the v4 loopback on a v4 socket.
    TestAddress const& test_addr = V4Loopback();
    sockaddr_storage bound_addr = test_addr.addr;
    const FileDescriptor bound_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                     test_addr.addr_len),
                SyscallSucceeds());

    // Listen iff TCP.
    if (param.type == SOCK_STREAM) {
      ASSERT_THAT(listen(bound_fd.get(), SOMAXCONN), SyscallSucceeds());
    }

    // Get the port that we bound.
    socklen_t bound_addr_len = test_addr.addr_len;
    ASSERT_THAT(
        getsockname(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                    &bound_addr_len),
        SyscallSucceeds());

    // Connect to bind an ephemeral port.
    const FileDescriptor connected_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    ASSERT_THAT(
        connect(connected_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                bound_addr_len),
        SyscallSucceeds());

    // Get the ephemeral port.
    sockaddr_storage connected_addr = {};
    socklen_t connected_addr_len = sizeof(connected_addr);
    ASSERT_THAT(getsockname(connected_fd.get(),
                            reinterpret_cast<sockaddr*>(&connected_addr),
                            &connected_addr_len),
                SyscallSucceeds());
    uint16_t const ephemeral_port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr.family(), connected_addr));

    // Verify that we actually got an ephemeral port.
    ASSERT_NE(ephemeral_port, 0);

    // Verify that the ephemeral port is reserved.
    const FileDescriptor checking_fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    EXPECT_THAT(
        bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
             connected_addr_len),
        SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v4 loopback on the same port with a v6 socket
    // fails.
    TestAddress const& test_addr_v4_mapped = V4MappedLoopback();
    sockaddr_storage addr_v4_mapped = test_addr_v4_mapped.addr;
    ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_mapped.family(), &addr_v4_mapped,
                                ephemeral_port));
    const FileDescriptor fd_v4_mapped = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v4_mapped.family(), param.type, 0));
    EXPECT_THAT(
        bind(fd_v4_mapped.get(), reinterpret_cast<sockaddr*>(&addr_v4_mapped),
             test_addr_v4_mapped.addr_len),
        SyscallFailsWithErrno(EADDRINUSE));

    // Verify that binding the v6 any on the same port with a dual-stack socket
    // fails.
    TestAddress const& test_addr_v6_any = V6Any();
    sockaddr_storage addr_v6_any = test_addr_v6_any.addr;
    ASSERT_NO_ERRNO(
        SetAddrPort(test_addr_v6_any.family(), &addr_v6_any, ephemeral_port));
    const FileDescriptor fd_v6_any = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(test_addr_v6_any.family(), param.type, 0));
    ASSERT_THAT(bind(fd_v6_any.get(), reinterpret_cast<sockaddr*>(&addr_v6_any),
                     test_addr_v6_any.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));

    // For some reason, binding the TCP v6-only any is flaky on Linux. Maybe we
    // tend to run out of ephemeral ports? Regardless, binding the v6 loopback
    // seems pretty reliable. Only try to bind the v6-only any on UDP and
    // gVisor.

    int ret = -1;

    if (!IsRunningOnGvisor() && param.type == SOCK_STREAM) {
      // Verify that we can still bind the v6 loopback on the same port.
      TestAddress const& test_addr_v6 = V6Loopback();
      sockaddr_storage addr_v6 = test_addr_v6.addr;
      ASSERT_NO_ERRNO(
          SetAddrPort(test_addr_v6.family(), &addr_v6, ephemeral_port));
      const FileDescriptor fd_v6 = ASSERT_NO_ERRNO_AND_VALUE(
          Socket(test_addr_v6.family(), param.type, 0));
      ret = bind(fd_v6.get(), reinterpret_cast<sockaddr*>(&addr_v6),
                 test_addr_v6.addr_len);
    } else {
      // Verify that we can still bind the v6 any on the same port with a
      // v6-only socket.
      const FileDescriptor fd_v6_only_any = ASSERT_NO_ERRNO_AND_VALUE(
          Socket(test_addr_v6_any.family(), param.type, 0));
      int one = 1;
      EXPECT_THAT(setsockopt(fd_v6_only_any.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                             &one, sizeof(one)),
                  SyscallSucceeds());
      ret =
          bind(fd_v6_only_any.get(), reinterpret_cast<sockaddr*>(&addr_v6_any),
               test_addr_v6_any.addr_len);
    }

    if (ret == -1 && errno == EADDRINUSE) {
      // Port may have been in use.
      ASSERT_LT(i, 100);  // Give up after 100 tries.
      continue;
    }
    EXPECT_THAT(ret, SyscallSucceeds());

    // No need to try again.
    break;
  }
}

INSTANTIATE_TEST_CASE_P(AllFamlies, SocketMultiProtocolInetLoopbackTest,
                        ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                                          ProtocolTestParam{"UDP", SOCK_DGRAM}),
                        DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
