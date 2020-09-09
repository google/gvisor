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
#include <poll.h>
#include <string.h>
#include <sys/socket.h>

#include <atomic>
#include <iostream>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

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

TEST(BadSocketPairArgs, ValidateErrForBadCallsToSocketPair) {
  int fd[2] = {};

  // Valid AF but invalid for socketpair(2) return ESOCKTNOSUPPORT.
  ASSERT_THAT(socketpair(AF_INET, 0, 0, fd),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  ASSERT_THAT(socketpair(AF_INET6, 0, 0, fd),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));

  // Invalid AF will return ENOAFSUPPORT or EPERM.
  ASSERT_THAT(socketpair(AF_MAX, 0, 0, fd),
              ::testing::AnyOf(SyscallFailsWithErrno(EAFNOSUPPORT),
                               SyscallFailsWithErrno(EPERM)));
  ASSERT_THAT(socketpair(8675309, 0, 0, fd),
              ::testing::AnyOf(SyscallFailsWithErrno(EAFNOSUPPORT),
                               SyscallFailsWithErrno(EPERM)));
}

enum class Operation {
  Bind,
  Connect,
  SendTo,
};

std::string OperationToString(Operation operation) {
  switch (operation) {
    case Operation::Bind:
      return "Bind";
    case Operation::Connect:
      return "Connect";
    // Operation::SendTo is the default.
    default:
      return "SendTo";
  }
}

using OperationSequence = std::vector<Operation>;

using DualStackSocketTest =
    ::testing::TestWithParam<std::tuple<TestAddress, OperationSequence>>;

TEST_P(DualStackSocketTest, AddressOperations) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_DGRAM, 0));

  const TestAddress& addr = std::get<0>(GetParam());
  const OperationSequence& operations = std::get<1>(GetParam());

  auto addr_in = reinterpret_cast<const sockaddr*>(&addr.addr);

  // sockets may only be bound once. Both `connect` and `sendto` cause a socket
  // to be bound.
  bool bound = false;
  for (const Operation& operation : operations) {
    bool sockname = false;
    bool peername = false;
    switch (operation) {
      case Operation::Bind: {
        ASSERT_NO_ERRNO(SetAddrPort(
            addr.family(), const_cast<sockaddr_storage*>(&addr.addr), 0));

        int bind_ret = bind(fd.get(), addr_in, addr.addr_len);

        // Dual stack sockets may only be bound to AF_INET6.
        if (!bound && addr.family() == AF_INET6) {
          EXPECT_THAT(bind_ret, SyscallSucceeds());
          bound = true;

          sockname = true;
        } else {
          EXPECT_THAT(bind_ret, SyscallFailsWithErrno(EINVAL));
        }
        break;
      }
      case Operation::Connect: {
        ASSERT_NO_ERRNO(SetAddrPort(
            addr.family(), const_cast<sockaddr_storage*>(&addr.addr), 1337));

        EXPECT_THAT(RetryEINTR(connect)(fd.get(), addr_in, addr.addr_len),
                    SyscallSucceeds())
            << GetAddrStr(addr_in);
        bound = true;

        sockname = true;
        peername = true;

        break;
      }
      case Operation::SendTo: {
        const char payload[] = "hello";
        ASSERT_NO_ERRNO(SetAddrPort(
            addr.family(), const_cast<sockaddr_storage*>(&addr.addr), 1337));

        ssize_t sendto_ret = sendto(fd.get(), &payload, sizeof(payload), 0,
                                    addr_in, addr.addr_len);

        EXPECT_THAT(sendto_ret, SyscallSucceedsWithValue(sizeof(payload)));
        sockname = !bound;
        bound = true;
        break;
      }
    }

    if (sockname) {
      sockaddr_storage sock_addr;
      socklen_t addrlen = sizeof(sock_addr);
      ASSERT_THAT(getsockname(fd.get(), reinterpret_cast<sockaddr*>(&sock_addr),
                              &addrlen),
                  SyscallSucceeds());
      ASSERT_EQ(addrlen, sizeof(struct sockaddr_in6));

      auto sock_addr_in6 = reinterpret_cast<const sockaddr_in6*>(&sock_addr);

      if (operation == Operation::SendTo) {
        EXPECT_EQ(sock_addr_in6->sin6_family, AF_INET6);
        EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(sock_addr_in6->sin6_addr.s6_addr32))
            << OperationToString(operation) << " getsocknam="
            << GetAddrStr(reinterpret_cast<sockaddr*>(&sock_addr));

        EXPECT_NE(sock_addr_in6->sin6_port, 0);
      } else if (IN6_IS_ADDR_V4MAPPED(
                     reinterpret_cast<const sockaddr_in6*>(addr_in)
                         ->sin6_addr.s6_addr32)) {
        EXPECT_TRUE(IN6_IS_ADDR_V4MAPPED(sock_addr_in6->sin6_addr.s6_addr32))
            << OperationToString(operation) << " getsocknam="
            << GetAddrStr(reinterpret_cast<sockaddr*>(&sock_addr));
      }
    }

    if (peername) {
      sockaddr_storage peer_addr;
      socklen_t addrlen = sizeof(peer_addr);
      ASSERT_THAT(getpeername(fd.get(), reinterpret_cast<sockaddr*>(&peer_addr),
                              &addrlen),
                  SyscallSucceeds());
      ASSERT_EQ(addrlen, sizeof(struct sockaddr_in6));

      if (addr.family() == AF_INET ||
          IN6_IS_ADDR_V4MAPPED(reinterpret_cast<const sockaddr_in6*>(addr_in)
                                   ->sin6_addr.s6_addr32)) {
        EXPECT_TRUE(IN6_IS_ADDR_V4MAPPED(
            reinterpret_cast<const sockaddr_in6*>(&peer_addr)
                ->sin6_addr.s6_addr32))
            << OperationToString(operation) << " getpeername="
            << GetAddrStr(reinterpret_cast<sockaddr*>(&peer_addr));
      }
    }
  }
}

// TODO(gvisor.dev/issue/1556): uncomment V4MappedAny.
INSTANTIATE_TEST_SUITE_P(
    All, DualStackSocketTest,
    ::testing::Combine(
        ::testing::Values(V4Any(), V4Loopback(), /*V4MappedAny(),*/
                          V4MappedLoopback(), V6Any(), V6Loopback()),
        ::testing::ValuesIn<OperationSequence>(
            {{Operation::Bind, Operation::Connect, Operation::SendTo},
             {Operation::Bind, Operation::SendTo, Operation::Connect},
             {Operation::Connect, Operation::Bind, Operation::SendTo},
             {Operation::Connect, Operation::SendTo, Operation::Bind},
             {Operation::SendTo, Operation::Bind, Operation::Connect},
             {Operation::SendTo, Operation::Connect, Operation::Bind}})),
    [](::testing::TestParamInfo<
        std::tuple<TestAddress, OperationSequence>> const& info) {
      const TestAddress& addr = std::get<0>(info.param);
      const OperationSequence& operations = std::get<1>(info.param);
      std::string s = addr.description;
      for (const Operation& operation : operations) {
        absl::StrAppend(&s, OperationToString(operation));
      }
      return s;
    });

void tcpSimpleConnectTest(TestAddress const& listener,
                          TestAddress const& connector, bool unbound) {
  // Create the listening socket.
  const FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  if (!unbound) {
    ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                     listener.addr_len),
                SyscallSucceeds());
  }
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

TEST_P(SocketInetLoopbackTest, TCP) {
  auto const& param = GetParam();
  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  tcpSimpleConnectTest(listener, connector, true);
}

TEST_P(SocketInetLoopbackTest, TCPListenUnbound) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  tcpSimpleConnectTest(listener, connector, false);
}

TEST_P(SocketInetLoopbackTest, TCPListenShutdownListen) {
  const auto& param = GetParam();

  const TestAddress& listener = param.listener;
  const TestAddress& connector = param.connector;

  constexpr int kBacklog = 5;

  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   listener.addr_len),
              SyscallSucceeds());

  ASSERT_THAT(listen(listen_fd.get(), kBacklog), SyscallSucceeds());
  ASSERT_THAT(shutdown(listen_fd.get(), SHUT_RD), SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), kBacklog), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
              SyscallSucceeds());
  const uint16_t port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));

  for (int i = 0; i < kBacklog; i++) {
    auto client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(RetryEINTR(connect)(client.get(),
                                    reinterpret_cast<sockaddr*>(&conn_addr),
                                    connector.addr_len),
                SyscallSucceeds());
  }
  for (int i = 0; i < kBacklog; i++) {
    ASSERT_THAT(accept(listen_fd.get(), nullptr, nullptr), SyscallSucceeds());
  }
}

TEST_P(SocketInetLoopbackTest, TCPListenShutdown) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  constexpr int kBacklog = 2;
  constexpr int kFDs = kBacklog + 1;

  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
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

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));

  // Shutdown the write of the listener, expect to not have any effect.
  ASSERT_THAT(shutdown(listen_fd.get(), SHUT_WR), SyscallSucceeds());

  for (int i = 0; i < kFDs; i++) {
    auto client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(RetryEINTR(connect)(client.get(),
                                    reinterpret_cast<sockaddr*>(&conn_addr),
                                    connector.addr_len),
                SyscallSucceeds());
    ASSERT_THAT(accept(listen_fd.get(), nullptr, nullptr), SyscallSucceeds());
  }

  // Shutdown the read of the listener, expect to fail subsequent
  // server accepts, binds and client connects.
  ASSERT_THAT(shutdown(listen_fd.get(), SHUT_RD), SyscallSucceeds());

  ASSERT_THAT(accept(listen_fd.get(), nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));

  // Check that shutdown did not release the port.
  FileDescriptor new_listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(
      bind(new_listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
           listener.addr_len),
      SyscallFailsWithErrno(EADDRINUSE));

  // Check that subsequent connection attempts receive a RST.
  auto client = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  for (int i = 0; i < kFDs; i++) {
    auto client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(RetryEINTR(connect)(client.get(),
                                    reinterpret_cast<sockaddr*>(&conn_addr),
                                    connector.addr_len),
                SyscallFailsWithErrno(ECONNREFUSED));
  }
}

TEST_P(SocketInetLoopbackTest, TCPListenClose) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  constexpr int kAcceptCount = 2;
  constexpr int kBacklog = kAcceptCount + 2;
  constexpr int kFDs = kBacklog * 3;

  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
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

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  std::vector<FileDescriptor> clients;
  for (int i = 0; i < kFDs; i++) {
    auto client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
    int ret = connect(client.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                      connector.addr_len);
    if (ret != 0) {
      EXPECT_THAT(ret, SyscallFailsWithErrno(EINPROGRESS));
    }
    clients.push_back(std::move(client));
  }
  for (int i = 0; i < kAcceptCount; i++) {
    auto accepted =
        ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
  }
}

void TestListenWhileConnect(const TestParam& param,
                            void (*stopListen)(FileDescriptor&)) {
  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  constexpr int kBacklog = 2;
  constexpr int kClients = kBacklog + 1;

  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
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

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  std::vector<FileDescriptor> clients;
  for (int i = 0; i < kClients; i++) {
    FileDescriptor client = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
    int ret = connect(client.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                      connector.addr_len);
    if (ret != 0) {
      EXPECT_THAT(ret, SyscallFailsWithErrno(EINPROGRESS));
      clients.push_back(std::move(client));
    }
  }

  stopListen(listen_fd);

  for (auto& client : clients) {
    const int kTimeout = 10000;
    struct pollfd pfd = {
        .fd = client.get(),
        .events = POLLIN,
    };
    // When the listening socket is closed, then we expect the remote to reset
    // the connection.
    ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
    ASSERT_EQ(pfd.revents, POLLIN | POLLHUP | POLLERR);
    char c;
    // Subsequent read can fail with:
    // ECONNRESET: If the client connection was established and was reset by the
    // remote.
    // ECONNREFUSED: If the client connection failed to be established.
    ASSERT_THAT(read(client.get(), &c, sizeof(c)),
                AnyOf(SyscallFailsWithErrno(ECONNRESET),
                      SyscallFailsWithErrno(ECONNREFUSED)));
  }
}

TEST_P(SocketInetLoopbackTest, TCPListenCloseWhileConnect) {
  TestListenWhileConnect(GetParam(), [](FileDescriptor& f) {
    ASSERT_THAT(close(f.release()), SyscallSucceeds());
  });
}

TEST_P(SocketInetLoopbackTest, TCPListenShutdownWhileConnect) {
  TestListenWhileConnect(GetParam(), [](FileDescriptor& f) {
    ASSERT_THAT(shutdown(f.get(), SHUT_RD), SyscallSucceeds());
  });
}

TEST_P(SocketInetLoopbackTest, TCPbacklog) {
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
  ASSERT_THAT(listen(listen_fd.get(), 2), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
  int i = 0;
  while (1) {
    int ret;

    // Connect to the listening socket.
    const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
    sockaddr_storage conn_addr = connector.addr;
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
    ret = connect(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                  connector.addr_len);
    if (ret != 0) {
      EXPECT_THAT(ret, SyscallFailsWithErrno(EINPROGRESS));
      struct pollfd pfd = {
          .fd = conn_fd.get(),
          .events = POLLOUT,
      };
      ret = poll(&pfd, 1, 3000);
      if (ret == 0) break;
      EXPECT_THAT(ret, SyscallSucceedsWithValue(1));
    }
    EXPECT_THAT(RetryEINTR(send)(conn_fd.get(), &i, sizeof(i), 0),
                SyscallSucceedsWithValue(sizeof(i)));
    ASSERT_THAT(shutdown(conn_fd.get(), SHUT_RDWR), SyscallSucceeds());
    i++;
  }

  for (; i != 0; i--) {
    // Accept the connection.
    //
    // We have to assign a name to the accepted socket, as unamed temporary
    // objects are destructed upon full evaluation of the expression it is in,
    // potentially causing the connecting socket to fail to shutdown properly.
    auto accepted =
        ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
  }
}

// TCPFinWait2Test creates a pair of connected sockets then closes one end to
// trigger FIN_WAIT2 state for the closed endpoint. Then it binds the same local
// IP/port on a new socket and tries to connect. The connect should fail w/
// an EADDRINUSE. Then we wait till the FIN_WAIT2 timeout is over and try the
// connect again with a new socket and this time it should succeed.
//
// TCP timers are not S/R today, this can cause this test to be flaky when run
// under random S/R due to timer being reset on a restore.
TEST_P(SocketInetLoopbackTest, TCPFinWait2Test_NoRandomSave) {
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
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  // Lower FIN_WAIT2 state to 5 seconds for test.
  constexpr int kTCPLingerTimeout = 5;
  EXPECT_THAT(setsockopt(conn_fd.get(), IPPROTO_TCP, TCP_LINGER2,
                         &kTCPLingerTimeout, sizeof(kTCPLingerTimeout)),
              SyscallSucceedsWithValue(0));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  // Get the address/port bound by the connecting socket.
  sockaddr_storage conn_bound_addr;
  socklen_t conn_addrlen = connector.addr_len;
  ASSERT_THAT(
      getsockname(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                  &conn_addrlen),
      SyscallSucceeds());

  // close the connecting FD to trigger FIN_WAIT2  on the connected fd.
  conn_fd.reset();

  // Now bind and connect a new socket.
  const FileDescriptor conn_fd2 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  // Disable cooperative saves after this point. As a save between the first
  // bind/connect and the second one can cause the linger timeout timer to
  // be restarted causing the final bind/connect to fail.
  DisableSave ds;

  ASSERT_THAT(bind(conn_fd2.get(),
                   reinterpret_cast<sockaddr*>(&conn_bound_addr), conn_addrlen),
              SyscallFailsWithErrno(EADDRINUSE));

  // Sleep for a little over the linger timeout to reduce flakiness in
  // save/restore tests.
  absl::SleepFor(absl::Seconds(kTCPLingerTimeout + 2));

  ds.reset();

  if (!IsRunningOnGvisor()) {
    ASSERT_THAT(
        bind(conn_fd2.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             conn_addrlen),
        SyscallSucceeds());
  }
  ASSERT_THAT(RetryEINTR(connect)(conn_fd2.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  conn_addrlen),
              SyscallSucceeds());
}

// TCPLinger2TimeoutAfterClose creates a pair of connected sockets
// then closes one end to trigger FIN_WAIT2 state for the closed endpont.
// It then sleeps for the TCP_LINGER2 timeout and verifies that bind/
// connecting the same address succeeds.
//
// TCP timers are not S/R today, this can cause this test to be flaky when run
// under random S/R due to timer being reset on a restore.
TEST_P(SocketInetLoopbackTest, TCPLinger2TimeoutAfterClose_NoRandomSave) {
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
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  // Get the address/port bound by the connecting socket.
  sockaddr_storage conn_bound_addr;
  socklen_t conn_addrlen = connector.addr_len;
  ASSERT_THAT(
      getsockname(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                  &conn_addrlen),
      SyscallSucceeds());

  // Disable cooperative saves after this point as TCP timers are not restored
  // across a S/R.
  {
    DisableSave ds;
    constexpr int kTCPLingerTimeout = 5;
    EXPECT_THAT(setsockopt(conn_fd.get(), IPPROTO_TCP, TCP_LINGER2,
                           &kTCPLingerTimeout, sizeof(kTCPLingerTimeout)),
                SyscallSucceedsWithValue(0));

    // close the connecting FD to trigger FIN_WAIT2  on the connected fd.
    conn_fd.reset();

    absl::SleepFor(absl::Seconds(kTCPLingerTimeout + 1));

    // ds going out of scope will Re-enable S/R's since at this point the timer
    // must have fired and cleaned up the endpoint.
  }

  // Now bind and connect a new socket and verify that we can immediately
  // rebind the address bound by the conn_fd as it never entered TIME_WAIT.
  const FileDescriptor conn_fd2 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(bind(conn_fd2.get(),
                   reinterpret_cast<sockaddr*>(&conn_bound_addr), conn_addrlen),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(connect)(conn_fd2.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  conn_addrlen),
              SyscallSucceeds());
}

// TCPResetAfterClose creates a pair of connected sockets then closes
// one end to trigger FIN_WAIT2 state for the closed endpoint verifies
// that we generate RSTs for any new data after the socket is fully
// closed.
TEST_P(SocketInetLoopbackTest, TCPResetAfterClose) {
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
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  // close the connecting FD to trigger FIN_WAIT2  on the connected fd.
  conn_fd.reset();

  int data = 1234;

  // Now send data which should trigger a RST as the other end should
  // have timed out and closed the socket.
  EXPECT_THAT(RetryEINTR(send)(accepted.get(), &data, sizeof(data), 0),
              SyscallSucceeds());
  // Sleep for a shortwhile to get a RST back.
  absl::SleepFor(absl::Seconds(1));

  // Try writing again and we should get an EPIPE back.
  EXPECT_THAT(RetryEINTR(send)(accepted.get(), &data, sizeof(data), 0),
              SyscallFailsWithErrno(EPIPE));

  // Trying to read should return zero as the other end did send
  // us a FIN. We do it twice to verify that the RST does not cause an
  // ECONNRESET on the read after EOF has been read by applicaiton.
  EXPECT_THAT(RetryEINTR(recv)(accepted.get(), &data, sizeof(data), 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(RetryEINTR(recv)(accepted.get(), &data, sizeof(data), 0),
              SyscallSucceedsWithValue(0));
}

// setupTimeWaitClose sets up a socket endpoint in TIME_WAIT state.
// Callers can choose to perform active close on either ends of the connection
// and also specify if they want to enabled SO_REUSEADDR.
void setupTimeWaitClose(const TestAddress* listener,
                        const TestAddress* connector, bool reuse,
                        bool accept_close, sockaddr_storage* listen_addr,
                        sockaddr_storage* conn_bound_addr) {
  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener->family(), SOCK_STREAM, IPPROTO_TCP));
  if (reuse) {
    ASSERT_THAT(setsockopt(listen_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(listen_addr),
                   listener->addr_len),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), SOMAXCONN), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener->addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(listen_addr), &addrlen),
              SyscallSucceeds());

  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener->family(), *listen_addr));

  // Connect to the listening socket.
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector->family(), SOCK_STREAM, IPPROTO_TCP));

  // We disable saves after this point as a S/R causes the netstack seed
  // to be regenerated which changes what ports/ISN is picked for a given
  // tuple (src ip,src port, dst ip, dst port). This can cause the final
  // SYN to use a sequence number that looks like one from the current
  // connection in TIME_WAIT and will not be accepted causing the test
  // to timeout.
  //
  // TODO(gvisor.dev/issue/940): S/R portSeed/portHint
  DisableSave ds;

  sockaddr_storage conn_addr = connector->addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector->family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector->addr_len),
              SyscallSucceeds());

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  // Get the address/port bound by the connecting socket.
  socklen_t conn_addrlen = connector->addr_len;
  ASSERT_THAT(
      getsockname(conn_fd.get(), reinterpret_cast<sockaddr*>(conn_bound_addr),
                  &conn_addrlen),
      SyscallSucceeds());

  FileDescriptor active_closefd, passive_closefd;
  if (accept_close) {
    active_closefd = std::move(accepted);
    passive_closefd = std::move(conn_fd);
  } else {
    active_closefd = std::move(conn_fd);
    passive_closefd = std::move(accepted);
  }

  // shutdown to trigger TIME_WAIT.
  ASSERT_THAT(shutdown(active_closefd.get(), SHUT_RDWR), SyscallSucceeds());
  {
    const int kTimeout = 10000;
    struct pollfd pfd = {
        .fd = passive_closefd.get(),
        .events = POLLIN,
    };
    ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
    ASSERT_EQ(pfd.revents, POLLIN);
  }
  ScopedThread t([&]() {
    constexpr int kTimeout = 10000;
    constexpr int16_t want_events = POLLHUP;
    struct pollfd pfd = {
        .fd = active_closefd.get(),
        .events = want_events,
    };
    ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
  });

  passive_closefd.reset();
  t.Join();
  active_closefd.reset();
  // This sleep is needed to reduce flake to ensure that the passive-close
  // ensures the state transitions to CLOSE from LAST_ACK.
  absl::SleepFor(absl::Seconds(1));
}

// These tests are disabled under random save as the the restore run
// results in the stack.Seed() being different which can cause
// sequence number of final connect to be one that is considered
// old and can cause the test to be flaky.
//
// Test re-binding of client and server bound addresses when the older
// connection is in TIME_WAIT.
TEST_P(SocketInetLoopbackTest, TCPPassiveCloseNoTimeWaitTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  setupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                     true /*accept_close*/, &listen_addr, &conn_bound_addr);

  // Now bind a new socket and verify that we can immediately rebind the address
  // bound by the conn_fd as it never entered TIME_WAIT.
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallSucceeds());

  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   param.listener.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketInetLoopbackTest,
       TCPPassiveCloseNoTimeWaitReuseTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  setupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                     true /*accept_close*/, &listen_addr, &conn_bound_addr);

  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(listen_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   param.listener.addr_len),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), SOMAXCONN), SyscallSucceeds());

  // Now bind and connect  new socket and verify that we can immediately rebind
  // the address bound by the conn_fd as it never entered TIME_WAIT.
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallSucceeds());

  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(param.listener.family(), listen_addr));
  sockaddr_storage conn_addr = param.connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(param.connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  param.connector.addr_len),
              SyscallSucceeds());
}

TEST_P(SocketInetLoopbackTest, TCPActiveCloseTimeWaitTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  setupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                     false /*accept_close*/, &listen_addr, &conn_bound_addr);
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketInetLoopbackTest, TCPActiveCloseTimeWaitReuseTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  setupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                     false /*accept_close*/, &listen_addr, &conn_bound_addr);
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketInetLoopbackTest, AcceptedInheritsTCPUserTimeout) {
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

  const uint16_t port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  // Set the userTimeout on the listening socket.
  constexpr int kUserTimeout = 10;
  ASSERT_THAT(setsockopt(listen_fd.get(), IPPROTO_TCP, TCP_USER_TIMEOUT,
                         &kUserTimeout, sizeof(kUserTimeout)),
              SyscallSucceeds());

  // Connect to the listening socket.
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
  // Verify that the accepted socket inherited the user timeout set on
  // listening socket.
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(accepted.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, &get, &get_len),
      SyscallSucceeds());
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kUserTimeout);
}

// TODO(gvisor.dev/issue/1688): Partially completed passive endpoints are not
// saved. Enable S/R once issue is fixed.
TEST_P(SocketInetLoopbackTest, TCPDeferAccept_NoRandomSave) {
  // TODO(gvisor.dev/issue/1688): Partially completed passive endpoints are not
  // saved. Enable S/R issue is fixed.
  DisableSave ds;

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

  const uint16_t port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  // Set the TCP_DEFER_ACCEPT on the listening socket.
  constexpr int kTCPDeferAccept = 3;
  ASSERT_THAT(setsockopt(listen_fd.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT,
                         &kTCPDeferAccept, sizeof(kTCPDeferAccept)),
              SyscallSucceeds());

  // Connect to the listening socket.
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Set the listening socket to nonblock so that we can verify that there is no
  // connection in queue despite the connect above succeeding since the peer has
  // sent no data and TCP_DEFER_ACCEPT is set on the listening socket. Set the
  // FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(listen_fd.get(), F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(listen_fd.get(), F_SETFL, opts), SyscallSucceeds());

  ASSERT_THAT(accept(listen_fd.get(), nullptr, nullptr),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Set FD back to blocking.
  opts &= ~O_NONBLOCK;
  ASSERT_THAT(fcntl(listen_fd.get(), F_SETFL, opts), SyscallSucceeds());

  // Now write some data to the socket.
  int data = 0;
  ASSERT_THAT(RetryEINTR(write)(conn_fd.get(), &data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));

  // This should now cause the connection to complete and be delivered to the
  // accept socket.

  // Accept the connection.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

  // Verify that the accepted socket returns the data written.
  int get = -1;
  ASSERT_THAT(RetryEINTR(recv)(accepted.get(), &get, sizeof(get), 0),
              SyscallSucceedsWithValue(sizeof(get)));

  EXPECT_EQ(get, data);
}

// TODO(gvisor.dev/issue/1688): Partially completed passive endpoints are not
// saved. Enable S/R once issue is fixed.
TEST_P(SocketInetLoopbackTest, TCPDeferAcceptTimeout_NoRandomSave) {
  // TODO(gvisor.dev/issue/1688): Partially completed passive endpoints are not
  // saved. Enable S/R once issue is fixed.
  DisableSave ds;

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

  const uint16_t port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  // Set the TCP_DEFER_ACCEPT on the listening socket.
  constexpr int kTCPDeferAccept = 3;
  ASSERT_THAT(setsockopt(listen_fd.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT,
                         &kTCPDeferAccept, sizeof(kTCPDeferAccept)),
              SyscallSucceeds());

  // Connect to the listening socket.
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  connector.addr_len),
              SyscallSucceeds());

  // Set the listening socket to nonblock so that we can verify that there is no
  // connection in queue despite the connect above succeeding since the peer has
  // sent no data and TCP_DEFER_ACCEPT is set on the listening socket. Set the
  // FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(listen_fd.get(), F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(listen_fd.get(), F_SETFL, opts), SyscallSucceeds());

  // Verify that there is no acceptable connection before TCP_DEFER_ACCEPT
  // timeout is hit.
  absl::SleepFor(absl::Seconds(kTCPDeferAccept - 1));
  ASSERT_THAT(accept(listen_fd.get(), nullptr, nullptr),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Set FD back to blocking.
  opts &= ~O_NONBLOCK;
  ASSERT_THAT(fcntl(listen_fd.get(), F_SETFL, opts), SyscallSucceeds());

  // Now sleep for a little over the TCP_DEFER_ACCEPT duration. When the timeout
  // is hit a SYN-ACK should be retransmitted by the listener as a last ditch
  // attempt to complete the connection with or without data.
  absl::SleepFor(absl::Seconds(2));

  // Verify that we have a connection that can be accepted even though no
  // data was written.
  auto accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
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

using SocketInetReusePortTest = ::testing::TestWithParam<TestParam>;

// TODO(gvisor.dev/issue/940): Remove _NoRandomSave when portHint/stack.Seed is
// saved/restored.
TEST_P(SocketInetReusePortTest, TcpPortReuseMultiThread_NoRandomSave) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;
  constexpr int kThreadCount = 3;
  constexpr int kConnectAttempts = 10000;

  // Create the listening socket.
  FileDescriptor listener_fds[kThreadCount];
  for (int i = 0; i < kThreadCount; i++) {
    listener_fds[i] = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
    int fd = listener_fds[i].get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());
    ASSERT_THAT(listen(fd, 40), SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (i != 0) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  std::atomic<int> connects_received = ATOMIC_VAR_INIT(0);
  std::unique_ptr<ScopedThread> listen_thread[kThreadCount];
  int accept_counts[kThreadCount] = {};
  // TODO(avagin): figure how to not disable S/R for the whole test.
  // We need to take into account that this test executes a lot of system
  // calls from many threads.
  DisableSave ds;

  for (int i = 0; i < kThreadCount; i++) {
    listen_thread[i] = absl::make_unique<ScopedThread>(
        [&listener_fds, &accept_counts, i, &connects_received]() {
          do {
            auto fd = Accept(listener_fds[i].get(), nullptr, nullptr);
            if (!fd.ok()) {
              if (connects_received >= kConnectAttempts) {
                // Another thread have shutdown our read side causing the
                // accept to fail.
                ASSERT_EQ(errno, EINVAL);
                break;
              }
              ASSERT_NO_ERRNO(fd);
              break;
            }
            // Receive some data from a socket to be sure that the connect()
            // system call has been completed on another side.
            // Do a short read and then close the socket to trigger a RST. This
            // ensures that both ends of the connection are cleaned up and no
            // goroutines hang around in TIME-WAIT. We do this so that this test
            // does not timeout under gotsan runs where lots of goroutines can
            // cause the test to use absurd amounts of memory.
            //
            // See: https://tools.ietf.org/html/rfc2525#page-50 section 2.17
            uint16_t data;
            EXPECT_THAT(
                RetryEINTR(recv)(fd.ValueOrDie().get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
            accept_counts[i]++;
          } while (++connects_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (int j = 0; j < kThreadCount; j++) {
            shutdown(listener_fds[j].get(), SHUT_RDWR);
          }
        });
  }

  ScopedThread connecting_thread([&connector, &conn_addr]() {
    for (int i = 0; i < kConnectAttempts; i++) {
      const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
          Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
      ASSERT_THAT(
          RetryEINTR(connect)(fd.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                              connector.addr_len),
          SyscallSucceeds());

      // Do two separate sends to ensure two segments are received. This is
      // required for netstack where read is incorrectly assuming a whole
      // segment is read when endpoint.Read() is called which is technically
      // incorrect as the syscall that invoked endpoint.Read() may only
      // consume it partially. This results in a case where a close() of
      // such a socket does not trigger a RST in netstack due to the
      // endpoint assuming that the endpoint has no unread data.
      EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                  SyscallSucceedsWithValue(sizeof(i)));

      // TODO(gvisor.dev/issue/1449): Remove this block once netstack correctly
      //   generates a RST.
      if (IsRunningOnGvisor()) {
        EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                    SyscallSucceedsWithValue(sizeof(i)));
      }
    }
  });

  // Join threads to be sure that all connections have been counted
  connecting_thread.Join();
  for (int i = 0; i < kThreadCount; i++) {
    listen_thread[i]->Join();
  }
  // Check that connections are distributed fairly between listening sockets
  for (int i = 0; i < kThreadCount; i++)
    EXPECT_THAT(accept_counts[i],
                EquivalentWithin((kConnectAttempts / kThreadCount), 0.10));
}

TEST_P(SocketInetReusePortTest, UdpPortReuseMultiThread_NoRandomSave) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;
  constexpr int kThreadCount = 3;

  // Create the listening socket.
  FileDescriptor listener_fds[kThreadCount];
  for (int i = 0; i < kThreadCount; i++) {
    listener_fds[i] =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(listener.family(), SOCK_DGRAM, 0));
    int fd = listener_fds[i].get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (i != 0) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> packets_received = ATOMIC_VAR_INIT(0);
  std::unique_ptr<ScopedThread> receiver_thread[kThreadCount];
  int packets_per_socket[kThreadCount] = {};
  // TODO(avagin): figure how to not disable S/R for the whole test.
  DisableSave ds;  // Too expensive.

  for (int i = 0; i < kThreadCount; i++) {
    receiver_thread[i] = absl::make_unique<ScopedThread>(
        [&listener_fds, &packets_per_socket, i, &packets_received]() {
          do {
            struct sockaddr_storage addr = {};
            socklen_t addrlen = sizeof(addr);
            int data;

            auto ret = RetryEINTR(recvfrom)(
                listener_fds[i].get(), &data, sizeof(data), 0,
                reinterpret_cast<struct sockaddr*>(&addr), &addrlen);

            if (packets_received < kConnectAttempts) {
              ASSERT_THAT(ret, SyscallSucceedsWithValue(sizeof(data)));
            }

            if (ret != sizeof(data)) {
              // Another thread may have shutdown our read side causing the
              // recvfrom to fail.
              break;
            }

            packets_received++;
            packets_per_socket[i]++;

            // A response is required to synchronize with the main thread,
            // otherwise the main thread can send more than can fit into receive
            // queues.
            EXPECT_THAT(RetryEINTR(sendto)(
                            listener_fds[i].get(), &data, sizeof(data), 0,
                            reinterpret_cast<sockaddr*>(&addr), addrlen),
                        SyscallSucceedsWithValue(sizeof(data)));
          } while (packets_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (int j = 0; j < kThreadCount; j++)
            shutdown(listener_fds[j].get(), SHUT_RDWR);
        });
  }

  ScopedThread main_thread([&connector, &conn_addr]() {
    for (int i = 0; i < kConnectAttempts; i++) {
      const FileDescriptor fd =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(connector.family(), SOCK_DGRAM, 0));
      EXPECT_THAT(RetryEINTR(sendto)(fd.get(), &i, sizeof(i), 0,
                                     reinterpret_cast<sockaddr*>(&conn_addr),
                                     connector.addr_len),
                  SyscallSucceedsWithValue(sizeof(i)));
      int data;
      EXPECT_THAT(RetryEINTR(recv)(fd.get(), &data, sizeof(data), 0),
                  SyscallSucceedsWithValue(sizeof(data)));
    }
  });

  main_thread.Join();

  // Join threads to be sure that all connections have been counted
  for (int i = 0; i < kThreadCount; i++) {
    receiver_thread[i]->Join();
  }
  // Check that packets are distributed fairly between listening sockets.
  for (int i = 0; i < kThreadCount; i++)
    EXPECT_THAT(packets_per_socket[i],
                EquivalentWithin((kConnectAttempts / kThreadCount), 0.10));
}

TEST_P(SocketInetReusePortTest, UdpPortReuseMultiThreadShort_NoRandomSave) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;
  constexpr int kThreadCount = 3;

  // TODO(b/141211329): endpointsByNic.seed has to be saved/restored.
  const DisableSave ds141211329;

  // Create listening sockets.
  FileDescriptor listener_fds[kThreadCount];
  for (int i = 0; i < kThreadCount; i++) {
    listener_fds[i] =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(listener.family(), SOCK_DGRAM, 0));
    int fd = listener_fds[i].get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (i != 0) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10;
  FileDescriptor client_fds[kConnectAttempts];

  // Do the first run without save/restore.
  DisableSave ds;
  for (int i = 0; i < kConnectAttempts; i++) {
    client_fds[i] =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(connector.family(), SOCK_DGRAM, 0));
    EXPECT_THAT(RetryEINTR(sendto)(client_fds[i].get(), &i, sizeof(i), 0,
                                   reinterpret_cast<sockaddr*>(&conn_addr),
                                   connector.addr_len),
                SyscallSucceedsWithValue(sizeof(i)));
  }
  ds.reset();

  // Check that a mapping of client and server sockets has
  // not been change after save/restore.
  for (int i = 0; i < kConnectAttempts; i++) {
    EXPECT_THAT(RetryEINTR(sendto)(client_fds[i].get(), &i, sizeof(i), 0,
                                   reinterpret_cast<sockaddr*>(&conn_addr),
                                   connector.addr_len),
                SyscallSucceedsWithValue(sizeof(i)));
  }

  struct pollfd pollfds[kThreadCount];
  for (int i = 0; i < kThreadCount; i++) {
    pollfds[i].fd = listener_fds[i].get();
    pollfds[i].events = POLLIN;
  }

  std::map<uint16_t, int> portToFD;

  int received = 0;
  while (received < kConnectAttempts * 2) {
    ASSERT_THAT(poll(pollfds, kThreadCount, -1),
                SyscallSucceedsWithValue(Gt(0)));

    for (int i = 0; i < kThreadCount; i++) {
      if ((pollfds[i].revents & POLLIN) == 0) {
        continue;
      }

      received++;

      const int fd = pollfds[i].fd;
      struct sockaddr_storage addr = {};
      socklen_t addrlen = sizeof(addr);
      int data;
      EXPECT_THAT(RetryEINTR(recvfrom)(
                      fd, &data, sizeof(data), 0,
                      reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
                  SyscallSucceedsWithValue(sizeof(data)));
      uint16_t const port =
          ASSERT_NO_ERRNO_AND_VALUE(AddrPort(connector.family(), addr));
      auto prev_port = portToFD.find(port);
      // Check that all packets from one client have been delivered to the
      // same server socket.
      if (prev_port == portToFD.end()) {
        portToFD[port] = fd;
      } else {
        EXPECT_EQ(portToFD[port], fd);
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    All, SocketInetReusePortTest,
    ::testing::Values(
        // Listeners bound to IPv4 addresses refuse connections using IPv6
        // addresses.
        TestParam{V4Any(), V4Loopback()},
        TestParam{V4Loopback(), V4MappedLoopback()},

        // Listeners bound to IN6ADDR_ANY accept all connections.
        TestParam{V6Any(), V4Loopback()}, TestParam{V6Any(), V6Loopback()},

        // Listeners bound to IN6ADDR_LOOPBACK refuse connections using IPv4
        // addresses.
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

  // Verify that binding the v4 any on the same port with a v4 socket
  // fails.
  TestAddress const& test_addr_v4_any = V4Any();
  sockaddr_storage addr_v4_any = test_addr_v4_any.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_any.family(), &addr_v4_any, port));
  const FileDescriptor fd_v4_any = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(test_addr_v4_any.family(), param.type, 0));
  ASSERT_THAT(bind(fd_v4_any.get(), reinterpret_cast<sockaddr*>(&addr_v4_any),
                   test_addr_v4_any.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketMultiProtocolInetLoopbackTest,
       DualStackV6AnyReuseAddrDoesNotReserveV4Any) {
  auto const& param = GetParam();

  // Bind the v6 any on a dual stack socket.
  TestAddress const& test_addr_dual = V6Any();
  sockaddr_storage addr_dual = test_addr_dual.addr;
  const FileDescriptor fd_dual =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_dual.family(), param.type, 0));
  ASSERT_THAT(setsockopt(fd_dual.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
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

  // Verify that binding the v4 any on the same port with a v4 socket succeeds.
  TestAddress const& test_addr_v4_any = V4Any();
  sockaddr_storage addr_v4_any = test_addr_v4_any.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_any.family(), &addr_v4_any, port));
  const FileDescriptor fd_v4_any = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(test_addr_v4_any.family(), param.type, 0));
  ASSERT_THAT(setsockopt(fd_v4_any.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(fd_v4_any.get(), reinterpret_cast<sockaddr*>(&addr_v4_any),
                   test_addr_v4_any.addr_len),
              SyscallSucceeds());
}

TEST_P(SocketMultiProtocolInetLoopbackTest,
       DualStackV6AnyReuseAddrListenReservesV4Any) {
  auto const& param = GetParam();

  // Only TCP sockets are supported.
  SKIP_IF((param.type & SOCK_STREAM) == 0);

  // Bind the v6 any on a dual stack socket.
  TestAddress const& test_addr_dual = V6Any();
  sockaddr_storage addr_dual = test_addr_dual.addr;
  const FileDescriptor fd_dual =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_dual.family(), param.type, 0));
  ASSERT_THAT(setsockopt(fd_dual.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                   test_addr_dual.addr_len),
              SyscallSucceeds());

  ASSERT_THAT(listen(fd_dual.get(), 5), SyscallSucceeds());

  // Get the port that we bound.
  socklen_t addrlen = test_addr_dual.addr_len;
  ASSERT_THAT(getsockname(fd_dual.get(),
                          reinterpret_cast<sockaddr*>(&addr_dual), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(test_addr_dual.family(), addr_dual));

  // Verify that binding the v4 any on the same port with a v4 socket succeeds.
  TestAddress const& test_addr_v4_any = V4Any();
  sockaddr_storage addr_v4_any = test_addr_v4_any.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_any.family(), &addr_v4_any, port));
  const FileDescriptor fd_v4_any = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(test_addr_v4_any.family(), param.type, 0));
  ASSERT_THAT(setsockopt(fd_v4_any.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(bind(fd_v4_any.get(), reinterpret_cast<sockaddr*>(&addr_v4_any),
                   test_addr_v4_any.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketMultiProtocolInetLoopbackTest,
       DualStackV6AnyWithListenReservesEverything) {
  auto const& param = GetParam();

  // Only TCP sockets are supported.
  SKIP_IF((param.type & SOCK_STREAM) == 0);

  // Bind the v6 any on a dual stack socket.
  TestAddress const& test_addr_dual = V6Any();
  sockaddr_storage addr_dual = test_addr_dual.addr;
  const FileDescriptor fd_dual =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr_dual.family(), param.type, 0));
  ASSERT_THAT(bind(fd_dual.get(), reinterpret_cast<sockaddr*>(&addr_dual),
                   test_addr_dual.addr_len),
              SyscallSucceeds());

  ASSERT_THAT(listen(fd_dual.get(), 5), SyscallSucceeds());

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

  // Verify that binding the v4 any on the same port with a v4 socket
  // fails.
  TestAddress const& test_addr_v4_any = V4Any();
  sockaddr_storage addr_v4_any = test_addr_v4_any.addr;
  ASSERT_NO_ERRNO(SetAddrPort(test_addr_v4_any.family(), &addr_v4_any, port));
  const FileDescriptor fd_v4_any = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(test_addr_v4_any.family(), param.type, 0));
  ASSERT_THAT(bind(fd_v4_any.get(), reinterpret_cast<sockaddr*>(&addr_v4_any),
                   test_addr_v4_any.addr_len),
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
    EXPECT_THAT(setsockopt(fd_dual.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                           &kSockOptOn, sizeof(kSockOptOn)),
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
    ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                    reinterpret_cast<sockaddr*>(&bound_addr),
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

TEST_P(SocketMultiProtocolInetLoopbackTest, V6EphemeralPortReservedReuseAddr) {
  auto const& param = GetParam();

  // Bind the v6 loopback on a dual stack socket.
  TestAddress const& test_addr = V6Loopback();
  sockaddr_storage bound_addr = test_addr.addr;
  const FileDescriptor bound_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                   test_addr.addr_len),
              SyscallSucceeds());
  ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
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
  ASSERT_THAT(setsockopt(connected_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                  reinterpret_cast<sockaddr*>(&bound_addr),
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

  // Verify that the ephemeral port is not reserved.
  const FileDescriptor checking_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  ASSERT_THAT(setsockopt(checking_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  EXPECT_THAT(
      bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
           connected_addr_len),
      SyscallSucceeds());
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V4MappedEphemeralPortReserved) {
  auto const& param = GetParam();

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
    ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                    reinterpret_cast<sockaddr*>(&bound_addr),
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
      EXPECT_THAT(setsockopt(fd_v6_only_any.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                             &kSockOptOn, sizeof(kSockOptOn)),
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

TEST_P(SocketMultiProtocolInetLoopbackTest,
       V4MappedEphemeralPortReservedResueAddr) {
  auto const& param = GetParam();

  // Bind the v4 loopback on a dual stack socket.
  TestAddress const& test_addr = V4MappedLoopback();
  sockaddr_storage bound_addr = test_addr.addr;
  const FileDescriptor bound_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                   test_addr.addr_len),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
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
  ASSERT_THAT(setsockopt(connected_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                  reinterpret_cast<sockaddr*>(&bound_addr),
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

  // Verify that the ephemeral port is not reserved.
  const FileDescriptor checking_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  ASSERT_THAT(setsockopt(checking_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  EXPECT_THAT(
      bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
           connected_addr_len),
      SyscallSucceeds());
}

TEST_P(SocketMultiProtocolInetLoopbackTest, V4EphemeralPortReserved) {
  auto const& param = GetParam();

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
    ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                    reinterpret_cast<sockaddr*>(&bound_addr),
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
      EXPECT_THAT(setsockopt(fd_v6_only_any.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                             &kSockOptOn, sizeof(kSockOptOn)),
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

TEST_P(SocketMultiProtocolInetLoopbackTest, V4EphemeralPortReservedReuseAddr) {
  auto const& param = GetParam();

  // Bind the v4 loopback on a v4 socket.
  TestAddress const& test_addr = V4Loopback();
  sockaddr_storage bound_addr = test_addr.addr;
  const FileDescriptor bound_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));

  ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

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

  ASSERT_THAT(setsockopt(connected_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(connected_fd.get(),
                                  reinterpret_cast<sockaddr*>(&bound_addr),
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

  // Verify that the ephemeral port is not reserved.
  const FileDescriptor checking_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  ASSERT_THAT(setsockopt(checking_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());
  EXPECT_THAT(
      bind(checking_fd.get(), reinterpret_cast<sockaddr*>(&connected_addr),
           connected_addr_len),
      SyscallSucceeds());
}

TEST_P(SocketMultiProtocolInetLoopbackTest,
       MultipleBindsAllowedNoListeningReuseAddr) {
  const auto& param = GetParam();
  // UDP sockets are allowed to bind/listen on the port w/ SO_REUSEADDR, for TCP
  // this is only permitted if there is no other listening socket.
  SKIP_IF(param.type != SOCK_STREAM);
  // Bind the v4 loopback on a v4 socket.
  const TestAddress& test_addr = V4Loopback();
  sockaddr_storage bound_addr = test_addr.addr;
  FileDescriptor bound_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));

  ASSERT_THAT(setsockopt(bound_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                   test_addr.addr_len),
              SyscallSucceeds());
  // Get the port that we bound.
  socklen_t bound_addr_len = test_addr.addr_len;
  ASSERT_THAT(
      getsockname(bound_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                  &bound_addr_len),
      SyscallSucceeds());

  // Now create a socket and bind it to the same port, this should
  // succeed since there is no listening socket for the same port.
  FileDescriptor second_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));

  ASSERT_THAT(setsockopt(second_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(second_fd.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                   test_addr.addr_len),
              SyscallSucceeds());
}

TEST_P(SocketMultiProtocolInetLoopbackTest, PortReuseTwoSockets) {
  auto const& param = GetParam();
  TestAddress const& test_addr = V4Loopback();
  sockaddr_storage addr = test_addr.addr;

  for (int i = 0; i < 2; i++) {
    const int portreuse1 = i % 2;
    auto s1 =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
    int fd1 = s1.get();
    socklen_t addrlen = test_addr.addr_len;

    EXPECT_THAT(
        setsockopt(fd1, SOL_SOCKET, SO_REUSEPORT, &portreuse1, sizeof(int)),
        SyscallSucceeds());

    ASSERT_THAT(bind(fd1, reinterpret_cast<sockaddr*>(&addr), addrlen),
                SyscallSucceeds());

    ASSERT_THAT(getsockname(fd1, reinterpret_cast<sockaddr*>(&addr), &addrlen),
                SyscallSucceeds());
    if (param.type == SOCK_STREAM) {
      ASSERT_THAT(listen(fd1, 1), SyscallSucceeds());
    }

    // j is less than 4 to check that the port reuse logic works correctly after
    // closing bound sockets.
    for (int j = 0; j < 4; j++) {
      const int portreuse2 = j % 2;
      auto s2 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
      int fd2 = s2.get();

      EXPECT_THAT(
          setsockopt(fd2, SOL_SOCKET, SO_REUSEPORT, &portreuse2, sizeof(int)),
          SyscallSucceeds());

      std::cout << portreuse1 << " " << portreuse2 << std::endl;
      int ret = bind(fd2, reinterpret_cast<sockaddr*>(&addr), addrlen);

      // Verify that two sockets can be bound to the same port only if
      // SO_REUSEPORT is set for both of them.
      if (!portreuse1 || !portreuse2) {
        ASSERT_THAT(ret, SyscallFailsWithErrno(EADDRINUSE));
      } else {
        ASSERT_THAT(ret, SyscallSucceeds());
      }
    }
  }
}

// Check that when a socket was bound to an address with REUSEPORT and then
// closed, we can bind a different socket to the same address without needing
// REUSEPORT.
TEST_P(SocketMultiProtocolInetLoopbackTest, NoReusePortFollowingReusePort) {
  auto const& param = GetParam();
  TestAddress const& test_addr = V4Loopback();
  sockaddr_storage addr = test_addr.addr;

  auto s = ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  int fd = s.get();
  socklen_t addrlen = test_addr.addr_len;
  int portreuse = 1;
  ASSERT_THAT(
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &portreuse, sizeof(portreuse)),
      SyscallSucceeds());
  ASSERT_THAT(bind(fd, reinterpret_cast<sockaddr*>(&addr), addrlen),
              SyscallSucceeds());
  ASSERT_THAT(getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  ASSERT_EQ(addrlen, test_addr.addr_len);

  s.reset();

  // Open a new socket and bind to the same address, but w/o REUSEPORT.
  s = ASSERT_NO_ERRNO_AND_VALUE(Socket(test_addr.family(), param.type, 0));
  fd = s.get();
  portreuse = 0;
  ASSERT_THAT(
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &portreuse, sizeof(portreuse)),
      SyscallSucceeds());
  ASSERT_THAT(bind(fd, reinterpret_cast<sockaddr*>(&addr), addrlen),
              SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(
    AllFamilies, SocketMultiProtocolInetLoopbackTest,
    ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                      ProtocolTestParam{"UDP", SOCK_DGRAM}),
    DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
