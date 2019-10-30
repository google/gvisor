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
#include <poll.h>
#include <string.h>
#include <sys/epoll.h>
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
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

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

TEST_P(SocketInetLoopbackTest, TCPListenClose) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;

  // Create the listening socket.
  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP));
  sockaddr_storage listen_addr = listener.addr;
  ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                   listener.addr_len),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), 1001), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = listener.addr_len;
  ASSERT_THAT(getsockname(listen_fd.get(),
                          reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
              SyscallSucceeds());
  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));

  DisableSave ds;  // Too many system calls.
  sockaddr_storage conn_addr = connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  constexpr int kFDs = 2048;
  constexpr int kThreadCount = 4;
  constexpr int kFDsPerThread = kFDs / kThreadCount;
  FileDescriptor clients[kFDs];
  std::unique_ptr<ScopedThread> threads[kThreadCount];
  for (int i = 0; i < kFDs; i++) {
    clients[i] = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
  }
  for (int i = 0; i < kThreadCount; i++) {
    threads[i] = absl::make_unique<ScopedThread>([&connector, &conn_addr,
                                                  &clients, i]() {
      for (int j = 0; j < kFDsPerThread; j++) {
        int k = i * kFDsPerThread + j;
        int ret =
            connect(clients[k].get(), reinterpret_cast<sockaddr*>(&conn_addr),
                    connector.addr_len);
        if (ret != 0) {
          EXPECT_THAT(ret, SyscallFailsWithErrno(EINPROGRESS));
        }
      }
    });
  }
  for (int i = 0; i < kThreadCount; i++) {
    threads[i]->Join();
  }
  for (int i = 0; i < 32; i++) {
    auto accepted =
        ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));
  }
  // TODO(b/138400178): Fix cooperative S/R failure when ds.reset() is invoked
  // before function end.
  // ds.reset()
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

TEST_P(SocketInetReusePortTest, TcpPortReuseMultiThread) {
  auto const& param = GetParam();

  TestAddress const& listener = param.listener;
  TestAddress const& connector = param.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;
  constexpr int kThreadCount = 3;

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

  constexpr int kConnectAttempts = 10000;
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
                break;
              }
              ASSERT_NO_ERRNO(fd);
              break;
            }
            // Receive some data from a socket to be sure that the connect()
            // system call has been completed on another side.
            int data;
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

      EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                  SyscallSucceedsWithValue(sizeof(i)));
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

TEST_P(SocketInetReusePortTest, UdpPortReuseMultiThread) {
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

TEST_P(SocketInetReusePortTest, UdpPortReuseMultiThreadShort) {
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

  int epollfd;
  ASSERT_THAT(epollfd = epoll_create1(0), SyscallSucceeds());

  for (int i = 0; i < kThreadCount; i++) {
    int fd = listener_fds[i].get();
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    ASSERT_THAT(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev), SyscallSucceeds());
  }

  std::map<uint16_t, int> portToFD;

  for (int i = 0; i < kConnectAttempts * 2; i++) {
    struct sockaddr_storage addr = {};
    socklen_t addrlen = sizeof(addr);
    struct epoll_event ev;
    int data, fd;

    ASSERT_THAT(epoll_wait(epollfd, &ev, 1, -1), SyscallSucceedsWithValue(1));

    fd = ev.data.fd;
    EXPECT_THAT(RetryEINTR(recvfrom)(fd, &data, sizeof(data), 0,
                                     reinterpret_cast<struct sockaddr*>(&addr),
                                     &addrlen),
                SyscallSucceedsWithValue(sizeof(data)));
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(connector.family(), addr));
    auto prev_port = portToFD.find(port);
    // Check that all packets from one client have been delivered to the same
    // server socket.
    if (prev_port == portToFD.end()) {
      portToFD[port] = ev.data.fd;
    } else {
      EXPECT_EQ(portToFD[port], ev.data.fd);
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

  // FIXME(b/114268588)
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

  // FIXME(b/114268588)
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

  // FIXME(b/114268588)
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

      std::cout << portreuse1 << " " << portreuse2;
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
    AllFamlies, SocketMultiProtocolInetLoopbackTest,
    ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                      ProtocolTestParam{"UDP", SOCK_DGRAM}),
    DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
