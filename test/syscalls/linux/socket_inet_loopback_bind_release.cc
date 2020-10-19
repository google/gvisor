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

#include <poll.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "test/syscalls/linux/socket_inet_loopback_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// The following tests are branched from socket_inet_loopback.cc. This is
// because the tests may disrupt each other native(linux) due to their pattern
// of acquiring a port with a bind call to port 0, subsequently releasing that
// port with a socket close operation, and then trying to immediately rebind.
// This will race with other tests calling bind to 0, as the test may be
// allocated that same port producing a EADDRINUSE failure. To fix this, we
// protect all bind calls with a mutex, treating the port space as a shared
// resource, ensuring the state of the port space doesn't change in
// bind-> release->bind operations.
//
// If adding a test to this file, you should protect any calls to bind port 0
// with the given helper functions and mutex and protect any operation where
// you bind->release->bind with the mutex.

// Global mutex protecting racy bind calls.
absl::Mutex bindMutex;

// Helper method to protect bind calls to port 0. We need to protect
// any bind call that binds to 0, as bind->release->bind operations may have
// just released a port and expect it not to be used by another test.
PosixErrorOr<int> protectedBind(int fd, struct sockaddr* addr,
                                socklen_t addr_len) {
  absl::MutexLock l(&bindMutex);
  int ret;
  if ((ret = bind(fd, addr, addr_len)) != 0) {
    return PosixError(errno);
  }
  return ret;
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
  ASSERT_THAT(
      protectedBind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                    listener.addr_len),
      IsPosixErrorOkAndHolds(0));
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

  // Get the address/port bound by the connecting socket.
  sockaddr_storage conn_bound_addr;
  socklen_t conn_addrlen = connector.addr_len;
  ASSERT_THAT(
      getsockname(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
                  &conn_addrlen),
      SyscallSucceeds());

  const FileDescriptor conn_fd2 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

  {
    absl::MutexLock l(&bindMutex);
    // Accept the connection.
    auto accepted =
        ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_fd.get(), nullptr, nullptr));

    // Close the connecting FD to trigger FIN_WAIT2 on the connected fd.
    conn_fd.reset();

    // Disable cooperative saves after this point. As a save between the first
    // bind/connect and the second one can cause the linger timeout timer to
    // be restarted causing the final bind/connect to fail.
    DisableSave ds;

    // Now bind and connect a new socket.
    ASSERT_THAT(
        bind(conn_fd2.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             conn_addrlen),
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
  }
  ASSERT_THAT(RetryEINTR(connect)(conn_fd2.get(),
                                  reinterpret_cast<sockaddr*>(&conn_addr),
                                  conn_addrlen),
              SyscallSucceeds());
}

// TCPLinger2TimeoutAfterClose creates a pair of connected sockets
// then closes one end to trigger FIN_WAIT2 state for the closed endpoint.
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
  {
    ASSERT_THAT(protectedBind(listen_fd.get(),
                              reinterpret_cast<sockaddr*>(&listen_addr),
                              listener.addr_len),
                IsPosixErrorOkAndHolds(0));
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

    absl::MutexLock l(&bindMutex);

    // close the connecting FD to trigger FIN_WAIT2  on the connected fd.
    conn_fd.reset();

    absl::SleepFor(absl::Seconds(kTCPLingerTimeout + 1));

    // ds being reset will Re-enable S/R's since at this point the timer
    // must have fired and cleaned up the endpoint.
    ds.reset();

    // Now bind and connect a new socket and verify that we can immediately
    // rebind the address bound by the conn_fd as it never entered TIME_WAIT.
    const FileDescriptor conn_fd2 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));

    ASSERT_THAT(
        bind(conn_fd2.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             conn_addrlen),
        SyscallSucceeds());
    ASSERT_THAT(RetryEINTR(connect)(conn_fd2.get(),
                                    reinterpret_cast<sockaddr*>(&conn_addr),
                                    conn_addrlen),
                SyscallSucceeds());
  }
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
  {
    ASSERT_THAT(protectedBind(listen_fd.get(),
                              reinterpret_cast<sockaddr*>(&listen_addr),
                              listener.addr_len),
                IsPosixErrorOkAndHolds(0));
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
  // ECONNRESET on the read after EOF has been read by the application.
  EXPECT_THAT(RetryEINTR(recv)(accepted.get(), &data, sizeof(data), 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(RetryEINTR(recv)(accepted.get(), &data, sizeof(data), 0),
              SyscallSucceedsWithValue(0));
}

// setupTimeWaitClose sets up a socket endpoint in TIME_WAIT state.
// Callers can choose to perform active close on either ends of the connection
// and also specify if they want to enabled SO_REUSEADDR.
//
// Caller is expected to hold a lock on "mutex".
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

// These tests are disabled under random save as the restore run
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
  {
    absl::MutexLock l(&bindMutex);
    setupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                       true /*accept_close*/, &listen_addr, &conn_bound_addr);

    // Now bind a new socket and verify that we can immediately rebind the
    // address bound by the conn_fd as it never entered TIME_WAIT.
    const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(
        bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             param.connector.addr_len),
        SyscallSucceeds());
    FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                     param.listener.addr_len),
                SyscallFailsWithErrno(EADDRINUSE));
  }
}

TEST_P(SocketInetLoopbackTest,
       TCPPassiveCloseNoTimeWaitReuseTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;

  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  {
    absl::MutexLock l(&bindMutex);
    setupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                       true /*accept_close*/, &listen_addr, &conn_bound_addr);

    ASSERT_THAT(setsockopt(listen_fd.get(), SOL_SOCKET, SO_REUSEADDR,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(bind(listen_fd.get(), reinterpret_cast<sockaddr*>(&listen_addr),
                     param.listener.addr_len),
                SyscallSucceeds());
    ASSERT_THAT(listen(listen_fd.get(), SOMAXCONN), SyscallSucceeds());

    // Now bind and connect new socket and verify that we can immediately
    // rebind the address bound by the conn_fd as it never entered TIME_WAIT.
    ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             param.connector.addr_len),
        SyscallSucceeds());
  }
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
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  {
    absl::MutexLock l(&bindMutex);
    setupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                       false /*accept_close*/, &listen_addr, &conn_bound_addr);

    ASSERT_THAT(
        bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             param.connector.addr_len),
        SyscallFailsWithErrno(EADDRINUSE));
  }
}

TEST_P(SocketInetLoopbackTest, TCPActiveCloseTimeWaitReuseTest_NoRandomSave) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;

  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  {
    absl::MutexLock l(&bindMutex);
    setupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                       false /*accept_close*/, &listen_addr, &conn_bound_addr);
    ASSERT_THAT(
        bind(conn_fd.get(), reinterpret_cast<sockaddr*>(&conn_bound_addr),
             param.connector.addr_len),
        SyscallFailsWithErrno(EADDRINUSE));
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

TEST_P(SocketMultiProtocolInetLoopbackTest,
       V4MappedEphemeralPortReservedReuseAddr) {
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

  // Listen if TCP.
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
  {
    absl::MutexLock l(&bindMutex);
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
}

INSTANTIATE_TEST_SUITE_P(
    AllFamilies, SocketMultiProtocolInetLoopbackTest,
    ::testing::Values(ProtocolTestParam{"TCP", SOCK_STREAM},
                      ProtocolTestParam{"UDP", SOCK_DGRAM}),
    DescribeProtocolTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor
