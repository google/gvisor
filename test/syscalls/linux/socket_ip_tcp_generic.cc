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

#include "test/syscalls/linux/socket_ip_tcp_generic.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(TCPSocketPairTest, TcpInfoSucceedes) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct tcp_info opt = {};
  socklen_t optLen = sizeof(opt);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_TCP, TCP_INFO, &opt, &optLen),
              SyscallSucceeds());
}

TEST_P(TCPSocketPairTest, ShortTcpInfoSucceedes) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct tcp_info opt = {};
  socklen_t optLen = 1;
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_TCP, TCP_INFO, &opt, &optLen),
              SyscallSucceeds());
}

TEST_P(TCPSocketPairTest, ZeroTcpInfoSucceedes) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct tcp_info opt = {};
  socklen_t optLen = 0;
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_TCP, TCP_INFO, &opt, &optLen),
              SyscallSucceeds());
}

// This test validates that an RST is sent instead of a FIN when data is
// unread on calls to close(2).
TEST_P(TCPSocketPairTest, RSTSentOnCloseWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until t_ sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now close the connected without reading the data.
  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());

  // Wait for the other end to receive the RST (up to 20 seconds).
  struct pollfd poll_fd2 = {sockets->first_fd(), POLLIN | POLLHUP, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // A shutdown with unread data will cause a RST to be sent instead
  // of a FIN, per RFC 2525 section 2.17; this is also what Linux does.
  ASSERT_THAT(RetryEINTR(read)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

// This test will validate that a RST will cause POLLHUP to trigger.
TEST_P(TCPSocketPairTest, RSTCausesPollHUP) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until second sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);

  // Confirm we at least have one unread byte.
  int bytes_available = 0;
  ASSERT_THAT(
      RetryEINTR(ioctl)(sockets->second_fd(), FIONREAD, &bytes_available),
      SyscallSucceeds());
  EXPECT_GT(bytes_available, 0);

  // Now close the connected socket without reading the data from the second,
  // this will cause a RST and we should see that with POLLHUP.
  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());

  // Wait for the other end to receive the RST (up to 20 seconds).
  struct pollfd poll_fd3 = {sockets->first_fd(), POLLHUP, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd3, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));
  ASSERT_NE(poll_fd3.revents & POLLHUP, 0);
}

// This test validates that even if a RST is sent the other end will not
// get an ECONNRESET until it's read all data.
TEST_P(TCPSocketPairTest, RSTSentOnCloseWithUnreadDataAllowsReadBuffered) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));
  ASSERT_THAT(RetryEINTR(write)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until second sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN, 0};
  constexpr int kPollTimeoutMs = 30000;  // Wait up to 30 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Wait until first sees the data on its side but don't read it.
  struct pollfd poll_fd2 = {sockets->first_fd(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now close the connected socket without reading the data from the second.
  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());

  // Wait for the other end to receive the RST (up to 30 seconds).
  struct pollfd poll_fd3 = {sockets->first_fd(), POLLHUP, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd3, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Since we also have data buffered we should be able to read it before
  // the syscall will fail with ECONNRESET.
  ASSERT_THAT(RetryEINTR(read)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // A shutdown with unread data will cause a RST to be sent instead
  // of a FIN, per RFC 2525 section 2.17; this is also what Linux does.
  ASSERT_THAT(RetryEINTR(read)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

// This test will verify that a clean shutdown (FIN) is preformed when there
// is unread data but only the write side is closed.
TEST_P(TCPSocketPairTest, FINSentOnShutdownWrWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until t_ sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now shutdown the write end leaving the read end open.
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_WR), SyscallSucceeds());

  // Wait for the other end to receive the FIN (up to 20 seconds).
  struct pollfd poll_fd2 = {sockets->first_fd(), POLLIN | POLLHUP, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Since we didn't shutdown the read end this will be a clean close.
  ASSERT_THAT(RetryEINTR(read)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));
}

// This test will verify that when data is received by a socket, even if it's
// not read SHUT_RD will not cause any packets to be generated.
TEST_P(TCPSocketPairTest, ShutdownRdShouldCauseNoPacketsWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until t_ sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now shutdown the read end, this will generate no packets to the other end.
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RD), SyscallSucceeds());

  // We should not receive any events on the other side of the socket.
  struct pollfd poll_fd2 = {sockets->first_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollNoResponseTimeoutMs = 3000;
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollNoResponseTimeoutMs),
              SyscallSucceedsWithValue(0));  // Timeout.
}

// This test will verify that a socket which has unread data will still allow
// the data to be read after shutting down the read side, and once there is no
// unread data left, then read will return an EOF.
TEST_P(TCPSocketPairTest, ShutdownRdAllowsReadOfReceivedDataBeforeEOF) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until t_ sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now shutdown the read end.
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RD), SyscallSucceeds());

  // Even though we did a SHUT_RD on the read end we can still read the data.
  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // After reading all of the data, reading the closed read end returns EOF.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));
  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));
}

TEST_P(TCPSocketPairTest, ClosedReadNonBlockingSocket) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set the read end to O_NONBLOCK.
  int opts = 0;
  ASSERT_THAT(opts = fcntl(sockets->second_fd(), F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(sockets->second_fd(), F_SETFL, opts | O_NONBLOCK),
              SyscallSucceeds());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(send)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until second_fd sees the data and then recv it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN, 0};
  constexpr int kPollTimeoutMs = 2000;  // Wait up to 2 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Now shutdown the write end leaving the read end open.
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  // Wait for close notification and recv again.
  struct pollfd poll_fd2 = {sockets->second_fd(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(0));
}

TEST_P(TCPSocketPairTest,
       ShutdownRdUnreadDataShouldCauseNoPacketsUnlessClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait until t_ sees the data on its side but don't read it.
  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now shutdown the read end, this will generate no packets to the other end.
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RD), SyscallSucceeds());

  // We should not receive any events on the other side of the socket.
  struct pollfd poll_fd2 = {sockets->first_fd(), POLLIN | POLLHUP, 0};
  constexpr int kPollNoResponseTimeoutMs = 3000;
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollNoResponseTimeoutMs),
              SyscallSucceedsWithValue(0));  // Timeout.

  // Now since we've fully closed the connection it will generate a RST.
  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd2, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));  // The other end has closed.

  // A shutdown with unread data will cause a RST to be sent instead
  // of a FIN, per RFC 2525 section 2.17; this is also what Linux does.
  ASSERT_THAT(RetryEINTR(read)(sockets->first_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

TEST_P(TCPSocketPairTest, TCPCorkDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TCPSocketPairTest, SetTCPCork) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  EXPECT_THAT(
      getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TCPSocketPairTest, TCPCork) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  constexpr char kData[] = "abc";
  ASSERT_THAT(WriteFd(sockets->first_fd(), kData, sizeof(kData)),
              SyscallSucceedsWithValue(sizeof(kData)));

  ASSERT_NO_FATAL_FAILURE(RecvNoData(sockets->second_fd()));

  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CORK,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  // Create a receive buffer larger than kData.
  char buf[(sizeof(kData) + 1) * 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(kData)));
  EXPECT_EQ(absl::string_view(kData, sizeof(kData)),
            absl::string_view(buf, sizeof(kData)));
}

TEST_P(TCPSocketPairTest, TCPQuickAckDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_QUICKACK, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(TCPSocketPairTest, SetTCPQuickAck) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_QUICKACK,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_QUICKACK, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_QUICKACK,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_QUICKACK, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(TCPSocketPairTest, SoKeepaliveDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TCPSocketPairTest, SetSoKeepalive) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TCPSocketPairTest, TCPKeepidleDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPIDLE, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 2 * 60 * 60);  // 2 hours.
}

TEST_P(TCPSocketPairTest, TCPKeepintvlDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPINTVL, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 75);  // 75 seconds.
}

TEST_P(TCPSocketPairTest, SetTCPKeepidleZero) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kZero = 0;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPIDLE, &kZero,
                         sizeof(kZero)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(TCPSocketPairTest, SetTCPKeepintvlZero) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kZero = 0;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPINTVL,
                         &kZero, sizeof(kZero)),
              SyscallFailsWithErrno(EINVAL));
}

// Copied from include/net/tcp.h.
constexpr int MAX_TCP_KEEPIDLE = 32767;
constexpr int MAX_TCP_KEEPINTVL = 32767;

TEST_P(TCPSocketPairTest, SetTCPKeepidleAboveMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kAboveMax = MAX_TCP_KEEPIDLE + 1;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPIDLE,
                         &kAboveMax, sizeof(kAboveMax)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(TCPSocketPairTest, SetTCPKeepintvlAboveMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kAboveMax = MAX_TCP_KEEPINTVL + 1;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPINTVL,
                         &kAboveMax, sizeof(kAboveMax)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(TCPSocketPairTest, SetTCPKeepidleToMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPIDLE,
                         &MAX_TCP_KEEPIDLE, sizeof(MAX_TCP_KEEPIDLE)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPIDLE, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, MAX_TCP_KEEPIDLE);
}

TEST_P(TCPSocketPairTest, SetTCPKeepintvlToMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPINTVL,
                         &MAX_TCP_KEEPINTVL, sizeof(MAX_TCP_KEEPINTVL)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_KEEPINTVL, &get,
                         &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, MAX_TCP_KEEPINTVL);
}

TEST_P(TCPSocketPairTest, SetOOBInline) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_OOBINLINE,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_OOBINLINE, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(TCPSocketPairTest, MsgTruncMsgPeek) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  // Read half of the data with MSG_TRUNC | MSG_PEEK. This way there will still
  // be some data left to read in the next step even if the data gets consumed.
  char received_data1[sizeof(sent_data) / 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data1,
                               sizeof(received_data1), MSG_TRUNC | MSG_PEEK),
              SyscallSucceedsWithValue(sizeof(received_data1)));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data1)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data1, sizeof(received_data1)));

  // Check that all of the data is still there.
  char received_data2[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data2,
                               sizeof(received_data2), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  EXPECT_EQ(0, memcmp(received_data2, sent_data, sizeof(sent_data)));
}

TEST_P(TCPSocketPairTest, SetCongestionControlSucceedsForSupported) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  // Netstack only supports reno & cubic so we only test these two values here.
  {
    const char kSetCC[kTcpCaNameMax] = "reno";
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &kSetCC, strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax];
    memset(got_cc, '1', sizeof(got_cc));
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &got_cc, &optlen),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kSetCC)));
  }
  {
    const char kSetCC[kTcpCaNameMax] = "cubic";
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &kSetCC, strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax];
    memset(got_cc, '1', sizeof(got_cc));
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &got_cc, &optlen),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kSetCC)));
  }
}

TEST_P(TCPSocketPairTest, SetGetTCPCongestionShortReadBuffer) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  {
    // Verify that getsockopt/setsockopt work with buffers smaller than
    // kTcpCaNameMax.
    const char kSetCC[] = "cubic";
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &kSetCC, strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[sizeof(kSetCC)];
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &got_cc, &optlen),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(got_cc)));
  }
}

TEST_P(TCPSocketPairTest, SetGetTCPCongestionLargeReadBuffer) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  {
    // Verify that getsockopt works with buffers larger than
    // kTcpCaNameMax.
    const char kSetCC[] = "cubic";
    ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &kSetCC, strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax + 5];
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                           &got_cc, &optlen),
                SyscallSucceedsWithValue(0));
    // Linux copies the minimum of kTcpCaNameMax or the length of the passed in
    // buffer and sets optlen to the number of bytes actually copied
    // irrespective of the actual length of the congestion control name.
    EXPECT_EQ(kTcpCaNameMax, optlen);
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kSetCC)));
  }
}

TEST_P(TCPSocketPairTest, SetCongestionControlFailsForUnsupported) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char old_cc[kTcpCaNameMax];
  socklen_t optlen = sizeof(old_cc);
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                         &old_cc, &optlen),
              SyscallSucceedsWithValue(0));

  const char kSetCC[] = "invalid_ca_cc";
  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                         &kSetCC, strlen(kSetCC)),
              SyscallFailsWithErrno(ENOENT));

  char got_cc[kTcpCaNameMax];
  optlen = sizeof(got_cc);
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_TCP, TCP_CONGESTION,
                         &got_cc, &optlen),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(0, memcmp(got_cc, old_cc, sizeof(old_cc)));
}

}  // namespace testing
}  // namespace gvisor
