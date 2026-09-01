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

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstdint>
#include <functional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of connected stream unix sockets.
using StreamUnixSocketPairTest = SocketPairTest;

TEST_P(StreamUnixSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  char data[10] = {};
  ASSERT_THAT(read(sockets->second_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, RecvmsgOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set timeout so that it will not wait for ever.
  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv,
                         sizeof(tv)),
              SyscallSucceeds());

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  char received_data[10] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(recvmsg(sockets->second_fd(), &msg, MSG_WAITALL),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosedWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

TEST_P(StreamUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  constexpr char kStr[] = "abc";
  ASSERT_THAT(sendto(sockets->second_fd(), kStr, 3, 0, (struct sockaddr*)&addr,
                     sizeof(addr)),
              SyscallFailsWithErrno(EISCONN));
}

TEST_P(StreamUnixSocketPairTest, SetAndGetSocketLinger) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct linger sl = {1, 5};
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)),
      SyscallSucceedsWithValue(0));

  struct linger got_linger = {};
  socklen_t length = sizeof(sl);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_LINGER,
                         &got_linger, &length),
              SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got_linger));
  EXPECT_EQ(0, memcmp(&got_linger, &sl, length));
}

TEST_P(StreamUnixSocketPairTest, GetSocketAcceptConn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
      SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

TEST_P(StreamUnixSocketPairTest, SetSocketSendBuf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  auto s = sockets->first_fd();
  int max = 0;
  int min = 0;
  {
    // Discover maximum buffer size by setting to a really large value.
    constexpr int kRcvBufSz = INT_MAX;
    ASSERT_THAT(
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by setting it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(
      setsockopt(s, SOL_SOCKET, SO_SNDBUF, &quarter_sz, sizeof(quarter_sz)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  // Linux doubles the value set by SO_SNDBUF/SO_SNDBUF.
  quarter_sz *= 2;
  ASSERT_EQ(quarter_sz, val);
}

TEST_P(StreamUnixSocketPairTest, SendBufferOverflow) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  auto s = sockets->first_fd();

  constexpr int kBufSz = 4096;
  std::vector<char> buf(kBufSz * 4);
  ASSERT_THAT(RetryEINTR(send)(s, buf.data(), buf.size(), MSG_DONTWAIT),
              SyscallSucceeds());
  // The new buffer size should be smaller that the amount of data in the queue.
  ASSERT_THAT(setsockopt(s, SOL_SOCKET, SO_SNDBUF, &kBufSz, sizeof(kBufSz)),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(send)(s, buf.data(), buf.size(), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(StreamUnixSocketPairTest, IncreasedSocketSendBufUnblocksWrites) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int sock = sockets->first_fd();
  int buf_size = 0;
  socklen_t buf_size_len = sizeof(buf_size);
  ASSERT_THAT(getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, &buf_size_len),
              SyscallSucceeds());
  int opts;
  ASSERT_THAT(opts = fcntl(sock, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(sock, F_SETFL, opts), SyscallSucceeds());

  std::vector<char> buf(buf_size / 4);
  // Write till the socket buffer is full.
  while (RetryEINTR(send)(sock, buf.data(), buf.size(), 0) != -1) {
    // Sleep to give linux a chance to move data from the send buffer to the
    // receive buffer.
    absl::SleepFor(absl::Milliseconds(10));  // 10ms.
  }
  // The last error should have been EWOULDBLOCK.
  ASSERT_EQ(errno, EWOULDBLOCK);

  // Now increase the socket send buffer.
  buf_size = buf_size * 2;
  ASSERT_THAT(
      setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)),
      SyscallSucceeds());

  // The send should succeed again.
  ASSERT_THAT(RetryEINTR(send)(sock, buf.data(), buf.size(), 0),
              SyscallSucceeds());
}

TEST_P(StreamUnixSocketPairTest, GetAcceptConn) {
  auto bound = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  struct sockaddr_un bind_addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  ASSERT_THAT(bind(bound.get(), AsSockAddr(&bind_addr), sizeof(bind_addr)),
              SyscallSucceeds());
  int opt = 0;
  socklen_t opt_len = sizeof(opt);
  ASSERT_THAT(
      getsockopt(bound.get(), SOL_SOCKET, SO_ACCEPTCONN, &opt, &opt_len),
      SyscallSucceeds());
  ASSERT_EQ(opt, 0);
  ASSERT_THAT(listen(bound.get(),
                     /* backlog = */ 5),  // NOLINT(bugprone-argument-comment)
              SyscallSucceeds());
  ASSERT_THAT(
      getsockopt(bound.get(), SOL_SOCKET, SO_ACCEPTCONN, &opt, &opt_len),
      SyscallSucceeds());
  ASSERT_EQ(opt, 1);
}

// All MSG_PEEK/MSG_TRUNC combinations, as exercised by the zero-length
// receive tests below.
constexpr int kZeroLengthRecvFlagCombos[] = {0, MSG_PEEK, MSG_TRUNC,
                                             MSG_PEEK | MSG_TRUNC};

// A zero-length receive on a stream socket with data pending returns 0
// without consuming any data, whatever the combination of
// MSG_PEEK/MSG_TRUNC: stream sockets ignore MSG_TRUNC (both as a length
// probe and in msg_flags), and there is no message boundary to consume.
TEST_P(StreamUnixSocketPairTest, ZeroLengthRecvPendingData) {
  char sent_data[3] = {'a', 'b', 'c'};
  for (int flags : kZeroLengthRecvFlagCombos) {
    SCOPED_TRACE(::testing::Message() << "flags=" << flags);
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
    ASSERT_THAT(
        RetryEINTR(send)(sockets->second_fd(), sent_data, sizeof(sent_data), 0),
        SyscallSucceedsWithValue(sizeof(sent_data)));

    struct msghdr msg = {};
    ASSERT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, flags),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(msg.msg_flags & MSG_TRUNC, 0);

    // The data is still there.
    char received_data[sizeof(sent_data)] = {};
    ASSERT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                                 sizeof(received_data), MSG_DONTWAIT),
                SyscallSucceedsWithValue(sizeof(sent_data)));
    EXPECT_EQ(memcmp(sent_data, received_data, sizeof(sent_data)), 0);
  }
}

// A zero-length non-blocking receive on an empty stream socket must fail
// with EAGAIN rather than return 0, whatever the combination of
// MSG_PEEK/MSG_TRUNC and control message space. Returning 0 on a zero-length
// request is a read(2) behavior; recvmsg(2) waits for data.
TEST_P(StreamUnixSocketPairTest, ZeroLengthRecvEmptyQueue) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  for (int flags : kZeroLengthRecvFlagCombos) {
    for (bool control_space : {false, true}) {
      SCOPED_TRACE(::testing::Message()
                   << "flags=" << flags << " control_space=" << control_space);
      char control[CMSG_SPACE(sizeof(int))];
      struct msghdr msg = {};
      if (control_space) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
      }
      EXPECT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg,
                                      flags | MSG_DONTWAIT | MSG_CMSG_CLOEXEC),
                  SyscallFailsWithErrno(EAGAIN));
    }
  }
}

// A zero-length receive on an empty stream socket returns 0, not EAGAIN,
// once the peer has shut down writes, whatever the combination of
// MSG_PEEK/MSG_TRUNC.
TEST_P(StreamUnixSocketPairTest, ZeroLengthRecvPeerShutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_WR), SyscallSucceeds());

  for (int flags : kZeroLengthRecvFlagCombos) {
    SCOPED_TRACE(::testing::Message() << "flags=" << flags);
    struct msghdr msg = {};
    EXPECT_THAT(
        RetryEINTR(recvmsg)(sockets->first_fd(), &msg, flags | MSG_DONTWAIT),
        SyscallSucceedsWithValue(0));
  }
}

constexpr int kBlockedPollTimeoutMs = 3000;

struct BlockedPollResult {
  int ret;
  int16_t revents;
};

// Blocks a poller on fd in a background thread — with an events mask that
// contains no data events, only POLLRDHUP or the implicit POLLHUP/POLLERR
// (events=0) — then runs trigger() and reports how poll returned. A kernel
// that fails to wake hangup-only waiters on shutdown makes poll ride out
// its full timeout and return 0.
BlockedPollResult PollDuringTrigger(int fd, int16_t events,
                                    const std::function<void()>& trigger) {
  BlockedPollResult res = {};
  struct pollfd pfd = {fd, events, 0};
  ScopedThread t([&] {
    res.ret = RetryEINTR(poll)(&pfd, 1, kBlockedPollTimeoutMs);
    res.revents = pfd.revents;
  });
  // Give the poller time to block. If the trigger still wins the race, the
  // test degrades to checking poll's entry-time readiness.
  absl::SleepFor(absl::Milliseconds(300));
  trigger();
  t.Join();
  return res;
}

// A blocked poller interested only in hangup events (events=0; POLLHUP is
// unmaskable) must be woken by a concurrent full shutdown of the socket:
// unix_shutdown() wakes all waiters via sk_state_change(), and the poller
// re-evaluates to POLLHUP.
TEST_P(StreamUnixSocketPairTest, ShutdownWakesHangupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int fd = sockets->first_fd();

  BlockedPollResult res = PollDuringTrigger(
      fd, 0, [fd] { ASSERT_THAT(shutdown(fd, SHUT_RDWR), SyscallSucceeds()); });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLHUP);
}

// A blocked POLLRDHUP-only poller must likewise be woken by a concurrent
// read shutdown.
TEST_P(StreamUnixSocketPairTest, ReadShutdownWakesRdHupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int fd = sockets->first_fd();

  BlockedPollResult res = PollDuringTrigger(fd, POLLRDHUP, [fd] {
    ASSERT_THAT(shutdown(fd, SHUT_RD), SyscallSucceeds());
  });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLRDHUP);
}

// A stream peer's full shutdown propagates both directions to this socket
// (see unix_shutdown() in net/unix/af_unix.c), so a blocked hangup-only
// poller here must be woken with POLLHUP.
TEST_P(StreamUnixSocketPairTest, PeerShutdownWakesHangupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int peer = sockets->second_fd();

  BlockedPollResult res = PollDuringTrigger(sockets->first_fd(), 0, [peer] {
    ASSERT_THAT(shutdown(peer, SHUT_RDWR), SyscallSucceeds());
  });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLHUP);
}

// A stream peer's write shutdown propagates to this socket's read side, so
// a blocked POLLRDHUP-only poller here must be woken.
TEST_P(StreamUnixSocketPairTest, PeerWriteShutdownWakesRdHupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int peer = sockets->second_fd();

  BlockedPollResult res = PollDuringTrigger(
      sockets->first_fd(), POLLRDHUP,
      [peer] { ASSERT_THAT(shutdown(peer, SHUT_WR), SyscallSucceeds()); });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLRDHUP);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, StreamUnixSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(UnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(FilesystemBoundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractBoundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK}))))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
