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

#include "test/syscalls/linux/socket_unix_dgram.h"

#include <poll.h>
#include <stdio.h>
#include <sys/un.h>

#include <cerrno>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(DgramUnixSocketPairTest, WriteOneSideClosed) {
  // FIXME(b/35925052): gVisor datagram sockets return EPIPE instead of
  // ECONNREFUSED.
  SKIP_IF(IsRunningOnGvisor());

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(DgramUnixSocketPairTest, IncreasedSocketSendBufUnblocksWrites) {
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

// POLLOUT on a datagram socket is capacity-based and unaffected by a write
// shutdown: unix_writable() in Linux does not consult SEND_SHUTDOWN. A
// socket with a full send buffer does not become "writable" just because
// sends now fail with EPIPE, and draining the peer restores POLLOUT even
// after the shutdown.
TEST_P(DgramUnixSocketPairTest, PollOutAfterWriteShutdownIsCapacityBased) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Fill the send direction until it reports EAGAIN.
  std::vector<char> buf(4096, 'x');
  int ret;
  for (int sent = 0;; sent++) {
    ASSERT_LT(sent, 1 << 16);
    ASSERT_THAT(
        ret = RetryEINTR(send)(sockets->first_fd(), buf.data(), buf.size(),
                               MSG_DONTWAIT),
        ::testing::AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EAGAIN)));
    if (ret == -1) {
      break;
    }
  }

  struct pollfd poll_fd = {sockets->first_fd(), POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_WR), SyscallSucceeds());

  // Still not writable: the full queue, not the shutdown, governs POLLOUT.
  poll_fd.revents = 0;
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(0));

  // Drain the peer: capacity, and with it POLLOUT, comes back despite the
  // shutdown.
  for (;;) {
    ASSERT_THAT(
        ret = RetryEINTR(recv)(sockets->second_fd(), buf.data(), buf.size(),
                               MSG_DONTWAIT),
        ::testing::AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EAGAIN)));
    if (ret <= 0) {
      break;
    }
  }

  poll_fd.revents = 0;
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(poll_fd.revents, POLLOUT);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
