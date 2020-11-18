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

#include "test/syscalls/linux/socket_stream_blocking.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

TEST_P(BlockingStreamSocketPairTest, BlockPartialWriteClosed) {
  // FIXME(b/35921550): gVisor doesn't support SO_SNDBUF on UDS, nor does it
  // enforce any limit; it will write arbitrary amounts of data without
  // blocking.
  SKIP_IF(IsRunningOnGvisor());

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int buffer_size = 8 << 10;  // 8 KiB
  socklen_t length = sizeof(buffer_size);
  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &buffer_size, length),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVBUF,
                         &buffer_size, length),
              SyscallSucceeds());

  int wfd = sockets->first_fd();
  ScopedThread t([wfd, buffer_size]() {
    std::vector<char> buf(buffer_size);

    // Temporarily set the fd to nonblocking so that we can fill the
    // send buffer without actually blocking on a write.
    int opts;
    ASSERT_THAT(opts = fcntl(wfd, F_GETFL), SyscallSucceeds());
    ASSERT_THAT(fcntl(wfd, F_SETFL, opts | O_NONBLOCK), SyscallSucceeds());

    // Write until we receive an error.
    while (RetryEINTR(send)(wfd, buf.data(), buf.size(), 0) != -1) {
      // Sleep to give linux a chance to move data from the send buffer to the
      // receive buffer.
      usleep(10000);  // 10ms.
    }
    // The last error should have been EWOULDBLOCK.
    ASSERT_EQ(errno, EWOULDBLOCK);

    // Restore the original opts to restore blocking behaviour on the socket.
    ASSERT_THAT(fcntl(wfd, F_SETFL, opts), SyscallSucceeds());

    // This write should now block as we just got an EWOULDBLOCK above.
    ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                ::testing::AnyOf(SyscallFailsWithErrno(EPIPE),
                                 SyscallFailsWithErrno(ECONNRESET)));
  });

  // Leave time for write to become blocked.
  absl::SleepFor(absl::Seconds(1));

  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());
}

// Random save may interrupt the call to sendmsg() in SendLargeSendMsg(),
// causing the write to be incomplete and the test to hang.
TEST_P(BlockingStreamSocketPairTest, SendMsgTooLarge_NoRandomSave) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int sndbuf;
  socklen_t length = sizeof(sndbuf);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF, &sndbuf, &length),
      SyscallSucceeds());

  // Make the call too large to fit in the send buffer.
  const int buffer_size = 3 * sndbuf;

  EXPECT_THAT(SendLargeSendMsg(sockets, buffer_size, true /* reader */),
              SyscallSucceedsWithValue(buffer_size));
}

TEST_P(BlockingStreamSocketPairTest, RecvLessThanBuffer) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[200] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
}

// Test that MSG_WAITALL causes recv to block until all requested data is
// received. Random save can interrupt blocking and cause received data to be
// returned, even if the amount received is less than the full requested amount.
TEST_P(BlockingStreamSocketPairTest, RecvLessThanBufferWaitAll_NoRandomSave) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  constexpr auto kDuration = absl::Milliseconds(200);
  auto before = Now(CLOCK_MONOTONIC);

  const ScopedThread t([&]() {
    absl::SleepFor(kDuration);

    // Don't let saving after the write interrupt the blocking recv.
    const DisableSave ds;

    ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
                SyscallSucceedsWithValue(sizeof(sent_data)));
  });

  char received_data[sizeof(sent_data) * 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_WAITALL),
              SyscallSucceedsWithValue(sizeof(received_data)));

  auto after = Now(CLOCK_MONOTONIC);
  EXPECT_GE(after - before, kDuration);
}

TEST_P(BlockingStreamSocketPairTest, SendTimeout) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  std::vector<char> buf(kPageSize);
  // We don't know how much data the socketpair will buffer, so we may do an
  // arbitrarily large number of writes; saving after each write causes this
  // test's time to explode.
  const DisableSave ds;
  for (;;) {
    int ret;
    ASSERT_THAT(
        ret = RetryEINTR(send)(sockets->first_fd(), buf.data(), buf.size(), 0),
        ::testing::AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EAGAIN)));
    if (ret == -1) {
      break;
    }
  }
}

}  // namespace testing
}  // namespace gvisor
