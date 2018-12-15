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

#include "test/syscalls/linux/socket_stream_blocking.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
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
    // FIXME: gVisor doesn't support SO_SNDBUF on UDS, nor does it
    // enforce any limit; it will write arbitrary amounts of data without
    // blocking.
    SKIP_IF(IsRunningOnGvisor());

    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

    int buffer_size;
    socklen_t length = sizeof(buffer_size);
    ASSERT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                           &buffer_size, &length),
                SyscallSucceeds());

    int wfd = sockets->first_fd();
    ScopedThread t([wfd, buffer_size]() {
      std::vector<char> buf(2 * buffer_size);
      // Write more than fits in the buffer. Blocks then returns partial write
      // when the other end is closed. The next call returns EPIPE.
      //
      // N.B. writes occur in chunks, so we may see less than buffer_size from
      // the first call.
      ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                  SyscallSucceedsWithValue(::testing::Gt(0)));
      ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                  ::testing::AnyOf(SyscallFailsWithErrno(EPIPE),
                                   SyscallFailsWithErrno(ECONNRESET)));
    });

    // Leave time for write to become blocked.
    absl::SleepFor(absl::Seconds(1.0));

    ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());
}

TEST_P(BlockingStreamSocketPairTest, SendMsgTooLarge) {
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

TEST_P(BlockingStreamSocketPairTest, RecvLessThanBufferWaitAll) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  constexpr auto kDuration = absl::Milliseconds(200);
  auto before = Now(CLOCK_MONOTONIC);

  const ScopedThread t([&]() {
    absl::SleepFor(kDuration);
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

  char buf[100] = {};
  for (;;) {
    int ret;
    ASSERT_THAT(
        ret = RetryEINTR(send)(sockets->first_fd(), buf, sizeof(buf), 0),
        ::testing::AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EAGAIN)));
    if (ret == -1) {
      break;
    }
  }
}

}  // namespace testing
}  // namespace gvisor
