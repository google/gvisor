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

#include <limits.h>
#include <signal.h>
#include <sys/select.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/base_poll_test.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

class SelectTest : public BasePollTest {
 protected:
  void SetUp() override { BasePollTest::SetUp(); }
  void TearDown() override { BasePollTest::TearDown(); }
};

// See that when there are no FD sets, select behaves like sleep.
TEST_F(SelectTest, NullFds) {
  struct timeval timeout = absl::ToTimeval(absl::Milliseconds(10));
  ASSERT_THAT(select(0, nullptr, nullptr, nullptr, &timeout),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_usec, 0);

  timeout = absl::ToTimeval(absl::Milliseconds(10));
  ASSERT_THAT(select(1, nullptr, nullptr, nullptr, &timeout),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_usec, 0);
}

TEST_F(SelectTest, NegativeNfds) {
  EXPECT_THAT(select(-1, nullptr, nullptr, nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(select(-100000, nullptr, nullptr, nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(select(INT_MIN, nullptr, nullptr, nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(SelectTest, ClosedFds) {
  fd_set read_set;
  FD_ZERO(&read_set);
  int fd;
  ASSERT_THAT(fd = dup(1), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
  FD_SET(fd, &read_set);
  struct timeval timeout = absl::ToTimeval(absl::Milliseconds(10));
  EXPECT_THAT(select(fd + 1, &read_set, nullptr, nullptr, &timeout),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(SelectTest, ZeroTimeout) {
  struct timeval timeout = {};
  EXPECT_THAT(select(1, nullptr, nullptr, nullptr, &timeout),
              SyscallSucceeds());
  // Ignore timeout as its value is now undefined.
}

// If random S/R interrupts the select, SIGALRM may be delivered before select
// restarts, causing the select to hang forever.
TEST_F(SelectTest, NoTimeout_NoRandomSave) {
  // When there's no timeout, select may never return so set a timer.
  SetTimer(absl::Milliseconds(100));
  // See that we get interrupted by the timer.
  ASSERT_THAT(select(1, nullptr, nullptr, nullptr, nullptr),
              SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
}

TEST_F(SelectTest, InvalidTimeoutNegative) {
  struct timeval timeout = absl::ToTimeval(absl::Microseconds(-1));
  EXPECT_THAT(select(1, nullptr, nullptr, nullptr, &timeout),
              SyscallFailsWithErrno(EINVAL));
  // Ignore timeout as its value is now undefined.
}

// Verify that a signal interrupts select.
//
// If random S/R interrupts the select, SIGALRM may be delivered before select
// restarts, causing the select to hang forever.
TEST_F(SelectTest, InterruptedBySignal_NoRandomSave) {
  absl::Duration duration(absl::Seconds(5));
  struct timeval timeout = absl::ToTimeval(duration);
  SetTimer(absl::Milliseconds(100));
  ASSERT_FALSE(TimerFired());
  ASSERT_THAT(select(1, nullptr, nullptr, nullptr, &timeout),
              SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
  // Ignore timeout as its value is now undefined.
}

TEST_F(SelectTest, IgnoreBitsAboveNfds) {
  // fd_set is a bit array with at least FD_SETSIZE bits. Test that bits
  // corresponding to file descriptors above nfds are ignored.
  fd_set read_set;
  FD_ZERO(&read_set);
  constexpr int kNfds = 1;
  for (int fd = kNfds; fd < FD_SETSIZE; fd++) {
    FD_SET(fd, &read_set);
  }
  // Pass a zero timeout so that select returns immediately.
  struct timeval timeout = {};
  EXPECT_THAT(select(kNfds, &read_set, nullptr, nullptr, &timeout),
              SyscallSucceedsWithValue(0));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
