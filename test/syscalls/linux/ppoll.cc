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
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/base_poll_test.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// Linux and glibc have a different idea of the sizeof sigset_t. When calling
// the syscall directly, use what the kernel expects.
unsigned kSigsetSize = SIGRTMAX / 8;

// Linux ppoll(2) differs from the glibc wrapper function in that Linux updates
// the timeout with the amount of time remaining. In order to test this behavior
// we need to use the syscall directly.
int syscallPpoll(struct pollfd* fds, nfds_t nfds, struct timespec* timeout_ts,
                 const sigset_t* sigmask, unsigned mask_size) {
  return syscall(SYS_ppoll, fds, nfds, timeout_ts, sigmask, mask_size);
}

class PpollTest : public BasePollTest {
 protected:
  void SetUp() override { BasePollTest::SetUp(); }
  void TearDown() override { BasePollTest::TearDown(); }
};

TEST_F(PpollTest, InvalidFds) {
  // fds is invalid because it's null, but we tell ppoll the length is non-zero.
  struct timespec timeout = {};
  sigset_t sigmask;
  TEST_PCHECK(sigemptyset(&sigmask) == 0);
  EXPECT_THAT(syscallPpoll(nullptr, 1, &timeout, &sigmask, kSigsetSize),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(syscallPpoll(nullptr, -1, &timeout, &sigmask, kSigsetSize),
              SyscallFailsWithErrno(EINVAL));
}

// See that when fds is null, ppoll behaves like sleep.
TEST_F(PpollTest, NullFds) {
  struct timespec timeout = absl::ToTimespec(absl::Milliseconds(10));
  ASSERT_THAT(syscallPpoll(nullptr, 0, &timeout, nullptr, 0),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 0);
}

TEST_F(PpollTest, ZeroTimeout) {
  struct timespec timeout = {};
  ASSERT_THAT(syscallPpoll(nullptr, 0, &timeout, nullptr, 0),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 0);
}

// If random S/R interrupts the ppoll, SIGALRM may be delivered before ppoll
// restarts, causing the ppoll to hang forever.
TEST_F(PpollTest, NoTimeout_NoRandomSave) {
  // When there's no timeout, ppoll may never return so set a timer.
  SetTimer(absl::Milliseconds(100));
  // See that we get interrupted by the timer.
  ASSERT_THAT(syscallPpoll(nullptr, 0, nullptr, nullptr, 0),
              SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
}

TEST_F(PpollTest, InvalidTimeoutNegative) {
  struct timespec timeout = absl::ToTimespec(absl::Nanoseconds(-1));
  EXPECT_THAT(syscallPpoll(nullptr, 0, &timeout, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(PpollTest, InvalidTimeoutNotNormalized) {
  struct timespec timeout = {0, 1000000001};
  EXPECT_THAT(syscallPpoll(nullptr, 0, &timeout, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(PpollTest, InvalidMaskSize) {
  struct timespec timeout = {};
  sigset_t sigmask;
  TEST_PCHECK(sigemptyset(&sigmask) == 0);
  EXPECT_THAT(syscallPpoll(nullptr, 0, &timeout, &sigmask, 128),
              SyscallFailsWithErrno(EINVAL));
}

// Verify that signals blocked by the ppoll mask (that would otherwise be
// allowed) do not interrupt ppoll.
TEST_F(PpollTest, SignalMaskBlocksSignal) {
  absl::Duration duration(absl::Seconds(30));
  struct timespec timeout = absl::ToTimespec(duration);
  absl::Duration timer_duration(absl::Seconds(10));

  // Call with a mask that blocks SIGALRM. See that ppoll is not interrupted
  // (i.e. returns 0) and that upon completion, the timer has fired.
  sigset_t mask;
  ASSERT_THAT(sigprocmask(0, nullptr, &mask), SyscallSucceeds());
  TEST_PCHECK(sigaddset(&mask, SIGALRM) == 0);
  SetTimer(timer_duration);
  MaybeSave();
  ASSERT_FALSE(TimerFired());
  ASSERT_THAT(syscallPpoll(nullptr, 0, &timeout, &mask, kSigsetSize),
              SyscallSucceeds());
  EXPECT_TRUE(TimerFired());
  EXPECT_EQ(absl::DurationFromTimespec(timeout), absl::Duration());
}

// Verify that signals allowed by the ppoll mask (that would otherwise be
// blocked) interrupt ppoll.
TEST_F(PpollTest, SignalMaskAllowsSignal) {
  absl::Duration duration(absl::Seconds(30));
  struct timespec timeout = absl::ToTimespec(duration);
  absl::Duration timer_duration(absl::Seconds(10));

  sigset_t mask;
  ASSERT_THAT(sigprocmask(0, nullptr, &mask), SyscallSucceeds());

  // Block SIGALRM.
  auto cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, SIGALRM));

  // Call with a mask that unblocks SIGALRM. See that ppoll is interrupted.
  SetTimer(timer_duration);
  MaybeSave();
  ASSERT_FALSE(TimerFired());
  ASSERT_THAT(syscallPpoll(nullptr, 0, &timeout, &mask, kSigsetSize),
              SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
  EXPECT_GT(absl::DurationFromTimespec(timeout), absl::Duration());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
