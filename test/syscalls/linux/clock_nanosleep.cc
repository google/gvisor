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

#include <time.h>

#include <atomic>
#include <utility>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

// sys_clock_nanosleep is defined because the glibc clock_nanosleep returns
// error numbers directly and does not set errno. This makes our Syscall
// matchers look a little weird when expecting failure:
// "SyscallSucceedsWithValue(ERRNO)".
int sys_clock_nanosleep(clockid_t clkid, int flags,
                        const struct timespec* request,
                        struct timespec* remain) {
  return syscall(SYS_clock_nanosleep, clkid, flags, request, remain);
}

PosixErrorOr<absl::Time> GetTime(clockid_t clk) {
  struct timespec ts = {};
  const int rc = clock_gettime(clk, &ts);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "clock_gettime");
  }
  return absl::TimeFromTimespec(ts);
}

class WallClockNanosleepTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(WallClockNanosleepTest, InvalidValues) {
  const struct timespec invalid[] = {
      {.tv_sec = -1, .tv_nsec = -1},       {.tv_sec = 0, .tv_nsec = INT32_MIN},
      {.tv_sec = 0, .tv_nsec = INT32_MAX}, {.tv_sec = 0, .tv_nsec = -1},
      {.tv_sec = -1, .tv_nsec = 0},
  };

  for (auto const ts : invalid) {
    EXPECT_THAT(sys_clock_nanosleep(GetParam(), 0, &ts, nullptr),
                SyscallFailsWithErrno(EINVAL));
  }
}

TEST_P(WallClockNanosleepTest, SleepOneSecond) {
  constexpr absl::Duration kSleepDuration = absl::Seconds(1);
  struct timespec duration = absl::ToTimespec(kSleepDuration);

  const absl::Time before = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));
  EXPECT_THAT(
      RetryEINTR(sys_clock_nanosleep)(GetParam(), 0, &duration, &duration),
      SyscallSucceeds());
  const absl::Time after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  EXPECT_GE(after - before, kSleepDuration);
}

TEST_P(WallClockNanosleepTest, InterruptedNanosleep) {
  constexpr absl::Duration kSleepDuration = absl::Seconds(60);
  struct timespec duration = absl::ToTimespec(kSleepDuration);

  // Install no-op signal handler for SIGALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_handler = +[](int signo) {};
  const auto cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Measure time since setting the alarm, since the alarm will interrupt the
  // sleep and hence determine how long we sleep.
  const absl::Time before = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  // Set an alarm to go off while sleeping.
  struct itimerval timer = {};
  timer.it_value.tv_sec = 1;
  timer.it_value.tv_usec = 0;
  timer.it_interval.tv_sec = 1;
  timer.it_interval.tv_usec = 0;
  const auto cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_REAL, timer));

  EXPECT_THAT(sys_clock_nanosleep(GetParam(), 0, &duration, &duration),
              SyscallFailsWithErrno(EINTR));
  const absl::Time after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  // Remaining time updated.
  const absl::Duration remaining = absl::DurationFromTimespec(duration);
  EXPECT_GE(after - before + remaining, kSleepDuration);
}

// Remaining time is *not* updated if nanosleep completes uninterrupted.
TEST_P(WallClockNanosleepTest, UninterruptedNanosleep) {
  constexpr absl::Duration kSleepDuration = absl::Milliseconds(10);
  const struct timespec duration = absl::ToTimespec(kSleepDuration);

  while (true) {
    constexpr int kRemainingMagic = 42;
    struct timespec remaining;
    remaining.tv_sec = kRemainingMagic;
    remaining.tv_nsec = kRemainingMagic;

    int ret = sys_clock_nanosleep(GetParam(), 0, &duration, &remaining);
    if (ret == EINTR) {
      // Retry from beginning. We want a single uninterrupted call.
      continue;
    }

    EXPECT_THAT(ret, SyscallSucceeds());
    EXPECT_EQ(remaining.tv_sec, kRemainingMagic);
    EXPECT_EQ(remaining.tv_nsec, kRemainingMagic);
    break;
  }
}

TEST_P(WallClockNanosleepTest, SleepUntil) {
  const absl::Time now = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));
  const absl::Time until = now + absl::Seconds(2);
  const struct timespec ts = absl::ToTimespec(until);

  EXPECT_THAT(
      RetryEINTR(sys_clock_nanosleep)(GetParam(), TIMER_ABSTIME, &ts, nullptr),
      SyscallSucceeds());
  const absl::Time after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  EXPECT_GE(after, until);
}

INSTANTIATE_TEST_SUITE_P(Sleepers, WallClockNanosleepTest,
                         ::testing::Values(CLOCK_REALTIME, CLOCK_MONOTONIC));

TEST(ClockNanosleepProcessTest, SleepFiveSeconds) {
  const absl::Duration kSleepDuration = absl::Seconds(5);
  struct timespec duration = absl::ToTimespec(kSleepDuration);

  // Ensure that CLOCK_PROCESS_CPUTIME_ID advances.
  std::atomic<bool> done(false);
  ScopedThread t([&] {
    while (!done.load()) {
    }
  });
  const auto cleanup_done = Cleanup([&] { done.store(true); });

  const absl::Time before =
      ASSERT_NO_ERRNO_AND_VALUE(GetTime(CLOCK_PROCESS_CPUTIME_ID));
  EXPECT_THAT(RetryEINTR(sys_clock_nanosleep)(CLOCK_PROCESS_CPUTIME_ID, 0,
                                              &duration, &duration),
              SyscallSucceeds());
  const absl::Time after =
      ASSERT_NO_ERRNO_AND_VALUE(GetTime(CLOCK_PROCESS_CPUTIME_ID));
  EXPECT_GE(after - before, kSleepDuration);
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
