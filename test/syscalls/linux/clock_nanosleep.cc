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
  int rc = clock_gettime(clk, &ts);
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
  absl::Duration const duration = absl::Seconds(1);
  struct timespec dur = absl::ToTimespec(duration);

  absl::Time const before = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));
  EXPECT_THAT(RetryEINTR(sys_clock_nanosleep)(GetParam(), 0, &dur, &dur),
              SyscallSucceeds());
  absl::Time const after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  EXPECT_GE(after - before, duration);
}

TEST_P(WallClockNanosleepTest, InterruptedNanosleep) {
  absl::Duration const duration = absl::Seconds(60);
  struct timespec dur = absl::ToTimespec(duration);

  // Install no-op signal handler for SIGALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_handler = +[](int signo) {};
  auto const cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Measure time since setting the alarm, since the alarm will interrupt the
  // sleep and hence determine how long we sleep.
  absl::Time const before = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  // Set an alarm to go off while sleeping.
  struct itimerval timer = {};
  timer.it_value.tv_sec = 1;
  timer.it_value.tv_usec = 0;
  timer.it_interval.tv_sec = 1;
  timer.it_interval.tv_usec = 0;
  auto const cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_REAL, timer));

  EXPECT_THAT(sys_clock_nanosleep(GetParam(), 0, &dur, &dur),
              SyscallFailsWithErrno(EINTR));
  absl::Time const after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  absl::Duration const remaining = absl::DurationFromTimespec(dur);
  EXPECT_GE(after - before + remaining, duration);
}

TEST_P(WallClockNanosleepTest, SleepUntil) {
  absl::Time const now = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));
  absl::Time const until = now + absl::Seconds(2);
  struct timespec ts = absl::ToTimespec(until);

  EXPECT_THAT(
      RetryEINTR(sys_clock_nanosleep)(GetParam(), TIMER_ABSTIME, &ts, nullptr),
      SyscallSucceeds());
  absl::Time const after = ASSERT_NO_ERRNO_AND_VALUE(GetTime(GetParam()));

  EXPECT_GE(after, until);
}

INSTANTIATE_TEST_CASE_P(Sleepers, WallClockNanosleepTest,
                        ::testing::Values(CLOCK_REALTIME, CLOCK_MONOTONIC));

TEST(ClockNanosleepProcessTest, SleepFiveSeconds) {
  absl::Duration const kDuration = absl::Seconds(5);
  struct timespec dur = absl::ToTimespec(kDuration);

  // Ensure that CLOCK_PROCESS_CPUTIME_ID advances.
  std::atomic<bool> done(false);
  ScopedThread t([&] {
    while (!done.load()) {
    }
  });
  auto const cleanup_done = Cleanup([&] { done.store(true); });

  absl::Time const before =
      ASSERT_NO_ERRNO_AND_VALUE(GetTime(CLOCK_PROCESS_CPUTIME_ID));
  EXPECT_THAT(
      RetryEINTR(sys_clock_nanosleep)(CLOCK_PROCESS_CPUTIME_ID, 0, &dur, &dur),
      SyscallSucceeds());
  absl::Time const after =
      ASSERT_NO_ERRNO_AND_VALUE(GetTime(CLOCK_PROCESS_CPUTIME_ID));
  EXPECT_GE(after - before, kDuration);
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
