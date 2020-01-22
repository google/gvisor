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

#include <errno.h>
#include <poll.h>
#include <sys/timerfd.h>
#include <time.h>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Wrapper around timerfd_create(2) that returns a FileDescriptor.
PosixErrorOr<FileDescriptor> TimerfdCreate(int clockid, int flags) {
  int fd = timerfd_create(clockid, flags);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "timerfd_create failed");
  }
  return FileDescriptor(fd);
}

// In tests that race a timerfd with a sleep, some slack is required because:
//
// - Timerfd expirations are asynchronous with respect to nanosleeps.
//
// - Because clock_gettime(CLOCK_MONOTONIC) is implemented through the VDSO,
// it technically uses a closely-related, but distinct, time domain from the
// CLOCK_MONOTONIC used to trigger timerfd expirations. The same applies to
// CLOCK_BOOTTIME which is an alias for CLOCK_MONOTONIC.
absl::Duration TimerSlack() { return absl::Milliseconds(500); }

class TimerfdTest : public ::testing::TestWithParam<int> {};

TEST_P(TimerfdTest, IsInitiallyStopped) {
  auto const tfd = ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), 0));
  struct itimerspec its = {};
  ASSERT_THAT(timerfd_gettime(tfd.get(), &its), SyscallSucceeds());
  EXPECT_EQ(0, its.it_value.tv_sec);
  EXPECT_EQ(0, its.it_value.tv_nsec);
}

TEST_P(TimerfdTest, SingleShot) {
  constexpr absl::Duration kDelay = absl::Seconds(1);

  auto const tfd = ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), 0));
  struct itimerspec its = {};
  its.it_value = absl::ToTimespec(kDelay);
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  // The timer should fire exactly once since the interval is zero.
  absl::SleepFor(kDelay + TimerSlack());
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  EXPECT_EQ(1, val);
}

TEST_P(TimerfdTest, Periodic) {
  constexpr absl::Duration kDelay = absl::Seconds(1);
  constexpr int kPeriods = 3;

  auto const tfd = ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), 0));
  struct itimerspec its = {};
  its.it_value = absl::ToTimespec(kDelay);
  its.it_interval = absl::ToTimespec(kDelay);
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  // Expect to see at least kPeriods expirations. More may occur due to the
  // timer slack, or due to delays from scheduling or save/restore.
  absl::SleepFor(kPeriods * kDelay + TimerSlack());
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  EXPECT_GE(val, kPeriods);
}

TEST_P(TimerfdTest, BlockingRead) {
  constexpr absl::Duration kDelay = absl::Seconds(3);

  auto const tfd = ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), 0));
  struct itimerspec its = {};
  its.it_value.tv_sec = absl::ToInt64Seconds(kDelay);
  auto const start_time = absl::Now();
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  // read should block until the timer fires.
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  auto const end_time = absl::Now();
  EXPECT_EQ(1, val);
  EXPECT_GE((end_time - start_time) + TimerSlack(), kDelay);
}

TEST_P(TimerfdTest, NonblockingRead_NoRandomSave) {
  constexpr absl::Duration kDelay = absl::Seconds(5);

  auto const tfd =
      ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), TFD_NONBLOCK));

  // Since the timer is initially disabled and has never fired, read should
  // return EAGAIN.
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallFailsWithErrno(EAGAIN));

  DisableSave ds;  // Timing-sensitive.

  // Arm the timer.
  struct itimerspec its = {};
  its.it_value.tv_sec = absl::ToInt64Seconds(kDelay);
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  // Since the timer has not yet fired, read should return EAGAIN.
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallFailsWithErrno(EAGAIN));

  ds.reset();  // No longer timing-sensitive.

  // After the timer fires, read should indicate 1 expiration.
  absl::SleepFor(kDelay + TimerSlack());
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  EXPECT_EQ(1, val);

  // The successful read should have reset the number of expirations.
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(TimerfdTest, BlockingPoll_SetTimeResetsExpirations) {
  constexpr absl::Duration kDelay = absl::Seconds(3);

  auto const tfd =
      ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), TFD_NONBLOCK));
  struct itimerspec its = {};
  its.it_value.tv_sec = absl::ToInt64Seconds(kDelay);
  auto const start_time = absl::Now();
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  // poll should block until the timer fires.
  struct pollfd pfd = {};
  pfd.fd = tfd.get();
  pfd.events = POLLIN;
  ASSERT_THAT(poll(&pfd, /* nfds = */ 1,
                   /* timeout = */ 2 * absl::ToInt64Seconds(kDelay) * 1000),
              SyscallSucceedsWithValue(1));
  auto const end_time = absl::Now();
  EXPECT_EQ(POLLIN, pfd.revents);
  EXPECT_GE((end_time - start_time) + TimerSlack(), kDelay);

  // Call timerfd_settime again with a value of 0. This should reset the number
  // of expirations to 0, causing read to return EAGAIN since the timerfd is
  // non-blocking.
  its.it_value.tv_sec = 0;
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(TimerfdTest, SetAbsoluteTime) {
  constexpr absl::Duration kDelay = absl::Seconds(3);

  // Use a non-blocking timerfd so that if TFD_TIMER_ABSTIME is incorrectly
  // non-functional, we get EAGAIN rather than a test timeout.
  auto const tfd =
      ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), TFD_NONBLOCK));
  struct itimerspec its = {};
  ASSERT_THAT(clock_gettime(GetParam(), &its.it_value), SyscallSucceeds());
  its.it_value.tv_sec += absl::ToInt64Seconds(kDelay);
  ASSERT_THAT(timerfd_settime(tfd.get(), TFD_TIMER_ABSTIME, &its, nullptr),
              SyscallSucceeds());

  absl::SleepFor(kDelay + TimerSlack());
  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  EXPECT_EQ(1, val);
}

TEST_P(TimerfdTest, IllegalReadWrite) {
  auto const tfd =
      ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(GetParam(), TFD_NONBLOCK));
  uint64_t val = 0;
  EXPECT_THAT(PreadFd(tfd.get(), &val, sizeof(val), 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(WriteFd(tfd.get(), &val, sizeof(val)),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(PwriteFd(tfd.get(), &val, sizeof(val), 0),
              SyscallFailsWithErrno(ESPIPE));
}

std::string PrintClockId(::testing::TestParamInfo<int> info) {
  switch (info.param) {
    case CLOCK_MONOTONIC:
      return "CLOCK_MONOTONIC";
    case CLOCK_BOOTTIME:
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

INSTANTIATE_TEST_SUITE_P(AllTimerTypes, TimerfdTest,
                         ::testing::Values(CLOCK_MONOTONIC, CLOCK_BOOTTIME),
                         PrintClockId);

TEST(TimerfdClockRealtimeTest, ClockRealtime) {
  // Since CLOCK_REALTIME can, by definition, change, we can't make any
  // non-flaky assertions about the amount of time it takes for a
  // CLOCK_REALTIME-based timer to expire. Just check that it expires at all,
  // and hope it happens before the test times out.
  constexpr int kDelaySecs = 1;

  auto const tfd = ASSERT_NO_ERRNO_AND_VALUE(TimerfdCreate(CLOCK_REALTIME, 0));
  struct itimerspec its = {};
  its.it_value.tv_sec = kDelaySecs;
  ASSERT_THAT(timerfd_settime(tfd.get(), /* flags = */ 0, &its, nullptr),
              SyscallSucceeds());

  uint64_t val = 0;
  ASSERT_THAT(ReadFd(tfd.get(), &val, sizeof(uint64_t)),
              SyscallSucceedsWithValue(sizeof(uint64_t)));
  EXPECT_EQ(1, val);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
