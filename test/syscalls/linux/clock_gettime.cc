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

#include <pthread.h>
#include <sys/time.h>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <list>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

int64_t clock_gettime_nsecs(clockid_t id) {
  struct timespec ts;
  TEST_PCHECK(clock_gettime(id, &ts) == 0);
  return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}

// Spin on the CPU for at least ns nanoseconds, based on
// CLOCK_THREAD_CPUTIME_ID.
void spin_ns(int64_t ns) {
  int64_t start = clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID);
  int64_t end = start + ns;

  do {
    constexpr int kLoopCount = 1000000;  // large and arbitrary
    // volatile to prevent the compiler from skipping this loop.
    for (volatile int i = 0; i < kLoopCount; i++) {
    }
  } while (clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID) < end);
}

// Test that CLOCK_PROCESS_CPUTIME_ID is a superset of CLOCK_THREAD_CPUTIME_ID.
TEST(ClockGettime, CputimeId) {
  // TODO(b/128871825,golang.org/issue/10958): Test times out when there is a
  // small number of core because one goroutine starves the others.
  printf("CPUS: %d\n", std::thread::hardware_concurrency());
  SKIP_IF(std::thread::hardware_concurrency() <= 2);

  constexpr int kNumThreads = 13;  // arbitrary

  absl::Duration spin_time = absl::Seconds(1);

  // Start off the worker threads and compute the aggregate time spent by
  // the workers. Note that we test CLOCK_PROCESS_CPUTIME_ID by having the
  // workers execute in parallel and verifying that CLOCK_PROCESS_CPUTIME_ID
  // accumulates the runtime of all threads.
  int64_t start = clock_gettime_nsecs(CLOCK_PROCESS_CPUTIME_ID);

  // Create a kNumThreads threads.
  std::list<ScopedThread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back(
        [spin_time] { spin_ns(absl::ToInt64Nanoseconds(spin_time)); });
  }
  for (auto& t : threads) {
    t.Join();
  }

  int64_t end = clock_gettime_nsecs(CLOCK_PROCESS_CPUTIME_ID);

  // The aggregate time spent in the worker threads must be at least
  // 'kNumThreads' times the time each thread spun.
  ASSERT_GE(end - start, kNumThreads * absl::ToInt64Nanoseconds(spin_time));
}

TEST(ClockGettime, JavaThreadTime) {
  clockid_t clockid;
  ASSERT_EQ(0, pthread_getcpuclockid(pthread_self(), &clockid));
  struct timespec tp;
  ASSERT_THAT(clock_getres(clockid, &tp), SyscallSucceeds());
  EXPECT_TRUE(tp.tv_sec > 0 || tp.tv_nsec > 0);
  // A thread cputime is updated each 10msec and there is no approximation
  // if a task is running.
  do {
    ASSERT_THAT(clock_gettime(clockid, &tp), SyscallSucceeds());
  } while (tp.tv_sec == 0 && tp.tv_nsec == 0);
  EXPECT_TRUE(tp.tv_sec > 0 || tp.tv_nsec > 0);
}

// There is not much to test here, since CLOCK_REALTIME may be discontiguous.
TEST(ClockGettime, RealtimeWorks) {
  struct timespec tp;
  EXPECT_THAT(clock_gettime(CLOCK_REALTIME, &tp), SyscallSucceeds());
}

class MonotonicClockTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(MonotonicClockTest, IsMonotonic) {
  auto end = absl::Now() + absl::Seconds(5);

  struct timespec tp;
  EXPECT_THAT(clock_gettime(GetParam(), &tp), SyscallSucceeds());

  auto prev = absl::TimeFromTimespec(tp);
  while (absl::Now() < end) {
    EXPECT_THAT(clock_gettime(GetParam(), &tp), SyscallSucceeds());
    auto now = absl::TimeFromTimespec(tp);
    EXPECT_GE(now, prev);
    prev = now;
  }
}

std::string PrintClockId(::testing::TestParamInfo<clockid_t> info) {
  switch (info.param) {
    case CLOCK_MONOTONIC:
      return "CLOCK_MONOTONIC";
    case CLOCK_MONOTONIC_COARSE:
      return "CLOCK_MONOTONIC_COARSE";
    case CLOCK_MONOTONIC_RAW:
      return "CLOCK_MONOTONIC_RAW";
    case CLOCK_BOOTTIME:
      // CLOCK_BOOTTIME is a monotonic clock.
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, MonotonicClockTest,
                         ::testing::Values(CLOCK_MONOTONIC,
                                           CLOCK_MONOTONIC_COARSE,
                                           CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME),
                         PrintClockId);

TEST(ClockGettime, UnimplementedReturnsEINVAL) {
  SKIP_IF(!IsRunningOnGvisor());

  struct timespec tp;
  EXPECT_THAT(clock_gettime(CLOCK_REALTIME_ALARM, &tp),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(clock_gettime(CLOCK_BOOTTIME_ALARM, &tp),
              SyscallFailsWithErrno(EINVAL));
}

TEST(ClockGettime, InvalidClockIDReturnsEINVAL) {
  struct timespec tp;
  EXPECT_THAT(clock_gettime(-1, &tp), SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
