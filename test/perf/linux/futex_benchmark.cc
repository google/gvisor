// Copyright 2020 The gVisor Authors.
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

#include <linux/futex.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <ctime>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

inline int FutexWait(std::atomic<int32_t>* v, int32_t val) {
  return syscall(SYS_futex, v, FUTEX_WAIT_PRIVATE, val, nullptr);
}

inline int FutexWaitMonotonicTimeout(std::atomic<int32_t>* v, int32_t val,
                                     const struct timespec* timeout) {
  return syscall(SYS_futex, v, FUTEX_WAIT_PRIVATE, val, timeout);
}

inline int FutexWaitMonotonicDeadline(std::atomic<int32_t>* v, int32_t val,
                                      const struct timespec* deadline) {
  return syscall(SYS_futex, v, FUTEX_WAIT_BITSET_PRIVATE, val, deadline,
                 nullptr, FUTEX_BITSET_MATCH_ANY);
}

inline int FutexWaitRealtimeDeadline(std::atomic<int32_t>* v, int32_t val,
                                     const struct timespec* deadline) {
  return syscall(SYS_futex, v, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME,
                 val, deadline, nullptr, FUTEX_BITSET_MATCH_ANY);
}

inline int FutexWake(std::atomic<int32_t>* v, int32_t count) {
  return syscall(SYS_futex, v, FUTEX_WAKE_PRIVATE, count);
}

// This just uses FUTEX_WAKE on an address with nothing waiting, very simple.
void BM_FutexWakeNop(benchmark::State& state) {
  std::atomic<int32_t> v(0);

  for (auto _ : state) {
    TEST_PCHECK(FutexWake(&v, 1) == 0);
  }
}

BENCHMARK(BM_FutexWakeNop)->MinTime(5);

// This just uses FUTEX_WAIT on an address whose value has changed, i.e., the
// syscall won't wait.
void BM_FutexWaitNop(benchmark::State& state) {
  std::atomic<int32_t> v(0);

  for (auto _ : state) {
    TEST_PCHECK(FutexWait(&v, 1) == -1 && errno == EAGAIN);
  }
}

BENCHMARK(BM_FutexWaitNop)->MinTime(5);

// This uses FUTEX_WAIT with a timeout on an address whose value never
// changes, such that it always times out. Timeout overhead can be estimated by
// timer overruns for short timeouts.
void BM_FutexWaitMonotonicTimeout(benchmark::State& state) {
  const absl::Duration timeout = absl::Nanoseconds(state.range(0));
  std::atomic<int32_t> v(0);
  auto ts = absl::ToTimespec(timeout);

  for (auto _ : state) {
    TEST_PCHECK(FutexWaitMonotonicTimeout(&v, 0, &ts) == -1 &&
                errno == ETIMEDOUT);
  }
}

BENCHMARK(BM_FutexWaitMonotonicTimeout)
    ->MinTime(5)
    ->UseRealTime()
    ->Arg(1)
    ->Arg(10)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000);

// This uses FUTEX_WAIT_BITSET with a deadline that is in the past. This allows
// estimation of the overhead of setting up a timer for a deadline (as opposed
// to a timeout as specified for FUTEX_WAIT).
void BM_FutexWaitMonotonicDeadline(benchmark::State& state) {
  std::atomic<int32_t> v(0);
  struct timespec ts = {};

  for (auto _ : state) {
    TEST_PCHECK(FutexWaitMonotonicDeadline(&v, 0, &ts) == -1 &&
                errno == ETIMEDOUT);
  }
}

BENCHMARK(BM_FutexWaitMonotonicDeadline)->MinTime(5);

// This is equivalent to BM_FutexWaitMonotonicDeadline, but uses CLOCK_REALTIME
// instead of CLOCK_MONOTONIC for the deadline.
void BM_FutexWaitRealtimeDeadline(benchmark::State& state) {
  std::atomic<int32_t> v(0);
  struct timespec ts = {};

  for (auto _ : state) {
    TEST_PCHECK(FutexWaitRealtimeDeadline(&v, 0, &ts) == -1 &&
                errno == ETIMEDOUT);
  }
}

BENCHMARK(BM_FutexWaitRealtimeDeadline)->MinTime(5);

int64_t GetCurrentMonotonicTimeNanos() {
  struct timespec ts;
  TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) != -1);
  return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void SpinNanos(int64_t delay_ns) {
  if (delay_ns <= 0) {
    return;
  }
  const int64_t end = GetCurrentMonotonicTimeNanos() + delay_ns;
  while (GetCurrentMonotonicTimeNanos() < end) {
    // spin
  }
}

// Each iteration of FutexRoundtripDelayed involves a thread sending a futex
// wakeup to another thread, which spins for delay_us and then sends a futex
// wakeup back. The time per iteration is 2 * (delay_us + kBeforeWakeDelayNs +
// futex/scheduling overhead).
void BM_FutexRoundtripDelayed(benchmark::State& state) {
  const int delay_us = state.range(0);
  const int64_t delay_ns = delay_us * 1000;
  // Spin for an extra kBeforeWakeDelayNs before invoking FUTEX_WAKE to reduce
  // the probability that the wakeup comes before the wait, preventing the wait
  // from ever taking effect and causing the benchmark to underestimate the
  // actual wakeup time.
  constexpr int64_t kBeforeWakeDelayNs = 500;
  std::atomic<int32_t> v(0);
  ScopedThread t([&] {
    for (benchmark::IterationCount i = 0; i < state.max_iterations; i++) {
      SpinNanos(delay_ns);
      while (v.load(std::memory_order_acquire) == 0) {
        FutexWait(&v, 0);
      }
      SpinNanos(kBeforeWakeDelayNs + delay_ns);
      v.store(0, std::memory_order_release);
      FutexWake(&v, 1);
    }
  });
  for (auto _ : state) {
    SpinNanos(kBeforeWakeDelayNs + delay_ns);
    v.store(1, std::memory_order_release);
    FutexWake(&v, 1);
    SpinNanos(delay_ns);
    while (v.load(std::memory_order_acquire) == 1) {
      FutexWait(&v, 1);
    }
  }
}

BENCHMARK(BM_FutexRoundtripDelayed)
    ->MinTime(5)
    ->UseRealTime()
    ->Arg(0)
    ->Arg(10)
    ->Arg(20)
    ->Arg(50)
    ->Arg(100);

}  // namespace

}  // namespace testing
}  // namespace gvisor
