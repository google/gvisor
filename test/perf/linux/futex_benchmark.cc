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
  return syscall(SYS_futex, v, FUTEX_BITSET_MATCH_ANY, nullptr);
}

inline int FutexWaitRelativeTimeout(std::atomic<int32_t>* v, int32_t val,
                                    const struct timespec* reltime) {
  return syscall(SYS_futex, v, FUTEX_WAIT_PRIVATE, reltime);
}

inline int FutexWaitAbsoluteTimeout(std::atomic<int32_t>* v, int32_t val,
                                    const struct timespec* abstime) {
  return syscall(SYS_futex, v, FUTEX_BITSET_MATCH_ANY, abstime);
}

inline int FutexWaitBitsetAbsoluteTimeout(std::atomic<int32_t>* v, int32_t val,
                                          int32_t bits,
                                          const struct timespec* abstime) {
  return syscall(SYS_futex, v, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME,
                 val, abstime, nullptr, bits);
}

inline int FutexWake(std::atomic<int32_t>* v, int32_t count) {
  return syscall(SYS_futex, v, FUTEX_WAKE_PRIVATE, count);
}

// This just uses FUTEX_WAKE on an address with nothing waiting, very simple.
void BM_FutexWakeNop(benchmark::State& state) {
  std::atomic<int32_t> v(0);

  for (auto _ : state) {
    EXPECT_EQ(0, FutexWake(&v, 1));
  }
}

BENCHMARK(BM_FutexWakeNop);

// This just uses FUTEX_WAIT on an address whose value has changed, i.e., the
// syscall won't wait.
void BM_FutexWaitNop(benchmark::State& state) {
  std::atomic<int32_t> v(0);

  for (auto _ : state) {
    EXPECT_EQ(-EAGAIN, FutexWait(&v, 1));
  }
}

BENCHMARK(BM_FutexWaitNop);

// This uses FUTEX_WAIT with a timeout on an address whose value never
// changes, such that it always times out. Timeout overhead can be estimated by
// timer overruns for short timeouts.
void BM_FutexWaitTimeout(benchmark::State& state) {
  const int timeout_ns = state.range(0);
  std::atomic<int32_t> v(0);
  auto ts = absl::ToTimespec(absl::Nanoseconds(timeout_ns));

  for (auto _ : state) {
    EXPECT_EQ(-ETIMEDOUT, FutexWaitRelativeTimeout(&v, 0, &ts));
  }
}

BENCHMARK(BM_FutexWaitTimeout)
    ->Arg(1)
    ->Arg(10)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000);

// This calls FUTEX_WAIT_BITSET with CLOCK_REALTIME.
void BM_FutexWaitBitset(benchmark::State& state) {
  std::atomic<int32_t> v(0);
  int timeout_ns = state.range(0);
  auto ts = absl::ToTimespec(absl::Nanoseconds(timeout_ns));
  for (auto _ : state) {
    EXPECT_EQ(-ETIMEDOUT, FutexWaitBitsetAbsoluteTimeout(&v, 0, 1, &ts));
  }
}

BENCHMARK(BM_FutexWaitBitset)->Range(0, 100000);

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
// wakeup back. The time per iteration is 2*  (delay_us + kBeforeWakeDelayNs +
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
    for (int i = 0; i < state.max_iterations; i++) {
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
    ->Arg(0)
    ->Arg(10)
    ->Arg(20)
    ->Arg(50)
    ->Arg(100);

// FutexLock is a simple, dumb futex based lock implementation.
// It will try to acquire the lock by atomically incrementing the
// lock word. If it did not increment the lock from 0 to 1, someone
// else has the lock, so it will FUTEX_WAIT until it is woken in
// the unlock path.
class FutexLock {
 public:
  FutexLock() : lock_word_(0) {}

  void lock(struct timespec* deadline) {
    int32_t val;
    while ((val = lock_word_.fetch_add(1, std::memory_order_acquire) + 1) !=
           1) {
      // If we didn't get the lock by incrementing from 0 to 1,
      // do a FUTEX_WAIT with the desired current value set to
      // val. If val is no longer what the atomic increment returned,
      // someone might have set it to 0 so we can try to acquire
      // again.
      int ret = FutexWaitAbsoluteTimeout(&lock_word_, val, deadline);
      if (ret == 0 || ret == -EWOULDBLOCK || ret == -EINTR) {
        continue;
      } else {
        FAIL() << "unexpected FUTEX_WAIT return: " << ret;
      }
    }
  }

  void unlock() {
    // Store 0 into the lock word and wake one waiter. We intentionally
    // ignore the return value of the FUTEX_WAKE here, since there may be
    // no waiters to wake anyway.
    lock_word_.store(0, std::memory_order_release);
    (void)FutexWake(&lock_word_, 1);
  }

 private:
  std::atomic<int32_t> lock_word_;
};

FutexLock* test_lock;  // Used below.

void FutexContend(benchmark::State& state, int thread_index,
                  struct timespec* deadline) {
  int counter = 0;
  if (thread_index == 0) {
    test_lock = new FutexLock();
  }
  for (auto _ : state) {
    test_lock->lock(deadline);
    counter++;
    test_lock->unlock();
  }
  if (thread_index == 0) {
    delete test_lock;
  }
  state.SetItemsProcessed(state.iterations());
}

void BM_FutexContend(benchmark::State& state) {
  FutexContend(state, state.thread_index, nullptr);
}

BENCHMARK(BM_FutexContend)->ThreadRange(1, 1024)->UseRealTime();

void BM_FutexDeadlineContend(benchmark::State& state) {
  auto deadline = absl::ToTimespec(absl::Now() + absl::Minutes(10));
  FutexContend(state, state.thread_index, &deadline);
}

BENCHMARK(BM_FutexDeadlineContend)->ThreadRange(1, 1024)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
