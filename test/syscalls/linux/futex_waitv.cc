// Copyright 2026 The gVisor Authors.
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
#include <linux/futex.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <functional>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif

namespace gvisor {
namespace testing {

namespace {

// struct futex_waitv and its flags, from <linux/futex.h>. They are defined here
// since older UAPI headers lack them.
struct FutexWaitv {
  uint64_t val;
  uint64_t uaddr;
  uint32_t flags;
  uint32_t reserved;
};

constexpr uint32_t kFutex2SizeU32 = 0x02;
constexpr uint32_t kFutex2SizeU64 = 0x03;
constexpr uint32_t kFutex2Private = FUTEX_PRIVATE_FLAG;
constexpr int kFutexWaitvMax = 128;

// Interval between retries of a wakeup or signal that must land while the
// waiter is blocked.
constexpr absl::Duration kRetryInterval = absl::Milliseconds(10);

int futex_waitv(FutexWaitv* waiters, unsigned int nr, unsigned int flags,
                const struct timespec* timeout, clockid_t clockid) {
  return syscall(SYS_futex_waitv, waiters, nr, flags, timeout, clockid);
}

int futex_wake(bool priv, std::atomic<uint32_t>* uaddr, int count) {
  return syscall(SYS_futex, uaddr, priv ? FUTEX_WAKE_PRIVATE : FUTEX_WAKE,
                 count);
}

// Upper bound on retries of a wakeup or signal, so that a test whose waiter
// never blocks fails instead of hanging.
constexpr absl::Duration kRetryTimeout = absl::Seconds(30);

// WakeUntilWoken calls FUTEX_WAKE on uaddr until it wakes a waiter, so the
// waiter is known to be blocked when it is woken. It gives up when done is set
// or after kRetryTimeout, and returns whether it woke a waiter.
bool WakeUntilWoken(bool priv, std::atomic<uint32_t>* uaddr,
                    const std::atomic<bool>* done = nullptr) {
  absl::Time const deadline = absl::Now() + kRetryTimeout;
  while (absl::Now() < deadline && !(done && done->load())) {
    int const n = futex_wake(priv, uaddr, 1);
    TEST_PCHECK(n >= 0);
    if (n == 1) {
      return true;
    }
    absl::SleepFor(kRetryInterval);
  }
  return false;
}

FutexWaitv Waiter(std::atomic<uint32_t>* uaddr, uint32_t val, bool priv) {
  return FutexWaitv{
      .val = val,
      .uaddr = reinterpret_cast<uint64_t>(uaddr),
      .flags = kFutex2SizeU32 | (priv ? kFutex2Private : 0),
      .reserved = 0,
  };
}

// FutexWaitvSupported returns false if the kernel predates futex_waitv(2),
// which Linux added in 5.16.
bool FutexWaitvSupported() {
  return futex_waitv(nullptr, 0, 0, nullptr, 0) == -1 && errno != ENOSYS;
}

class FutexWaitvTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!IsRunningOnGvisor() && !FutexWaitvSupported());
  }
};

class FutexWaitvWakeTest : public FutexWaitvTest,
                           public ::testing::WithParamInterface<int> {};

TEST_P(FutexWaitvWakeTest, ReturnsWokenIndex) {
  int const woken = GetParam();
  std::atomic<uint32_t> words[3] = {};
  std::vector<FutexWaitv> waiters;
  for (auto& word : words) {
    waiters.push_back(Waiter(&word, 0, true));
  }

  std::atomic<bool> returned(false);
  ScopedThread waker([&] { WakeUntilWoken(true, &words[woken], &returned); });
  EXPECT_THAT(futex_waitv(waiters.data(), waiters.size(), 0, nullptr, 0),
              SyscallSucceedsWithValue(woken));
  returned.store(true);
}

INSTANTIATE_TEST_SUITE_P(Indexes, FutexWaitvWakeTest,
                         ::testing::Values(0, 1, 2));

TEST_F(FutexWaitvTest, MaxFutexes) {
  std::vector<std::atomic<uint32_t>> words(kFutexWaitvMax);
  std::vector<FutexWaitv> waiters;
  for (auto& word : words) {
    word.store(0);
    waiters.push_back(Waiter(&word, 0, true));
  }

  std::atomic<bool> returned(false);
  ScopedThread waker(
      [&] { WakeUntilWoken(true, &words[kFutexWaitvMax - 1], &returned); });
  EXPECT_THAT(futex_waitv(waiters.data(), waiters.size(), 0, nullptr, 0),
              SyscallSucceedsWithValue(kFutexWaitvMax - 1));
  returned.store(true);
}

TEST_F(FutexWaitvTest, ValueMismatch) {
  std::atomic<uint32_t> words[2] = {};
  FutexWaitv waiters[] = {Waiter(&words[0], 0, true),
                          Waiter(&words[1], 1, true)};

  EXPECT_THAT(futex_waitv(waiters, 2, 0, nullptr, 0),
              SyscallFailsWithErrno(EAGAIN));
  // The waiter on the matching futex was removed.
  EXPECT_THAT(futex_wake(true, &words[0], 1), SyscallSucceedsWithValue(0));
}

class FutexWaitvClockTest : public FutexWaitvTest,
                            public ::testing::WithParamInterface<clockid_t> {};

TEST_P(FutexWaitvClockTest, AbsoluteTimeout) {
  clockid_t const clock = GetParam();
  constexpr absl::Duration kTimeout = absl::Milliseconds(100);
  std::atomic<uint32_t> word(0);
  FutexWaitv waiter = Waiter(&word, 0, true);

  struct timespec now;
  ASSERT_THAT(clock_gettime(clock, &now), SyscallSucceeds());
  struct timespec const deadline =
      absl::ToTimespec(absl::DurationFromTimespec(now) + kTimeout);
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, &deadline, clock),
              SyscallFailsWithErrno(ETIMEDOUT));

  struct timespec after;
  ASSERT_THAT(clock_gettime(clock, &after), SyscallSucceeds());
  EXPECT_GE(absl::DurationFromTimespec(after),
            absl::DurationFromTimespec(deadline));
}

TEST_P(FutexWaitvClockTest, PastDeadline) {
  std::atomic<uint32_t> word(0);
  FutexWaitv waiter = Waiter(&word, 0, true);
  struct timespec const deadline = {.tv_sec = 0, .tv_nsec = 0};
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, &deadline, GetParam()),
              SyscallFailsWithErrno(ETIMEDOUT));
}

INSTANTIATE_TEST_SUITE_P(Clocks, FutexWaitvClockTest,
                         ::testing::Values(CLOCK_MONOTONIC, CLOCK_REALTIME));

TEST_F(FutexWaitvTest, InvalidArguments) {
  std::atomic<uint32_t> word(0);
  FutexWaitv waiter = Waiter(&word, 0, true);
  std::vector<FutexWaitv> too_many(kFutexWaitvMax + 1, waiter);
  struct timespec const deadline = {.tv_sec = 1, .tv_nsec = 0};

  EXPECT_THAT(futex_waitv(&waiter, 0, 0, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(futex_waitv(too_many.data(), too_many.size(), 0, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(futex_waitv(nullptr, 1, 0, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(futex_waitv(&waiter, 1, 1, nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, &deadline, CLOCK_BOOTTIME),
              SyscallFailsWithErrno(EINVAL));

  struct timespec const bad_nsec = {.tv_sec = 1, .tv_nsec = 1000000000};
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, &bad_nsec, CLOCK_MONOTONIC),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(FutexWaitvTest, InvalidWaiter) {
  // Each waiter is invalid in one way. The futex word matches its value, so a
  // waiter that is accepted blocks until the timeout.
  alignas(8) std::atomic<uint32_t> words[2] = {};
  std::vector<FutexWaitv> bad;
  FutexWaitv w = Waiter(&words[0], 0, true);
  w.flags = kFutex2Private;  // No size.
  bad.push_back(w);
  w.flags = kFutex2SizeU64;
  bad.push_back(w);
  w.flags = kFutex2SizeU32 | 0x10;  // Unknown flag.
  bad.push_back(w);
  w = Waiter(&words[0], 0, true);
  w.reserved = 1;
  bad.push_back(w);
  w = Waiter(&words[0], 0, true);
  w.val = 1ULL << 32;  // Does not fit in 32 bits.
  bad.push_back(w);
  w = Waiter(&words[0], 0, true);
  w.uaddr += 2;  // Unaligned.
  bad.push_back(w);

  struct timespec const deadline = {.tv_sec = 0, .tv_nsec = 0};
  for (size_t i = 0; i < bad.size(); i++) {
    FutexWaitv waiters[] = {Waiter(&words[1], 0, true), bad[i]};
    EXPECT_THAT(futex_waitv(waiters, 2, 0, &deadline, CLOCK_MONOTONIC),
                SyscallFailsWithErrno(EINVAL))
        << "waiter " << i;
  }
}

TEST_F(FutexWaitvTest, BadAddress) {
  auto const mapping =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  auto const unmapped = static_cast<FutexWaitv*>(mapping.ptr());
  EXPECT_THAT(futex_waitv(unmapped, 1, 0, nullptr, 0),
              SyscallFailsWithErrno(EFAULT));

  FutexWaitv waiter =
      Waiter(reinterpret_cast<std::atomic<uint32_t>*>(mapping.ptr()), 0, true);
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, nullptr, 0),
              SyscallFailsWithErrno(EFAULT));

  std::atomic<uint32_t> word(0);
  waiter = Waiter(&word, 0, true);
  EXPECT_THAT(futex_waitv(&waiter, 1, 0,
                          reinterpret_cast<struct timespec*>(mapping.ptr()),
                          CLOCK_MONOTONIC),
              SyscallFailsWithErrno(EFAULT));
}

std::atomic<int> signal_count;

void CountSignal(int sig) { signal_count.fetch_add(1); }

// SignalUntil sends sig to the thread tid until done returns true or
// kRetryTimeout passes.
void SignalUntil(pid_t tid, int sig, std::function<bool()> done) {
  absl::Time const deadline = absl::Now() + kRetryTimeout;
  while (!done() && absl::Now() < deadline) {
    TEST_PCHECK(syscall(SYS_tgkill, getpid(), tid, sig) == 0);
    absl::SleepFor(kRetryInterval);
  }
}

TEST_F(FutexWaitvTest, InterruptedBySignal) {
  struct sigaction sa = {};
  sa.sa_handler = CountSignal;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));
  signal_count.store(0);

  std::atomic<uint32_t> word(0);
  FutexWaitv waiter = Waiter(&word, 0, true);
  std::atomic<bool> returned(false);
  pid_t const tid = syscall(SYS_gettid);
  ScopedThread signaler(
      [&] { SignalUntil(tid, SIGUSR1, [&] { return returned.load(); }); });

  // Without SA_RESTART, the first signal that arrives while blocked ends the
  // wait.
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, nullptr, 0),
              SyscallFailsWithErrno(EINTR));
  returned.store(true);
}

TEST_F(FutexWaitvTest, RestartedAfterSignal) {
  struct sigaction sa = {};
  sa.sa_handler = CountSignal;
  sa.sa_flags = SA_RESTART;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));
  signal_count.store(0);

  std::atomic<uint32_t> word(0);
  FutexWaitv waiter = Waiter(&word, 0, true);
  pid_t const tid = syscall(SYS_gettid);
  std::atomic<bool> returned(false);
  ScopedThread waker([&] {
    SignalUntil(tid, SIGUSR1,
                [&] { return signal_count.load() >= 3 || returned.load(); });
    WakeUntilWoken(true, &word, &returned);
  });

  // With SA_RESTART, the wait resumes after each signal and ends with the
  // wakeup.
  EXPECT_THAT(futex_waitv(&waiter, 1, 0, nullptr, 0),
              SyscallSucceedsWithValue(0));
  returned.store(true);
  EXPECT_GE(signal_count.load(), 3);
}

TEST_F(FutexWaitvTest, MixedPrivateAndShared) {
  // words[0] is private to this process. words[1] is in a shared mapping and
  // waited on as a shared futex, so another process can wake it.
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto const shared = static_cast<std::atomic<uint32_t>*>(mapping.ptr());
  shared->store(0);
  std::atomic<uint32_t> priv(0);
  FutexWaitv waiters[] = {Waiter(&priv, 0, true), Waiter(shared, 0, false)};

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    _exit(WakeUntilWoken(false, shared) ? 0 : 1);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  EXPECT_THAT(futex_waitv(waiters, 2, 0, nullptr, 0),
              SyscallSucceedsWithValue(1));

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST_F(FutexWaitvTest, WakeWrongKind) {
  std::atomic<uint32_t> words[2] = {};
  FutexWaitv waiters[] = {Waiter(&words[0], 0, true),
                          Waiter(&words[1], 0, false)};
  std::atomic<bool> done(false);

  ScopedThread waker([&] {
    // A wakeup of the wrong kind wakes neither waiter. Retry it until the
    // right kind wakes words[1], which shows that the waiter was queued.
    absl::Time const deadline = absl::Now() + kRetryTimeout;
    while (!done.load() && absl::Now() < deadline) {
      TEST_PCHECK(futex_wake(false, &words[0], 1) == 0);
      int const n = futex_wake(true, &words[1], 1);
      TEST_PCHECK(n == 0);
      if (futex_wake(false, &words[1], 1) == 1) {
        return;
      }
      absl::SleepFor(kRetryInterval);
    }
  });

  EXPECT_THAT(futex_waitv(waiters, 2, 0, nullptr, 0),
              SyscallSucceedsWithValue(1));
  done.store(true);
}

// A waiter moved to another futex by FUTEX_CMP_REQUEUE is woken there, and
// futex_waitv returns the index it was waiting at.
TEST_F(FutexWaitvTest, WokenAfterRequeue) {
  std::atomic<uint32_t> words[3] = {};
  FutexWaitv waiters[] = {Waiter(&words[0], 0, true),
                          Waiter(&words[1], 0, true)};
  std::atomic<bool> done(false);

  ScopedThread waker([&] {
    // Retry until the waiter was queued, moved and woken. A wakeup of
    // words[2] finds no waiter until the requeue has moved it there.
    absl::Time const deadline = absl::Now() + kRetryTimeout;
    while (!done.load() && absl::Now() < deadline) {
      TEST_PCHECK(syscall(SYS_futex, &words[1], FUTEX_CMP_REQUEUE_PRIVATE, 0, 1,
                          &words[2], 0) >= 0);
      int const n = futex_wake(true, &words[2], 1);
      TEST_PCHECK(n >= 0);
      if (n == 1) {
        return;
      }
      absl::SleepFor(kRetryInterval);
    }
  });

  EXPECT_THAT(futex_waitv(waiters, 2, 0, nullptr, 0),
              SyscallSucceedsWithValue(1));
  done.store(true);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
