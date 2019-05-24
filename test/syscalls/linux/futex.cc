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
#include <linux/futex.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/memory_util.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/time_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

// Amount of time we wait for threads doing futex_wait to start running before
// doing futex_wake.
constexpr auto kWaiterStartupDelay = absl::Seconds(3);

// Default timeout for waiters in tests where we expect a futex_wake to be
// ineffective.
constexpr auto kIneffectiveWakeTimeout = absl::Seconds(6);

static_assert(kWaiterStartupDelay < kIneffectiveWakeTimeout,
              "futex_wait will time out before futex_wake is called");

int futex_wait(bool priv, std::atomic<int>* uaddr, int val,
               absl::Duration timeout = absl::InfiniteDuration()) {
  int op = FUTEX_WAIT;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }

  if (timeout == absl::InfiniteDuration()) {
    return RetryEINTR(syscall)(SYS_futex, uaddr, op, val, nullptr);
  }

  // FUTEX_WAIT doesn't adjust the timeout if it returns EINTR, so we have to do
  // so.
  while (true) {
    auto const timeout_ts = absl::ToTimespec(timeout);
    MonotonicTimer timer;
    timer.Start();
    int const ret = syscall(SYS_futex, uaddr, op, val, &timeout_ts);
    if (ret != -1 || errno != EINTR) {
      return ret;
    }
    timeout = std::max(timeout - timer.Duration(), absl::ZeroDuration());
  }
}

int futex_wait_bitset(bool priv, std::atomic<int>* uaddr, int val, int bitset,
                      absl::Time deadline = absl::InfiniteFuture()) {
  int op = FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }

  auto const deadline_ts = absl::ToTimespec(deadline);
  return RetryEINTR(syscall)(
      SYS_futex, uaddr, op, val,
      deadline == absl::InfiniteFuture() ? nullptr : &deadline_ts, nullptr,
      bitset);
}

int futex_wake(bool priv, std::atomic<int>* uaddr, int count) {
  int op = FUTEX_WAKE;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return syscall(SYS_futex, uaddr, op, count);
}

int futex_wake_bitset(bool priv, std::atomic<int>* uaddr, int count,
                      int bitset) {
  int op = FUTEX_WAKE_BITSET;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return syscall(SYS_futex, uaddr, op, count, nullptr, nullptr, bitset);
}

int futex_wake_op(bool priv, std::atomic<int>* uaddr1, std::atomic<int>* uaddr2,
                  int nwake1, int nwake2, uint32_t sub_op) {
  int op = FUTEX_WAKE_OP;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return syscall(SYS_futex, uaddr1, op, nwake1, nwake2, uaddr2, sub_op);
}

int futex_lock_pi(bool priv, std::atomic<int>* uaddr) {
  int op = FUTEX_LOCK_PI;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return RetryEINTR(syscall)(SYS_futex, uaddr, op, nullptr, nullptr);
}

int futex_trylock_pi(bool priv, std::atomic<int>* uaddr) {
  int op = FUTEX_TRYLOCK_PI;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return RetryEINTR(syscall)(SYS_futex, uaddr, op, nullptr, nullptr);
}

int futex_unlock_pi(bool priv, std::atomic<int>* uaddr) {
  int op = FUTEX_UNLOCK_PI;
  if (priv) {
    op |= FUTEX_PRIVATE_FLAG;
  }
  return RetryEINTR(syscall)(SYS_futex, uaddr, op, nullptr, nullptr);
}

// Fixture for futex tests parameterized by whether to use private or shared
// futexes.
class PrivateAndSharedFutexTest : public ::testing::TestWithParam<bool> {
 protected:
  bool IsPrivate() const { return GetParam(); }
  int PrivateFlag() const { return IsPrivate() ? FUTEX_PRIVATE_FLAG : 0; }
};

// FUTEX_WAIT with 0 timeout does not block.
TEST_P(PrivateAndSharedFutexTest, Wait_ZeroTimeout) {
  struct timespec timeout = {};

  // Don't use the futex_wait helper because it adjusts timeout.
  int a = 1;
  EXPECT_THAT(syscall(SYS_futex, &a, FUTEX_WAIT | PrivateFlag(), a, &timeout),
              SyscallFailsWithErrno(ETIMEDOUT));
}

TEST_P(PrivateAndSharedFutexTest, Wait_Timeout) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);

  MonotonicTimer timer;
  timer.Start();
  constexpr absl::Duration kTimeout = absl::Seconds(1);
  EXPECT_THAT(futex_wait(IsPrivate(), &a, a, kTimeout),
              SyscallFailsWithErrno(ETIMEDOUT));
  EXPECT_GE(timer.Duration(), kTimeout);
}

TEST_P(PrivateAndSharedFutexTest, Wait_BitsetTimeout) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);

  MonotonicTimer timer;
  timer.Start();
  constexpr absl::Duration kTimeout = absl::Seconds(1);
  EXPECT_THAT(
      futex_wait_bitset(IsPrivate(), &a, a, 0xffffffff, absl::Now() + kTimeout),
      SyscallFailsWithErrno(ETIMEDOUT));
  EXPECT_GE(timer.Duration(), kTimeout);
}

TEST_P(PrivateAndSharedFutexTest, WaitBitset_NegativeTimeout) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);

  MonotonicTimer timer;
  timer.Start();
  EXPECT_THAT(futex_wait_bitset(IsPrivate(), &a, a, 0xffffffff,
                                absl::Now() - absl::Seconds(1)),
              SyscallFailsWithErrno(ETIMEDOUT));
}

TEST_P(PrivateAndSharedFutexTest, Wait_WrongVal) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);
  EXPECT_THAT(futex_wait(IsPrivate(), &a, a + 1),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(PrivateAndSharedFutexTest, Wait_ZeroBitset) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);
  EXPECT_THAT(futex_wait_bitset(IsPrivate(), &a, a, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PrivateAndSharedFutexTest, Wake1_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  // Prevent save/restore from interrupting futex_wait, which will cause it to
  // return EAGAIN instead of the expected result if futex_wait is restarted
  // after we change the value of a below.
  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), &a, kInitialValue),
                SyscallSucceedsWithValue(0));
  });
  absl::SleepFor(kWaiterStartupDelay);

  // Change a so that if futex_wake happens before futex_wait, the latter
  // returns EAGAIN instead of hanging the test.
  a.fetch_add(1);
  EXPECT_THAT(futex_wake(IsPrivate(), &a, 1), SyscallSucceedsWithValue(1));
}

TEST_P(PrivateAndSharedFutexTest, WakeAll_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  constexpr int kThreads = 5;
  std::vector<std::unique_ptr<ScopedThread>> threads;
  threads.reserve(kThreads);
  for (int i = 0; i < kThreads; i++) {
    threads.push_back(absl::make_unique<ScopedThread>([&] {
      EXPECT_THAT(futex_wait(IsPrivate(), &a, kInitialValue),
                  SyscallSucceeds());
    }));
  }
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake(IsPrivate(), &a, kThreads),
              SyscallSucceedsWithValue(kThreads));
}

TEST_P(PrivateAndSharedFutexTest, WakeSome_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  constexpr int kThreads = 5;
  constexpr int kWokenThreads = 3;
  static_assert(kWokenThreads < kThreads,
                "can't wake more threads than are created");
  std::vector<std::unique_ptr<ScopedThread>> threads;
  threads.reserve(kThreads);
  std::vector<int> rets;
  rets.reserve(kThreads);
  std::vector<int> errs;
  errs.reserve(kThreads);
  for (int i = 0; i < kThreads; i++) {
    rets.push_back(-1);
    errs.push_back(0);
  }
  for (int i = 0; i < kThreads; i++) {
    threads.push_back(absl::make_unique<ScopedThread>([&, i] {
      rets[i] =
          futex_wait(IsPrivate(), &a, kInitialValue, kIneffectiveWakeTimeout);
      errs[i] = errno;
    }));
  }
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake(IsPrivate(), &a, kWokenThreads),
              SyscallSucceedsWithValue(kWokenThreads));

  int woken = 0;
  int timedout = 0;
  for (int i = 0; i < kThreads; i++) {
    threads[i]->Join();
    if (rets[i] == 0) {
      woken++;
    } else if (errs[i] == ETIMEDOUT) {
      timedout++;
    } else {
      ADD_FAILURE() << " thread " << i << ": returned " << rets[i] << ", errno "
                    << errs[i];
    }
  }
  EXPECT_EQ(woken, kWokenThreads);
  EXPECT_EQ(timedout, kThreads - kWokenThreads);
}

TEST_P(PrivateAndSharedFutexTest, WaitBitset_Wake_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait_bitset(IsPrivate(), &a, kInitialValue, 0b01001000),
                SyscallSucceeds());
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake(IsPrivate(), &a, 1), SyscallSucceedsWithValue(1));
}

TEST_P(PrivateAndSharedFutexTest, Wait_WakeBitset_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), &a, kInitialValue), SyscallSucceeds());
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake_bitset(IsPrivate(), &a, 1, 0b01001000),
              SyscallSucceedsWithValue(1));
}

TEST_P(PrivateAndSharedFutexTest, WaitBitset_WakeBitsetMatch_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  constexpr int kBitset = 0b01001000;

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait_bitset(IsPrivate(), &a, kInitialValue, kBitset),
                SyscallSucceeds());
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake_bitset(IsPrivate(), &a, 1, kBitset),
              SyscallSucceedsWithValue(1));
}

TEST_P(PrivateAndSharedFutexTest, WaitBitset_WakeBitsetNoMatch_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  constexpr int kWaitBitset = 0b01000001;
  constexpr int kWakeBitset = 0b00101000;
  static_assert((kWaitBitset & kWakeBitset) == 0,
                "futex_wake_bitset will wake waiter");

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait_bitset(IsPrivate(), &a, kInitialValue, kWaitBitset,
                                  absl::Now() + kIneffectiveWakeTimeout),
                SyscallFailsWithErrno(ETIMEDOUT));
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  EXPECT_THAT(futex_wake_bitset(IsPrivate(), &a, 1, kWakeBitset),
              SyscallSucceedsWithValue(0));
}

TEST_P(PrivateAndSharedFutexTest, WakeOpCondSuccess_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);
  std::atomic<int> b = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  ScopedThread thread_a([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), &a, kInitialValue), SyscallSucceeds());
  });
  ScopedThread thread_b([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), &b, kInitialValue), SyscallSucceeds());
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  b.fetch_add(1);
  // This futex_wake_op should:
  // - Wake 1 waiter on a unconditionally.
  // - Wake 1 waiter on b if b == kInitialValue + 1, which it is.
  // - Do "b += 1".
  EXPECT_THAT(futex_wake_op(IsPrivate(), &a, &b, 1, 1,
                            FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ,
                                     (kInitialValue + 1))),
              SyscallSucceedsWithValue(2));
  EXPECT_EQ(b, kInitialValue + 2);
}

TEST_P(PrivateAndSharedFutexTest, WakeOpCondFailure_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);
  std::atomic<int> b = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  ScopedThread thread_a([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), &a, kInitialValue), SyscallSucceeds());
  });
  ScopedThread thread_b([&] {
    EXPECT_THAT(
        futex_wait(IsPrivate(), &b, kInitialValue, kIneffectiveWakeTimeout),
        SyscallFailsWithErrno(ETIMEDOUT));
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  b.fetch_add(1);
  // This futex_wake_op should:
  // - Wake 1 waiter on a unconditionally.
  // - Wake 1 waiter on b if b == kInitialValue - 1, which it isn't.
  // - Do "b += 1".
  EXPECT_THAT(futex_wake_op(IsPrivate(), &a, &b, 1, 1,
                            FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ,
                                     (kInitialValue - 1))),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(b, kInitialValue + 2);
}

TEST_P(PrivateAndSharedFutexTest, NoWakeInterprocessPrivateAnon_NoRandomSave) {
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  auto const ptr = static_cast<std::atomic<int>*>(mapping.ptr());
  constexpr int kInitialValue = 1;
  ptr->store(kInitialValue);

  DisableSave ds;
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(futex_wait(IsPrivate(), ptr, kInitialValue,
                           kIneffectiveWakeTimeout) == -1 &&
                errno == ETIMEDOUT);
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());
  absl::SleepFor(kWaiterStartupDelay);

  EXPECT_THAT(futex_wake(IsPrivate(), ptr, 1), SyscallSucceedsWithValue(0));

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST_P(PrivateAndSharedFutexTest, WakeAfterCOWBreak_NoRandomSave) {
  // Use a futex on a non-stack mapping so we can be sure that the child process
  // below isn't the one that breaks copy-on-write.
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  auto const ptr = static_cast<std::atomic<int>*>(mapping.ptr());
  constexpr int kInitialValue = 1;
  ptr->store(kInitialValue);

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(futex_wait(IsPrivate(), ptr, kInitialValue), SyscallSucceeds());
  });
  absl::SleepFor(kWaiterStartupDelay);

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // Wait to be killed by the parent.
    while (true) pause();
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());
  auto cleanup_child = Cleanup([&] {
    EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        << " status " << status;
  });

  // In addition to preventing a late futex_wait from sleeping, this breaks
  // copy-on-write on the mapped page.
  ptr->fetch_add(1);
  EXPECT_THAT(futex_wake(IsPrivate(), ptr, 1), SyscallSucceedsWithValue(1));
}

TEST_P(PrivateAndSharedFutexTest, WakeWrongKind_NoRandomSave) {
  constexpr int kInitialValue = 1;
  std::atomic<int> a = ATOMIC_VAR_INIT(kInitialValue);

  DisableSave ds;
  ScopedThread thread([&] {
    EXPECT_THAT(
        futex_wait(IsPrivate(), &a, kInitialValue, kIneffectiveWakeTimeout),
        SyscallFailsWithErrno(ETIMEDOUT));
  });
  absl::SleepFor(kWaiterStartupDelay);

  a.fetch_add(1);
  // The value of priv passed to futex_wake is the opposite of that passed to
  // the futex_waiter; we expect this not to wake the waiter.
  EXPECT_THAT(futex_wake(!IsPrivate(), &a, 1), SyscallSucceedsWithValue(0));
}

INSTANTIATE_TEST_SUITE_P(SharedPrivate, PrivateAndSharedFutexTest,
                         ::testing::Bool());

// Passing null as the address only works for private futexes.

TEST(PrivateFutexTest, WakeOp0Set) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);

  int futex_op = FUTEX_OP(FUTEX_OP_SET, 2, 0, 0);
  EXPECT_THAT(futex_wake_op(true, nullptr, &a, 0, 0, futex_op),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(a, 2);
}

TEST(PrivateFutexTest, WakeOp0Add) {
  std::atomic<int> a = ATOMIC_VAR_INIT(1);
  int futex_op = FUTEX_OP(FUTEX_OP_ADD, 1, 0, 0);
  EXPECT_THAT(futex_wake_op(true, nullptr, &a, 0, 0, futex_op),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(a, 2);
}

TEST(PrivateFutexTest, WakeOp0Or) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0b01);
  int futex_op = FUTEX_OP(FUTEX_OP_OR, 0b10, 0, 0);
  EXPECT_THAT(futex_wake_op(true, nullptr, &a, 0, 0, futex_op),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(a, 0b11);
}

TEST(PrivateFutexTest, WakeOp0Andn) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0b11);
  int futex_op = FUTEX_OP(FUTEX_OP_ANDN, 0b10, 0, 0);
  EXPECT_THAT(futex_wake_op(true, nullptr, &a, 0, 0, futex_op),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(a, 0b01);
}

TEST(PrivateFutexTest, WakeOp0Xor) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0b1010);
  int futex_op = FUTEX_OP(FUTEX_OP_XOR, 0b1100, 0, 0);
  EXPECT_THAT(futex_wake_op(true, nullptr, &a, 0, 0, futex_op),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(a, 0b0110);
}

TEST(SharedFutexTest, WakeInterprocessSharedAnon_NoRandomSave) {
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto const ptr = static_cast<std::atomic<int>*>(mapping.ptr());
  constexpr int kInitialValue = 1;
  ptr->store(kInitialValue);

  DisableSave ds;
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(futex_wait(false, ptr, kInitialValue) == 0);
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());
  auto kill_child = Cleanup(
      [&] { EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds()); });
  absl::SleepFor(kWaiterStartupDelay);

  ptr->fetch_add(1);
  // This is an ASSERT so that if it fails, we immediately abort the test (and
  // kill the subprocess).
  ASSERT_THAT(futex_wake(false, ptr, 1), SyscallSucceedsWithValue(1));

  kill_child.Release();
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(SharedFutexTest, WakeInterprocessFile_NoRandomSave) {
  auto const file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(truncate(file.path().c_str(), kPageSize), SyscallSucceeds());
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0));
  auto const ptr = static_cast<std::atomic<int>*>(mapping.ptr());
  constexpr int kInitialValue = 1;
  ptr->store(kInitialValue);

  DisableSave ds;
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(futex_wait(false, ptr, kInitialValue) == 0);
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());
  auto kill_child = Cleanup(
      [&] { EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds()); });
  absl::SleepFor(kWaiterStartupDelay);

  ptr->fetch_add(1);
  // This is an ASSERT so that if it fails, we immediately abort the test (and
  // kill the subprocess).
  ASSERT_THAT(futex_wake(false, ptr, 1), SyscallSucceedsWithValue(1));

  kill_child.Release();
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST_P(PrivateAndSharedFutexTest, PIBasic) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0);

  ASSERT_THAT(futex_lock_pi(IsPrivate(), &a), SyscallSucceeds());
  EXPECT_EQ(a.load(), gettid());
  EXPECT_THAT(futex_lock_pi(IsPrivate(), &a), SyscallFailsWithErrno(EDEADLK));

  ASSERT_THAT(futex_unlock_pi(IsPrivate(), &a), SyscallSucceeds());
  EXPECT_EQ(a.load(), 0);
  EXPECT_THAT(futex_unlock_pi(IsPrivate(), &a), SyscallFailsWithErrno(EPERM));
}

TEST_P(PrivateAndSharedFutexTest, PIConcurrency_NoRandomSave) {
  DisableSave ds;  // Too many syscalls.

  std::atomic<int> a = ATOMIC_VAR_INIT(0);
  const bool is_priv = IsPrivate();

  std::unique_ptr<ScopedThread> threads[100];
  for (size_t i = 0; i < ABSL_ARRAYSIZE(threads); ++i) {
    threads[i] = absl::make_unique<ScopedThread>([is_priv, &a] {
      for (size_t j = 0; j < 10; ++j) {
        ASSERT_THAT(futex_lock_pi(is_priv, &a), SyscallSucceeds());
        EXPECT_EQ(a.load() & FUTEX_TID_MASK, gettid());
        SleepSafe(absl::Milliseconds(5));
        ASSERT_THAT(futex_unlock_pi(is_priv, &a), SyscallSucceeds());
      }
    });
  }
}

TEST_P(PrivateAndSharedFutexTest, PIWaiters) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0);
  const bool is_priv = IsPrivate();

  ASSERT_THAT(futex_lock_pi(is_priv, &a), SyscallSucceeds());
  EXPECT_EQ(a.load(), gettid());

  ScopedThread th([is_priv, &a] {
    ASSERT_THAT(futex_lock_pi(is_priv, &a), SyscallSucceeds());
    ASSERT_THAT(futex_unlock_pi(is_priv, &a), SyscallSucceeds());
  });

  // Wait until the thread blocks on the futex, setting the waiters bit.
  auto start = absl::Now();
  while (a.load() != (FUTEX_WAITERS | gettid())) {
    ASSERT_LT(absl::Now() - start, absl::Seconds(5));
    absl::SleepFor(absl::Milliseconds(100));
  }
  ASSERT_THAT(futex_unlock_pi(is_priv, &a), SyscallSucceeds());
}

TEST_P(PrivateAndSharedFutexTest, PITryLock) {
  std::atomic<int> a = ATOMIC_VAR_INIT(0);
  const bool is_priv = IsPrivate();

  ASSERT_THAT(futex_trylock_pi(IsPrivate(), &a), SyscallSucceeds());
  EXPECT_EQ(a.load(), gettid());

  EXPECT_THAT(futex_trylock_pi(is_priv, &a), SyscallFailsWithErrno(EDEADLK));
  ScopedThread th([is_priv, &a] {
    EXPECT_THAT(futex_trylock_pi(is_priv, &a), SyscallFailsWithErrno(EAGAIN));
  });
  th.Join();

  ASSERT_THAT(futex_unlock_pi(IsPrivate(), &a), SyscallSucceeds());
}

TEST_P(PrivateAndSharedFutexTest, PITryLockConcurrency_NoRandomSave) {
  DisableSave ds;  // Too many syscalls.

  std::atomic<int> a = ATOMIC_VAR_INIT(0);
  const bool is_priv = IsPrivate();

  std::unique_ptr<ScopedThread> threads[100];
  for (size_t i = 0; i < ABSL_ARRAYSIZE(threads); ++i) {
    threads[i] = absl::make_unique<ScopedThread>([is_priv, &a] {
      for (size_t j = 0; j < 10;) {
        if (futex_trylock_pi(is_priv, &a) >= 0) {
          ++j;
          EXPECT_EQ(a.load() & FUTEX_TID_MASK, gettid());
          SleepSafe(absl::Milliseconds(5));
          ASSERT_THAT(futex_unlock_pi(is_priv, &a), SyscallSucceeds());
        }
      }
    });
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
