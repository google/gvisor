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

#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <atomic>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

DEFINE_bool(timers_test_sleep, false,
            "If true, sleep forever instead of running tests.");

using ::testing::_;
using ::testing::AnyOf;

namespace gvisor {
namespace testing {
namespace {

#ifndef CPUCLOCK_PROF
#define CPUCLOCK_PROF 0
#endif  // CPUCLOCK_PROF

PosixErrorOr<absl::Duration> ProcessCPUTime(pid_t pid) {
  // Use pid-specific CPUCLOCK_PROF, which is the clock used to enforce
  // RLIMIT_CPU.
  clockid_t clockid = (~static_cast<clockid_t>(pid) << 3) | CPUCLOCK_PROF;

  struct timespec ts;
  int ret = clock_gettime(clockid, &ts);
  if (ret < 0) {
    return PosixError(errno, "clock_gettime failed");
  }

  return absl::DurationFromTimespec(ts);
}

void NoopSignalHandler(int signo) {
  TEST_CHECK_MSG(SIGXCPU == signo,
                 "NoopSigHandler did not receive expected signal");
}

void UninstallingSignalHandler(int signo) {
  TEST_CHECK_MSG(SIGXCPU == signo,
                 "UninstallingSignalHandler did not receive expected signal");
  struct sigaction rev_action;
  rev_action.sa_handler = SIG_DFL;
  rev_action.sa_flags = 0;
  sigemptyset(&rev_action.sa_mask);
  sigaction(SIGXCPU, &rev_action, nullptr);
}

TEST(TimerTest, ProcessKilledOnCPUSoftLimit) {
  constexpr absl::Duration kSoftLimit = absl::Seconds(1);
  constexpr absl::Duration kHardLimit = absl::Seconds(3);

  struct rlimit cpu_limits;
  cpu_limits.rlim_cur = absl::ToInt64Seconds(kSoftLimit);
  cpu_limits.rlim_max = absl::ToInt64Seconds(kHardLimit);

  int pid = fork();
  MaybeSave();
  if (pid == 0) {
    TEST_PCHECK(setrlimit(RLIMIT_CPU, &cpu_limits) == 0);
    MaybeSave();
    for (;;) {
    }
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  auto c = Cleanup([pid] {
    int status;
    EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGXCPU);
  });

  // Wait for the child to exit, but do not reap it. This will allow us to check
  // its CPU usage while it is zombied.
  EXPECT_THAT(waitid(P_PID, pid, nullptr, WEXITED | WNOWAIT),
              SyscallSucceeds());

  // Assert that the child spent 1s of CPU before getting killed.
  //
  // We must be careful to use CPUCLOCK_PROF, the same clock used for RLIMIT_CPU
  // enforcement, to get correct results. Note that this is slightly different
  // from rusage-reported CPU usage:
  //
  // RLIMIT_CPU, CPUCLOCK_PROF use kernel/sched/cputime.c:thread_group_cputime.
  // rusage uses kernel/sched/cputime.c:thread_group_cputime_adjusted.
  absl::Duration cpu = ASSERT_NO_ERRNO_AND_VALUE(ProcessCPUTime(pid));
  EXPECT_GE(cpu, kSoftLimit);

  // Child did not make it to the hard limit.
  //
  // Linux sends SIGXCPU synchronously with CPU tick updates. See
  // kernel/time/timer.c:update_process_times:
  //   => account_process_tick  // update task CPU usage.
  //   => run_posix_cpu_timers  // enforce RLIMIT_CPU, sending signal.
  //
  // Thus, only chance for this to flake is if the system time required to
  // deliver the signal exceeds 2s.
  EXPECT_LT(cpu, kHardLimit);
}

TEST(TimerTest, ProcessPingedRepeatedlyAfterCPUSoftLimit) {
  struct sigaction new_action;
  new_action.sa_handler = UninstallingSignalHandler;
  new_action.sa_flags = 0;
  sigemptyset(&new_action.sa_mask);

  constexpr absl::Duration kSoftLimit = absl::Seconds(1);
  constexpr absl::Duration kHardLimit = absl::Seconds(10);

  struct rlimit cpu_limits;
  cpu_limits.rlim_cur = absl::ToInt64Seconds(kSoftLimit);
  cpu_limits.rlim_max = absl::ToInt64Seconds(kHardLimit);

  int pid = fork();
  MaybeSave();
  if (pid == 0) {
    TEST_PCHECK(sigaction(SIGXCPU, &new_action, nullptr) == 0);
    MaybeSave();
    TEST_PCHECK(setrlimit(RLIMIT_CPU, &cpu_limits) == 0);
    MaybeSave();
    for (;;) {
    }
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  auto c = Cleanup([pid] {
    int status;
    EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGXCPU);
  });

  // Wait for the child to exit, but do not reap it. This will allow us to check
  // its CPU usage while it is zombied.
  EXPECT_THAT(waitid(P_PID, pid, nullptr, WEXITED | WNOWAIT),
              SyscallSucceeds());

  absl::Duration cpu = ASSERT_NO_ERRNO_AND_VALUE(ProcessCPUTime(pid));
  // Following signals come every CPU second.
  EXPECT_GE(cpu, kSoftLimit + absl::Seconds(1));

  // Child did not make it to the hard limit.
  //
  // As above, should not flake.
  EXPECT_LT(cpu, kHardLimit);
}

TEST(TimerTest, ProcessKilledOnCPUHardLimit) {
  struct sigaction new_action;
  new_action.sa_handler = NoopSignalHandler;
  new_action.sa_flags = 0;
  sigemptyset(&new_action.sa_mask);

  constexpr absl::Duration kSoftLimit = absl::Seconds(1);
  constexpr absl::Duration kHardLimit = absl::Seconds(3);

  struct rlimit cpu_limits;
  cpu_limits.rlim_cur = absl::ToInt64Seconds(kSoftLimit);
  cpu_limits.rlim_max = absl::ToInt64Seconds(kHardLimit);

  int pid = fork();
  MaybeSave();
  if (pid == 0) {
    TEST_PCHECK(sigaction(SIGXCPU, &new_action, nullptr) == 0);
    MaybeSave();
    TEST_PCHECK(setrlimit(RLIMIT_CPU, &cpu_limits) == 0);
    MaybeSave();
    for (;;) {
    }
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  auto c = Cleanup([pid] {
    int status;
    EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGKILL);
  });

  // Wait for the child to exit, but do not reap it. This will allow us to check
  // its CPU usage while it is zombied.
  EXPECT_THAT(waitid(P_PID, pid, nullptr, WEXITED | WNOWAIT),
              SyscallSucceeds());

  absl::Duration cpu = ASSERT_NO_ERRNO_AND_VALUE(ProcessCPUTime(pid));
  EXPECT_GE(cpu, kHardLimit);
}

// RAII type for a kernel "POSIX" interval timer. (The kernel provides system
// calls such as timer_create that behave very similarly, but not identically,
// to those described by timer_create(2); in particular, the kernel does not
// implement SIGEV_THREAD. glibc builds POSIX-compliant interval timers based on
// these kernel interval timers.)
//
// Compare implementation to FileDescriptor.
class IntervalTimer {
 public:
  IntervalTimer() = default;

  explicit IntervalTimer(int id) { set_id(id); }

  IntervalTimer(IntervalTimer&& orig) : id_(orig.release()) {}

  IntervalTimer& operator=(IntervalTimer&& orig) {
    if (this == &orig) return *this;
    reset(orig.release());
    return *this;
  }

  IntervalTimer(const IntervalTimer& other) = delete;
  IntervalTimer& operator=(const IntervalTimer& other) = delete;

  ~IntervalTimer() { reset(); }

  int get() const { return id_; }

  int release() {
    int const id = id_;
    id_ = -1;
    return id;
  }

  void reset() { reset(-1); }

  void reset(int id) {
    if (id_ >= 0) {
      TEST_PCHECK(syscall(SYS_timer_delete, id_) == 0);
      MaybeSave();
    }
    set_id(id);
  }

  PosixErrorOr<struct itimerspec> Set(
      int flags, const struct itimerspec& new_value) const {
    struct itimerspec old_value = {};
    if (syscall(SYS_timer_settime, id_, flags, &new_value, &old_value) < 0) {
      return PosixError(errno, "timer_settime");
    }
    MaybeSave();
    return old_value;
  }

  PosixErrorOr<struct itimerspec> Get() const {
    struct itimerspec curr_value = {};
    if (syscall(SYS_timer_gettime, id_, &curr_value) < 0) {
      return PosixError(errno, "timer_gettime");
    }
    MaybeSave();
    return curr_value;
  }

  PosixErrorOr<int> Overruns() const {
    int rv = syscall(SYS_timer_getoverrun, id_);
    if (rv < 0) {
      return PosixError(errno, "timer_getoverrun");
    }
    MaybeSave();
    return rv;
  }

 private:
  void set_id(int id) { id_ = std::max(id, -1); }

  // Kernel timer_t is int; glibc timer_t is void*.
  int id_ = -1;
};

PosixErrorOr<IntervalTimer> TimerCreate(clockid_t clockid,
                                        const struct sigevent& sev) {
  int timerid;
  if (syscall(SYS_timer_create, clockid, &sev, &timerid) < 0) {
    return PosixError(errno, "timer_create");
  }
  MaybeSave();
  return IntervalTimer(timerid);
}

// See timerfd.cc:TimerSlack() for rationale.
constexpr absl::Duration kTimerSlack = absl::Milliseconds(500);

TEST(IntervalTimerTest, IsInitiallyStopped) {
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_NONE;
  const auto timer =
      ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));
  const struct itimerspec its = ASSERT_NO_ERRNO_AND_VALUE(timer.Get());
  EXPECT_EQ(0, its.it_value.tv_sec);
  EXPECT_EQ(0, its.it_value.tv_nsec);
}

TEST(IntervalTimerTest, SingleShotSilent) {
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_NONE;
  const auto timer =
      ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kDelay = absl::Seconds(1);
  struct itimerspec its = {};
  its.it_value = absl::ToTimespec(kDelay);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  // The timer should count down to 0 and stop since the interval is zero. No
  // overruns should be counted.
  absl::SleepFor(kDelay + kTimerSlack);
  its = ASSERT_NO_ERRNO_AND_VALUE(timer.Get());
  EXPECT_EQ(0, its.it_value.tv_sec);
  EXPECT_EQ(0, its.it_value.tv_nsec);
  EXPECT_THAT(timer.Overruns(), IsPosixErrorOkAndHolds(0));
}

TEST(IntervalTimerTest, PeriodicSilent) {
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_NONE;
  const auto timer =
      ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  absl::SleepFor(kPeriod * 3 + kTimerSlack);

  // The timer should still be running.
  its = ASSERT_NO_ERRNO_AND_VALUE(timer.Get());
  EXPECT_TRUE(its.it_value.tv_nsec != 0 || its.it_value.tv_sec != 0);

  // Timer expirations are not counted as overruns under SIGEV_NONE.
  EXPECT_THAT(timer.Overruns(), IsPosixErrorOkAndHolds(0));
}

std::atomic<int> counted_signals;

void IntervalTimerCountingSignalHandler(int sig, siginfo_t* info,
                                        void* ucontext) {
  counted_signals.fetch_add(1 + info->si_overrun);
}

TEST(IntervalTimerTest, PeriodicGroupDirectedSignal) {
  constexpr int kSigno = SIGUSR1;
  constexpr int kSigvalue = 42;

  // Install our signal handler.
  counted_signals.store(0);
  struct sigaction sa = {};
  sa.sa_sigaction = IntervalTimerCountingSignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));

  // Ensure that kSigno is unblocked on at least one thread.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, kSigno));

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  constexpr int kCycles = 3;
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  absl::SleepFor(kPeriod * kCycles + kTimerSlack);
  EXPECT_GE(counted_signals.load(), kCycles);
}

// From Linux's include/uapi/asm-generic/siginfo.h.
#ifndef sigev_notify_thread_id
#define sigev_notify_thread_id _sigev_un._tid
#endif

TEST(IntervalTimerTest, PeriodicThreadDirectedSignal) {
  constexpr int kSigno = SIGUSR1;
  constexpr int kSigvalue = 42;

  // Block kSigno so that we can accumulate overruns.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, mask));

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  sev.sigev_notify_thread_id = gettid();
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  constexpr int kCycles = 3;
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));
  absl::SleepFor(kPeriod * kCycles + kTimerSlack);

  // At least kCycles expirations should have occurred, resulting in kCycles-1
  // overruns (the first expiration sent the signal successfully).
  siginfo_t si;
  struct timespec zero_ts = absl::ToTimespec(absl::ZeroDuration());
  ASSERT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallSucceedsWithValue(kSigno));
  EXPECT_EQ(si.si_signo, kSigno);
  EXPECT_EQ(si.si_code, SI_TIMER);
  EXPECT_EQ(si.si_timerid, timer.get());
  EXPECT_GE(si.si_overrun, kCycles - 1);
  EXPECT_EQ(si.si_int, kSigvalue);

  // Kill the timer, then drain any additional signal it may have enqueued. We
  // can't do this before the preceding sigtimedwait because stopping or
  // deleting the timer resets si_overrun to 0.
  timer.reset();
  sigtimedwait(&mask, &si, &zero_ts);
}

TEST(IntervalTimerTest, OtherThreadGroup) {
  constexpr int kSigno = SIGUSR1;

  // Create a subprocess that does nothing until killed.
  pid_t child_pid;
  const auto sp = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      "/proc/self/exe", ExecveArray({"timers", "--timers_test_sleep"}),
      ExecveArray(), &child_pid, nullptr));

  // Verify that we can't create a timer that would send signals to it.
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = kSigno;
  sev.sigev_notify_thread_id = child_pid;
  EXPECT_THAT(TimerCreate(CLOCK_MONOTONIC, sev), PosixErrorIs(EINVAL, _));
}

TEST(IntervalTimerTest, RealTimeSignalsAreNotDuplicated) {
  const int kSigno = SIGRTMIN;
  constexpr int kSigvalue = 42;

  // Block signo so that we can accumulate overruns.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  const auto scoped_sigmask = ScopedSignalMask(SIG_BLOCK, mask);

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  sev.sigev_notify_thread_id = gettid();
  const auto timer =
      ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  constexpr int kCycles = 3;
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));
  absl::SleepFor(kPeriod * kCycles + kTimerSlack);

  // Stop the timer so that no further signals are enqueued after sigtimedwait.
  struct timespec zero_ts = absl::ToTimespec(absl::ZeroDuration());
  its.it_value = its.it_interval = zero_ts;
  ASSERT_NO_ERRNO(timer.Set(0, its));

  // The timer should have sent only a single signal, even though the kernel
  // supports enqueueing of multiple RT signals.
  siginfo_t si;
  ASSERT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallSucceedsWithValue(kSigno));
  EXPECT_EQ(si.si_signo, kSigno);
  EXPECT_EQ(si.si_code, SI_TIMER);
  EXPECT_EQ(si.si_timerid, timer.get());
  // si_overrun was reset by timer_settime.
  EXPECT_EQ(si.si_overrun, 0);
  EXPECT_EQ(si.si_int, kSigvalue);
  EXPECT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(IntervalTimerTest, AlreadyPendingSignal) {
  constexpr int kSigno = SIGUSR1;
  constexpr int kSigvalue = 42;

  // Block kSigno so that we can accumulate overruns.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, mask));

  // Send ourselves a signal, preventing the timer from enqueuing.
  ASSERT_THAT(tgkill(getpid(), gettid(), kSigno), SyscallSucceeds());

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  sev.sigev_notify_thread_id = gettid();
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  constexpr int kCycles = 3;
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  // End the sleep one cycle short; we will sleep for one more cycle below.
  absl::SleepFor(kPeriod * (kCycles - 1));

  // Dequeue the first signal, which we sent to ourselves with tgkill.
  siginfo_t si;
  struct timespec zero_ts = absl::ToTimespec(absl::ZeroDuration());
  ASSERT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallSucceedsWithValue(kSigno));
  EXPECT_EQ(si.si_signo, kSigno);
  // glibc sigtimedwait silently replaces SI_TKILL with SI_USER:
  // sysdeps/unix/sysv/linux/sigtimedwait.c:__sigtimedwait(). This isn't
  // documented, so we don't depend on it.
  EXPECT_THAT(si.si_code, AnyOf(SI_USER, SI_TKILL));

  // Sleep for 1 more cycle to give the timer time to send a signal.
  absl::SleepFor(kPeriod + kTimerSlack);

  // At least kCycles expirations should have occurred, resulting in kCycles-1
  // overruns (the last expiration sent the signal successfully).
  ASSERT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallSucceedsWithValue(kSigno));
  EXPECT_EQ(si.si_signo, kSigno);
  EXPECT_EQ(si.si_code, SI_TIMER);
  EXPECT_EQ(si.si_timerid, timer.get());
  EXPECT_GE(si.si_overrun, kCycles - 1);
  EXPECT_EQ(si.si_int, kSigvalue);

  // Kill the timer, then drain any additional signal it may have enqueued. We
  // can't do this before the preceding sigtimedwait because stopping or
  // deleting the timer resets si_overrun to 0.
  timer.reset();
  sigtimedwait(&mask, &si, &zero_ts);
}

TEST(IntervalTimerTest, IgnoredSignalCountsAsOverrun) {
  constexpr int kSigno = SIGUSR1;
  constexpr int kSigvalue = 42;

  // Ignore kSigno.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));

  // Unblock kSigno so that ignored signals will be discarded.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, mask));

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  sev.sigev_notify_thread_id = gettid();
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  constexpr int kCycles = 3;
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  // End the sleep one cycle short; we will sleep for one more cycle below.
  absl::SleepFor(kPeriod * (kCycles - 1));

  // Block kSigno so that ignored signals will be enqueued.
  scoped_sigmask.Release()();
  scoped_sigmask = ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, mask));

  // Sleep for 1 more cycle to give the timer time to send a signal.
  absl::SleepFor(kPeriod + kTimerSlack);

  // At least kCycles expirations should have occurred, resulting in kCycles-1
  // overruns (the last expiration sent the signal successfully).
  siginfo_t si;
  struct timespec zero_ts = absl::ToTimespec(absl::ZeroDuration());
  ASSERT_THAT(sigtimedwait(&mask, &si, &zero_ts),
              SyscallSucceedsWithValue(kSigno));
  EXPECT_EQ(si.si_signo, kSigno);
  EXPECT_EQ(si.si_code, SI_TIMER);
  EXPECT_EQ(si.si_timerid, timer.get());
  EXPECT_GE(si.si_overrun, kCycles - 1);
  EXPECT_EQ(si.si_int, kSigvalue);

  // Kill the timer, then drain any additional signal it may have enqueued. We
  // can't do this before the preceding sigtimedwait because stopping or
  // deleting the timer resets si_overrun to 0.
  timer.reset();
  sigtimedwait(&mask, &si, &zero_ts);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (FLAGS_timers_test_sleep) {
    while (true) {
      absl::SleepFor(absl::Seconds(10));
    }
  }

  return RUN_ALL_TESTS();
}
