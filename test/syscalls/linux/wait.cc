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

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

using ::testing::UnorderedElementsAre;

// These unit tests focus on the wait4(2) system call, but include a basic
// checks for the i386 waitpid(2) syscall, which is a subset of wait4(2).
//
// NOTE(b/22640830,b/27680907,b/29049891): Some functionality is not tested as
// it is not currently supported by gVisor:
// * UID in waitid(2) siginfo.
// * Process groups.
// * Core dump status (WCOREDUMP).
// * Linux only option __WNOTHREAD.
//
// Tests for waiting on stopped/continued children are in sigstop.cc.

namespace gvisor {
namespace testing {

namespace {

// The CloneChild function seems to need more than one page of stack space.
static const size_t kStackSize = 2 * kPageSize;

// The child thread created in CloneAndExit runs this function.
// This child does not have the TLS setup, so it must not use glibc functions.
int CloneChild(void* priv) {
  int64_t sleep = reinterpret_cast<int64_t>(priv);
  SleepSafe(absl::Seconds(sleep));

  // glibc's _exit(2) function wrapper will helpfully call exit_group(2),
  // exiting the entire process.
  syscall(__NR_exit, 0);
  return 1;
}

// ForkAndExit forks a child process which exits with exit_code, after
// sleeping for the specified duration (seconds).
pid_t ForkAndExit(int exit_code, int64_t sleep) {
  pid_t child = fork();
  if (child == 0) {
    SleepSafe(absl::Seconds(sleep));
    _exit(exit_code);
  }
  return child;
}

int64_t clock_gettime_nsecs(clockid_t id) {
  struct timespec ts;
  TEST_PCHECK(clock_gettime(id, &ts) == 0);
  return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}

void spin(int64_t sec) {
  int64_t ns = sec * 1000000000;
  int64_t start = clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID);
  int64_t end = start + ns;

  do {
    constexpr int kLoopCount = 1000000;  // large and arbitrary
    // volatile to prevent the compiler from skipping this loop.
    for (volatile int i = 0; i < kLoopCount; i++) {
    }
  } while (clock_gettime_nsecs(CLOCK_THREAD_CPUTIME_ID) < end);
}

// ForkSpinAndExit forks a child process which exits with exit_code, after
// spinning for the specified duration (seconds).
pid_t ForkSpinAndExit(int exit_code, int64_t spintime) {
  pid_t child = fork();
  if (child == 0) {
    spin(spintime);
    _exit(exit_code);
  }
  return child;
}

absl::Duration RusageCpuTime(const struct rusage& ru) {
  return absl::DurationFromTimeval(ru.ru_utime) +
         absl::DurationFromTimeval(ru.ru_stime);
}

// Returns the address of the top of the stack.
// Free with FreeStack.
uintptr_t AllocStack() {
  void* addr = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (addr == MAP_FAILED) {
    return reinterpret_cast<uintptr_t>(MAP_FAILED);
  }

  return reinterpret_cast<uintptr_t>(addr) + kStackSize;
}

// Frees a stack page allocated with AllocStack.
int FreeStack(uintptr_t addr) {
  addr -= kStackSize;
  return munmap(reinterpret_cast<void*>(addr), kPageSize);
}

// CloneAndExit clones a child thread, which exits with 0 after sleeping for
// the specified duration (must be in seconds). extra_flags are ORed against
// the standard clone(2) flags.
int CloneAndExit(int64_t sleep, uintptr_t stack, int extra_flags) {
  return clone(CloneChild, reinterpret_cast<void*>(stack),
               CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_VM | extra_flags,
               reinterpret_cast<void*>(sleep));
}

// Simple wrappers around wait4(2) and waitid(2) that ignore interrupts.
constexpr auto Wait4 = RetryEINTR(wait4);
constexpr auto Waitid = RetryEINTR(waitid);

// Fixture for tests parameterized by a function that waits for any child to
// exit with the given options, checks that it exited with the given code, and
// then returns its PID.
//
// N.B. These tests run in a multi-threaded environment. We assume that
// background threads do not create child processes and are not themselves
// created with clone(... | SIGCHLD). Either may cause these tests to
// erroneously wait on child processes/threads.
class WaitAnyChildTest : public ::testing::TestWithParam<
                             std::function<PosixErrorOr<pid_t>(int, int)>> {
 protected:
  PosixErrorOr<pid_t> WaitAny(int code) { return WaitAnyWithOptions(code, 0); }

  PosixErrorOr<pid_t> WaitAnyWithOptions(int code, int options) {
    return GetParam()(code, options);
  }
};

// Wait for any child to exit.
TEST_P(WaitAnyChildTest, Fork) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 0), SyscallSucceeds());

  EXPECT_THAT(WaitAny(0), IsPosixErrorOkAndHolds(child));
}

// Call wait4 for any process after the child has already exited.
TEST_P(WaitAnyChildTest, AfterExit) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 0), SyscallSucceeds());

  absl::SleepFor(absl::Seconds(5));

  EXPECT_THAT(WaitAny(0), IsPosixErrorOkAndHolds(child));
}

// Wait for multiple children to exit, waiting for either at a time.
TEST_P(WaitAnyChildTest, MultipleFork) {
  pid_t child1, child2;
  ASSERT_THAT(child1 = ForkAndExit(0, 0), SyscallSucceeds());
  ASSERT_THAT(child2 = ForkAndExit(0, 0), SyscallSucceeds());

  std::vector<pid_t> pids;
  pids.push_back(ASSERT_NO_ERRNO_AND_VALUE(WaitAny(0)));
  pids.push_back(ASSERT_NO_ERRNO_AND_VALUE(WaitAny(0)));
  EXPECT_THAT(pids, UnorderedElementsAre(child1, child2));
}

// Wait for any child to exit.
// A non-CLONE_THREAD child which sends SIGCHLD upon exit behaves much like
// a forked process.
TEST_P(WaitAnyChildTest, CloneSIGCHLD) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  ASSERT_THAT(child = CloneAndExit(0, stack, SIGCHLD), SyscallSucceeds());

  EXPECT_THAT(WaitAny(0), IsPosixErrorOkAndHolds(child));
}

// Wait for a child thread and process.
TEST_P(WaitAnyChildTest, ForkAndClone) {
  pid_t process;
  ASSERT_THAT(process = ForkAndExit(0, 0), SyscallSucceeds());

  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int thread;
  // Send SIGCHLD for normal wait semantics.
  ASSERT_THAT(thread = CloneAndExit(0, stack, SIGCHLD), SyscallSucceeds());

  std::vector<pid_t> pids;
  pids.push_back(ASSERT_NO_ERRNO_AND_VALUE(WaitAny(0)));
  pids.push_back(ASSERT_NO_ERRNO_AND_VALUE(WaitAny(0)));
  EXPECT_THAT(pids, UnorderedElementsAre(process, thread));
}

// Return immediately if no child has exited.
TEST_P(WaitAnyChildTest, WaitWNOHANG) {
  EXPECT_THAT(
      WaitAnyWithOptions(0, WNOHANG),
      PosixErrorIs(ECHILD, ::testing::AnyOf(::testing::StrEq("waitid"),
                                            ::testing::StrEq("wait4"))));
}

// Bad options passed
TEST_P(WaitAnyChildTest, BadOption) {
  EXPECT_THAT(
      WaitAnyWithOptions(0, 123456),
      PosixErrorIs(EINVAL, ::testing::AnyOf(::testing::StrEq("waitid"),
                                            ::testing::StrEq("wait4"))));
}

TEST_P(WaitAnyChildTest, WaitedChildRusage) {
  struct rusage before;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &before), SyscallSucceeds());

  pid_t child;
  constexpr absl::Duration kSpin = absl::Seconds(3);
  ASSERT_THAT(child = ForkSpinAndExit(0, absl::ToInt64Seconds(kSpin)),
              SyscallSucceeds());
  ASSERT_THAT(WaitAny(0), IsPosixErrorOkAndHolds(child));

  struct rusage after;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &after), SyscallSucceeds());

  EXPECT_GE(RusageCpuTime(after) - RusageCpuTime(before), kSpin);
}

TEST_P(WaitAnyChildTest, IgnoredChildRusage) {
  // "POSIX.1-2001 specifies that if the disposition of SIGCHLD is
  // set to SIG_IGN or the SA_NOCLDWAIT flag is set for SIGCHLD (see
  // sigaction(2)), then children that terminate do not become zombies and a
  // call to wait() or waitpid() will block until all children have terminated,
  // and then fail with errno set to ECHILD." - waitpid(2)
  //
  // "RUSAGE_CHILDREN: Return resource usage statistics for all children of the
  // calling process that have terminated *and been waited for*." -
  // getrusage(2), emphasis added

  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  const auto cleanup_sigact =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGCHLD, sa));

  struct rusage before;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &before), SyscallSucceeds());

  const absl::Duration start =
      absl::Nanoseconds(clock_gettime_nsecs(CLOCK_MONOTONIC));

  constexpr absl::Duration kSpin = absl::Seconds(3);

  // ForkAndSpin uses CLOCK_THREAD_CPUTIME_ID, which is lower resolution than,
  // and may diverge from, CLOCK_MONOTONIC, so we allow a small grace period but
  // still check that we blocked for a while.
  constexpr absl::Duration kSpinGrace = absl::Milliseconds(100);

  pid_t child;
  ASSERT_THAT(child = ForkSpinAndExit(0, absl::ToInt64Seconds(kSpin)),
              SyscallSucceeds());
  ASSERT_THAT(WaitAny(0), PosixErrorIs(ECHILD, ::testing::AnyOf(
                                                   ::testing::StrEq("waitid"),
                                                   ::testing::StrEq("wait4"))));
  const absl::Duration end =
      absl::Nanoseconds(clock_gettime_nsecs(CLOCK_MONOTONIC));
  EXPECT_GE(end - start, kSpin - kSpinGrace);

  struct rusage after;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &after), SyscallSucceeds());
  EXPECT_EQ(before.ru_utime.tv_sec, after.ru_utime.tv_sec);
  EXPECT_EQ(before.ru_utime.tv_usec, after.ru_utime.tv_usec);
  EXPECT_EQ(before.ru_stime.tv_sec, after.ru_stime.tv_sec);
  EXPECT_EQ(before.ru_stime.tv_usec, after.ru_stime.tv_usec);
}

INSTANTIATE_TEST_SUITE_P(
    Waiters, WaitAnyChildTest,
    ::testing::Values(
        [](int code, int options) -> PosixErrorOr<pid_t> {
          int status;
          auto const pid = Wait4(-1, &status, options, nullptr);
          MaybeSave();
          if (pid < 0) {
            return PosixError(errno, "wait4");
          }
          if (!WIFEXITED(status) || WEXITSTATUS(status) != code) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected wait status: got ", status,
                                     ", wanted ", code));
          }
          return static_cast<pid_t>(pid);
        },
        [](int code, int options) -> PosixErrorOr<pid_t> {
          siginfo_t si;
          auto const rv = Waitid(P_ALL, 0, &si, WEXITED | options);
          MaybeSave();
          if (rv < 0) {
            return PosixError(errno, "waitid");
          }
          if (si.si_signo != SIGCHLD) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected signo: got ", si.si_signo,
                                     ", wanted ", SIGCHLD));
          }
          if (si.si_status != code) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected status: got ", si.si_status,
                                     ", wanted ", code));
          }
          if (si.si_code != CLD_EXITED) {
            return PosixError(EINVAL,
                              absl::StrCat("unexpected code: got ", si.si_code,
                                           ", wanted ", CLD_EXITED));
          }
          auto const uid = getuid();
          if (si.si_uid != uid) {
            return PosixError(EINVAL,
                              absl::StrCat("unexpected uid: got ", si.si_uid,
                                           ", wanted ", uid));
          }
          return static_cast<pid_t>(si.si_pid);
        }));

// Fixture for tests parameterized by a function that takes the PID of a
// specific child to wait for, waits for it to exit, and checks that it exits
// with the given code.
class WaitSpecificChildTest
    : public ::testing::TestWithParam<std::function<PosixError(pid_t, int)>> {
 protected:
  PosixError WaitFor(pid_t pid, int code) { return GetParam()(pid, code); }
};

// Wait for specific child to exit.
TEST_P(WaitSpecificChildTest, Fork) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 0), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

// Non-zero exit codes are correctly propagated.
TEST_P(WaitSpecificChildTest, NormalExit) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(42, 0), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child, 42));
}

// Wait for multiple children to exit.
TEST_P(WaitSpecificChildTest, MultipleFork) {
  pid_t child1, child2;
  ASSERT_THAT(child1 = ForkAndExit(0, 0), SyscallSucceeds());
  ASSERT_THAT(child2 = ForkAndExit(0, 0), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child1, 0));
  EXPECT_NO_ERRNO(WaitFor(child2, 0));
}

// Wait for multiple children to exit, out of the order they were created.
TEST_P(WaitSpecificChildTest, MultipleForkOutOfOrder) {
  pid_t child1, child2;
  ASSERT_THAT(child1 = ForkAndExit(0, 0), SyscallSucceeds());
  ASSERT_THAT(child2 = ForkAndExit(0, 0), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child2, 0));
  EXPECT_NO_ERRNO(WaitFor(child1, 0));
}

// Wait for specific child to exit, entering wait4 before the exit occurs.
TEST_P(WaitSpecificChildTest, ForkSleep) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 5), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

// Wait should block until the child exits.
TEST_P(WaitSpecificChildTest, ForkBlock) {
  pid_t child;

  auto start = absl::Now();
  ASSERT_THAT(child = ForkAndExit(0, 5), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child, 0));

  EXPECT_GE(absl::Now() - start, absl::Seconds(5));
}

// Waiting after the child has already exited returns immediately.
TEST_P(WaitSpecificChildTest, AfterExit) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 0), SyscallSucceeds());

  absl::SleepFor(absl::Seconds(5));

  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

// Wait for specific child to exit.
// A non-CLONE_THREAD child which sends SIGCHLD upon exit behaves much like
// a forked process.
TEST_P(WaitSpecificChildTest, CloneSIGCHLD) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  ASSERT_THAT(child = CloneAndExit(0, stack, SIGCHLD), SyscallSucceeds());

  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

// Wait for specific child to exit.
// A non-CLONE_THREAD child which does not send SIGCHLD upon exit can be waited
// on, but returns ECHILD.
TEST_P(WaitSpecificChildTest, CloneNoSIGCHLD) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  ASSERT_THAT(child = CloneAndExit(0, stack, 0), SyscallSucceeds());

  EXPECT_THAT(
      WaitFor(child, 0),
      PosixErrorIs(ECHILD, ::testing::AnyOf(::testing::StrEq("waitid"),
                                            ::testing::StrEq("wait4"))));
}

// Waiting after the child has already exited returns immediately.
TEST_P(WaitSpecificChildTest, CloneAfterExit) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  // Send SIGCHLD for normal wait semantics.
  ASSERT_THAT(child = CloneAndExit(0, stack, SIGCHLD), SyscallSucceeds());

  absl::SleepFor(absl::Seconds(5));

  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

// A CLONE_THREAD child cannot be waited on.
TEST_P(WaitSpecificChildTest, CloneThread) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  ASSERT_THAT(child = CloneAndExit(15, stack, CLONE_THREAD), SyscallSucceeds());
  auto start = absl::Now();

  EXPECT_THAT(
      WaitFor(child, 0),
      PosixErrorIs(ECHILD, ::testing::AnyOf(::testing::StrEq("waitid"),
                                            ::testing::StrEq("wait4"))));

  // Ensure wait4 didn't block.
  EXPECT_LE(absl::Now() - start, absl::Seconds(10));

  // Since we can't wait on the child, we sleep to try to avoid freeing its
  // stack before it exits.
  absl::SleepFor(absl::Seconds(5));
}

// Return ECHILD for bad child.
TEST_P(WaitSpecificChildTest, BadChild) {
  EXPECT_THAT(
      WaitFor(42, 0),
      PosixErrorIs(ECHILD, ::testing::AnyOf(::testing::StrEq("waitid"),
                                            ::testing::StrEq("wait4"))));
}

// Wait for a child process that only exits after calling execve(2) from a
// non-leader thread.
TEST_P(WaitSpecificChildTest, AfterChildExecve) {
  ExecveArray const owned_child_argv = {"/bin/true"};
  char* const* const child_argv = owned_child_argv.get();

  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  pid_t const child = fork();
  if (child == 0) {
    // Give the parent some time to start waiting.
    SleepSafe(absl::Seconds(5));
    // Pass CLONE_VFORK to block the original thread in the child process until
    // the clone thread calls execve, annihilating them both. (This means that
    // if clone returns at all, something went wrong.)
    //
    // N.B. clone(2) is not officially async-signal-safe, but at minimum glibc's
    // x86_64 implementation is safe. See glibc
    // sysdeps/unix/sysv/linux/x86_64/clone.S.
    clone(
        +[](void* arg) {
          auto child_argv = static_cast<char* const*>(arg);
          execve(child_argv[0], child_argv, /* envp = */ nullptr);
          return errno;
        },
        reinterpret_cast<void*>(stack),
        CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD | CLONE_VM |
            CLONE_VFORK,
        const_cast<char**>(child_argv));
    _exit(errno);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  EXPECT_NO_ERRNO(WaitFor(child, 0));
}

INSTANTIATE_TEST_SUITE_P(
    Waiters, WaitSpecificChildTest,
    ::testing::Values(
        [](pid_t pid, int code) -> PosixError {
          int status;
          auto const rv = Wait4(pid, &status, 0, nullptr);
          MaybeSave();
          if (rv < 0) {
            return PosixError(errno, "wait4");
          } else if (rv != pid) {
            return PosixError(EINVAL, absl::StrCat("unexpected pid: got ", rv,
                                                   ", wanted ", pid));
          }
          if (!WIFEXITED(status) || WEXITSTATUS(status) != code) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected wait status: got ", status,
                                     ", wanted ", code));
          }
          return NoError();
        },
        [](pid_t pid, int code) -> PosixError {
          siginfo_t si;
          auto const rv = Waitid(P_PID, pid, &si, WEXITED);
          MaybeSave();
          if (rv < 0) {
            return PosixError(errno, "waitid");
          }
          if (si.si_pid != pid) {
            return PosixError(EINVAL,
                              absl::StrCat("unexpected pid: got ", si.si_pid,
                                           ", wanted ", pid));
          }
          if (si.si_signo != SIGCHLD) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected signo: got ", si.si_signo,
                                     ", wanted ", SIGCHLD));
          }
          if (si.si_status != code) {
            return PosixError(
                EINVAL, absl::StrCat("unexpected status: got ", si.si_status,
                                     ", wanted ", code));
          }
          if (si.si_code != CLD_EXITED) {
            return PosixError(EINVAL,
                              absl::StrCat("unexpected code: got ", si.si_code,
                                           ", wanted ", CLD_EXITED));
          }
          return NoError();
        }));

// WIFEXITED, WIFSIGNALED, WTERMSIG indicate signal exit.
TEST(WaitTest, SignalExit) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 10), SyscallSucceeds());

  EXPECT_THAT(kill(child, SIGKILL), SyscallSucceeds());

  int status;
  EXPECT_THAT(Wait4(child, &status, 0, nullptr),
              SyscallSucceedsWithValue(child));

  EXPECT_FALSE(WIFEXITED(status));
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGKILL, WTERMSIG(status));
}

// A child that does not send a SIGCHLD on exit may be waited on with
// the __WCLONE flag.
TEST(WaitTest, CloneWCLONE) {
  uintptr_t stack;
  ASSERT_THAT(stack = AllocStack(), SyscallSucceeds());
  auto free =
      Cleanup([stack] { ASSERT_THAT(FreeStack(stack), SyscallSucceeds()); });

  int child;
  ASSERT_THAT(child = CloneAndExit(0, stack, 0), SyscallSucceeds());

  EXPECT_THAT(Wait4(child, nullptr, __WCLONE, nullptr),
              SyscallSucceedsWithValue(child));
}

// waitid requires at least one option.
TEST(WaitTest, WaitidOptions) {
  EXPECT_THAT(Waitid(P_ALL, 0, nullptr, 0), SyscallFailsWithErrno(EINVAL));
}

// waitid does not wait for a child to exit if not passed WEXITED.
TEST(WaitTest, WaitidNoWEXITED) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(0, 0), SyscallSucceeds());
  EXPECT_THAT(Waitid(P_ALL, 0, nullptr, WSTOPPED),
              SyscallFailsWithErrno(ECHILD));
  EXPECT_THAT(Waitid(P_ALL, 0, nullptr, WEXITED), SyscallSucceeds());
}

// WNOWAIT allows the same wait result to be returned again.
TEST(WaitTest, WaitidWNOWAIT) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(42, 0), SyscallSucceeds());

  siginfo_t info;
  ASSERT_THAT(Waitid(P_PID, child, &info, WEXITED | WNOWAIT),
              SyscallSucceeds());
  EXPECT_EQ(child, info.si_pid);
  EXPECT_EQ(SIGCHLD, info.si_signo);
  EXPECT_EQ(CLD_EXITED, info.si_code);
  EXPECT_EQ(42, info.si_status);

  ASSERT_THAT(Waitid(P_PID, child, &info, WEXITED), SyscallSucceeds());
  EXPECT_EQ(child, info.si_pid);
  EXPECT_EQ(SIGCHLD, info.si_signo);
  EXPECT_EQ(CLD_EXITED, info.si_code);
  EXPECT_EQ(42, info.si_status);

  EXPECT_THAT(Waitid(P_PID, child, &info, WEXITED),
              SyscallFailsWithErrno(ECHILD));
}

// waitpid(pid, status, options) is equivalent to
// wait4(pid, status, options, nullptr).
// This is a dedicated syscall on i386, glibc maps it to wait4 on amd64.
TEST(WaitTest, WaitPid) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(42, 0), SyscallSucceeds());

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));

  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(42, WEXITSTATUS(status));
}

// Test that signaling a zombie succeeds. This is a signals test that is in this
// file for some reason.
TEST(WaitTest, KillZombie) {
  pid_t child;
  ASSERT_THAT(child = ForkAndExit(42, 0), SyscallSucceeds());

  // Sleep for three seconds to ensure the child has exited.
  absl::SleepFor(absl::Seconds(3));

  // The child is now a zombie. Check that killing it returns 0.
  EXPECT_THAT(kill(child, SIGTERM), SyscallSucceeds());
  EXPECT_THAT(kill(child, 0), SyscallSucceeds());

  EXPECT_THAT(Wait4(child, nullptr, 0, nullptr),
              SyscallSucceedsWithValue(child));
}

TEST(WaitTest, Wait4Rusage) {
  pid_t child;
  constexpr absl::Duration kSpin = absl::Seconds(3);
  ASSERT_THAT(child = ForkSpinAndExit(21, absl::ToInt64Seconds(kSpin)),
              SyscallSucceeds());

  int status;
  struct rusage rusage = {};
  ASSERT_THAT(Wait4(child, &status, 0, &rusage),
              SyscallSucceedsWithValue(child));

  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(21, WEXITSTATUS(status));

  EXPECT_GE(RusageCpuTime(rusage), kSpin);
}

TEST(WaitTest, WaitidRusage) {
  pid_t child;
  constexpr absl::Duration kSpin = absl::Seconds(3);
  ASSERT_THAT(child = ForkSpinAndExit(27, absl::ToInt64Seconds(kSpin)),
              SyscallSucceeds());

  siginfo_t si = {};
  struct rusage rusage = {};

  // From waitid(2):
  // The  raw  waitid()  system  call  takes a fifth argument, of type
  // struct rusage *. If this argument is non-NULL, then  it  is  used
  // to return resource  usage  information  about  the  child,  in the
  // same manner as wait4(2).
  EXPECT_THAT(
      RetryEINTR(syscall)(SYS_waitid, P_PID, child, &si, WEXITED, &rusage),
      SyscallSucceeds());
  EXPECT_EQ(si.si_signo, SIGCHLD);
  EXPECT_EQ(si.si_code, CLD_EXITED);
  EXPECT_EQ(si.si_status, 27);
  EXPECT_EQ(si.si_pid, child);

  EXPECT_GE(RusageCpuTime(rusage), kSpin);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
