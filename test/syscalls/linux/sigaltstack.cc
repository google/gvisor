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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <functional>
#include <vector>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<Cleanup> ScopedSigaltstack(stack_t const& stack) {
  stack_t old_stack;
  int rc = sigaltstack(&stack, &old_stack);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "sigaltstack failed");
  }
  return Cleanup([old_stack] {
    EXPECT_THAT(sigaltstack(&old_stack, nullptr), SyscallSucceeds());
  });
}

volatile bool got_signal = false;
volatile int sigaltstack_errno = 0;
volatile int ss_flags = 0;

void sigaltstack_handler(int sig, siginfo_t* siginfo, void* arg) {
  got_signal = true;

  stack_t stack;
  int ret = sigaltstack(nullptr, &stack);
  MaybeSave();
  if (ret < 0) {
    sigaltstack_errno = errno;
    return;
  }
  ss_flags = stack.ss_flags;
}

TEST(SigaltstackTest, Success) {
  std::vector<char> stack_mem(SIGSTKSZ);
  stack_t stack = {};
  stack.ss_sp = stack_mem.data();
  stack.ss_size = stack_mem.size();
  auto const cleanup_sigstack =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaltstack(stack));

  struct sigaction sa = {};
  sa.sa_sigaction = sigaltstack_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  auto const cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  // Send signal to this thread, as sigaltstack is per-thread.
  EXPECT_THAT(tgkill(getpid(), gettid(), SIGUSR1), SyscallSucceeds());

  EXPECT_TRUE(got_signal);
  EXPECT_EQ(sigaltstack_errno, 0);
  EXPECT_NE(0, ss_flags & SS_ONSTACK);
}

TEST(SigaltstackTest, ResetByExecve) {
  std::vector<char> stack_mem(SIGSTKSZ);
  stack_t stack = {};
  stack.ss_sp = stack_mem.data();
  stack.ss_size = stack_mem.size();
  auto const cleanup_sigstack =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaltstack(stack));

  std::string full_path = RunfilePath("test/syscalls/linux/sigaltstack_check");

  pid_t child_pid = -1;
  int execve_errno = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(full_path, {"sigaltstack_check"}, {}, nullptr, &child_pid,
                  &execve_errno));

  ASSERT_GT(child_pid, 0);
  ASSERT_EQ(execve_errno, 0);

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0);
}

volatile bool badhandler_on_sigaltstack = true;      // Set by the handler.
char* volatile badhandler_low_water_mark = nullptr;  // Set by the handler.
volatile uint8_t badhandler_recursive_faults = 0;    // Consumed by the handler.

void badhandler(int sig, siginfo_t* siginfo, void* arg) {
  char stack_var = 0;
  char* current_ss = &stack_var;

  stack_t stack;
  int ret = sigaltstack(nullptr, &stack);
  if (ret < 0 || (stack.ss_flags & SS_ONSTACK) != SS_ONSTACK) {
    // We should always be marked as being on the stack. Don't allow this to hit
    // the bottom if this is ever not true (the main test will fail as a
    // result, but we still need to unwind the recursive faults).
    badhandler_on_sigaltstack = false;
  }
  if (current_ss < badhandler_low_water_mark) {
    // Record the low point for the signal stack. We never expected this to be
    // before stack bottom, but this is asserted in the actual test.
    badhandler_low_water_mark = current_ss;
  }
  if (badhandler_recursive_faults > 0) {
    badhandler_recursive_faults--;
    Fault();
  }
  FixupFault(reinterpret_cast<ucontext_t*>(arg));
}

TEST(SigaltstackTest, WalksOffBottom) {
  // This test marks the upper half of the stack_mem array as the signal stack.
  // It asserts that when a fault occurs in the handler (already on the signal
  // stack), we eventually continue to fault our way off the stack. We should
  // not revert to the top of the signal stack when we fall off the bottom and
  // the signal stack should remain "in use". When we fall off the signal stack,
  // we should have an unconditional signal delivered and not start using the
  // first part of the stack_mem array.
  std::vector<char> stack_mem(SIGSTKSZ * 2);
  stack_t stack = {};
  stack.ss_sp = stack_mem.data() + SIGSTKSZ;  // See above: upper half.
  stack.ss_size = SIGSTKSZ;                   // Only one half the array.
  auto const cleanup_sigstack =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaltstack(stack));

  // Setup the handler: this must be for SIGSEGV, and it must allow proper
  // nesting (no signal mask, no defer) so that we can trigger multiple times.
  //
  // When we walk off the bottom of the signal stack and force signal delivery
  // of a SIGSEGV, the handler will revert to the default behavior (kill).
  struct sigaction sa = {};
  sa.sa_sigaction = badhandler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  auto const cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

  // Trigger a single fault.
  badhandler_low_water_mark =
      static_cast<char*>(stack.ss_sp) + SIGSTKSZ;  // Expected top.
  badhandler_recursive_faults = 0;                 // Disable refault.
  Fault();
  EXPECT_TRUE(badhandler_on_sigaltstack);
  EXPECT_THAT(sigaltstack(nullptr, &stack), SyscallSucceeds());
  EXPECT_EQ(stack.ss_flags & SS_ONSTACK, 0);
  EXPECT_LT(badhandler_low_water_mark,
            reinterpret_cast<char*>(stack.ss_sp) + 2 * SIGSTKSZ);
  EXPECT_GT(badhandler_low_water_mark, reinterpret_cast<char*>(stack.ss_sp));

  // Trigger two faults.
  char* prev_low_water_mark = badhandler_low_water_mark;  // Previous top.
  badhandler_recursive_faults = 1;                        // One refault.
  Fault();
  ASSERT_TRUE(badhandler_on_sigaltstack);
  EXPECT_THAT(sigaltstack(nullptr, &stack), SyscallSucceeds());
  EXPECT_EQ(stack.ss_flags & SS_ONSTACK, 0);
  EXPECT_LT(badhandler_low_water_mark, prev_low_water_mark);
  EXPECT_GT(badhandler_low_water_mark, reinterpret_cast<char*>(stack.ss_sp));

  // Calculate the stack growth for a fault, and set the recursive faults to
  // ensure that the signal handler stack required exceeds our marked stack area
  // by a minimal amount. It should remain in the valid stack_mem area so that
  // we can test the signal is forced merely by going out of the signal stack
  // bounds, not by a genuine fault.
  uintptr_t frame_size =
      static_cast<uintptr_t>(prev_low_water_mark - badhandler_low_water_mark);
  badhandler_recursive_faults = (SIGSTKSZ + frame_size) / frame_size;
  EXPECT_EXIT(Fault(), ::testing::KilledBySignal(SIGSEGV), "");
}

volatile int setonstack_retval = 0;  // Set by the handler.
volatile int setonstack_errno = 0;   // Set by the handler.

void setonstack(int sig, siginfo_t* siginfo, void* arg) {
  char stack_mem[SIGSTKSZ];
  stack_t stack = {};
  stack.ss_sp = &stack_mem[0];
  stack.ss_size = SIGSTKSZ;
  setonstack_retval = sigaltstack(&stack, nullptr);
  setonstack_errno = errno;
  FixupFault(reinterpret_cast<ucontext_t*>(arg));
}

TEST(SigaltstackTest, SetWhileOnStack) {
  // Reserve twice as much stack here, since the handler will allocate a vector
  // of size SIGTKSZ and attempt to set the sigaltstack to that value.
  std::vector<char> stack_mem(2 * SIGSTKSZ);
  stack_t stack = {};
  stack.ss_sp = stack_mem.data();
  stack.ss_size = stack_mem.size();
  auto const cleanup_sigstack =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaltstack(stack));

  // See above.
  struct sigaction sa = {};
  sa.sa_sigaction = setonstack;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  auto const cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

  // Trigger a fault.
  Fault();

  // The set should have failed.
  EXPECT_EQ(setonstack_retval, -1);
  EXPECT_EQ(setonstack_errno, EPERM);
}

TEST(SigaltstackTest, SetCurrentStack) {
  // This is executed as an exit test because once the signal stack is set to
  // the local stack, there's no good way to unwind. We don't want to taint the
  // test of any other tests that might run within this process.
  EXPECT_EXIT(
      {
        char stack_value = 0;
        stack_t stack = {};
        stack.ss_sp = &stack_value - kPageSize;  // Lower than current level.
        stack.ss_size = 2 * kPageSize;  // => &stack_value +/- kPageSize.
        TEST_CHECK(sigaltstack(&stack, nullptr) == 0);
        TEST_CHECK(sigaltstack(nullptr, &stack) == 0);
        TEST_CHECK((stack.ss_flags & SS_ONSTACK) != 0);

        // Should not be able to change the stack (even no-op).
        TEST_CHECK(sigaltstack(&stack, nullptr) == -1 && errno == EPERM);

        // Should not be able to disable the stack.
        stack.ss_flags = SS_DISABLE;
        TEST_CHECK(sigaltstack(&stack, nullptr) == -1 && errno == EPERM);
        exit(0);
      },
      ::testing::ExitedWithCode(0), "");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
