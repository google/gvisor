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
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr uint64_t kOrigRcx = 0xdeadbeeffacefeed;
constexpr uint64_t kOrigR11 = 0xfacefeedbaad1dea;

volatile int gotvtalrm, ready;

void sigvtalrm(int sig, siginfo_t* siginfo, void* _uc) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(_uc);

  // Verify that:
  // - test is in the busy-wait loop waiting for signal.
  // - %rcx and %r11 values in mcontext_t match kOrigRcx and kOrigR11.
  if (ready &&
      static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_RCX]) == kOrigRcx &&
      static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_R11]) == kOrigR11) {
    // Modify the values %rcx and %r11 in the ucontext. These are the
    // values seen by the application after the signal handler returns.
    uc->uc_mcontext.gregs[REG_RCX] = ~kOrigRcx;
    uc->uc_mcontext.gregs[REG_R11] = ~kOrigR11;
    gotvtalrm = 1;
  }
}

TEST(SigIretTest, CheckRcxR11) {
  // Setup signal handler for SIGVTALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_sigaction = sigvtalrm;
  sa.sa_flags = SA_SIGINFO;
  auto const action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGVTALRM, sa));

  auto const mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGVTALRM));

  // Setup itimer to fire after 500 msecs.
  struct itimerval itimer = {};
  itimer.it_value.tv_usec = 500 * 1000;  // 500 msecs.
  auto const timer_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_VIRTUAL, itimer));

  // Initialize %rcx and %r11 and spin until the signal handler returns.
  uint64_t rcx = kOrigRcx;
  uint64_t r11 = kOrigR11;
  asm volatile(
      "movq %[rcx], %%rcx;"                      // %rcx = rcx
      "movq %[r11], %%r11;"                      // %r11 = r11
      "movl $1, %[ready];"                       // ready = 1
      "1: pause; cmpl $0, %[gotvtalrm]; je 1b;"  // while (!gotvtalrm);
      "movq %%rcx, %[rcx];"                      // rcx = %rcx
      "movq %%r11, %[r11];"                      // r11 = %r11
      : [ready] "=m"(ready), [rcx] "+m"(rcx), [r11] "+m"(r11)
      : [gotvtalrm] "m"(gotvtalrm)
      : "cc", "memory", "rcx", "r11");

  // If sigreturn(2) returns via 'sysret' then %rcx and %r11 will be
  // clobbered and set to 'ptregs->rip' and 'ptregs->rflags' respectively.
  //
  // The following check verifies that %rcx and %r11 were not clobbered
  // when returning from the signal handler (via sigreturn(2)).
  EXPECT_EQ(rcx, ~kOrigRcx);
  EXPECT_EQ(r11, ~kOrigR11);
}

constexpr uint64_t kNonCanonicalRip = 0xCCCC000000000000;

// Test that a non-canonical signal handler faults as expected.
TEST(SigIretTest, BadHandler) {
  struct sigaction sa = {};
  sa.sa_sigaction =
      reinterpret_cast<void (*)(int, siginfo_t*, void*)>(kNonCanonicalRip);
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  pid_t pid = fork();
  if (pid == 0) {
    // Child, wait for signal.
    while (1) {
      pause();
    }
  }
  ASSERT_THAT(pid, SyscallSucceeds());

  EXPECT_THAT(kill(pid, SIGUSR1), SyscallSucceeds());

  int status;
  EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
      << "status = " << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // SigIretTest.CheckRcxR11 depends on delivering SIGVTALRM to the main thread.
  // Block SIGVTALRM so that any other threads created by TestInit will also
  // have SIGVTALRM blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGVTALRM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
