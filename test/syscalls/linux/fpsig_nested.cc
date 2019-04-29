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

// This program verifies that application floating point state is restored
// correctly after a signal handler returns. It also verifies that this works
// with nested signals.
#include <sys/time.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#define GET_XMM(__var, __xmm) \
  asm volatile("movq %%" #__xmm ", %0" : "=r"(__var))
#define SET_XMM(__var, __xmm) asm volatile("movq %0, %%" #__xmm : : "r"(__var))

int pid;
int tid;

volatile uint64_t entryxmm[2] = {~0UL, ~0UL};
volatile uint64_t exitxmm[2];

void sigusr2(int s, siginfo_t* siginfo, void* _uc) {
  uint64_t val = SIGUSR2;

  // Record the value of %xmm0 on entry and then clobber it.
  GET_XMM(entryxmm[1], xmm0);
  SET_XMM(val, xmm0);
  GET_XMM(exitxmm[1], xmm0);
}

void sigusr1(int s, siginfo_t* siginfo, void* _uc) {
  uint64_t val = SIGUSR1;

  // Record the value of %xmm0 on entry and then clobber it.
  GET_XMM(entryxmm[0], xmm0);
  SET_XMM(val, xmm0);

  // Send a SIGUSR2 to ourself. The signal mask is configured such that
  // the SIGUSR2 handler will run before this handler returns.
  asm volatile(
      "movl %[killnr], %%eax;"
      "movl %[pid], %%edi;"
      "movl %[tid], %%esi;"
      "movl %[sig], %%edx;"
      "syscall;"
      :
      : [killnr] "i"(__NR_tgkill), [pid] "rm"(pid), [tid] "rm"(tid),
        [sig] "i"(SIGUSR2)
      : "rax", "rdi", "rsi", "rdx",
        // Clobbered by syscall.
        "rcx", "r11");

  // Record value of %xmm0 again to verify that the nested signal handler
  // does not clobber it.
  GET_XMM(exitxmm[0], xmm0);
}

TEST(FPSigTest, NestedSignals) {
  pid = getpid();
  tid = gettid();

  struct sigaction sa = {};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = sigusr1;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

  sa.sa_sigaction = sigusr2;
  ASSERT_THAT(sigaction(SIGUSR2, &sa, nullptr), SyscallSucceeds());

  // The amd64 ABI specifies that the XMM register set is caller-saved. This
  // implies that if there is any function call between SET_XMM and GET_XMM the
  // compiler might save/restore xmm0 implicitly. This defeats the entire
  // purpose of the test which is to verify that fpstate is restored by
  // sigreturn(2).
  //
  // This is the reason why 'tgkill(getpid(), gettid(), SIGUSR1)' is implemented
  // in inline assembly below.
  //
  // If the OS is broken and registers are clobbered by the signal, using tgkill
  // to signal the current thread ensures that this is the clobbered thread.

  uint64_t expected = 0xdeadbeeffacefeed;
  SET_XMM(expected, xmm0);

  asm volatile(
      "movl %[killnr], %%eax;"
      "movl %[pid], %%edi;"
      "movl %[tid], %%esi;"
      "movl %[sig], %%edx;"
      "syscall;"
      :
      : [killnr] "i"(__NR_tgkill), [pid] "rm"(pid), [tid] "rm"(tid),
        [sig] "i"(SIGUSR1)
      : "rax", "rdi", "rsi", "rdx",
        // Clobbered by syscall.
        "rcx", "r11");

  uint64_t got;
  GET_XMM(got, xmm0);

  //
  // The checks below verifies the following:
  // - signal handlers must called with a clean fpu state.
  // - sigreturn(2) must restore fpstate of the interrupted context.
  //
  EXPECT_EQ(expected, got);
  EXPECT_EQ(entryxmm[0], 0);
  EXPECT_EQ(entryxmm[1], 0);
  EXPECT_EQ(exitxmm[0], SIGUSR1);
  EXPECT_EQ(exitxmm[1], SIGUSR2);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
