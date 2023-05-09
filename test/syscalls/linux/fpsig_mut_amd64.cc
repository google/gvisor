// Copyright 2022 The gVisor Authors.
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

// This program verifies that application floating point state is visible in
// signal frames, and that changes to said state is visible after the signal
// handler returns.
#include <sys/time.h>
#include <sys/ucontext.h>

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

volatile uint64_t handlerxmm = ~0UL;
volatile uint64_t framexmm = ~0UL;

constexpr uint64_t kOldFPRegValue = 0xdeadbeeffacefeed;
constexpr uint64_t kNewFPRegValue = 0xfacefeedbaad1dea;

void sigusr1(int s, siginfo_t* siginfo, void* _uc) {
  uint64_t val = SIGUSR1;

  // Record the value of %xmm0 on entry and then clobber it.
  GET_XMM(handlerxmm, xmm0);
  SET_XMM(val, xmm0);

  // Record the value of %xmm0 stored in _uc and then replace it.
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(_uc);
  auto* uc_xmm0 = &uc->uc_mcontext.fpregs->_xmm[0];
  framexmm = (static_cast<uint64_t>(uc_xmm0->element[1]) << 32) |
             static_cast<uint64_t>(uc_xmm0->element[0]);
  uc_xmm0->element[1] = static_cast<uint32_t>(kNewFPRegValue >> 32);
  uc_xmm0->element[0] = static_cast<uint32_t>(kNewFPRegValue);
}

TEST(FPSigTest, StateInFrame) {
  pid = getpid();
  tid = gettid();

  struct sigaction sa = {};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = sigusr1;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

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
  SET_XMM(kOldFPRegValue, xmm0);

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
  EXPECT_EQ(handlerxmm, 0);
  EXPECT_EQ(framexmm, kOldFPRegValue);
  EXPECT_EQ(got, kNewFPRegValue);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
