// Copyright 2021 The gVisor Authors.
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

#include <execinfo.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr uint64_t kOrigX7 = 0xdeadbeeffacefeed;

void sigvtalrm(int sig, siginfo_t* siginfo, void* _uc) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(_uc);

  // Verify that:
  // - x7 value in mcontext_t matches kOrigX7.
  if (uc->uc_mcontext.regs[7] == kOrigX7) {
    // Modify the value x7 in the ucontext. This is the value seen by the
    // application after the signal handler returns.
    uc->uc_mcontext.regs[7] = ~kOrigX7;
  }
}

int testX7(uint64_t* val, uint64_t sysno, uint64_t tgid, uint64_t tid,
           uint64_t signo) {
  register uint64_t* x9 __asm__("x9") = val;
  register uint64_t x8 __asm__("x8") = sysno;
  register uint64_t x0 __asm__("x0") = tgid;
  register uint64_t x1 __asm__("x1") = tid;
  register uint64_t x2 __asm__("x2") = signo;

  // Initialize x7, send SIGVTALRM to itself and read x7.
  __asm__(
      "ldr x7, [x9, 0]\n"
      "svc 0\n"
      "str x7, [x9, 0]\n"
      : "=r"(x0)
      : "r"(x0), "r"(x1), "r"(x2), "r"(x9), "r"(x8)
      : "x7");
  return x0;
}

// On ARM64, when ptrace stops on a system call, it uses the x7 register to
// indicate whether the stop has been signalled from syscall entry or syscall
// exit. This means that we can't get a value of this register and we can't
// change it. More details are in the comment for tracehook_report_syscall in
// arch/arm64/kernel/ptrace.c.
//
// CheckR7 checks that the ptrace platform handles the x7 register properly.
TEST(SigreturnTest, CheckX7) {
  // Setup signal handler for SIGVTALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_sigaction = sigvtalrm;
  sa.sa_flags = SA_SIGINFO;
  auto const action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGVTALRM, sa));

  auto const mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGVTALRM));

  uint64_t x7 = kOrigX7;

  int ret = testX7(&x7, __NR_tgkill, getpid(), syscall(__NR_gettid), SIGVTALRM);

  EXPECT_EQ(ret, 0);
  // The following check verifies that %x7 was not clobbered
  // when returning from the signal handler (via sigreturn(2)).
  EXPECT_EQ(x7, ~kOrigX7);
}

// Values recorded by sigframeHandler.
uintptr_t handler_cfa;
uintptr_t handler_info;
uintptr_t handler_uc;
uint64_t handler_pc;
int backtrace_size;
bool backtrace_has_pc;

void sigframeHandler(int sig, siginfo_t* siginfo, void* _uc) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(_uc);
  // The CFA of the signal handler is the stack pointer at handler entry.
  handler_cfa = reinterpret_cast<uintptr_t>(__builtin_dwarf_cfa());
  handler_info = reinterpret_cast<uintptr_t>(siginfo);
  handler_uc = reinterpret_cast<uintptr_t>(uc);
  handler_pc = uc->uc_mcontext.pc;

  // Unwind through the signal frame. The unwinder finds the interrupted
  // context at a fixed offset from the stack pointer.
  void* pcs[32];
  backtrace_size = backtrace(pcs, 32);
  backtrace_has_pc = false;
  for (int i = 0; i < backtrace_size; i++) {
    if (reinterpret_cast<uint64_t>(pcs[i]) == handler_pc) {
      backtrace_has_pc = true;
    }
  }
}

// Sends SIGUSR1 to the current thread and checks that the signal frame has
// siginfo at the stack pointer, followed by the ucontext.
void CheckSignalFrameLayout(int sa_flags) {
  // backtrace() can allocate memory on its first call. Call it before the
  // signal handler does.
  void* pcs[1];
  backtrace(pcs, 1);

  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_sigaction = sigframeHandler;
  sa.sa_flags = SA_SIGINFO | sa_flags;
  auto const action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));
  auto const mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGUSR1));

  handler_cfa = 0;
  ASSERT_THAT(syscall(__NR_tgkill, getpid(), syscall(__NR_gettid), SIGUSR1),
              SyscallSucceeds());
  ASSERT_NE(handler_cfa, 0u);

  EXPECT_EQ(handler_cfa % 16, 0u);
  EXPECT_EQ(handler_info, handler_cfa);
  EXPECT_EQ(handler_uc, handler_cfa + sizeof(siginfo_t));
  EXPECT_TRUE(backtrace_has_pc)
      << "backtrace() returned " << backtrace_size
      << " frames, none at the interrupted pc " << handler_pc;
}

TEST(SigreturnTest, SignalFrameLayout) { CheckSignalFrameLayout(0); }

TEST(SigreturnTest, SignalFrameLayoutOnAltStack) {
  std::vector<char> altstack(64 * 1024);
  stack_t ss = {};
  ss.ss_sp = altstack.data();
  ss.ss_size = altstack.size();
  stack_t old_ss;
  ASSERT_THAT(sigaltstack(&ss, &old_ss), SyscallSucceeds());

  CheckSignalFrameLayout(SA_ONSTACK);
  EXPECT_GE(handler_cfa, reinterpret_cast<uintptr_t>(altstack.data()));
  EXPECT_LT(handler_cfa,
            reinterpret_cast<uintptr_t>(altstack.data()) + altstack.size());

  ASSERT_THAT(sigaltstack(&old_ss, nullptr), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
