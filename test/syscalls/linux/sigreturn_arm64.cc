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

#include <linux/unistd.h>
#include <signal.h>
#include <sys/syscall.h>
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

  testX7(&x7, __NR_tgkill, getpid(), syscall(__NR_gettid), SIGVTALRM);

  // The following check verifies that %x7 was not clobbered
  // when returning from the signal handler (via sigreturn(2)).
  EXPECT_EQ(x7, ~kOrigX7);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
