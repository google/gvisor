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

constexpr uint64_t kA0 = 0xdeadbeeffacefeed;

void sigvtalrm(int sig, siginfo_t* siginfo, void* _uc) {
  ucontext_t* uc = reinterpret_cast<ucontext_t*>(_uc);

  // Verify that:
  // - orig_a0 value in mcontext_t matches kA0.
  if (uc->uc_mcontext.__gregs[32] == getpid()) {
    // Modify the value orig_a0 in the ucontext. This is the value seen by the
    // application after the signal handler returns.
    uc->uc_mcontext.__gregs[10] = ~kA0;
  }
}

uint64_t testA0(uint64_t sysno, uint64_t tgid, uint64_t tid,
           uint64_t signo) {
  register uint64_t a7 __asm__("a7") = sysno;
  register uint64_t a0 __asm__("a0") = tgid;
  register uint64_t a1 __asm__("a1") = tid;
  register uint64_t a2 __asm__("a2") = signo;

  // Initialize a6, send SIGVTALRM to itself and read a6.
  __asm__(
      "ecall \n"
      : "=r"(a0)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a7));
  return a0;
}

// CheckA0 checks that the ptrace platform handles the a0 register properly.
TEST(SigreturnTest, CheckA0) {
  // Setup signal handler for SIGVTALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_sigaction = sigvtalrm;
  sa.sa_flags = SA_SIGINFO;
  auto const action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGVTALRM, sa));

  auto const mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGVTALRM));

  uint64_t ret = testA0(__NR_tgkill, getpid(), syscall(__NR_gettid), SIGVTALRM);

  EXPECT_EQ(ret, ~kA0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
