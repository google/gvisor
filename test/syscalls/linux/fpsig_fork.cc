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

// This test verifies that fork(2) in a signal handler will correctly
// restore floating point state after the signal handler returns in both
// the child and parent.
#include <sys/time.h>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#define GET_XMM(__var, __xmm) \
  asm volatile("movq %%" #__xmm ", %0" : "=r"(__var))
#define SET_XMM(__var, __xmm) asm volatile("movq %0, %%" #__xmm : : "r"(__var))

int parent, child;

void sigusr1(int s, siginfo_t* siginfo, void* _uc) {
  // Fork and clobber %xmm0. The fpstate should be restored by sigreturn(2)
  // in both parent and child.
  child = fork();
  TEST_CHECK_MSG(child >= 0, "fork failed");

  uint64_t val = SIGUSR1;
  SET_XMM(val, xmm0);
}

TEST(FPSigTest, Fork) {
  parent = getpid();
  pid_t parent_tid = gettid();

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
  // If the OS is broken and registers are clobbered by the child, using tgkill
  // to signal the current thread increases the likelihood that this thread will
  // be the one clobbered.

  uint64_t expected = 0xdeadbeeffacefeed;
  SET_XMM(expected, xmm0);

  asm volatile(
      "movl %[killnr], %%eax;"
      "movl %[parent], %%edi;"
      "movl %[tid], %%esi;"
      "movl %[sig], %%edx;"
      "syscall;"
      :
      : [killnr] "i"(__NR_tgkill), [parent] "rm"(parent),
        [tid] "rm"(parent_tid), [sig] "i"(SIGUSR1)
      : "rax", "rdi", "rsi", "rdx",
        // Clobbered by syscall.
        "rcx", "r11");

  uint64_t got;
  GET_XMM(got, xmm0);

  if (getpid() == parent) {  // Parent.
    int status;
    ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  // TEST_CHECK_MSG since this may run in the child.
  TEST_CHECK_MSG(expected == got, "Bad xmm0 value");

  if (getpid() != parent) {  // Child.
    _exit(0);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
