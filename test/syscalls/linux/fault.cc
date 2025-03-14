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

#define _GNU_SOURCE 1
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

__attribute__((noinline)) void Fault(void) {
  volatile int* foo = nullptr;
  *foo = 0;
}

int GetPcFromUcontext(ucontext_t* uc, uintptr_t* pc) {
#if defined(__x86_64__)
  *pc = uc->uc_mcontext.gregs[REG_RIP];
  return 1;
#elif defined(__i386__)
  *pc = uc->uc_mcontext.gregs[REG_EIP];
  return 1;
#elif defined(__aarch64__)
  *pc = uc->uc_mcontext.pc;
  return 1;
#else
  return 0;
#endif
}

void sigact_handler(int sig, siginfo_t* siginfo, void* context) {
  uintptr_t pc;
  if (GetPcFromUcontext(reinterpret_cast<ucontext_t*>(context), &pc)) {
    /* Expect Fault() to be at most 64 bytes in size. */
    uintptr_t fault_addr = reinterpret_cast<uintptr_t>(&Fault);
    EXPECT_GE(pc, fault_addr);
    EXPECT_LT(pc, fault_addr + 64);

    // The following file is used to detect tests that exit prematurely. Since
    // we need to call exit() here, delete the file by hand.
    const char* exit_file = getenv("TEST_PREMATURE_EXIT_FILE");
    if (exit_file != nullptr) {
      ASSERT_THAT(unlink(exit_file), SyscallSucceeds());
    }
    exit(0);
  }
}

#if defined(__aarch64__)
#define APPLY_ADDRESS_TAG(addr) ((void*)((uint64_t)addr | (1ULL << 57)))

TEST(TaggedAddressesTest, MemoryFault) {
  void* addr = mmap(0, kPageSize, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  ASSERT_NE(addr, MAP_FAILED);
  addr = APPLY_ADDRESS_TAG(addr);
  ((uint64_t*)addr)[0] =
      5;  // trigger a memory fault that is handled in the Sentry.
  EXPECT_THAT(munmap(addr, kPageSize), SyscallSucceeds());
}
#endif

TEST(FaultTest, InRange) {
  // Reset the signal handler to do nothing so that it doesn't freak out
  // the test runner when we fire an alarm.
  struct sigaction sa = {};
  sa.sa_sigaction = sigact_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  ASSERT_THAT(sigaction(SIGSEGV, &sa, nullptr), SyscallSucceeds());

  Fault();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
