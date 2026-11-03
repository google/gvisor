// Copyright 2026 The gVisor Authors.
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
#include <linux/audit.h>
#include <linux/prctl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON 1
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif

#ifndef PR_SYS_DISPATCH_INCLUSIVE_ON
#define PR_SYS_DISPATCH_INCLUSIVE_ON 2
#endif

#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

// RawSyscall makes syscall nr from a single known instruction, whose return
// address is RawSyscallReturn.
extern "C" long RawSyscall(long nr);
extern "C" char RawSyscallReturn[];
asm(".text\n"
    ".globl RawSyscall\n"
    "RawSyscall:\n"
    "  mov %rdi, %rax\n"
    "  syscall\n"
    ".globl RawSyscallReturn\n"
    "RawSyscallReturn:\n"
    "  ret\n");

namespace gvisor {
namespace testing {

namespace {

volatile char selector = SYSCALL_DISPATCH_FILTER_ALLOW;

int SetDispatch(unsigned long mode, unsigned long offset, unsigned long len,
                const volatile char* sel) {
  return prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, offset, len, sel);
}

// Fields of the last SIGSYS, recorded by RecordSigsys.
volatile int sigsys_count;
siginfo_t sigsys_info;
greg_t sigsys_rax;

void RecordSigsys(int, siginfo_t* info, void* uc) {
  sigsys_info = *info;
  sigsys_rax = static_cast<ucontext_t*>(uc)->uc_mcontext.gregs[REG_RAX];
  sigsys_count = sigsys_count + 1;
  // Allow syscalls again, so that the return through rt_sigreturn is not
  // dispatched as well.
  selector = SYSCALL_DISPATCH_FILTER_ALLOW;
}

void IgnoreSignal(int) {}

void InstallRecordSigsys() {
  struct sigaction sa = {};
  sa.sa_sigaction = RecordSigsys;
  sa.sa_flags = SA_SIGINFO;
  TEST_PCHECK(sigaction(SIGSYS, &sa, nullptr) == 0);
}

// Each test that turns dispatch on does so in a child process, since dispatch
// with a blocking selector diverts every syscall the test framework makes.

TEST(SyscallUserDispatchTest, OffWithNonzeroArgumentsIsInvalid) {
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_OFF, 1, 0, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_OFF, 0, 1, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_OFF, 0, 0, &selector),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SyscallUserDispatchTest, OffSucceeds) {
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_OFF, 0, 0, nullptr),
              SyscallSucceeds());
}

TEST(SyscallUserDispatchTest, OnWithAWrappingRangeIsInvalid) {
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_ON, 0x1000, ~0ul, &selector),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SyscallUserDispatchTest, OnWithZeroOffsetAcceptsAnyLength) {
  EXPECT_THAT(
      InForkedProcess([] {
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, ~0ul, &selector) == 0);
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, InclusiveOnWithAnEmptyRangeIsInvalid) {
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_INCLUSIVE_ON, 0x1000, 0, &selector),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SyscallUserDispatchTest, UnknownModeIsInvalid) {
  EXPECT_THAT(SetDispatch(3, 0, 0, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SyscallUserDispatchTest, KernelSelectorIsAFault) {
  EXPECT_THAT(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0,
                          reinterpret_cast<char*>(0xffff800000000000ul)),
              SyscallFailsWithErrno(EFAULT));
}

TEST(SyscallUserDispatchTest, AllowSelectorRunsTheSyscall) {
  EXPECT_THAT(
      InForkedProcess([] {
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
        TEST_CHECK(RawSyscall(SYS_getpid) == getpid());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, BlockSelectorSendsSigsys) {
  EXPECT_THAT(
      InForkedProcess([] {
        InstallRecordSigsys();
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        long const ret = RawSyscall(SYS_getpid);
        TEST_CHECK(sigsys_count == 1);
        TEST_CHECK(sigsys_info.si_signo == SIGSYS);
        TEST_CHECK(sigsys_info.si_code == SYS_USER_DISPATCH);
        TEST_CHECK(sigsys_info.si_errno == 0);
        TEST_CHECK(sigsys_info.si_call_addr == RawSyscallReturn);
        TEST_CHECK(sigsys_info.si_syscall == SYS_getpid);
        TEST_CHECK(sigsys_info.si_arch == AUDIT_ARCH_X86_64);
        // The syscall did not run, and RAX holds its number again.
        TEST_CHECK(sigsys_rax == SYS_getpid);
        TEST_CHECK(ret == SYS_getpid);
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, ExemptRangeRunsTheSyscall) {
  EXPECT_THAT(
      InForkedProcess([] {
        InstallRecordSigsys();
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON,
                                reinterpret_cast<uintptr_t>(RawSyscallReturn),
                                1, &selector) == 0);
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        long const ret = RawSyscall(SYS_getpid);
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        TEST_CHECK(sigsys_count == 0);
        TEST_CHECK(ret == getpid());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, InclusiveRangeDispatchesOnlyInsideIt) {
  EXPECT_THAT(
      InForkedProcess([] {
        InstallRecordSigsys();
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_INCLUSIVE_ON,
                                reinterpret_cast<uintptr_t>(RawSyscallReturn),
                                1, &selector) == 0);
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        // getpid from libc returns outside the range, so it runs.
        pid_t const pid = getpid();
        TEST_CHECK(sigsys_count == 0);
        long const ret = RawSyscall(SYS_getpid);
        TEST_CHECK(sigsys_count == 1);
        TEST_CHECK(ret == SYS_getpid);
        TEST_CHECK(pid > 0);
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, OffStopsDispatch) {
  EXPECT_THAT(
      InForkedProcess([] {
        InstallRecordSigsys();
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_OFF, 0, 0, nullptr) == 0);
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        long const ret = RawSyscall(SYS_getpid);
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        TEST_CHECK(sigsys_count == 0);
        TEST_CHECK(ret == getpid());
      }),
      IsPosixErrorOkAndHolds(0));
}

// A syscall from the exempt range runs without reading the selector, so it
// runs even when the selector is unmapped. The child then exits with
// exit_group from the exempt range, whose status is the syscall number that
// RawSyscall leaves in its first argument.
TEST(SyscallUserDispatchTest, ExemptSyscallDoesNotReadTheSelector) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    void* const page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_PCHECK(page != MAP_FAILED);
    TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON,
                            reinterpret_cast<uintptr_t>(RawSyscallReturn), 1,
                            static_cast<char*>(page)) == 0);
    // munmap itself runs, since the selector is still readable.
    munmap(page, kPageSize);
    RawSyscall(SYS_getpid);
    RawSyscall(SYS_exit_group);
  }));
  EXPECT_TRUE(WIFEXITED(status) &&
              WEXITSTATUS(status) == (SYS_exit_group & 0xff))
      << "status " << status;
}

// SIGSYS from dispatch is forced, so a blocked SIGSYS is unblocked with its
// default action and kills the process.
TEST(SyscallUserDispatchTest, BlockedSigsysKills) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    InstallRecordSigsys();
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSYS);
    TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);
    TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
    selector = SYSCALL_DISPATCH_FILTER_BLOCK;
    RawSyscall(SYS_getpid);
  }));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

// The creating thread dispatches only RawSyscall, which it never calls, so a
// new thread that inherited its configuration would get SIGSYS from
// RawSyscall.
TEST(SyscallUserDispatchTest, NewThreadStartsWithoutDispatch) {
  EXPECT_THAT(
      InForkedProcess([] {
        InstallRecordSigsys();
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_INCLUSIVE_ON,
                                reinterpret_cast<uintptr_t>(RawSyscallReturn),
                                1, &selector) == 0);
        pthread_t thread;
        TEST_PCHECK(pthread_create(
                        &thread, nullptr,
                        [](void*) -> void* {
                          return reinterpret_cast<void*>(
                              RawSyscall(SYS_getpid));
                        },
                        nullptr) == 0);
        void* ret;
        TEST_PCHECK(pthread_join(thread, &ret) == 0);
        TEST_CHECK(sigsys_count == 0);
        TEST_CHECK(reinterpret_cast<long>(ret) == getpid());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, NullSelectorBlocksEverySyscall) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, nullptr) == 0);
    RawSyscall(SYS_getpid);
  }));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

TEST(SyscallUserDispatchTest, InvalidSelectorKillsWithSigsys) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // The handler is bypassed.
    TEST_PCHECK(signal(SIGSYS, IgnoreSignal) != SIG_ERR);
    TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
    selector = 2;
    RawSyscall(SYS_getpid);
  }));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

void ExitZero(int) { _exit(0); }

// A sibling thread that keeps installing a SIGSYS handler cannot keep an
// invalid selector from killing the process, since Linux kills it with
// force_exit_sig().
TEST(SyscallUserDispatchTest, InvalidSelectorKillIgnoresConcurrentSigaction) {
  for (int i = 0; i < 20; i++) {
    int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
      pthread_t thread;
      TEST_PCHECK(pthread_create(
                      &thread, nullptr,
                      [](void*) -> void* {
                        struct sigaction sa = {};
                        sa.sa_handler = ExitZero;
                        while (true) {
                          sigaction(SIGSYS, &sa, nullptr);
                        }
                        return nullptr;
                      },
                      nullptr) == 0);
      TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
      selector = 2;
      RawSyscall(SYS_getpid);
    }));
    ASSERT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
        << "status " << status;
  }
}

TEST(SyscallUserDispatchTest, UnreadableSelectorKillsWithSigsegv) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // The handler is bypassed.
    TEST_PCHECK(signal(SIGSEGV, IgnoreSignal) != SIG_ERR);
    void* const page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_PCHECK(page != MAP_FAILED);
    TEST_PCHECK(
        SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, static_cast<char*>(page)) == 0);
    // munmap itself runs, since the selector is still readable.
    munmap(page, kPageSize);
    RawSyscall(SYS_getpid);
  }));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
      << "status " << status;
}

TEST(SyscallUserDispatchTest, ForkedChildDoesNotInherit) {
  EXPECT_THAT(
      InForkedProcess([] {
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        TEST_PCHECK(SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, &selector) == 0);
        pid_t const child = fork();
        if (child == 0) {
          // Dispatch inherited across fork kills the child here.
          selector = SYSCALL_DISPATCH_FILTER_BLOCK;
          RawSyscall(SYS_getpid);
          selector = SYSCALL_DISPATCH_FILTER_ALLOW;
          _exit(0);
        }
        TEST_PCHECK(child > 0);
        int status;
        TEST_PCHECK(waitpid(child, &status, 0) == child);
        TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SyscallUserDispatchTest, ExecveTurnsDispatchOff) {
  int const status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // The selector page does not exist in the new image, so dispatch that
    // survives execve kills the new image with SIGSEGV at its first syscall.
    void* const page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_PCHECK(page != MAP_FAILED);
    TEST_PCHECK(
        SetDispatch(PR_SYS_DISPATCH_ON, 0, 0, static_cast<char*>(page)) == 0);
    char* const argv[] = {const_cast<char*>("/bin/true"), nullptr};
    execv(argv[0], argv);
    _exit(3);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
