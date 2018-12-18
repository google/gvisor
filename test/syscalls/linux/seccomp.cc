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

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <atomic>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/proc_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

namespace gvisor {
namespace testing {

namespace {

// A syscall not implemented by Linux that we don't expect to be called.
constexpr uint32_t kFilteredSyscall = SYS_vserver;

// Applies a seccomp-bpf filter that returns `filtered_result` for
// `sysno` and allows all other syscalls. Async-signal-safe.
void ApplySeccompFilter(uint32_t sysno, uint32_t filtered_result,
                        uint32_t flags = 0) {
  // "Prior to [PR_SET_SECCOMP], the task must call prctl(PR_SET_NO_NEW_PRIVS,
  // 1) or run with CAP_SYS_ADMIN privileges in its namespace." -
  // Documentation/prctl/seccomp_filter.txt
  //
  // prctl(PR_SET_NO_NEW_PRIVS, 1) may be called repeatedly; calls after the
  // first are no-ops.
  TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
  MaybeSave();

  struct sock_filter filter[] = {
      // A = seccomp_data.arch
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 4),
      // if (A != AUDIT_ARCH_X86_64) goto kill
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4),
      // A = seccomp_data.nr
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0),
      // if (A != sysno) goto allow
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysno, 0, 1),
      // return filtered_result
      BPF_STMT(BPF_RET | BPF_K, filtered_result),
      // allow: return SECCOMP_RET_ALLOW
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      // kill: return SECCOMP_RET_KILL
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };
  struct sock_fprog prog;
  prog.len = ABSL_ARRAYSIZE(filter);
  prog.filter = filter;
  if (flags) {
    TEST_CHECK(syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog) ==
               0);
  } else {
    TEST_PCHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0);
  }
  MaybeSave();
}

// Wrapper for sigaction. Async-signal-safe.
void RegisterSignalHandler(int signum,
                           void (*handler)(int, siginfo_t*, void*)) {
  struct sigaction sa = {};
  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  TEST_PCHECK(sigaction(signum, &sa, nullptr) == 0);
  MaybeSave();
}

// All of the following tests execute in a subprocess to ensure that each test
// is run in a separate process. This avoids cross-contamination of seccomp
// state between tests, and is necessary to ensure that test processes killed
// by SECCOMP_RET_KILL are single-threaded (since SECCOMP_RET_KILL only kills
// the offending thread, not the whole thread group).

TEST(SeccompTest, RetKillCausesDeathBySIGSYS) {
  pid_t const pid = fork();
  if (pid == 0) {
    // Register a signal handler for SIGSYS that we don't expect to be invoked.
    RegisterSignalHandler(SIGSYS, +[](int, siginfo_t*, void*) { _exit(1); });
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_KILL);
    syscall(kFilteredSyscall);
    TEST_CHECK_MSG(false, "Survived invocation of test syscall");
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

TEST(SeccompTest, RetKillOnlyKillsOneThread) {
  Mapping stack = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));

  pid_t const pid = fork();
  if (pid == 0) {
    // Register a signal handler for SIGSYS that we don't expect to be invoked.
    RegisterSignalHandler(SIGSYS, +[](int, siginfo_t*, void*) { _exit(1); });
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_KILL);
    // Pass CLONE_VFORK to block the original thread in the child process until
    // the clone thread exits with SIGSYS.
    //
    // N.B. clone(2) is not officially async-signal-safe, but at minimum glibc's
    // x86_64 implementation is safe. See glibc
    // sysdeps/unix/sysv/linux/x86_64/clone.S.
    clone(
        +[](void* arg) {
          syscall(kFilteredSyscall);  // should kill the thread
          _exit(1);                   // should be unreachable
          return 2;  // should be very unreachable, shut up the compiler
        },
        stack.endptr(),
        CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD | CLONE_VM |
            CLONE_VFORK,
        nullptr);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

TEST(SeccompTest, RetTrapCausesSIGSYS) {
  pid_t const pid = fork();
  if (pid == 0) {
    constexpr uint16_t kTrapValue = 0xdead;
    RegisterSignalHandler(SIGSYS, +[](int signo, siginfo_t* info, void*) {
      // This is a signal handler, so we must stay async-signal-safe.
      TEST_CHECK(info->si_signo == SIGSYS);
      TEST_CHECK(info->si_code == SYS_SECCOMP);
      TEST_CHECK(info->si_errno == kTrapValue);
      TEST_CHECK(info->si_call_addr != nullptr);
      TEST_CHECK(info->si_syscall == kFilteredSyscall);
      TEST_CHECK(info->si_arch == AUDIT_ARCH_X86_64);
      _exit(0);
    });
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_TRAP | kTrapValue);
    syscall(kFilteredSyscall);
    TEST_CHECK_MSG(false, "Survived invocation of test syscall");
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

constexpr uint64_t kVsyscallTimeEntry = 0xffffffffff600400;

time_t vsyscall_time(time_t* t) {
  return reinterpret_cast<time_t (*)(time_t*)>(kVsyscallTimeEntry)(t);
}

TEST(SeccompTest, SeccompAppliesToVsyscall) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));

  pid_t const pid = fork();
  if (pid == 0) {
    constexpr uint16_t kTrapValue = 0xdead;
    RegisterSignalHandler(SIGSYS, +[](int signo, siginfo_t* info, void*) {
      // This is a signal handler, so we must stay async-signal-safe.
      TEST_CHECK(info->si_signo == SIGSYS);
      TEST_CHECK(info->si_code == SYS_SECCOMP);
      TEST_CHECK(info->si_errno == kTrapValue);
      TEST_CHECK(info->si_call_addr != nullptr);
      TEST_CHECK(info->si_syscall == SYS_time);
      TEST_CHECK(info->si_arch == AUDIT_ARCH_X86_64);
      _exit(0);
    });
    ApplySeccompFilter(SYS_time, SECCOMP_RET_TRAP | kTrapValue);
    vsyscall_time(nullptr);  // Should result in death.
    TEST_CHECK_MSG(false, "Survived invocation of test syscall");
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

TEST(SeccompTest, RetKillVsyscallCausesDeathBySIGSYS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));

  pid_t const pid = fork();
  if (pid == 0) {
    // Register a signal handler for SIGSYS that we don't expect to be invoked.
    RegisterSignalHandler(
        SIGSYS, +[](int, siginfo_t*, void*) { _exit(1); });
    ApplySeccompFilter(SYS_time, SECCOMP_RET_KILL);
    vsyscall_time(nullptr);  // Should result in death.
    TEST_CHECK_MSG(false, "Survived invocation of test syscall");
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

TEST(SeccompTest, RetTraceWithoutPtracerReturnsENOSYS) {
  pid_t const pid = fork();
  if (pid == 0) {
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_TRACE);
    TEST_CHECK(syscall(kFilteredSyscall) == -1 && errno == ENOSYS);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

TEST(SeccompTest, RetErrnoReturnsErrno) {
  pid_t const pid = fork();
  if (pid == 0) {
    // ENOTNAM: "Not a XENIX named type file"
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_ERRNO | ENOTNAM);
    TEST_CHECK(syscall(kFilteredSyscall) == -1 && errno == ENOTNAM);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

TEST(SeccompTest, RetAllowAllowsSyscall) {
  pid_t const pid = fork();
  if (pid == 0) {
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_ALLOW);
    TEST_CHECK(syscall(kFilteredSyscall) == -1 && errno == ENOSYS);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

// This test will validate that TSYNC will apply to all threads.
TEST(SeccompTest, TsyncAppliesToAllThreads) {
  Mapping stack = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));

  // We don't want to apply this policy to other test runner threads, so fork.
  const pid_t pid = fork();

  if (pid == 0) {
    // First check that we receive a ENOSYS before the policy is applied.
    TEST_CHECK(syscall(kFilteredSyscall) == -1 && errno == ENOSYS);

    // N.B. clone(2) is not officially async-signal-safe, but at minimum glibc's
    // x86_64 implementation is safe. See glibc
    // sysdeps/unix/sysv/linux/x86_64/clone.S.
    clone(
        +[](void* arg) {
          ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_ERRNO | ENOTNAM,
                             SECCOMP_FILTER_FLAG_TSYNC);
          return 0;
        },
        stack.endptr(),
        CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD | CLONE_VM |
            CLONE_VFORK,
        nullptr);

    // Because we're using CLONE_VFORK this thread will be blocked until
    // the second thread has released resources to our virtual memory, since
    // we're not execing that will happen on _exit.

    // Now verify that the policy applied to this thread too.
    TEST_CHECK(syscall(kFilteredSyscall) == -1 && errno == ENOTNAM);
    _exit(0);
  }

  ASSERT_THAT(pid, SyscallSucceeds());
  int status = 0;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

// This test will validate that seccomp(2) rejects unsupported flags.
TEST(SeccompTest, SeccompRejectsUnknownFlags) {
  constexpr uint32_t kInvalidFlag = 123;
  ASSERT_THAT(
      syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, kInvalidFlag, nullptr),
      SyscallFailsWithErrno(EINVAL));
}

TEST(SeccompTest, LeastPermissiveFilterReturnValueApplies) {
  // This is RetKillCausesDeathBySIGSYS, plus extra filters before and after the
  // one that causes the kill that should be ignored.
  pid_t const pid = fork();
  if (pid == 0) {
    RegisterSignalHandler(SIGSYS, +[](int, siginfo_t*, void*) { _exit(1); });
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_TRACE);
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_KILL);
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_ERRNO | ENOTNAM);
    syscall(kFilteredSyscall);
    TEST_CHECK_MSG(false, "Survived invocation of test syscall");
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      << "status " << status;
}

// Passed as argv[1] to cause the test binary to invoke kFilteredSyscall and
// exit. Not a real flag since flag parsing happens during initialization,
// which may create threads.
constexpr char kInvokeFilteredSyscallFlag[] = "--seccomp_test_child";

TEST(SeccompTest, FiltersPreservedAcrossForkAndExecve) {
  ExecveArray const grandchild_argv(
      {"/proc/self/exe", kInvokeFilteredSyscallFlag});

  pid_t const pid = fork();
  if (pid == 0) {
    ApplySeccompFilter(kFilteredSyscall, SECCOMP_RET_KILL);
    pid_t const grandchild_pid = fork();
    if (grandchild_pid == 0) {
      execve(grandchild_argv.get()[0], grandchild_argv.get(),
             /* envp = */ nullptr);
      TEST_PCHECK_MSG(false, "execve failed");
    }
    int status;
    TEST_PCHECK(waitpid(grandchild_pid, &status, 0) == grandchild_pid);
    TEST_CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  if (argc >= 2 &&
      strcmp(argv[1], gvisor::testing::kInvokeFilteredSyscallFlag) == 0) {
    syscall(gvisor::testing::kFilteredSyscall);
    exit(0);
  }

  gvisor::testing::TestInit(&argc, &argv);
  return RUN_ALL_TESTS();
}
