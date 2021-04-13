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

#include <elf.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/platform_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/time_util.h"

ABSL_FLAG(bool, ptrace_test_execve_child, false,
          "If true, run the "
          "PtraceExecveTest_Execve_GetRegs_PeekUser_SIGKILL_TraceClone_"
          "TraceExit child workload.");
ABSL_FLAG(bool, ptrace_test_trace_descendants_allowed, false,
          "If set, run the child workload for "
          "PtraceTest_TraceDescendantsAllowed.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_pid, false,
          "If set, run the child workload for PtraceTest_PrctlSetPtracerPID.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_any, false,
          "If set, run the child workload for PtraceTest_PrctlSetPtracerAny.");
ABSL_FLAG(bool, ptrace_test_prctl_clear_ptracer, false,
          "If set, run the child workload for PtraceTest_PrctlClearPtracer.");
ABSL_FLAG(bool, ptrace_test_prctl_replace_ptracer, false,
          "If set, run the child workload for PtraceTest_PrctlReplacePtracer.");
ABSL_FLAG(int, ptrace_test_prctl_replace_ptracer_tid, -1,
          "Specifies the replacement tracer tid in the child workload for "
          "PtraceTest_PrctlReplacePtracer.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_and_exit_tracee_thread, false,
          "If set, run the child workload for "
          "PtraceTest_PrctlSetPtracerPersistsPastTraceeThreadExit.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_and_exec_non_leader, false,
          "If set, run the child workload for "
          "PtraceTest_PrctlSetPtracerDoesNotPersistPastNonLeaderExec.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_and_exit_tracer_thread, false,
          "If set, run the child workload for "
          "PtraceTest_PrctlSetPtracerDoesNotPersistPastTracerThreadExit.");
ABSL_FLAG(int, ptrace_test_prctl_set_ptracer_and_exit_tracer_thread_tid, -1,
          "Specifies the tracee tid in the child workload for "
          "PtraceTest_PrctlSetPtracerDoesNotPersistPastTracerThreadExit.");
ABSL_FLAG(bool, ptrace_test_prctl_set_ptracer_respects_tracer_thread_id, false,
          "If set, run the child workload for PtraceTest_PrctlSetPtracePID.");
ABSL_FLAG(int, ptrace_test_prctl_set_ptracer_respects_tracer_thread_id_tid, -1,
          "Specifies the thread tid to be traced in the child workload "
          "for PtraceTest_PrctlSetPtracerRespectsTracerThreadID.");

ABSL_FLAG(bool, ptrace_test_tracee, false,
          "If true, run the tracee process for the "
          "PrctlSetPtracerDoesNotPersistPastLeaderExec and "
          "PrctlSetPtracerDoesNotPersistPastNonLeaderExec workloads.");
ABSL_FLAG(int, ptrace_test_trace_tid, -1,
          "If set, run a process to ptrace attach to the thread with the "
          "specified pid for the PrctlSetPtracerRespectsTracerThreadID "
          "workload.");
ABSL_FLAG(int, ptrace_test_fd, -1,
          "Specifies the fd used for communication between tracer and tracee "
          "processes across exec.");

namespace gvisor {
namespace testing {

namespace {

// PTRACE_GETSIGMASK and PTRACE_SETSIGMASK are not defined until glibc 2.23
// (fb53a27c5741 "Add new header definitions from Linux 4.4 (plus older ptrace
// definitions)").
constexpr auto kPtraceGetSigMask = static_cast<__ptrace_request>(0x420a);
constexpr auto kPtraceSetSigMask = static_cast<__ptrace_request>(0x420b);

// PTRACE_SYSEMU is not defined until glibc 2.27 (c48831d0eebf "linux/x86: sync
// sys/ptrace.h with Linux 4.14 [BZ #22433]").
constexpr auto kPtraceSysemu = static_cast<__ptrace_request>(31);

// PTRACE_EVENT_STOP is not defined until glibc 2.26 (3f67d1a7021e "Add Linux
// PTRACE_EVENT_STOP").
constexpr int kPtraceEventStop = 128;

// Sends sig to the current process with tgkill(2).
//
// glibc's raise(2) may change the signal mask before sending the signal. These
// extra syscalls make tests of syscall, signal interception, etc. difficult to
// write.
void RaiseSignal(int sig) {
  pid_t pid = getpid();
  TEST_PCHECK(pid > 0);
  pid_t tid = gettid();
  TEST_PCHECK(tid > 0);
  TEST_PCHECK(tgkill(pid, tid, sig) == 0);
}

constexpr char kYamaPtraceScopePath[] = "/proc/sys/kernel/yama/ptrace_scope";

// Returns the Yama ptrace scope.
PosixErrorOr<int> YamaPtraceScope() {
  ASSIGN_OR_RETURN_ERRNO(bool exists, Exists(kYamaPtraceScopePath));
  if (!exists) {
    // File doesn't exist means no Yama, so the scope is disabled -> 0.
    return 0;
  }

  std::string contents;
  RETURN_IF_ERRNO(GetContents(kYamaPtraceScopePath, &contents));

  int scope;
  if (!absl::SimpleAtoi(contents, &scope)) {
    return PosixError(EINVAL, absl::StrCat(contents, ": not a valid number"));
  }

  return scope;
}

int CheckPtraceAttach(pid_t pid) {
  int ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
  MaybeSave();
  if (ret < 0) {
    return ret;
  }

  int status;
  TEST_PCHECK(waitpid(pid, &status, 0) == pid);
  MaybeSave();
  TEST_CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  TEST_PCHECK(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);
  MaybeSave();
  return 0;
}

TEST(PtraceTest, AttachSelf) {
  EXPECT_THAT(ptrace(PTRACE_ATTACH, gettid(), 0, 0),
              SyscallFailsWithErrno(EPERM));
}

TEST(PtraceTest, AttachSameThreadGroup) {
  pid_t const tid = gettid();
  ScopedThread([&] {
    EXPECT_THAT(ptrace(PTRACE_ATTACH, tid, 0, 0), SyscallFailsWithErrno(EPERM));
  });
}

TEST(PtraceTest, TraceParentNotAllowed) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) < 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    TEST_CHECK(CheckPtraceAttach(getppid()) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(PtraceTest, TraceNonDescendantNotAllowed) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) < 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    TEST_CHECK(CheckPtraceAttach(tracee_pid) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  EXPECT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, TraceNonDescendantWithCapabilityAllowed) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_PTRACE)));
  // Skip if disallowed by YAMA despite having CAP_SYS_PTRACE.
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) > 2);

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    TEST_PCHECK(CheckPtraceAttach(tracee_pid) == 0);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, TraceDescendantsAllowed) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) > 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use socket pair to communicate tids to this process from its grandchild.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_trace_descendants_allowed",
      "--ptrace_test_fd", std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    TEST_PCHECK(close(sockets[1]) == 0);
    pid_t const grandchild_pid = fork();
    if (grandchild_pid == 0) {
      // This test will create a new thread in the grandchild process.
      // pthread_create(2) isn't async-signal-safe, so we execve() first.
      execve(child_argv[0], child_argv, /* envp = */ nullptr);
      TEST_PCHECK_MSG(false, "Survived execve to test child");
    }
    TEST_PCHECK(grandchild_pid > 0);
    MaybeSave();

    // Wait for grandchild. Our parent process will kill it once it's done.
    int status;
    TEST_PCHECK(waitpid(grandchild_pid, &status, 0) == grandchild_pid);
    TEST_CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    MaybeSave();
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  // We should be able to attach to any thread in the grandchild.
  pid_t grandchild_tid1, grandchild_tid2;
  ASSERT_THAT(read(sockets[1], &grandchild_tid1, sizeof(grandchild_tid1)),
              SyscallSucceedsWithValue(sizeof(grandchild_tid1)));
  ASSERT_THAT(read(sockets[1], &grandchild_tid2, sizeof(grandchild_tid2)),
              SyscallSucceedsWithValue(sizeof(grandchild_tid2)));

  EXPECT_THAT(CheckPtraceAttach(grandchild_tid1), SyscallSucceeds());
  EXPECT_THAT(CheckPtraceAttach(grandchild_tid2), SyscallSucceeds());

  // Clean up grandchild.
  ASSERT_THAT(kill(grandchild_tid1, SIGKILL), SyscallSucceeds());

  // Clean up child.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

[[noreturn]] void RunTraceDescendantsAllowed(int fd) {
  // Let the tracer know our tid through the socket fd.
  pid_t const tid = gettid();
  TEST_PCHECK(write(fd, &tid, sizeof(tid)) == sizeof(tid));
  MaybeSave();

  ScopedThread t([fd] {
    // See if any arbitrary thread (whose tid differs from the process id) can
    // be traced as well.
    pid_t const tid = gettid();
    TEST_PCHECK(write(fd, &tid, sizeof(tid)) == sizeof(tid));
    MaybeSave();
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  });

  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

TEST(PtraceTest, PrctlSetPtracerInvalidPID) {
  // EINVAL should also be returned if PR_SET_PTRACER is not supported.
  EXPECT_THAT(prctl(PR_SET_PTRACER, 123456789), SyscallFailsWithErrno(EINVAL));
}

TEST(PtraceTest, PrctlSetPtracerPID) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);

  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_prctl_set_ptracer_pid",
      "--ptrace_test_fd", std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(CheckPtraceAttach(tracee_pid) == 0);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerPID(int fd) {
  ScopedThread t([fd] {
    // Perform prctl in a separate thread to verify that it is process-wide.
    TEST_PCHECK(prctl(PR_SET_PTRACER, getppid()) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(fd, "x", 1) == 1);
    MaybeSave();
  });
  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

TEST(PtraceTest, PrctlSetPtracerAny) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_prctl_set_ptracer_any",
      "--ptrace_test_fd", std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    TEST_PCHECK(close(sockets[1]) == 0);
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(CheckPtraceAttach(tracee_pid) == 0);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerAny(int fd) {
  ScopedThread t([fd] {
    // Perform prctl in a separate thread to verify that it is process-wide.
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(fd, "x", 1) == 1);
    MaybeSave();
  });
  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

TEST(PtraceTest, PrctlClearPtracer) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_prctl_clear_ptracer", "--ptrace_test_fd",
      std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    TEST_PCHECK(close(sockets[1]) == 0);
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_CHECK(CheckPtraceAttach(tracee_pid) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlClearPtracer(int fd) {
  ScopedThread t([fd] {
    // Perform prctl in a separate thread to verify that it is process-wide.
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();
    TEST_PCHECK(prctl(PR_SET_PTRACER, 0) == 0);
    MaybeSave();
    // Indicate that the prctl has been set/cleared.
    TEST_PCHECK(write(fd, "x", 1) == 1);
    MaybeSave();
  });
  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

TEST(PtraceTest, PrctlReplacePtracer) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  pid_t const unused_pid = fork();
  if (unused_pid == 0) {
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(unused_pid, SyscallSucceeds());

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe",
      "--ptrace_test_prctl_replace_ptracer",
      "--ptrace_test_prctl_replace_ptracer_tid",
      std::to_string(unused_pid),
      "--ptrace_test_fd",
      std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_CHECK(CheckPtraceAttach(tracee_pid) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;

  // Clean up unused.
  ASSERT_THAT(kill(unused_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(unused_pid, &status, 0),
              SyscallSucceedsWithValue(unused_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlReplacePtracer(int new_tracer_pid, int fd) {
  TEST_PCHECK(prctl(PR_SET_PTRACER, getppid()) == 0);
  MaybeSave();

  ScopedThread t([new_tracer_pid, fd] {
    TEST_PCHECK(prctl(PR_SET_PTRACER, new_tracer_pid) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(fd, "x", 1) == 1);
    MaybeSave();
  });
  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

// Tests that YAMA exceptions store tracees by thread group leader. Exceptions
// are preserved even after the tracee thread exits, as long as the tracee's
// thread group leader is still around.
TEST(PtraceTest, PrctlSetPtracerPersistsPastTraceeThreadExit) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe",
      "--ptrace_test_prctl_set_ptracer_and_exit_tracee_thread",
      "--ptrace_test_fd", std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    TEST_PCHECK(close(sockets[1]) == 0);
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until the tracee thread calling prctl has terminated.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(CheckPtraceAttach(tracee_pid) == 0);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerPersistsPastTraceeThreadExit(int fd) {
  ScopedThread t([] {
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();
  });
  t.Join();
  // Indicate that thread setting the prctl has exited.
  TEST_PCHECK(write(fd, "x", 1) == 1);
  MaybeSave();

  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

// Tests that YAMA exceptions store tracees by thread group leader. Exceptions
// are preserved across exec as long as the thread group leader does not change,
// even if the tracee thread is terminated.
TEST(PtraceTest, PrctlSetPtracerPersistsPastLeaderExec) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_tracee", "--ptrace_test_fd",
      std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();

    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until the tracee has exec'd.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(CheckPtraceAttach(tracee_pid) == 0);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunTracee(int fd) {
  // Indicate that we have exec'd.
  TEST_PCHECK(write(fd, "x", 1) == 1);
  MaybeSave();

  while (true) {
    SleepSafe(absl::Seconds(1));
  }
}

// Tests that YAMA exceptions store tracees by thread group leader. Exceptions
// are cleared if the tracee process's thread group leader is terminated by
// exec.
TEST(PtraceTest, PrctlSetPtracerDoesNotPersistPastNonLeaderExec) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe", "--ptrace_test_prctl_set_ptracer_and_exec_non_leader",
      "--ptrace_test_fd", std::to_string(sockets[0])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    TEST_PCHECK(close(sockets[1]) == 0);
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until the tracee has exec'd.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_CHECK(CheckPtraceAttach(tracee_pid) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerDoesNotPersistPastNonLeaderExec(int fd) {
  ScopedThread t([fd] {
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();

    ExecveArray const owned_child_argv = {
        "/proc/self/exe", "--ptrace_test_tracee", "--ptrace_test_fd",
        std::to_string(fd)};
    char* const* const child_argv = owned_child_argv.get();

    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  });
  t.Join();
  TEST_CHECK_MSG(false, "Survived execve? (main)");
  _exit(1);
}

// Tests that YAMA exceptions store the tracer itself rather than the thread
// group leader. Exceptions are cleared when the tracer task exits, rather than
// when its thread group leader exits.
TEST(PtraceTest, PrctlSetPtracerDoesNotPersistPastTracerThreadExit) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    pid_t tracer_tid;
    TEST_PCHECK(read(sockets[0], &tracer_tid, sizeof(tracer_tid)) ==
                sizeof(tracer_tid));
    MaybeSave();

    TEST_PCHECK(prctl(PR_SET_PTRACER, tracer_tid) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(sockets[0], "x", 1) == 1);
    MaybeSave();

    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe",
      "--ptrace_test_prctl_set_ptracer_and_exit_tracer_thread",
      "--ptrace_test_prctl_set_ptracer_and_exit_tracer_thread_tid",
      std::to_string(tracee_pid),
      "--ptrace_test_fd",
      std::to_string(sockets[1])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerDoesNotPersistPastTracerThreadExit(
    int tracee_tid, int fd) {
  TEST_PCHECK(SetCapability(CAP_SYS_PTRACE, false).ok());

  ScopedThread t([fd] {
    pid_t const tracer_tid = gettid();
    TEST_PCHECK(write(fd, &tracer_tid, sizeof(tracer_tid)) ==
                sizeof(tracer_tid));

    // Wait until the prctl has been set.
    char done;
    TEST_PCHECK(read(fd, &done, 1) == 1);
    MaybeSave();
  });
  t.Join();

  // Sleep for a bit before verifying the invalidation. The thread exit above
  // should cause the ptrace exception to be invalidated, but in Linux, this is
  // not done immediately. The YAMA exception is dropped during
  // __put_task_struct(), which occurs (at the earliest) one RCU grace period
  // after exit_notify() ==> release_task().
  SleepSafe(absl::Milliseconds(100));

  TEST_CHECK(CheckPtraceAttach(tracee_tid) == -1);
  TEST_PCHECK(errno == EPERM);
  _exit(0);
}

// Tests that YAMA exceptions store the tracer thread itself rather than the
// thread group leader. Exceptions are preserved across exec in the tracer
// thread, even if the thread group leader is terminated.
TEST(PtraceTest, PrctlSetPtracerRespectsTracerThreadID) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    pid_t tracer_tid;
    TEST_PCHECK(read(sockets[0], &tracer_tid, sizeof(tracer_tid)) ==
                sizeof(tracer_tid));
    MaybeSave();

    TEST_PCHECK(prctl(PR_SET_PTRACER, tracer_tid) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(sockets[0], "x", 1) == 1);
    MaybeSave();

    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  // Allocate vector before forking (not async-signal-safe).
  ExecveArray const owned_child_argv = {
      "/proc/self/exe",
      "--ptrace_test_prctl_set_ptracer_respects_tracer_thread_id",
      "--ptrace_test_prctl_set_ptracer_respects_tracer_thread_id_tid",
      std::to_string(tracee_pid),
      "--ptrace_test_fd",
      std::to_string(sockets[1])};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // This test will create a new thread in the child process.
    // pthread_create(2) isn't async-signal-safe, so we execve() first.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunPrctlSetPtracerRespectsTracerThreadID(int tracee_tid,
                                                           int fd) {
  // Create a separate thread for tracing (i.e., not the thread group
  // leader). After the subsequent execve(), the current thread group leader
  // will no longer be exist, but the YAMA exception installed with this
  // thread should still be valid.
  ScopedThread t([tracee_tid, fd] {
    pid_t const tracer_tid = gettid();
    TEST_PCHECK(write(fd, &tracer_tid, sizeof(tracer_tid)));
    MaybeSave();

    // Wait until the tracee has made the PR_SET_PTRACER prctl.
    char done;
    TEST_PCHECK(read(fd, &done, 1) == 1);
    MaybeSave();

    ExecveArray const owned_child_argv = {
        "/proc/self/exe", "--ptrace_test_trace_tid", std::to_string(tracee_tid),
        "--ptrace_test_fd", std::to_string(fd)};
    char* const* const child_argv = owned_child_argv.get();

    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  });
  t.Join();
  TEST_CHECK_MSG(false, "Survived execve? (main)");
  _exit(1);
}

[[noreturn]] void RunTraceTID(int tracee_tid, int fd) {
  TEST_PCHECK(SetCapability(CAP_SYS_PTRACE, false).ok());
  TEST_PCHECK(CheckPtraceAttach(tracee_tid) == 0);
  _exit(0);
}

// Tests that removing a YAMA exception does not affect a tracer that is already
// attached.
TEST(PtraceTest, PrctlClearPtracerDoesNotAffectCurrentTracer) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Use sockets to synchronize between tracer and tracee.
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(sockets[0], "x", 1) == 1);
    MaybeSave();

    // Wait until tracer has attached before clearing PR_SET_PTRACER.
    char done;
    TEST_PCHECK(read(sockets[0], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(prctl(PR_SET_PTRACER, 0) == 0);
    MaybeSave();
    // Indicate that the prctl has been set.
    TEST_PCHECK(write(sockets[0], "x", 1) == 1);
    MaybeSave();

    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  std::string mem_path = "/proc/" + std::to_string(tracee_pid) + "/mem";
  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl, or else we won't be able to attach.
    char done;
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();

    TEST_PCHECK(ptrace(PTRACE_ATTACH, tracee_pid, 0, 0) == 0);
    MaybeSave();
    // Indicate that we have attached.
    TEST_PCHECK(write(sockets[1], &done, 1) == 1);
    MaybeSave();

    // Block until tracee enters signal-delivery-stop as a result of the
    // SIGSTOP sent by PTRACE_ATTACH.
    int status;
    TEST_PCHECK(waitpid(tracee_pid, &status, 0) == tracee_pid);
    MaybeSave();
    TEST_CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    MaybeSave();

    TEST_PCHECK(ptrace(PTRACE_CONT, tracee_pid, 0, 0) == 0);
    MaybeSave();

    // Wait until tracee has cleared PR_SET_PTRACER. Even though it was cleared,
    // we should still be able to access /proc/[pid]/mem because we are already
    // attached.
    TEST_PCHECK(read(sockets[1], &done, 1) == 1);
    MaybeSave();
    TEST_PCHECK(open(mem_path.c_str(), O_RDONLY) != -1);
    MaybeSave();
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, PrctlNotInherited) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope()) != 1);
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));

  // Allow any ptracer. This should not affect the child processes.
  ASSERT_THAT(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY), SyscallSucceeds());

  pid_t const tracee_pid = fork();
  if (tracee_pid == 0) {
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());

  pid_t const tracer_pid = fork();
  if (tracer_pid == 0) {
    TEST_CHECK(CheckPtraceAttach(tracee_pid) == -1);
    TEST_PCHECK(errno == EPERM);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  // Clean up tracer.
  int status;
  ASSERT_THAT(waitpid(tracer_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Clean up tracee.
  ASSERT_THAT(kill(tracee_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(tracee_pid, &status, 0),
              SyscallSucceedsWithValue(tracee_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, AttachParent_PeekData_PokeData_SignalSuppression) {
  // Yama prevents attaching to a parent. Skip the test if the scope is anything
  // except disabled.
  const int yama_scope = ASSERT_NO_ERRNO_AND_VALUE(YamaPtraceScope());
  SKIP_IF(yama_scope > 1);
  if (yama_scope == 1) {
    // Allow child to trace us.
    ASSERT_THAT(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY), SyscallSucceeds());
  }

  // Test PTRACE_POKE/PEEKDATA on both anonymous and file mappings.
  const auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_NO_ERRNO(Truncate(file.path(), kPageSize));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  const auto file_mapping = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0));

  constexpr long kBeforePokeDataAnonValue = 10;
  constexpr long kAfterPokeDataAnonValue = 20;
  constexpr long kBeforePokeDataFileValue = 0;  // implicit, due to truncate()
  constexpr long kAfterPokeDataFileValue = 30;

  volatile long anon_word = kBeforePokeDataAnonValue;
  auto* file_word_ptr = static_cast<volatile long*>(file_mapping.ptr());

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Attach to the parent.
    pid_t const parent_pid = getppid();
    TEST_PCHECK(ptrace(PTRACE_ATTACH, parent_pid, 0, 0) == 0);
    MaybeSave();

    // Block until the parent enters signal-delivery-stop as a result of the
    // SIGSTOP sent by PTRACE_ATTACH.
    int status;
    TEST_PCHECK(waitpid(parent_pid, &status, 0) == parent_pid);
    MaybeSave();
    TEST_CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

    // Replace the value of anon_word in the parent process with
    // kAfterPokeDataAnonValue.
    long parent_word = ptrace(PTRACE_PEEKDATA, parent_pid, &anon_word, 0);
    MaybeSave();
    TEST_CHECK(parent_word == kBeforePokeDataAnonValue);
    TEST_PCHECK(ptrace(PTRACE_POKEDATA, parent_pid, &anon_word,
                       kAfterPokeDataAnonValue) == 0);
    MaybeSave();

    // Replace the value pointed to by file_word_ptr in the mapped file with
    // kAfterPokeDataFileValue, via the parent process' mapping.
    parent_word = ptrace(PTRACE_PEEKDATA, parent_pid, file_word_ptr, 0);
    MaybeSave();
    TEST_CHECK(parent_word == kBeforePokeDataFileValue);
    TEST_PCHECK(ptrace(PTRACE_POKEDATA, parent_pid, file_word_ptr,
                       kAfterPokeDataFileValue) == 0);
    MaybeSave();

    // Detach from the parent and suppress the SIGSTOP. If the SIGSTOP is not
    // suppressed, the parent will hang in group-stop, causing the test to time
    // out.
    TEST_PCHECK(ptrace(PTRACE_DETACH, parent_pid, 0, 0) == 0);
    MaybeSave();
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to complete.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Check that the child's PTRACE_POKEDATA was effective.
  EXPECT_EQ(kAfterPokeDataAnonValue, anon_word);
  EXPECT_EQ(kAfterPokeDataFileValue, *file_word_ptr);
}

TEST(PtraceTest, GetSigMask) {
  // glibc and the Linux kernel define a sigset_t with different sizes. To avoid
  // creating a kernel_sigset_t and recreating all the modification functions
  // (sigemptyset, etc), we just hardcode the kernel sigset size.
  constexpr int kSizeofKernelSigset = 8;
  constexpr int kBlockSignal = SIGUSR1;
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, kBlockSignal);

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Install a signal handler for kBlockSignal to avoid termination and block
    // it.
    TEST_PCHECK(signal(
                    kBlockSignal, +[](int signo) {}) != SIG_ERR);
    MaybeSave();
    TEST_PCHECK(sigprocmask(SIG_SETMASK, &blocked, nullptr) == 0);
    MaybeSave();

    // Enable tracing.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();

    // This should be blocked.
    RaiseSignal(kBlockSignal);

    // This should be suppressed by parent, who will change signal mask in the
    // meantime, which means kBlockSignal should be delivered once this resumes.
    RaiseSignal(SIGSTOP);

    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Get current signal mask.
  sigset_t set;
  EXPECT_THAT(ptrace(kPtraceGetSigMask, child_pid, kSizeofKernelSigset, &set),
              SyscallSucceeds());
  EXPECT_THAT(blocked, EqualsSigset(set));

  // Try to get current signal mask with bad size argument.
  EXPECT_THAT(ptrace(kPtraceGetSigMask, child_pid, 0, nullptr),
              SyscallFailsWithErrno(EINVAL));

  // Try to set bad signal mask.
  sigset_t* bad_addr = reinterpret_cast<sigset_t*>(-1);
  EXPECT_THAT(
      ptrace(kPtraceSetSigMask, child_pid, kSizeofKernelSigset, bad_addr),
      SyscallFailsWithErrno(EFAULT));

  // Set signal mask to empty set.
  sigset_t set1;
  sigemptyset(&set1);
  EXPECT_THAT(ptrace(kPtraceSetSigMask, child_pid, kSizeofKernelSigset, &set1),
              SyscallSucceeds());

  // Suppress SIGSTOP and resume the child. It should re-enter
  // signal-delivery-stop for kBlockSignal.
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == kBlockSignal)
      << " status " << status;

  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  // Let's see that process exited normally.
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(PtraceTest, GetSiginfo_SetSiginfo_SignalInjection) {
  constexpr int kOriginalSigno = SIGUSR1;
  constexpr int kInjectedSigno = SIGUSR2;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Override all signal handlers.
    struct sigaction sa = {};
    sa.sa_handler = +[](int signo) { _exit(signo); };
    TEST_PCHECK(sigfillset(&sa.sa_mask) == 0);
    for (int signo = 1; signo < 32; signo++) {
      if (signo == SIGKILL || signo == SIGSTOP) {
        continue;
      }
      TEST_PCHECK(sigaction(signo, &sa, nullptr) == 0);
    }
    for (int signo = SIGRTMIN; signo <= SIGRTMAX; signo++) {
      TEST_PCHECK(sigaction(signo, &sa, nullptr) == 0);
    }

    // Unblock all signals.
    TEST_PCHECK(sigprocmask(SIG_UNBLOCK, &sa.sa_mask, nullptr) == 0);
    MaybeSave();

    // Send ourselves kOriginalSignal while ptraced and exit with the signal we
    // actually receive via the signal handler, if any, or 0 if we don't receive
    // a signal.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();
    RaiseSignal(kOriginalSigno);
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself kOriginalSigno and enter
  // signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == kOriginalSigno)
      << " status " << status;

  siginfo_t siginfo = {};
  ASSERT_THAT(ptrace(PTRACE_GETSIGINFO, child_pid, 0, &siginfo),
              SyscallSucceeds());
  EXPECT_EQ(kOriginalSigno, siginfo.si_signo);
  EXPECT_EQ(SI_TKILL, siginfo.si_code);

  // Replace the signal with kInjectedSigno, and check that the child exits
  // with kInjectedSigno, indicating that signal injection was successful.
  siginfo.si_signo = kInjectedSigno;
  ASSERT_THAT(ptrace(PTRACE_SETSIGINFO, child_pid, 0, &siginfo),
              SyscallSucceeds());
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, kInjectedSigno),
              SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kInjectedSigno)
      << " status " << status;
}

TEST(PtraceTest, SIGKILLDoesNotCauseSignalDeliveryStop) {
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();
    RaiseSignal(SIGKILL);
    TEST_CHECK_MSG(false, "Survived SIGKILL?");
    _exit(1);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Expect the child to die to SIGKILL without entering signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, PtraceKill) {
  constexpr int kOriginalSigno = SIGUSR1;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();

    // PTRACE_KILL only works if tracee has entered signal-delivery-stop.
    RaiseSignal(kOriginalSigno);
    TEST_CHECK_MSG(false, "Failed to kill the process?");
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself kOriginalSigno and enter
  // signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == kOriginalSigno)
      << " status " << status;

  ASSERT_THAT(ptrace(PTRACE_KILL, child_pid, 0, 0), SyscallSucceeds());

  // Expect the child to die with SIGKILL.
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, GetRegSet) {
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Enable tracing.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();

    // Use kill explicitly because we check the syscall argument register below.
    kill(getpid(), SIGSTOP);

    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Get the general registers.
  struct user_regs_struct regs;
  struct iovec iov;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  EXPECT_THAT(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov),
              SyscallSucceeds());

  // Read exactly the full register set.
  EXPECT_EQ(iov.iov_len, sizeof(regs));

#if defined(__x86_64__)
  // Child called kill(2), with SIGSTOP as arg 2.
  EXPECT_EQ(regs.rsi, SIGSTOP);
#elif defined(__aarch64__)
  EXPECT_EQ(regs.regs[1], SIGSTOP);
#endif

  // Suppress SIGSTOP and resume the child.
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  // Let's see that process exited normally.
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(PtraceTest, AttachingConvertsGroupStopToPtraceStop) {
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    while (true) {
      pause();
    }
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // SIGSTOP the child and wait for it to stop.
  ASSERT_THAT(kill(child_pid, SIGSTOP), SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, WUNTRACED),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Attach to the child and expect it to re-enter a traced group-stop despite
  // already being stopped.
  ASSERT_THAT(ptrace(PTRACE_ATTACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Verify that the child is ptrace-stopped by checking that it can receive
  // ptrace commands requiring a ptrace-stop.
  EXPECT_THAT(ptrace(PTRACE_SETOPTIONS, child_pid, 0, 0), SyscallSucceeds());

  // Group-stop is distinguished from signal-delivery-stop by PTRACE_GETSIGINFO
  // failing with EINVAL.
  siginfo_t siginfo = {};
  EXPECT_THAT(ptrace(PTRACE_GETSIGINFO, child_pid, 0, &siginfo),
              SyscallFailsWithErrno(EINVAL));

  // Detach from the child and expect it to stay stopped without a notification.
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, WUNTRACED | WNOHANG),
              SyscallSucceedsWithValue(0));

  // Sending it SIGCONT should cause it to leave its stop.
  ASSERT_THAT(kill(child_pid, SIGCONT), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, WCONTINUED),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFCONTINUED(status)) << " status " << status;

  // Clean up the child.
  ASSERT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

// Fixture for tests parameterized by whether or not to use PTRACE_O_TRACEEXEC.
class PtraceExecveTest : public ::testing::TestWithParam<bool> {
 protected:
  bool TraceExec() const { return GetParam(); }
};

TEST_P(PtraceExecveTest, Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit) {
  ExecveArray const owned_child_argv = {"/proc/self/exe",
                                        "--ptrace_test_execve_child"};
  char* const* const child_argv = owned_child_argv.get();

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process. The test relies on calling execve() in a non-leader
    // thread; pthread_create() isn't async-signal-safe, so the safest way to
    // do this is to execve() first, then enable tracing and run the expected
    // child process behavior in the new subprocess.
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve to test child");
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Enable PTRACE_O_TRACECLONE so we can get the ID of the child's non-leader
  // thread, PTRACE_O_TRACEEXIT so we can observe the leader's death, and
  // PTRACE_O_TRACEEXEC if required by the test. (The leader doesn't call
  // execve, but options should be inherited across clone.)
  long opts = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;
  if (TraceExec()) {
    opts |= PTRACE_O_TRACEEXEC;
  }
  ASSERT_THAT(ptrace(PTRACE_SETOPTIONS, child_pid, 0, opts), SyscallSucceeds());

  // Suppress the SIGSTOP and wait for the child's leader thread to report
  // PTRACE_EVENT_CLONE. Get the new thread's ID from the event.
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_CLONE << 8), status >> 8);
  unsigned long eventmsg;
  ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &eventmsg),
              SyscallSucceeds());
  pid_t const nonleader_tid = eventmsg;
  pid_t const leader_tid = child_pid;

  // The new thread should be ptraced and in signal-delivery-stop by SIGSTOP due
  // to PTRACE_O_TRACECLONE.
  //
  // Before bf959931ddb88c4e4366e96dd22e68fa0db9527c "wait/ptrace: assume __WALL
  // if the child is traced" (4.7) , waiting on it requires __WCLONE since, as a
  // non-leader, its termination signal is 0. After, a standard wait is
  // sufficient.
  ASSERT_THAT(waitpid(nonleader_tid, &status, __WCLONE),
              SyscallSucceedsWithValue(nonleader_tid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Resume both child threads.
  for (pid_t const tid : {leader_tid, nonleader_tid}) {
    ASSERT_THAT(ptrace(PTRACE_CONT, tid, 0, 0), SyscallSucceeds());
  }

  // The non-leader child thread should call execve, causing the leader thread
  // to enter PTRACE_EVENT_EXIT with an apparent exit code of 0. At this point,
  // the leader has not yet exited, so the non-leader should be blocked in
  // execve.
  ASSERT_THAT(waitpid(leader_tid, &status, 0),
              SyscallSucceedsWithValue(leader_tid));
  EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_EXIT << 8), status >> 8);
  ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, leader_tid, 0, &eventmsg),
              SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(eventmsg) && WEXITSTATUS(eventmsg) == 0)
      << " eventmsg " << eventmsg;
  EXPECT_THAT(waitpid(nonleader_tid, &status, __WCLONE | WNOHANG),
              SyscallSucceedsWithValue(0));

  // Allow the leader to continue exiting. This should allow the non-leader to
  // complete its execve, causing the original leader to be reaped without
  // further notice and the non-leader to steal its ID.
  ASSERT_THAT(ptrace(PTRACE_CONT, leader_tid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(leader_tid, &status, 0),
              SyscallSucceedsWithValue(leader_tid));
  if (TraceExec()) {
    // If PTRACE_O_TRACEEXEC was enabled, the execing thread should be in
    // PTRACE_EVENT_EXEC-stop, with the event message set to its old thread ID.
    EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_EXEC << 8), status >> 8);
    ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, leader_tid, 0, &eventmsg),
                SyscallSucceeds());
    EXPECT_EQ(nonleader_tid, eventmsg);
  } else {
    // Otherwise, the execing thread should have received SIGTRAP and should now
    // be in signal-delivery-stop.
    EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        << " status " << status;
  }

#ifdef __x86_64__
  {
    // CS should be 0x33, indicating an 64-bit binary.
    constexpr uint64_t kAMD64UserCS = 0x33;
    EXPECT_THAT(ptrace(PTRACE_PEEKUSER, leader_tid,
                       offsetof(struct user_regs_struct, cs), 0),
                SyscallSucceedsWithValue(kAMD64UserCS));
    struct user_regs_struct regs = {};
    ASSERT_THAT(ptrace(PTRACE_GETREGS, leader_tid, 0, &regs),
                SyscallSucceeds());
    EXPECT_EQ(kAMD64UserCS, regs.cs);
  }
#endif  // defined(__x86_64__)

  // PTRACE_O_TRACEEXIT should have been inherited across execve. Send SIGKILL,
  // which should end the PTRACE_EVENT_EXEC-stop or signal-delivery-stop and
  // leave the child in PTRACE_EVENT_EXIT-stop.
  ASSERT_THAT(kill(leader_tid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(leader_tid, &status, 0),
              SyscallSucceedsWithValue(leader_tid));
  EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_EXIT << 8), status >> 8);
  ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, leader_tid, 0, &eventmsg),
              SyscallSucceeds());
  EXPECT_TRUE(WIFSIGNALED(eventmsg) && WTERMSIG(eventmsg) == SIGKILL)
      << " eventmsg " << eventmsg;

  // End the PTRACE_EVENT_EXIT stop, allowing the child to exit.
  ASSERT_THAT(ptrace(PTRACE_CONT, leader_tid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(leader_tid, &status, 0),
              SyscallSucceedsWithValue(leader_tid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

[[noreturn]] void RunExecveChild() {
  // Enable tracing, then raise SIGSTOP and expect our parent to suppress it.
  TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
  MaybeSave();
  RaiseSignal(SIGSTOP);
  MaybeSave();

  // Call execve() in a non-leader thread. As long as execve() succeeds, what
  // exactly we execve() shouldn't really matter, since the tracer should kill
  // us after execve() completes.
  ScopedThread t([&] {
    ExecveArray const owned_child_argv = {"/proc/self/exe",
                                          "--this_flag_shouldnt_exist"};
    char* const* const child_argv = owned_child_argv.get();
    execve(child_argv[0], child_argv, /* envp = */ nullptr);
    TEST_PCHECK_MSG(false, "Survived execve? (thread)");
  });
  t.Join();
  TEST_CHECK_MSG(false, "Survived execve? (main)");
  _exit(1);
}

INSTANTIATE_TEST_SUITE_P(TraceExec, PtraceExecveTest, ::testing::Bool());

// This test has expectations on when syscall-enter/exit-stops occur that are
// violated if saving occurs, since saving interrupts all syscalls, causing
// premature syscall-exit.
TEST(PtraceTest, ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone) {
  constexpr int kExitTraceeExitCode = 99;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Block SIGCHLD so it doesn't interrupt wait4.
    sigset_t mask;
    TEST_PCHECK(sigemptyset(&mask) == 0);
    TEST_PCHECK(sigaddset(&mask, SIGCHLD) == 0);
    TEST_PCHECK(sigprocmask(SIG_SETMASK, &mask, nullptr) == 0);
    MaybeSave();

    // Enable tracing, then raise SIGSTOP and expect our parent to suppress it.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();
    RaiseSignal(SIGSTOP);
    MaybeSave();

    // Spawn a vfork child that exits immediately, and reap it. Don't save
    // after vfork since the parent expects to see wait4 as the next syscall.
    pid_t const pid = vfork();
    if (pid == 0) {
      _exit(kExitTraceeExitCode);
    }
    TEST_PCHECK_MSG(pid > 0, "vfork failed");

    int status;
    TEST_PCHECK(wait4(pid, &status, 0, nullptr) > 0);
    MaybeSave();
    TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == kExitTraceeExitCode);
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(child_pid, SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Enable PTRACE_O_TRACEVFORK so we can get the ID of the grandchild,
  // PTRACE_O_TRACEVFORKDONE so we can observe PTRACE_EVENT_VFORK_DONE, and
  // PTRACE_O_TRACESYSGOOD so syscall-enter/exit-stops are unambiguously
  // indicated by a stop signal of SIGTRAP|0x80 rather than just SIGTRAP.
  ASSERT_THAT(ptrace(PTRACE_SETOPTIONS, child_pid, 0,
                     PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE |
                         PTRACE_O_TRACESYSGOOD),
              SyscallSucceeds());

  // Suppress the SIGSTOP and wait for the child to report PTRACE_EVENT_VFORK.
  // Get the new process' ID from the event.
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_VFORK << 8), status >> 8);
  unsigned long eventmsg;
  ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &eventmsg),
              SyscallSucceeds());
  pid_t const grandchild_pid = eventmsg;

  // The grandchild should be traced by us and in signal-delivery-stop by
  // SIGSTOP due to PTRACE_O_TRACEVFORK. This allows us to wait on it even
  // though we're not its parent.
  ASSERT_THAT(waitpid(grandchild_pid, &status, 0),
              SyscallSucceedsWithValue(grandchild_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Resume the child with PTRACE_SYSCALL. Since the grandchild is still in
  // signal-delivery-stop, the child should remain in vfork() waiting for the
  // grandchild to exec or exit.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));
  ASSERT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Suppress the grandchild's SIGSTOP and wait for the grandchild to exit. Pass
  // WNOWAIT to waitid() so that we don't acknowledge the grandchild's exit yet.
  ASSERT_THAT(ptrace(PTRACE_CONT, grandchild_pid, 0, 0), SyscallSucceeds());
  siginfo_t siginfo = {};
  ASSERT_THAT(waitid(P_PID, grandchild_pid, &siginfo, WEXITED | WNOWAIT),
              SyscallSucceeds());
  EXPECT_EQ(SIGCHLD, siginfo.si_signo);
  EXPECT_EQ(CLD_EXITED, siginfo.si_code);
  EXPECT_EQ(kExitTraceeExitCode, siginfo.si_status);
  EXPECT_EQ(grandchild_pid, siginfo.si_pid);
  EXPECT_EQ(getuid(), siginfo.si_uid);

  // The child should now be in PTRACE_EVENT_VFORK_DONE stop. The event
  // message should still be the grandchild's PID.
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8), status >> 8);
  ASSERT_THAT(ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &eventmsg),
              SyscallSucceeds());
  EXPECT_EQ(grandchild_pid, eventmsg);

  // Resume the child with PTRACE_SYSCALL again and expect it to enter
  // syscall-exit-stop for vfork() or clone(), either of which should return the
  // grandchild's PID from the syscall. Aside from PTRACE_O_TRACESYSGOOD,
  // syscall-stops are distinguished from signal-delivery-stop by
  // PTRACE_GETSIGINFO returning a siginfo for which si_code == SIGTRAP or
  // SIGTRAP|0x80.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
      << " status " << status;
  ASSERT_THAT(ptrace(PTRACE_GETSIGINFO, child_pid, 0, &siginfo),
              SyscallSucceeds());
  EXPECT_TRUE(siginfo.si_code == SIGTRAP || siginfo.si_code == (SIGTRAP | 0x80))
      << "si_code = " << siginfo.si_code;

  {
    struct user_regs_struct regs = {};
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    EXPECT_THAT(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov),
                SyscallSucceeds());
#if defined(__x86_64__)
    EXPECT_TRUE(regs.orig_rax == SYS_vfork || regs.orig_rax == SYS_clone)
        << "orig_rax = " << regs.orig_rax;
    EXPECT_EQ(grandchild_pid, regs.rax);
#elif defined(__aarch64__)
    EXPECT_TRUE(regs.regs[8] == SYS_clone) << "regs[8] = " << regs.regs[8];
    EXPECT_EQ(grandchild_pid, regs.regs[0]);
#endif  // defined(__x86_64__)
  }

  // After this point, the child will be making wait4 syscalls that will be
  // interrupted by saving, so saving is not permitted. Note that this is
  // explicitly released below once the grandchild exits.
  DisableSave ds;

  // Resume the child with PTRACE_SYSCALL again and expect it to enter
  // syscall-enter-stop for wait4().
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
      << " status " << status;
  ASSERT_THAT(ptrace(PTRACE_GETSIGINFO, child_pid, 0, &siginfo),
              SyscallSucceeds());
  EXPECT_TRUE(siginfo.si_code == SIGTRAP || siginfo.si_code == (SIGTRAP | 0x80))
      << "si_code = " << siginfo.si_code;
#ifdef __x86_64__
  {
    EXPECT_THAT(ptrace(PTRACE_PEEKUSER, child_pid,
                       offsetof(struct user_regs_struct, orig_rax), 0),
                SyscallSucceedsWithValue(SYS_wait4));
  }
#endif  // defined(__x86_64__)

  // Resume the child with PTRACE_SYSCALL again. Since the grandchild is
  // waiting for the tracer (us) to acknowledge its exit first, wait4 should
  // block.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));
  ASSERT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Acknowledge the grandchild's exit.
  ASSERT_THAT(waitpid(grandchild_pid, &status, 0),
              SyscallSucceedsWithValue(grandchild_pid));
  ds.reset();

  // Now the child should enter syscall-exit-stop for wait4, returning with the
  // grandchild's PID.
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
      << " status " << status;
  {
    struct user_regs_struct regs = {};
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    EXPECT_THAT(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov),
                SyscallSucceeds());
#if defined(__x86_64__)
    EXPECT_EQ(SYS_wait4, regs.orig_rax);
    EXPECT_EQ(grandchild_pid, regs.rax);
#elif defined(__aarch64__)
    EXPECT_EQ(SYS_wait4, regs.regs[8]);
    EXPECT_EQ(grandchild_pid, regs.regs[0]);
#endif  // defined(__x86_64__)
  }

  // Detach from the child and wait for it to exit.
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

// These tests requires knowledge of architecture-specific syscall convention.
#ifdef __x86_64__
TEST(PtraceTest, Int3) {
  SKIP_IF(PlatformSupportInt3() == PlatformSupport::NotSupported);

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Enable tracing.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);

    // Interrupt 3 - trap to debugger
    asm("int3");

    _exit(56);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << " status " << status;

  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());

  // The child should validate the injected return value and then exit normally.
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 56)
      << " status " << status;
}

TEST(PtraceTest, Sysemu_PokeUser) {
  constexpr int kSysemuHelperFirstExitCode = 126;
  constexpr uint64_t kSysemuInjectedExitGroupReturn = 42;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Enable tracing, then raise SIGSTOP and expect our parent to suppress it.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    RaiseSignal(SIGSTOP);

    // Try to exit_group, expecting the tracer to skip the syscall and set its
    // own return value.
    int const rv = syscall(SYS_exit_group, kSysemuHelperFirstExitCode);
    TEST_PCHECK_MSG(rv == kSysemuInjectedExitGroupReturn,
                    "exit_group returned incorrect value");

    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Suppress the SIGSTOP and wait for the child to enter syscall-enter-stop
  // for its first exit_group syscall.
  ASSERT_THAT(ptrace(kPtraceSysemu, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << " status " << status;

  struct user_regs_struct regs = {};
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child_pid, 0, &regs), SyscallSucceeds());
  EXPECT_EQ(SYS_exit_group, regs.orig_rax);
  EXPECT_EQ(-ENOSYS, regs.rax);
  EXPECT_EQ(kSysemuHelperFirstExitCode, regs.rdi);

  // Replace the exit_group return value, then resume the child, which should
  // automatically skip the syscall.
  ASSERT_THAT(
      ptrace(PTRACE_POKEUSER, child_pid, offsetof(struct user_regs_struct, rax),
             kSysemuInjectedExitGroupReturn),
      SyscallSucceeds());
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());

  // The child should validate the injected return value and then exit normally.
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

// This test also cares about syscall-exit-stop.
TEST(PtraceTest, ERESTART) {
  constexpr int kSigno = SIGUSR1;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.

    // Ignore, but unblock, kSigno.
    struct sigaction sa = {};
    sa.sa_handler = SIG_IGN;
    TEST_PCHECK(sigfillset(&sa.sa_mask) == 0);
    TEST_PCHECK(sigaction(kSigno, &sa, nullptr) == 0);
    MaybeSave();
    TEST_PCHECK(sigprocmask(SIG_UNBLOCK, &sa.sa_mask, nullptr) == 0);
    MaybeSave();

    // Enable tracing, then raise SIGSTOP and expect our parent to suppress it.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    RaiseSignal(SIGSTOP);

    // Invoke the pause syscall, which normally should not return until we
    // receive a signal that "either terminates the process or causes the
    // invocation of a signal-catching function".
    pause();

    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // After this point, the child's pause syscall will be interrupted by saving,
  // so saving is not permitted. Note that this is explicitly released below
  // once the child is stopped.
  DisableSave ds;

  // Suppress the SIGSTOP and wait for the child to enter syscall-enter-stop for
  // its pause syscall.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << " status " << status;

  struct user_regs_struct regs = {};
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child_pid, 0, &regs), SyscallSucceeds());
  EXPECT_EQ(SYS_pause, regs.orig_rax);
  EXPECT_EQ(-ENOSYS, regs.rax);

  // Resume the child with PTRACE_SYSCALL and expect it to block in the pause
  // syscall.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));
  ASSERT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Send the child kSigno, causing it to return ERESTARTNOHAND and enter
  // syscall-exit-stop from the pause syscall.
  constexpr int ERESTARTNOHAND = 514;
  ASSERT_THAT(kill(child_pid, kSigno), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << " status " << status;
  ds.reset();

  ASSERT_THAT(ptrace(PTRACE_GETREGS, child_pid, 0, &regs), SyscallSucceeds());
  EXPECT_EQ(SYS_pause, regs.orig_rax);
  EXPECT_EQ(-ERESTARTNOHAND, regs.rax);

  // Replace the return value from pause with 0, causing pause to not be
  // restarted despite kSigno being ignored.
  ASSERT_THAT(ptrace(PTRACE_POKEUSER, child_pid,
                     offsetof(struct user_regs_struct, rax), 0),
              SyscallSucceeds());

  // Detach from the child and wait for it to exit.
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}
#endif  // defined(__x86_64__)

TEST(PtraceTest, Seize_Interrupt_Listen) {
  volatile long child_should_spin = 1;
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    while (child_should_spin) {
      SleepSafe(absl::Seconds(1));
    }
    _exit(1);
  }

  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Attach to the child with PTRACE_SEIZE; doing so should not stop the child.
  ASSERT_THAT(ptrace(PTRACE_SEIZE, child_pid, 0, 0), SyscallSucceeds());
  int status;
  EXPECT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Stop the child with PTRACE_INTERRUPT.
  ASSERT_THAT(ptrace(PTRACE_INTERRUPT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (kPtraceEventStop << 8), status >> 8);

  // Unset child_should_spin to verify that the child never leaves the spin
  // loop.
  ASSERT_THAT(ptrace(PTRACE_POKEDATA, child_pid, &child_should_spin, 0),
              SyscallSucceeds());

  // Send SIGSTOP to the child, then resume it, allowing it to proceed to
  // signal-delivery-stop.
  ASSERT_THAT(kill(child_pid, SIGSTOP), SyscallSucceeds());
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // Release the child from signal-delivery-stop without suppressing the
  // SIGSTOP, causing it to enter group-stop.
  ASSERT_THAT(ptrace(PTRACE_CONT, child_pid, 0, SIGSTOP), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGSTOP | (kPtraceEventStop << 8), status >> 8);

  // "The state of the tracee after PTRACE_LISTEN is somewhat of a gray area: it
  // is not in any ptrace-stop (ptrace commands won't work on it, and it will
  // deliver waitpid(2) notifications), but it also may be considered 'stopped'
  // because it is not executing instructions (is not scheduled), and if it was
  // in group-stop before PTRACE_LISTEN, it will not respond to signals until
  // SIGCONT is received." - ptrace(2).
  ASSERT_THAT(ptrace(PTRACE_LISTEN, child_pid, 0, 0), SyscallSucceeds());
  EXPECT_THAT(ptrace(PTRACE_CONT, child_pid, 0, 0),
              SyscallFailsWithErrno(ESRCH));
  EXPECT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(kill(child_pid, SIGTERM), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));
  EXPECT_THAT(waitpid(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Send SIGCONT to the child, causing it to leave group-stop and re-trap due
  // to PTRACE_LISTEN.
  EXPECT_THAT(kill(child_pid, SIGCONT), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (kPtraceEventStop << 8), status >> 8);

  // Detach the child and expect it to exit due to the SIGTERM we sent while
  // it was stopped by PTRACE_LISTEN.
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM)
      << " status " << status;
}

TEST(PtraceTest, Interrupt_Listen_RequireSeize) {
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    MaybeSave();
    raise(SIGSTOP);
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Wait for the child to send itself SIGSTOP and enter signal-delivery-stop.
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << " status " << status;

  // PTRACE_INTERRUPT and PTRACE_LISTEN should fail since the child wasn't
  // attached with PTRACE_SEIZE, leaving the child in signal-delivery-stop.
  EXPECT_THAT(ptrace(PTRACE_INTERRUPT, child_pid, 0, 0),
              SyscallFailsWithErrno(EIO));
  EXPECT_THAT(ptrace(PTRACE_LISTEN, child_pid, 0, 0),
              SyscallFailsWithErrno(EIO));

  // Suppress SIGSTOP and detach from the child, expecting it to exit normally.
  ASSERT_THAT(ptrace(PTRACE_DETACH, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(PtraceTest, SeizeSetOptions) {
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    while (true) {
      SleepSafe(absl::Seconds(1));
    }
  }

  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());

  // Attach to the child with PTRACE_SEIZE while setting PTRACE_O_TRACESYSGOOD.
  ASSERT_THAT(ptrace(PTRACE_SEIZE, child_pid, 0, PTRACE_O_TRACESYSGOOD),
              SyscallSucceeds());

  // Stop the child with PTRACE_INTERRUPT.
  ASSERT_THAT(ptrace(PTRACE_INTERRUPT, child_pid, 0, 0), SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_EQ(SIGTRAP | (kPtraceEventStop << 8), status >> 8);

  // Resume the child with PTRACE_SYSCALL and wait for it to enter
  // syscall-enter-stop. The stop signal status from the syscall stop should be
  // SIGTRAP|0x80, reflecting PTRACE_O_TRACESYSGOOD.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
      << " status " << status;

  // Clean up the child.
  ASSERT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
    // "SIGKILL kills even within system calls (syscall-exit-stop is not
    // generated prior to death by SIGKILL). The net effect is that SIGKILL
    // always kills the process (all its threads), even if some threads of the
    // process are ptraced." - ptrace(2). This is technically true, but...
    //
    // When we send SIGKILL to the child, kernel/signal.c:complete_signal() =>
    // signal_wake_up(resume=1) kicks the tracee out of the syscall-enter-stop.
    // The pending SIGKILL causes the syscall to be skipped, but the child
    // thread still reports syscall-exit before checking for pending signals; in
    // current kernels, this is
    // arch/x86/entry/common.c:syscall_return_slowpath() =>
    // syscall_slow_exit_work() =>
    // include/linux/tracehook.h:tracehook_report_syscall_exit() =>
    // ptrace_report_syscall() => kernel/signal.c:ptrace_notify() =>
    // ptrace_do_notify() => ptrace_stop().
    //
    // ptrace_stop() sets the task's state to TASK_TRACED and the task's
    // exit_code to SIGTRAP|0x80 (passed by ptrace_report_syscall()), then calls
    // freezable_schedule(). freezable_schedule() eventually reaches
    // __schedule(), which detects signal_pending_state() due to the pending
    // SIGKILL, sets the task's state back to TASK_RUNNING, and returns without
    // descheduling. Thus, the task never enters syscall-exit-stop. However, if
    // our wait4() => kernel/exit.c:wait_task_stopped() racily observes the
    // TASK_TRACED state and the non-zero exit code set by ptrace_stop() before
    // __schedule() sets the state back to TASK_RUNNING, it will return the
    // task's exit_code as status W_STOPCODE(SIGTRAP|0x80). So we get a spurious
    // syscall-exit-stop notification, and need to wait4() again for task exit.
    //
    // gVisor is not susceptible to this race because
    // kernel.Task.waitCollectTraceeStopLocked() checks specifically for an
    // active ptraceStop, which is not initiated if SIGKILL is pending.
    std::cout << "Observed syscall-exit after SIGKILL" << std::endl;
    ASSERT_THAT(waitpid(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
  }
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << " status " << status;
}

TEST(PtraceTest, SetYAMAPtraceScope) {
  SKIP_IF(IsRunningWithVFS1());

  // Do not modify the ptrace scope on the host.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(std::string(kYamaPtraceScopePath), O_RDWR));

  ASSERT_THAT(write(fd.get(), "0", 1), SyscallSucceedsWithValue(1));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  std::vector<char> buf(10);
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()), SyscallSucceeds());
  EXPECT_STREQ(buf.data(), "0\n");

  // Test that a child can attach to its parent when ptrace_scope is 0.
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_PTRACE, false));
  pid_t const child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(CheckPtraceAttach(getppid()) == 0);
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;

  // Set ptrace_scope back to 1 (and try writing with a newline).
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  ASSERT_THAT(write(fd.get(), "1\n", 2), SyscallSucceedsWithValue(2));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()), SyscallSucceeds());
  EXPECT_STREQ(buf.data(), "1\n");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (absl::GetFlag(FLAGS_ptrace_test_execve_child)) {
    gvisor::testing::RunExecveChild();
  }

  int fd = absl::GetFlag(FLAGS_ptrace_test_fd);

  if (absl::GetFlag(FLAGS_ptrace_test_trace_descendants_allowed)) {
    gvisor::testing::RunTraceDescendantsAllowed(fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_prctl_set_ptracer_pid)) {
    gvisor::testing::RunPrctlSetPtracerPID(fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_prctl_set_ptracer_any)) {
    gvisor::testing::RunPrctlSetPtracerAny(fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_prctl_clear_ptracer)) {
    gvisor::testing::RunPrctlClearPtracer(fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_prctl_replace_ptracer)) {
    gvisor::testing::RunPrctlReplacePtracer(
        absl::GetFlag(FLAGS_ptrace_test_prctl_replace_ptracer_tid), fd);
  }

  if (absl::GetFlag(
          FLAGS_ptrace_test_prctl_set_ptracer_and_exit_tracee_thread)) {
    gvisor::testing::RunPrctlSetPtracerPersistsPastTraceeThreadExit(fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_prctl_set_ptracer_and_exec_non_leader)) {
    gvisor::testing::RunPrctlSetPtracerDoesNotPersistPastNonLeaderExec(
        fd);
  }

  if (absl::GetFlag(
          FLAGS_ptrace_test_prctl_set_ptracer_and_exit_tracer_thread)) {
    gvisor::testing::RunPrctlSetPtracerDoesNotPersistPastTracerThreadExit(
        absl::GetFlag(
            FLAGS_ptrace_test_prctl_set_ptracer_and_exit_tracer_thread_tid),
        fd);
  }

  if (absl::GetFlag(
          FLAGS_ptrace_test_prctl_set_ptracer_respects_tracer_thread_id)) {
    gvisor::testing::RunPrctlSetPtracerRespectsTracerThreadID(
        absl::GetFlag(
            FLAGS_ptrace_test_prctl_set_ptracer_respects_tracer_thread_id_tid),
        fd);
  }

  if (absl::GetFlag(FLAGS_ptrace_test_tracee)) {
    gvisor::testing::RunTracee(fd);
  }

  int pid = absl::GetFlag(FLAGS_ptrace_test_trace_tid);
  if (pid != -1) {
    gvisor::testing::RunTraceTID(pid, fd);
  }

  return gvisor::testing::RunAllTests();
}
