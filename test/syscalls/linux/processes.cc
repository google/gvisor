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

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(bool, processes_test_exec_swap, false,
          "If true, run the ExecSwap function.");
ABSL_FLAG(int, processes_test_exec_swap_pre_clone_pid, -1,
          "Process ID from before clone; required when using "
          "--processes_test_exec_swap.");
ABSL_FLAG(int, processes_test_exec_swap_pre_clone_tid, -1,
          "Thread ID from before clone; required when using "
          "--processes_test_exec_swap.");
ABSL_FLAG(int, processes_test_exec_swap_pre_exec_pid, -1,
          "Process ID from before exec; required when using "
          "--processes_test_exec_swap.");
ABSL_FLAG(int, processes_test_exec_swap_pre_exec_tid, -1,
          "Thread ID from before exec; required when using "
          "--processes_test_exec_swap.");
ABSL_FLAG(int, processes_test_exec_swap_pipe_fd, -1,
          "File descriptor to write data to; required when using "
          "--processes_test_exec_swap.");

namespace gvisor {
namespace testing {

int testSetPGIDOfZombie(void* arg) {
  int p[2];

  TEST_PCHECK(pipe(p) == 0);

  pid_t pid = fork();
  if (pid == 0) {
    pid = fork();
    // Create a second child to repeat one of syzkaller reproducers.
    if (pid == 0) {
      pid = getpid();
      TEST_PCHECK(setpgid(pid, 0) == 0);
      TEST_PCHECK(WriteFd(p[1], &pid, sizeof(pid)) == sizeof(pid));
      _exit(0);
    }
    TEST_PCHECK(pid > 0);
    _exit(0);
  }
  close(p[1]);
  TEST_PCHECK(pid > 0);

  // Get PID of the second child.
  pid_t cpid;
  TEST_PCHECK(ReadFd(p[0], &cpid, sizeof(cpid)) == sizeof(cpid));

  // Wait when both child processes will die.
  int c;
  TEST_PCHECK(ReadFd(p[0], &c, sizeof(c)) == 0);

  // Wait the second child process to collect its zombie.
  int status;
  TEST_PCHECK(RetryEINTR(waitpid)(cpid, &status, 0) == cpid);

  // Set the child's group.
  TEST_PCHECK(setpgid(pid, pid) == 0);

  TEST_PCHECK(RetryEINTR(waitpid)(-pid, &status, 0) == pid);

  TEST_PCHECK(status == 0);
  _exit(0);
}

TEST(Processes, SetPGIDOfZombie) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Fork a test process in a new PID namespace, because it needs to manipulate
  // with reparented processes.
  struct clone_arg {
    // Reserve some space for clone() to locate arguments and retcode in this
    // place.
    char stack[128] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  pid_t pid;
  ASSERT_THAT(pid = clone(testSetPGIDOfZombie, ca.stack_ptr,
                          CLONE_NEWPID | SIGCHLD, &ca),
              SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_EQ(status, 0);
}

// Clones fn as the init process of a new PID namespace and returns its pid.
pid_t CloneNewPidNamespace(int (*fn)(void*)) {
  // Reserve some space for clone() to locate arguments and retcode in this
  // place. Some of the children below take a signal on this stack, so leave
  // room for a signal frame.
  static struct {
    char stack[64 * 1024] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  return clone(fn, ca.stack_ptr, CLONE_NEWPID | SIGCHLD, nullptr);
}

// Runs fn as the init process of a new PID namespace and expects it to exit
// with status 0.
void RunInNewPidNamespace(int (*fn)(void*)) {
  pid_t pid;
  ASSERT_THAT(pid = CloneNewPidNamespace(fn), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

// Runs fn in a child of the calling init process and reaps it.
void RunMemberAndReap(const std::function<void()>& fn) {
  pid_t pid = fork();
  if (pid == 0) {
    fn();
    _exit(0);
  }
  TEST_PCHECK(pid > 0);
  int status;
  TEST_PCHECK(RetryEINTR(waitpid)(pid, &status, 0) == pid);
  TEST_PCHECK(status == 0);
}

sigset_t SignalMask(int sig) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, sig);
  return mask;
}

int testPidNsInitIgnoresSelfSentSignals(void* arg) {
  TEST_PCHECK(getpid() == 1);
  TEST_PCHECK(kill(1, SIGKILL) == 0);
  TEST_PCHECK(kill(1, SIGTERM) == 0);
  TEST_PCHECK(syscall(SYS_tkill, 1, SIGKILL) == 0);
  _exit(0);
}

TEST(Processes, PidNamespaceInitIgnoresSelfSentSignals) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitIgnoresSelfSentSignals);
}

int testPidNsInitIgnoresMemberSignals(void* arg) {
  TEST_PCHECK(getpid() == 1);
  RunMemberAndReap([] {
    TEST_PCHECK(kill(1, SIGTERM) == 0);
    TEST_PCHECK(kill(1, SIGSTOP) == 0);
    TEST_PCHECK(kill(1, SIGKILL) == 0);
  });
  _exit(0);
}

TEST(Processes, PidNamespaceInitIgnoresMemberSignals) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitIgnoresMemberSignals);
}

volatile sig_atomic_t signal_handled;

void RecordSignalHandled(int sig) { signal_handled = 1; }

int testPidNsInitReceivesHandledMemberSignal(void* arg) {
  TEST_PCHECK(getpid() == 1);
  signal_handled = 0;
  struct sigaction sa = {};
  sa.sa_handler = RecordSignalHandled;
  TEST_PCHECK(sigaction(SIGTERM, &sa, nullptr) == 0);
  sigset_t mask = SignalMask(SIGTERM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &mask, nullptr) == 0);
  RunMemberAndReap([] { TEST_PCHECK(kill(1, SIGTERM) == 0); });
  sigset_t suspend_mask;
  TEST_PCHECK(sigprocmask(SIG_BLOCK, nullptr, &suspend_mask) == 0);
  sigdelset(&suspend_mask, SIGTERM);
  TEST_PCHECK(sigsuspend(&suspend_mask) == -1 && errno == EINTR);
  TEST_PCHECK(signal_handled == 1);
  _exit(0);
}

TEST(Processes, PidNamespaceInitReceivesHandledMemberSignal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitReceivesHandledMemberSignal);
}

int testPidNsInitDropsQueuedMemberSignalOnUnblock(void* arg) {
  TEST_PCHECK(getpid() == 1);
  sigset_t mask = SignalMask(SIGTERM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &mask, nullptr) == 0);
  RunMemberAndReap([] { TEST_PCHECK(kill(1, SIGTERM) == 0); });
  sigset_t pending;
  TEST_PCHECK(sigpending(&pending) == 0);
  TEST_PCHECK(sigismember(&pending, SIGTERM) == 1);
  TEST_PCHECK(sigprocmask(SIG_UNBLOCK, &mask, nullptr) == 0);
  _exit(0);
}

TEST(Processes, PidNamespaceInitDropsQueuedMemberSignalOnUnblock) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitDropsQueuedMemberSignalOnUnblock);
}

int testPidNsInitSigwaitsMemberSignal(void* arg) {
  TEST_PCHECK(getpid() == 1);
  sigset_t mask = SignalMask(SIGTERM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &mask, nullptr) == 0);
  RunMemberAndReap([] { TEST_PCHECK(kill(1, SIGTERM) == 0); });
  struct timespec timeout = {.tv_sec = 30};
  TEST_PCHECK(sigtimedwait(&mask, nullptr, &timeout) == SIGTERM);
  _exit(0);
}

TEST(Processes, PidNamespaceInitSigwaitsMemberSignal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitSigwaitsMemberSignal);
}

void QueueSignalToInit(int code, pid_t sender) {
  siginfo_t si = {};
  si.si_signo = SIGKILL;
  si.si_code = code;
  si.si_pid = sender;
  si.si_uid = getuid();
  TEST_PCHECK(syscall(SYS_rt_sigqueueinfo, 1, SIGKILL, &si) == 0);
}

int testPidNsInitIgnoresOwnForgedSignal(void* arg) {
  TEST_PCHECK(getpid() == 1);
  QueueSignalToInit(SI_QUEUE, 1);
  QueueSignalToInit(1, 1);
  _exit(0);
}

TEST(Processes, PidNamespaceInitIgnoresOwnForgedSignal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitIgnoresOwnForgedSignal);
}

int testPidNsInitIgnoresForgedMemberSignal(void* arg) {
  TEST_PCHECK(getpid() == 1);
  RunMemberAndReap([] {
    QueueSignalToInit(SI_QUEUE, getpid());
    QueueSignalToInit(SI_QUEUE, 0);
    QueueSignalToInit(SI_TIMER, getpid());
    QueueSignalToInit(SI_SIGIO, getpid());
  });
  _exit(0);
}

TEST(Processes, PidNamespaceInitIgnoresForgedMemberSignal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewPidNamespace(testPidNsInitIgnoresForgedMemberSignal);
}

int testPidNsInitIgnoresMemberSignalWhileTraced(void* arg) {
  TEST_PCHECK(getpid() == 1);
  RunMemberAndReap([] {
    TEST_PCHECK(ptrace(PTRACE_SEIZE, 1, nullptr, nullptr) == 0);
    TEST_PCHECK(kill(1, SIGKILL) == 0);
    TEST_PCHECK(kill(1, SIGTERM) == 0);
    int status;
    TEST_PCHECK(RetryEINTR(waitpid)(1, &status, WUNTRACED) == 1);
    TEST_PCHECK(WIFSTOPPED(status));
    // A tracer cannot make a member's signal look kernel-sent.
    siginfo_t si = {};
    TEST_PCHECK(ptrace(PTRACE_GETSIGINFO, 1, nullptr, &si) == 0);
    si.si_code = SI_KERNEL;
    TEST_PCHECK(ptrace(PTRACE_SETSIGINFO, 1, nullptr, &si) == 0);
    TEST_PCHECK(ptrace(PTRACE_CONT, 1, nullptr, SIGTERM) == 0);
  });
  _exit(0);
}

TEST(Processes, PidNamespaceInitIgnoresMemberSignalWhileTraced) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_PTRACE)));
  RunInNewPidNamespace(testPidNsInitIgnoresMemberSignalWhileTraced);
}

int testPidNsInitDiesOnFault(void* arg) {
  TEST_PCHECK(getpid() == 1);
  *reinterpret_cast<volatile int*>(0) = 1;
  _exit(0);
}

TEST(Processes, PidNamespaceInitDiesOnFault) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  pid_t pid;
  ASSERT_THAT(pid = CloneNewPidNamespace(testPidNsInitDiesOnFault),
              SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
      << "status = " << status;
}

// Shared with the cloned init process, which needs them after clone().
int toPidNsInit[2];
int fromPidNsInit[2];

int testPidNsInitEchoes(void* arg) {
  TEST_PCHECK(getpid() == 1);
  TEST_PCHECK(close(toPidNsInit[1]) == 0);
  TEST_PCHECK(close(fromPidNsInit[0]) == 0);
  char c = 0;
  TEST_PCHECK(WriteFd(fromPidNsInit[1], &c, 1) == 1);
  TEST_PCHECK(ReadFd(toPidNsInit[0], &c, 1) == 1);
  TEST_PCHECK(WriteFd(fromPidNsInit[1], &c, 1) == 1);
  while (true) {
    pause();
  }
  return 0;
}

TEST(Processes, PidNamespaceInitSignaledFromParentNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  ASSERT_THAT(pipe(toPidNsInit), SyscallSucceeds());
  ASSERT_THAT(pipe(fromPidNsInit), SyscallSucceeds());
  pid_t pid;
  ASSERT_THAT(pid = CloneNewPidNamespace(testPidNsInitEchoes),
              SyscallSucceeds());
  ASSERT_THAT(close(toPidNsInit[0]), SyscallSucceeds());
  ASSERT_THAT(close(fromPidNsInit[1]), SyscallSucceeds());
  char c = 0;
  ASSERT_THAT(ReadFd(fromPidNsInit[0], &c, 1), SyscallSucceedsWithValue(1));

  // Only SIGKILL and SIGSTOP reach an init process with no handler, even from
  // the parent namespace.
  ASSERT_THAT(kill(pid, SIGTERM), SyscallSucceeds());
  ASSERT_THAT(WriteFd(toPidNsInit[1], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(ReadFd(fromPidNsInit[0], &c, 1), SyscallSucceedsWithValue(1));

  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << "status = " << status;
  EXPECT_THAT(close(toPidNsInit[1]), SyscallSucceeds());
  EXPECT_THAT(close(fromPidNsInit[0]), SyscallSucceeds());
}

void WritePIDToPipe(int* pipe_fds) {
  pid_t child_pid;
  TEST_PCHECK(child_pid = getpid());
  TEST_PCHECK(child_pid != gettid());
  TEST_PCHECK(WriteFd(pipe_fds[1], &child_pid, sizeof(child_pid)) ==
              sizeof(child_pid));
}

TEST(Processes, TheadSharesSamePID) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  pid_t test_pid;
  ASSERT_THAT(test_pid = getpid(), SyscallSucceeds());
  EXPECT_NE(test_pid, 0);
  ScopedThread([&pipe_fds]() { WritePIDToPipe(pipe_fds); }).Join();
  ASSERT_THAT(close(pipe_fds[1]), SyscallSucceeds());
  pid_t pid_from_child;
  TEST_PCHECK(ReadFd(pipe_fds[0], &pid_from_child, sizeof(pid_from_child)) ==
              sizeof(pid_from_child));
  int buf;
  TEST_PCHECK(ReadFd(pipe_fds[0], &buf, sizeof(buf)) ==
              0);  // Wait for cloned thread to exit
  ASSERT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_EQ(test_pid, pid_from_child);
}

TEST(Processes, ThousandsOfThreads) {
  const DisableSave ds;  // Too many syscalls.
  const int kThreadCount = 1000;
  const int kSyscallsPerThread = 1000;
  std::unique_ptr<ScopedThread> threads[kThreadCount];
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  for (int i = 0; i < kThreadCount; i++) {
    threads[i] = std::make_unique<ScopedThread>([&pipe_fds]() {
      char c;
      EXPECT_THAT(ReadFd(pipe_fds[0], &c, 1), SyscallSucceedsWithValue(0));
      for (int j = 0; j < kSyscallsPerThread; j++) {
        syscall(SYS_close, -1);
      }
    });
  }
  close(pipe_fds[1]);
  for (int i = 0; i < kThreadCount; i++) {
    threads[i]->Join();
  }
}

// ExecSwapResult is used to carry PIDs and TIDs in ExecSwapThreadGroupLeader.
struct ExecSwapResult {
  int pipe_fd;  // FD to write result data to.

  // PID and TID before we call clone().
  pid_t pre_clone_pid;
  pid_t pre_clone_tid;

  // PID and TID before the clone calls execv().
  pid_t pre_exec_pid;
  pid_t pre_exec_tid;

  // PID and TID after the execv().
  pid_t post_exec_pid;
  pid_t post_exec_tid;
};

// The number of elements in ExecSwapArg.execve_array.
constexpr int kExecveArraySize = 7;

// The size of the preallocated elements of execve_array that are populated
// in ExecSwapPreExec. Should be large enough to hold any flag string.
constexpr int kExecveArrayComponentsSize = 256;

// ExecSwapArg is passed as argument to ExecSwapPreExec.
struct ExecSwapArg {
  // The pipe FD to write results to.
  int pipe_fd;

  // Data from prior to cloning.
  pid_t pre_clone_pid;
  pid_t pre_clone_tid;

  // Pre-allocated array to use in execve, so that we can use it without doing
  // allocations in ExecSwapPreExec.
  char* execve_array[kExecveArraySize];
};

// ExecSwapPostExec is the third part of the ExecSwapThreadGroupLeader test.
// It is called after the test has fork()'d, clone()'d, and exec()'d into
// this. It writes all the PIDs and TIDs from each part of the test to a pipe.
int ExecSwapPostExec() {
  std::cerr << "Test exec'd." << std::endl;
  pid_t pid;
  TEST_PCHECK(pid = getpid());
  pid_t tid;
  TEST_PCHECK(tid = gettid());
  ExecSwapResult result;
  result.pipe_fd = absl::GetFlag(FLAGS_processes_test_exec_swap_pipe_fd);
  result.pre_clone_pid =
      absl::GetFlag(FLAGS_processes_test_exec_swap_pre_clone_pid);
  result.pre_clone_tid =
      absl::GetFlag(FLAGS_processes_test_exec_swap_pre_clone_tid);
  result.pre_exec_pid =
      absl::GetFlag(FLAGS_processes_test_exec_swap_pre_exec_pid);
  result.pre_exec_tid =
      absl::GetFlag(FLAGS_processes_test_exec_swap_pre_exec_tid);
  result.post_exec_pid = pid;
  result.post_exec_tid = tid;
  std::cerr << "Test writing results to pipe FD." << std::endl;
  TEST_PCHECK(WriteFd(result.pipe_fd, &result, sizeof(result)) ==
              sizeof(result));
  if (close(result.pipe_fd) != 0) {
    std::cerr << "Failed to close pipe FD: " << errno << std::endl;
  }
  std::cerr << "Test results written out." << std::endl;
  return 0;
}

// ExecSwapPreExec is the second part of the ExecSwapThreadGroupLeader test.
// It is called after the test has fork()'d and clone()'d.
// It calls exec() with flags that cause the test binary to run
// ExecSwapPostExec.
[[noreturn]] int ExecSwapPreExec(void* void_arg) {
  ExecSwapArg* arg = reinterpret_cast<ExecSwapArg*>(void_arg);
  pid_t pid = getpid();
  TEST_PCHECK(pid > 0);
  pid_t tid = gettid();
  TEST_PCHECK(tid > 0);

  strncpy(arg->execve_array[0], "/proc/self/exe", kExecveArrayComponentsSize);
  strncpy(arg->execve_array[1], "--processes_test_exec_swap",
          kExecveArrayComponentsSize);
  absl::SNPrintF(arg->execve_array[2], kExecveArrayComponentsSize,
                 "--processes_test_exec_swap_pre_clone_pid=%d",
                 arg->pre_clone_pid);
  absl::SNPrintF(arg->execve_array[3], kExecveArrayComponentsSize,
                 "--processes_test_exec_swap_pre_clone_tid=%d",
                 arg->pre_clone_tid);
  absl::SNPrintF(arg->execve_array[4], kExecveArrayComponentsSize,
                 "--processes_test_exec_swap_pre_exec_pid=%d", pid);
  absl::SNPrintF(arg->execve_array[5], kExecveArrayComponentsSize,
                 "--processes_test_exec_swap_pre_exec_tid=%d", tid);
  absl::SNPrintF(arg->execve_array[6], kExecveArrayComponentsSize,
                 "--processes_test_exec_swap_pipe_fd=%d", arg->pipe_fd);
  std::cerr << "Test exec'ing:" << std::endl;
  for (int i = 0; i < kExecveArraySize; ++i) {
    std::cerr << "  execve_array[" << i << "] = " << arg->execve_array[i]
              << std::endl;
  }
  TEST_PCHECK(execv("/proc/self/exe", arg->execve_array) == 0);
  _exit(1);  // Should be unreachable.
}

// ExecSwapPreClone is the first part of the ExecSwapThreadGroupLeader test.
// It is called after the test has fork()'d.
// It calls clone() to run ExecSwapPreExec.
// We need to disable HWASan, for this, because we cannot tag the stack region
// used by the clone() call.
[[noreturn]] __attribute__((no_sanitize("hwaddress"))) void ExecSwapPreClone(
    ExecSwapArg* exec_swap_arg) {
  pid_t pid = getpid();
  TEST_PCHECK(pid > 0);
  pid_t tid = gettid();
  TEST_PCHECK(tid > 0);
  struct clone_arg {
    char stack[4096] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  exec_swap_arg->pre_clone_pid = pid;
  exec_swap_arg->pre_clone_tid = tid;
  std::cerr << "Test cloning." << std::endl;
  TEST_PCHECK(clone(ExecSwapPreExec, ca.stack_ptr,
                    CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_FS,
                    exec_swap_arg) > 0);
  // The clone thread will call exec, so just sit around here until it does.
  while (true) {
    absl::SleepFor(absl::Milliseconds(500));
  }
}

TEST(Processes, ExecSwapThreadGroupLeader) {
  // This test verifies that a non-leading thread calling exec() replaces the
  // former leader of its thread group and adopts its thread ID.
  // This is the zeroth part of this test, which calls fork() to run
  // ExecSwapPreClone in a separate thread group.

  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  pid_t test_pid;
  ASSERT_THAT(test_pid = getpid(), SyscallSucceeds());
  pid_t test_tid;
  ASSERT_THAT(test_tid = gettid(), SyscallSucceeds());

  // Preallocate ExecSwapArg ahead of fork().
  // This uses shared memory because we use it after fork()+clone().
  ExecSwapArg* exec_swap_arg =
      (ExecSwapArg*)mmap(NULL, sizeof(ExecSwapArg), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(exec_swap_arg, MAP_FAILED);
  exec_swap_arg->pipe_fd = pipe_fds[1];
  char* execve_array_component;
  for (int i = 0; i < kExecveArraySize; ++i) {
    execve_array_component =
        (char*)mmap(NULL, kExecveArrayComponentsSize * sizeof(char),
                    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(execve_array_component, MAP_FAILED);
    exec_swap_arg->execve_array[i] = execve_array_component;
  }

  std::cerr << "Test forking." << std::endl;
  pid_t fork_pid = fork();
  if (fork_pid == 0) {
    ExecSwapPreClone(exec_swap_arg);
  }
  ASSERT_THAT(close(pipe_fds[1]), SyscallSucceeds());

  std::cerr << "Waiting for test results." << std::endl;
  ExecSwapResult result;
  TEST_PCHECK(ReadFd(pipe_fds[0], &result, sizeof(result)) == sizeof(result));

  std::cerr << "ExecSwap results:" << std::endl;
  std::cerr << "  Parent test process PID / TID:" << test_pid << " / "
            << test_tid << std::endl;
  std::cerr << "  Parent test child PID, as seen by parent:" << fork_pid
            << std::endl;
  std::cerr << "  Pre-clone PID / TID: " << result.pre_clone_pid << " / "
            << result.pre_clone_tid << std::endl;
  std::cerr << "  Pre-exec  PID / TID: " << result.pre_exec_pid << " / "
            << result.pre_exec_tid << std::endl;
  std::cerr << "  Post-exec PID / TID: " << result.post_exec_pid << " / "
            << result.post_exec_tid << std::endl;

  ASSERT_THAT(close(pipe_fds[0]), SyscallSucceeds());

  // Test starts out as the thread group leader of itself.
  EXPECT_EQ(test_pid, test_tid);

  // The child is a different thread group altogether.
  EXPECT_NE(test_pid, fork_pid);
  EXPECT_EQ(fork_pid, result.pre_clone_pid);  // Sanity check.

  // Before cloning, PID == TID, the child thread is leader of its thread
  // group.
  EXPECT_EQ(result.pre_clone_pid, result.pre_clone_tid);

  // PID should not change with clone.
  EXPECT_EQ(result.pre_clone_pid, result.pre_exec_pid);

  // But TID should change with clone.
  EXPECT_NE(result.pre_clone_tid, result.pre_exec_tid);

  // So we now have PID != TID.
  EXPECT_NE(result.pre_exec_pid, result.pre_exec_tid);

  // exec'ing does not change the PID, even when done from non-leader thread.
  EXPECT_EQ(result.pre_exec_pid, result.post_exec_pid);

  // After exec, the PID is back to matching TID.
  EXPECT_EQ(result.post_exec_pid, result.post_exec_tid);

  // The TID matches the one from before clone.
  EXPECT_EQ(result.post_exec_tid, result.pre_clone_tid);
}

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (absl::GetFlag(FLAGS_processes_test_exec_swap)) {
    return gvisor::testing::ExecSwapPostExec();
  }
  return gvisor::testing::RunAllTests();
}
