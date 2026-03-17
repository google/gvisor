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
#include <fcntl.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#if defined(__x86_64__)
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#elif defined(__aarch64__)
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#else
#error "Unknown architecture"
#endif

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

// A flag for clone3().
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

// A flag for waitid().
#ifndef P_PIDFD
#define P_PIDFD static_cast<idtype_t>(3)
#endif

// A flag for pidfd_open().
#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

// A flag for pidfd_send_signal().
#ifndef PIDFD_SIGNAL_THREAD
#define PIDFD_SIGNAL_THREAD (1UL << 0)
#endif

ABSL_FLAG(std::string, pidfd_helper, "",
          "The name of the helper logic to run.");
ABSL_FLAG(int, pidfd_pipe_fd, -1, "The FD of a pipe for coordination.");
ABSL_FLAG(int, pidfd_tid_pipe_fd, -1, "Another pipe FD for TID reporting.");

namespace gvisor {
namespace testing {

// RunLeaderDelayedHelper implements the helper logic for the test
// PidfdThreadLeaderDelayedNotification. Threadgroup leader creates a subthread
// that waits on a pipe, and then exits immediately. The subthread sticks around
// until signalled.
void RunLeaderDelayedHelper() {
  int rfd = absl::GetFlag(FLAGS_pidfd_pipe_fd);
  // Use raw pthread_create instead of ScopedThread to avoid dependency on the
  // (shortly exiting) leader.
  pthread_t pt;
  TEST_PCHECK(pthread_create(
                  &pt, nullptr,
                  [](void* arg) -> void* {
                    int fd = static_cast<int>(reinterpret_cast<intptr_t>(arg));
                    char buf;
                    (void)read(fd, &buf, 1);  // Wait to be signaled.
                    close(fd);
                    _exit(0);
                    return nullptr;
                  },
                  reinterpret_cast<void*>(static_cast<intptr_t>(rfd))) == 0);
  syscall(SYS_exit, 0);  // Leader (just the thread) exits.
}

// RunSubthreadNotificationHelper implements the helper logic for
// PidfdThreadSubthreadNotification. The thread-group leader creates a subthread
// that reports its TID on a pipe and then waits on another pipe. The leader
// then pauses.
void RunSubthreadNotificationHelper() {
  int rfd = absl::GetFlag(FLAGS_pidfd_pipe_fd);
  int wfd = absl::GetFlag(FLAGS_pidfd_tid_pipe_fd);
  ScopedThread thread([rfd, wfd] {
    pid_t tid = gettid();
    (void)write(wfd, &tid, sizeof(tid));  // Report TID.
    char buf;
    (void)read(rfd, &buf, 1);  // Wait to be signaled.
    close(rfd);
    close(wfd);
  });
  pause();  // Leader pauses.
}

// RunExecRevivalHelper implements the child process for the
// PidfdThreadExecRevival test. The leader spawns a subthread and then pauses.
// The subthread reports its TID, and then execve()s to a program that pauses.
void RunExecRevivalHelper() {
  int rfd = absl::GetFlag(FLAGS_pidfd_pipe_fd);
  int wfd = absl::GetFlag(FLAGS_pidfd_tid_pipe_fd);

  ScopedThread t([rfd, wfd] {
    pid_t tid = gettid();
    (void)write(wfd, &tid, sizeof(tid));  // Report TID.

    char buf;
    (void)read(rfd, &buf, 1);  // Wait to be signaled.
    close(rfd);
    close(wfd);
    char* const argv[] = {const_cast<char*>("/proc/self/exe"),
                          const_cast<char*>("--pidfd_helper=RunPauseHelper"),
                          nullptr};
    execve(argv[0], argv, nullptr);  // execve() to become leader.
    _exit(errno);
  });
  pause();  // Leader pauses.
}

// RunPauseHelper implements a simple helper that pauses indefinitely.
void RunPauseHelper() { pause(); }

namespace {

class ScopedChildReaper {
 public:
  explicit ScopedChildReaper(pid_t child) : child_(child) {}

  ~ScopedChildReaper() {
    if (child_ <= 0) return;
    kill(child_, SIGKILL);
    kill(child_, SIGCONT);
    int status;
    RetryEINTR(waitpid)(child_, &status, 0);
  }

  void Release() { child_ = -1; }

 private:
  pid_t child_;
};

PosixErrorOr<FileDescriptor> PidfdOpen(pid_t pid, unsigned int flags) {
  int fd = syscall(SYS_pidfd_open, pid, flags);
  if (fd < 0) {
    return PosixError(errno, "pidfd_open failed");
  }
  return FileDescriptor(fd);
}

int PidfdSendSignal(int pidfd, int sig, siginfo_t* info, unsigned int flags) {
  return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

PosixErrorOr<FileDescriptor> PidfdGetfd(int pidfd, int targetfd,
                                        unsigned int flags) {
  int fd = syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
  if (fd < 0) {
    return PosixError(errno, "pidfd_getfd failed");
  }
  return FileDescriptor(fd);
}

template <typename ChildFunc>
PosixErrorOr<FileDescriptor> Clone3Pidfd(pid_t& child, ChildFunc&& child_func) {
  clone_args ca = {};
  ca.flags = CLONE_PIDFD;
  ca.exit_signal = SIGCHLD;
  int fd = -1;
  ca.pidfd = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&fd));

  child = syscall(SYS_clone3, &ca, sizeof(ca));
  if (child == 0) {
    child_func();
    _exit(0);
  }
  if (child < 0) {
    return PosixError(errno, "clone3 failed");
  }
  if (fd < 0) {
    return PosixError(errno, "clone3 succeeded but no pidfd returned");
  }
  return FileDescriptor(fd);
}

TEST(PidfdTest, PidfdOpenInvalid) {
  EXPECT_THAT(PidfdOpen(-1, 0), PosixErrorIs(EINVAL));
  EXPECT_THAT(PidfdOpen(getpid(), 1), PosixErrorIs(EINVAL));
}

TEST(PidfdTest, OpenPidfdSelfSucceeds) {
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(getpid(), 0));
  int flags = fcntl(pidfd.get(), F_GETFD, 0);
  EXPECT_TRUE(flags & FD_CLOEXEC);
}

static std::atomic<int> signal_received{0};
static void sigusr1_handler(int sig) {
  if (sig == SIGUSR1) signal_received.store(1, std::memory_order_relaxed);
}

// "PidfdOpenPidfd" refers to a pidfd obtained via pidfd_open().
TEST(PidfdTest, SendSignalViaPidfdOpenPidfdToSelfSucceeds) {
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(getpid(), 0));
  auto sighandler = signal(SIGUSR1, sigusr1_handler);
  // Restore old handler after the test.
  auto cleanup = Cleanup([sighandler] { signal(SIGUSR1, sighandler); });
  signal_received.store(0, std::memory_order_relaxed);

  EXPECT_THAT(PidfdSendSignal(pidfd.get(), SIGUSR1, nullptr, 0),
              SyscallSucceeds());
  absl::Time start = absl::Now();
  while (signal_received.load(std::memory_order_relaxed) == 0) {
    if (absl::Now() - start > absl::Seconds(2)) break;
    sched_yield();
  }
  EXPECT_EQ(signal_received.load(std::memory_order_relaxed), 1);
}

TEST(PidfdTest, SendSignalViaPidfdOpenPidfdToExitedChildFails) {
  pid_t child = fork();
  if (child == 0) {
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  ScopedChildReaper cleanup(child);
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(child, 0));

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  cleanup.Release();

  EXPECT_THAT(PidfdSendSignal(pidfd.get(), 0, nullptr, 0),
              SyscallFailsWithErrno(ESRCH));
}

TEST(PidfdTest, SendSignalToExitedChildFails) {
  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() { _exit(0); }));
  ScopedChildReaper cleanup(child);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  cleanup.Release();
  EXPECT_THAT(PidfdSendSignal(pidfd.get(), 0, nullptr, 0),
              SyscallFailsWithErrno(ESRCH));
}

TEST(PidfdTest, SendSignalToStoppedChildSucceeds) {
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    raise(SIGSTOP);
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, WSTOPPED),
              SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFSTOPPED(status));
  EXPECT_EQ(WSTOPSIG(status), SIGSTOP);

  EXPECT_THAT(PidfdSendSignal(pidfd.get(), SIGCONT, nullptr, 0),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  cleanup.Release();
}

TEST(PidfdTest, SendSignalToPausedChildFailsWhenUnprivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);

  int pidfd_raw = pidfd.get();
  constexpr int kFeebleUid = 65534;
  EXPECT_THAT(InForkedProcess([pidfd_raw] {
                TEST_PCHECK(setresuid(kFeebleUid, kFeebleUid, kFeebleUid) == 0);
                TEST_PCHECK_MSG(!HaveCapability(CAP_KILL).ValueOrDie(),
                                "Still have CAP_KILL");
                TEST_CHECK_ERRNO(
                    syscall(SYS_pidfd_send_signal, pidfd_raw, 0, nullptr, 0),
                    EPERM);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(PidfdTest, GetfdUnknown) {
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);
  // The child is very unlikely to have an fd at 666.
  EXPECT_THAT(PidfdGetfd(pidfd.get(), 666, 0), PosixErrorIs(EBADF));
}

TEST(PidfdTest, GetfdInvalidFlags) {
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);
  EXPECT_THAT(PidfdGetfd(pidfd.get(), 0, 1), PosixErrorIs(EINVAL));
}

TEST(PidfdTest, GetfdWorks) {
  int pfd[2];
  ASSERT_THAT(pipe(pfd), SyscallSucceeds());
  FileDescriptor read_pipe(pfd[0]);
  FileDescriptor write_pipe(pfd[1]);

  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);

  // Close our read end of the pipe.
  int childs_read_fd = read_pipe.get();
  read_pipe.reset();
  // And get the child's copy instead.
  auto duped_readfd =
      ASSERT_NO_ERRNO_AND_VALUE(PidfdGetfd(pidfd.get(), childs_read_fd, 0));
  int flags = fcntl(duped_readfd.get(), F_GETFD, 0);
  EXPECT_TRUE(flags & FD_CLOEXEC);

  // Verify that the stolen read fd works.
  const char write_buf[] = "hello pidfd";
  EXPECT_THAT(write(write_pipe.get(), write_buf, sizeof(write_buf)),
              SyscallSucceedsWithValue(sizeof(write_buf)));
  char read_buf[sizeof(write_buf)] = {};
  EXPECT_THAT(read(duped_readfd.get(), read_buf, sizeof(read_buf)),
              SyscallSucceedsWithValue(sizeof(read_buf)));
  EXPECT_STREQ(read_buf, write_buf);
}

TEST(PidfdTest, GetfdFailsWhenUnprivileged) {
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);
  int stdin_fd = 0;

  // We can get at the child's stdin.
  auto duped_fd =
      ASSERT_NO_ERRNO_AND_VALUE(PidfdGetfd(pidfd.get(), stdin_fd, 0));
  // But our unprivileged other child cannot.
  EXPECT_THAT(InForkedProcess([&pidfd, stdin_fd] {
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER));
                TEST_CHECK_ERRNO(
                    syscall(SYS_pidfd_getfd, pidfd.get(), stdin_fd, 0), EPERM);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(PidfdTest, InvalidPidfd) {
  constexpr int kNotAPidfd = 0;
  EXPECT_THAT(PidfdSendSignal(kNotAPidfd, SIGKILL, nullptr, 0),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(PidfdGetfd(kNotAPidfd, 0, 0), PosixErrorIs(EBADF));
}

TEST(PidfdTest, WaitSingleState) {
  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() { _exit(66); }));
  ScopedChildReaper cleanup(child);

  siginfo_t info = {};
  int ret = RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WEXITED);
  ASSERT_THAT(ret, SyscallSucceeds());
  cleanup.Release();

  EXPECT_EQ(info.si_signo, SIGCHLD);
  EXPECT_EQ(info.si_code, CLD_EXITED);
  EXPECT_EQ(info.si_status, 66);
  EXPECT_EQ(info.si_pid, child);
}

TEST(PidfdTest, WaitMultipleStates) {
  int pfd[2];
  ASSERT_THAT(pipe(pfd), SyscallSucceeds());
  FileDescriptor read_pipe(pfd[0]);
  FileDescriptor write_pipe(pfd[1]);

  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, [&write_pipe, &read_pipe]() {
        write_pipe.reset();
        TEST_CHECK_SUCCESS(kill(getpid(), SIGSTOP));
        char buf;
        TEST_PCHECK(read(read_pipe.get(), &buf, 1) == 1);
        read_pipe.reset();
        TEST_CHECK_SUCCESS(kill(getpid(), SIGSTOP));
        _exit(0);
      }));
  ScopedChildReaper cleanup(child);
  read_pipe.reset();

  siginfo_t info = {};
  ASSERT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WSTOPPED),
              SyscallSucceeds());
  EXPECT_EQ(info.si_code, CLD_STOPPED);

  EXPECT_THAT(PidfdSendSignal(pidfd.get(), SIGCONT, nullptr, 0),
              SyscallSucceeds());
  info = {};
  ASSERT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WCONTINUED),
              SyscallSucceeds());
  EXPECT_EQ(info.si_code, CLD_CONTINUED);

  info = {};
  ASSERT_THAT(write(write_pipe.get(), "C", 1), SyscallSucceedsWithValue(1));
  write_pipe.reset();
  ASSERT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WSTOPPED),
              SyscallSucceeds());
  EXPECT_EQ(info.si_code, CLD_STOPPED);

  info = {};
  EXPECT_THAT(PidfdSendSignal(pidfd.get(), SIGKILL, nullptr, 0),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WEXITED),
              SyscallSucceeds());
  EXPECT_EQ(info.si_code, CLD_KILLED);
  cleanup.Release();
}

TEST(PidfdTest, WaitNonblock) {
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);

  int flags = fcntl(pidfd.get(), F_GETFL, 0);
  ASSERT_THAT(fcntl(pidfd.get(), F_SETFL, flags | O_NONBLOCK),
              SyscallSucceeds());

  siginfo_t info = {};
  EXPECT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WEXITED),
              SyscallFailsWithErrno(EAGAIN));
  EXPECT_THAT(
      RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WEXITED | WNOHANG),
      SyscallSucceedsWithValue(0));

  kill(child, SIGKILL);
  ASSERT_THAT(fcntl(pidfd.get(), F_SETFL, flags), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(waitid)(P_PIDFD, pidfd.get(), &info, WEXITED),
              SyscallSucceeds());
  EXPECT_EQ(info.si_code, CLD_KILLED);
  cleanup.Release();
}

TEST(PidfdTest, Poll) {
  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() { _exit(0); }));
  ScopedChildReaper cleanup(child);

  // Wait for the child to become a zombie.
  siginfo_t info = {};
  ASSERT_THAT(RetryEINTR(waitid)(P_PID, child, &info, WEXITED | WNOWAIT),
              SyscallSucceeds());

  // The child is already a zombie, POLLIN should be immediately available.
  struct pollfd fds = {
      .fd = pidfd.get(),
      .events = POLLIN,
  };
  ASSERT_THAT(poll(&fds, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(fds.revents & POLLIN);

  // Reap the child to observe POLLHUP.
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  cleanup.Release();
  fds.revents = 0;
  ASSERT_THAT(poll(&fds, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(fds.revents & POLLIN);
  KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
  if (IsRunningOnGvisor() ||
      (version.major > 6 || (version.major == 6 && version.minor >= 10))) {
    EXPECT_TRUE(fds.revents & POLLHUP);
  }
}

TEST(PidfdTest, Epoll) {
  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() { _exit(0); }));
  ScopedChildReaper cleanup(child);

  // Wait for the child to become a zombie.
  siginfo_t info = {};
  ASSERT_THAT(RetryEINTR(waitid)(P_PID, child, &info, WEXITED | WNOWAIT),
              SyscallSucceeds());

  int epfd = epoll_create1(0);
  ASSERT_THAT(epfd, SyscallSucceeds());
  FileDescriptor epollfd(epfd);

  struct epoll_event ev = {};
  ev.events = EPOLLIN;
  ev.data.fd = pidfd.get();
  ASSERT_THAT(epoll_ctl(epollfd.get(), EPOLL_CTL_ADD, pidfd.get(), &ev),
              SyscallSucceeds());

  struct epoll_event events[1];
  // The child is already a zombie, EPOLLIN should be immediately available.
  ASSERT_THAT(epoll_wait(epollfd.get(), events, 1, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_TRUE(events[0].events & EPOLLIN);

  // Reap the child to observe EPOLLHUP.
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  cleanup.Release();
  events[0].events = 0;
  ASSERT_THAT(epoll_wait(epollfd.get(), events, 1, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_TRUE(events[0].events & EPOLLIN);
  KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
  if (IsRunningOnGvisor() ||
      (version.major > 6 || (version.major == 6 && version.minor >= 10))) {
    EXPECT_TRUE(events[0].events & EPOLLHUP);
  }
}

TEST(PidfdTest, SetnsInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  pid_t child = -1;
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() {
    pause();
    _exit(0);
  }));
  ScopedChildReaper cleanup(child);

  EXPECT_THAT(setns(pidfd.get(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(setns(pidfd.get(), -1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(setns(pidfd.get(), CLONE_VM), SyscallFailsWithErrno(EINVAL));
}

TEST(PidfdTest, SetnsPtraceEPERM) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  AutoCapability cap(CAP_SYS_PTRACE, false);

  int before;
  ASSERT_THAT(before = prctl(PR_GET_DUMPABLE), SyscallSucceeds());
  auto cleanup = Cleanup([before] {
    ASSERT_THAT(prctl(PR_SET_DUMPABLE, before), SyscallSucceeds());
  });
  // Mark ourselves as not dumpable.
  constexpr int kSuidDumpDisable = 0;
  TEST_PCHECK(prctl(PR_SET_DUMPABLE, kSuidDumpDisable, 0, 0, 0) == 0);

  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(getpid(), 0));
  EXPECT_THAT(InForkedProcess([&pidfd] {
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWNET));
                TEST_CHECK_ERRNO(syscall(SYS_setns, pidfd.get(), CLONE_NEWNET),
                                 EPERM);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(PidfdTest, SetnsExitedChild) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  pid_t child = -1;
  auto pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(Clone3Pidfd(child, []() { _exit(0); }));
  ScopedChildReaper cleanup(child);

  int std_status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &std_status, 0),
              SyscallSucceedsWithValue(child));
  cleanup.Release();
  EXPECT_THAT(setns(pidfd.get(), CLONE_NEWNET), SyscallFailsWithErrno(ESRCH));
}

TEST(PidfdTest, SetnsSingleNamespaceWorks) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int pfd[2];
  ASSERT_THAT(pipe(pfd), SyscallSucceeds());
  FileDescriptor pipe_read(pfd[0]);
  FileDescriptor pipe_write(pfd[1]);

  pid_t child = -1;
  constexpr char kNewHostname[] = "pidfd-uts-test";
  auto pidfd = ASSERT_NO_ERRNO_AND_VALUE(
      Clone3Pidfd(child, [&pipe_write, &kNewHostname]() {
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUTS));
        TEST_CHECK_SUCCESS(sethostname(kNewHostname, sizeof(kNewHostname) - 1));
        TEST_CHECK_SUCCESS(write(pipe_write.get(), "R", 1));
        pause();
        _exit(0);
      }));
  ScopedChildReaper cleanup(child);

  char buf;
  ASSERT_THAT(read(pipe_read.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(
      InForkedProcess([&pidfd, &kNewHostname] {
        TEST_CHECK_SUCCESS(syscall(SYS_setns, pidfd.get(), CLONE_NEWUTS));
        char current_hostname[256] = {};
        TEST_CHECK_SUCCESS(
            gethostname(current_hostname, sizeof(current_hostname)));
        TEST_PCHECK_MSG(strcmp(current_hostname, kNewHostname) == 0,
                        "hostname mismatch");
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(PidfdTest, PidfdThreadTracksSingleThread) {
  std::atomic<bool> stop_sibling{false};
  std::atomic<pid_t> tid{-1};

  auto t = std::make_unique<ScopedThread>([&]() {
    tid.store(syscall(SYS_gettid));
    while (!stop_sibling.load()) {
      sched_yield();
    }
  });
  auto cleanup = Cleanup([&t, &stop_sibling] {
    stop_sibling.store(true);
    t.reset();
  });

  // Wait till the sibling tells us its tid.
  while (tid.load() == -1) {
    sched_yield();
  }

  int pidfd_raw = syscall(SYS_pidfd_open, tid.load(), PIDFD_THREAD);
  if (pidfd_raw == -1 && errno == EINVAL) {
    GTEST_SKIP() << "PIDFD_THREAD not supported on this kernel";
  }
  ASSERT_THAT(pidfd_raw, SyscallSucceeds());
  FileDescriptor pidfd(pidfd_raw);

  // In the absence of PIDFD_THREAD, we should see ENOENT (EINVAL on older
  // kernels).
  int want_errno = ENOENT;
  if (!IsRunningOnGvisor()) {
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 15)) {
      want_errno = EINVAL;
    }
  }
  ASSERT_THAT(syscall(SYS_pidfd_open, tid.load(), 0),
              SyscallFailsWithErrno(want_errno));

  struct pollfd pfd = {
      .fd = pidfd.get(),
      .events = POLLIN,
  };
  // The sibling thread is alive, so the pidfd should NOT be readable.
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 0), SyscallSucceedsWithValue(0));
  // And we should be able to send it signals.
  EXPECT_THAT(PidfdSendSignal(pidfd_raw, 0, nullptr, PIDFD_SIGNAL_THREAD),
              SyscallSucceedsWithValue(0));

  // Stop the sibling thread to make the poll report POLLIN.
  stop_sibling.store(true);
  t.reset();
  cleanup.Release();
  pfd.revents = 0;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 1000), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(pfd.revents & POLLIN);
}

// PidfdThreadLeaderDelayedNotification verifies that a PIDFD_THREAD for a
// thread group leader only notifies when the entire thread group exits, even
// if the leader thread itself has already exited.
TEST(PidfdTest, PidfdThreadLeaderDelayedNotification) {
  if (!IsRunningOnGvisor()) {
    // Test only on kernels bearing this patch:
    // https://github.com/torvalds/linux/commit/0fb482728ba1
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 15)) {
      GTEST_SKIP() << "PIDFD_THREAD behavior requires kernel 6.15+";
    }
  }

  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  FileDescriptor read_pipe(pipe_fds[0]);
  FileDescriptor write_pipe(pipe_fds[1]);

  pid_t child;
  int exec_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe",
                  {"/proc/self/exe", "--pidfd_helper=RunLeaderDelayedHelper",
                   absl::StrCat("--pidfd_pipe_fd=", read_pipe.get())},
                  {}, &child, &exec_errno));
  ASSERT_EQ(exec_errno, 0);
  ASSERT_THAT(child, SyscallSucceeds());
  read_pipe.reset();
  auto leader_pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(child, PIDFD_THREAD));

  // Poll should timeout on the leader thread pidfd as long as the subthread is
  // alive.
  struct pollfd pfd = {
      .fd = leader_pidfd.get(),
      .events = POLLIN,
  };
  EXPECT_THAT(poll(&pfd, 1, 1000), SyscallSucceedsWithValue(0));

  // Let the subthread exit.
  ASSERT_THAT(write(write_pipe.get(), "a", 1), SyscallSucceedsWithValue(1));
  write_pipe.reset();
  // Now poll should succeed.
  EXPECT_THAT(poll(&pfd, 1, 5000), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(pfd.revents & POLLIN);
}

// PidfdThreadSubthreadNotification verifies that a PIDFD_THREAD for a
// non-leader thread notifies as soon as that thread exits, even if other
// threads (including the leader) in the same group are still alive.
TEST(PidfdTest, PidfdThreadSubthreadNotification) {
  if (!IsRunningOnGvisor()) {
    // Test only on kernels bearing this patch:
    // https://github.com/torvalds/linux/commit/0fb482728ba1
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 15)) {
      GTEST_SKIP() << "PIDFD_THREAD behavior requires kernel 6.15+";
    }
  }

  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  FileDescriptor read_pipe(pipe_fds[0]);
  FileDescriptor write_pipe(pipe_fds[1]);

  int tid_pipe_fds[2];
  ASSERT_THAT(pipe(tid_pipe_fds), SyscallSucceeds());
  FileDescriptor tid_read_pipe(tid_pipe_fds[0]);
  FileDescriptor tid_write_pipe(tid_pipe_fds[1]);

  pid_t child;
  int exec_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      "/proc/self/exe",
      {"/proc/self/exe", "--pidfd_helper=RunSubthreadNotificationHelper",
       absl::StrCat("--pidfd_pipe_fd=", read_pipe.get()),
       absl::StrCat("--pidfd_tid_pipe_fd=", tid_write_pipe.get())},
      {}, &child, &exec_errno));
  ASSERT_EQ(exec_errno, 0);
  ASSERT_THAT(child, SyscallSucceeds());
  tid_write_pipe.reset();
  read_pipe.reset();

  pid_t subthread_tid;
  ASSERT_THAT(read(tid_read_pipe.get(), &subthread_tid, sizeof(subthread_tid)),
              SyscallSucceedsWithValue(sizeof(subthread_tid)));
  auto subthread_pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(subthread_tid, PIDFD_THREAD));

  // Poll should timeout on the subthread pidfd as long as the subthread is
  // alive.
  struct pollfd pfd = {
      .fd = subthread_pidfd.get(),
      .events = POLLIN,
  };
  EXPECT_THAT(poll(&pfd, 1, 1000), SyscallSucceedsWithValue(0));
  // Let subthread exit.
  ASSERT_THAT(write(write_pipe.get(), "a", 1), SyscallSucceedsWithValue(1));
  write_pipe.reset();
  // Poll on subthread pidfd should succeed even while leader is alive.
  EXPECT_THAT(poll(&pfd, 1, 5000), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(pfd.revents & POLLIN);
}

// PidfdThreadExecRevival verifies that an execve() "revives" a thread group
// and prevents a PIDFD_THREAD for the leader PID from notifying, even if the
// original leader has exited.
TEST(PidfdTest, PidfdThreadExecRevival) {
  if (!IsRunningOnGvisor()) {
    // Test only on kernels bearing this patch:
    // https://github.com/torvalds/linux/commit/0fb482728ba1
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 15)) {
      GTEST_SKIP() << "PIDFD_THREAD behavior requires kernel 6.15+";
    }
  }

  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  FileDescriptor read_pipe(pipe_fds[0]);
  FileDescriptor write_pipe(pipe_fds[1]);

  int tid_pipe_fds[2];
  ASSERT_THAT(pipe(tid_pipe_fds), SyscallSucceeds());
  FileDescriptor tid_read_pipe(tid_pipe_fds[0]);
  FileDescriptor tid_write_pipe(tid_pipe_fds[1]);

  pid_t child;
  int exec_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe",
                  {"/proc/self/exe", "--pidfd_helper=RunExecRevivalHelper",
                   absl::StrCat("--pidfd_pipe_fd=", read_pipe.get()),
                   absl::StrCat("--pidfd_tid_pipe_fd=", tid_write_pipe.get())},
                  {}, &child, &exec_errno));
  ASSERT_EQ(exec_errno, 0);
  ASSERT_THAT(child, SyscallSucceeds());
  tid_write_pipe.reset();
  read_pipe.reset();

  pid_t subthread_tid;
  ASSERT_THAT(read(tid_read_pipe.get(), &subthread_tid, sizeof(subthread_tid)),
              SyscallSucceedsWithValue(sizeof(subthread_tid)));
  auto leader_pidfd = ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(child, PIDFD_THREAD));
  auto subthread_pidfd =
      ASSERT_NO_ERRNO_AND_VALUE(PidfdOpen(subthread_tid, PIDFD_THREAD));

  // Signal subthread to exec.
  ASSERT_THAT(write(write_pipe.get(), "a", 1), SyscallSucceedsWithValue(1));
  write_pipe.reset();
  // The subthread should notify because it is killed by the above exec.
  struct pollfd sub_pfd = {
      .fd = subthread_pidfd.get(),
      .events = POLLIN,
  };
  EXPECT_THAT(poll(&sub_pfd, 1, 5000), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(sub_pfd.revents & POLLIN);

  // The leader pidfd should NOT notify because it is "revived" by the exec.
  struct pollfd leader_pfd = {
      .fd = leader_pidfd.get(),
      .events = POLLIN,
  };
  EXPECT_THAT(poll(&leader_pfd, 1, 1000), SyscallSucceedsWithValue(0));

  // Now kill the revived process and verify the leader pidfd finally notifies.
  EXPECT_THAT(kill(child, SIGKILL), SyscallSucceeds());
  EXPECT_THAT(poll(&leader_pfd, 1, 5000), SyscallSucceedsWithValue(1));
  EXPECT_TRUE(leader_pfd.revents & POLLIN);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  std::string helper = absl::GetFlag(FLAGS_pidfd_helper);
  if (!helper.empty()) {
    if (helper == "RunLeaderDelayedHelper") {
      gvisor::testing::RunLeaderDelayedHelper();
    } else if (helper == "RunSubthreadNotificationHelper") {
      gvisor::testing::RunSubthreadNotificationHelper();
    } else if (helper == "RunExecRevivalHelper") {
      gvisor::testing::RunExecRevivalHelper();
    } else if (helper == "RunPauseHelper") {
      gvisor::testing::RunPauseHelper();
    }
    return 0;
  }

  return gvisor::testing::RunAllTests();
}
