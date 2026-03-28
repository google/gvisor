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
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
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

namespace gvisor {
namespace testing {
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

}  // namespace
}  // namespace testing
}  // namespace gvisor
