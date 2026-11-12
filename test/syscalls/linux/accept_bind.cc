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

#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/signal_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(AllSocketPairTest, Listen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenIncreaseBacklog) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 10), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenDecreaseBacklog) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 1), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenBacklogSizes) {
  DisableSave ds;
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  int type;
  socklen_t typelen = sizeof(type);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &typelen),
      SyscallSucceeds());

  std::array<int, 3> backlogs = {-1, 0, 1};
  for (auto& backlog : backlogs) {
    ASSERT_THAT(listen(sockets->first_fd(), backlog), SyscallSucceeds());

    int expected_accepts = backlog;
    if (backlog < 0) {
      expected_accepts = 1024;
    }
    for (int i = 0; i < expected_accepts; i++) {
      SCOPED_TRACE(absl::StrCat("i=", i));
      // Connect to the listening socket.
      const FileDescriptor client =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
      ASSERT_THAT(connect(client.get(), sockets->first_addr(),
                          sockets->first_addr_size()),
                  SyscallSucceeds());
      const FileDescriptor accepted = ASSERT_NO_ERRNO_AND_VALUE(
          Accept(sockets->first_fd(), nullptr, nullptr));
    }
  }
}

// ListenWithFullQueue makes the first socket listen with a full accept queue
// and returns the pending connection that fills it.
PosixErrorOr<FileDescriptor> ListenWithFullQueue(const SocketPair& sockets,
                                                 int type) {
  RETURN_ERROR_IF_SYSCALL_FAIL(bind(sockets.first_fd(), sockets.first_addr(),
                                    sockets.first_addr_size()));
  RETURN_ERROR_IF_SYSCALL_FAIL(listen(sockets.first_fd(), 0));
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor pending,
                         Socket(AF_UNIX, type | SOCK_NONBLOCK, 0));
  RETURN_ERROR_IF_SYSCALL_FAIL(
      connect(pending.get(), sockets.first_addr(), sockets.first_addr_size()));
  return pending;
}

TEST_P(AllSocketPairTest, ConnectBlocksWhileBacklogFull) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  const FileDescriptor pending =
      ASSERT_NO_ERRNO_AND_VALUE(ListenWithFullQueue(*sockets, type));
  const FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));

  ScopedThread accepter([&] {
    absl::SleepFor(absl::Milliseconds(100));
    MaybeSave();
    EXPECT_NO_ERRNO(Accept(sockets->first_fd(), nullptr, nullptr));
  });
  EXPECT_THAT(
      connect(client.get(), sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceeds());
}

void NoopSignalHandler(int) {}

// WaitUntilSleeping waits until thread tid is in an interruptible sleep.
void WaitUntilSleeping(pid_t tid) {
  const std::string path = absl::StrCat("/proc/", tid, "/stat");
  while (true) {
    const std::string stat = ASSERT_NO_ERRNO_AND_VALUE(GetContents(path));
    if (stat[stat.rfind(')') + 2] == 'S') {
      return;
    }
    absl::SleepFor(absl::Milliseconds(10));
  }
}

TEST_P(AllSocketPairTest, InterruptedConnectUsesTimeoutFromStart) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 0), SyscallSucceeds());

  struct sigaction sa = {};
  sa.sa_handler = NoopSignalHandler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  const auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGURG, sa));
  const pthread_t target = pthread_self();
  const pid_t tid = gettid();

  // A signal fails a connect that started with a timeout, even with
  // SA_RESTART, and restarts one that started without, whatever the timeout
  // is changed to while it waits.
  for (const bool timed : {true, false}) {
    const FileDescriptor pending =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type | SOCK_NONBLOCK, 0));
    ASSERT_THAT(connect(pending.get(), sockets->first_addr(),
                        sockets->first_addr_size()),
                SyscallSucceeds());
    const FileDescriptor client =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
    const struct timeval timeout = {.tv_sec = timed ? 10 : 0};
    ASSERT_THAT(setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
                           sizeof(timeout)),
                SyscallSucceeds());

    ScopedThread interrupter([&] {
      // A save here would restart an untimed connect, which would then read
      // the new timeout.
      DisableSave ds;
      WaitUntilSleeping(tid);
      const struct timeval changed = {.tv_sec = timed ? 0 : 10};
      EXPECT_THAT(setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &changed,
                             sizeof(changed)),
                  SyscallSucceeds());
      EXPECT_EQ(pthread_kill(target, SIGURG), 0);
      ds.reset();
      absl::SleepFor(absl::Milliseconds(100));
      EXPECT_NO_ERRNO(Accept(sockets->first_fd(), nullptr, nullptr));
    });
    if (timed) {
      EXPECT_THAT(connect(client.get(), sockets->first_addr(),
                          sockets->first_addr_size()),
                  SyscallFailsWithErrno(EINTR));
    } else {
      EXPECT_THAT(connect(client.get(), sockets->first_addr(),
                          sockets->first_addr_size()),
                  SyscallSucceeds());
    }
  }
}

TEST_P(AllSocketPairTest, BlockedConnectTimesOut) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  const FileDescriptor pending =
      ASSERT_NO_ERRNO_AND_VALUE(ListenWithFullQueue(*sockets, type));
  const FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
  const struct timeval timeout = {.tv_sec = 1};
  ASSERT_THAT(setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(timeout)),
              SyscallSucceeds());

  const auto now = [] {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return absl::TimeFromTimespec(ts);
  };
  const absl::Time start = now();
  EXPECT_THAT(
      connect(client.get(), sockets->first_addr(), sockets->first_addr_size()),
      SyscallFailsWithErrno(EAGAIN));
  const absl::Duration elapsed = now() - start;
  EXPECT_GE(elapsed, absl::Milliseconds(990));
}

TEST_P(AllSocketPairTest, SaveDuringTracedConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  const FileDescriptor pending =
      ASSERT_NO_ERRNO_AND_VALUE(ListenWithFullQueue(*sockets, type));

  const pid_t child = fork();
  if (child == 0) {
    // Linux never resumes connect with restart_syscall, so deny it.
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_restart_syscall, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {.len = 4, .filter = filter};
    TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_PCHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0);
    TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
    TEST_PCHECK(raise(SIGSTOP) == 0);
    const int fd = socket(AF_UNIX, type, 0);
    TEST_PCHECK(fd >= 0);
    const struct timeval timeout = {.tv_sec = 10};
    TEST_PCHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                           sizeof(timeout)) == 0);
    TEST_PCHECK(
        connect(fd, sockets->first_addr(), sockets->first_addr_size()) == 0);
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());

  // The save makes the tracer see the connect exit before it restarts.
  ScopedThread accepter([&] {
    // Saves while polling would keep waking the connect before it sleeps.
    DisableSave ds;
    WaitUntilSleeping(child);
    ds.reset();
    MaybeSave();
    EXPECT_NO_ERRNO(Accept(sockets->first_fd(), nullptr, nullptr));
  });
  // Syscall matchers would save at every stop, so the connect would never
  // stay asleep for the accepter.
  int status;
  while (true) {
    ASSERT_EQ(waitpid(child, &status, 0), child);
    if (!WIFSTOPPED(status)) {
      break;
    }
    const int sig = WSTOPSIG(status);
    ASSERT_EQ(ptrace(PTRACE_SYSCALL, child, 0,
                     sig == SIGSTOP || sig == SIGTRAP ? 0 : sig),
              0);
  }
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

TEST_P(AllSocketPairTest, ListenerCloseFailsBlockedConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  const FileDescriptor pending =
      ASSERT_NO_ERRNO_AND_VALUE(ListenWithFullQueue(*sockets, type));
  const FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
  FileDescriptor listener(sockets->release_first_fd());
  const pid_t tid = gettid();

  ScopedThread closer([&] {
    WaitUntilSleeping(tid);
    listener.reset();
  });
  EXPECT_THAT(
      connect(client.get(), sockets->first_addr(), sockets->first_addr_size()),
      SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, ListenBacklogIncreaseWakesBlockedConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int type = GetParam().type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  const FileDescriptor pending =
      ASSERT_NO_ERRNO_AND_VALUE(ListenWithFullQueue(*sockets, type));
  const FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
  const pid_t tid = gettid();

  ScopedThread lister([&] {
    WaitUntilSleeping(tid);
    EXPECT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  });
  EXPECT_THAT(
      connect(client.get(), sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenWithoutBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(listen(sockets->first_fd(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, DoubleBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, BindListenBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, DoubleListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, DoubleConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(EISCONN));
}

TEST_P(AllSocketPairTest, Connect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ConnectWithWrongType) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int type;
  socklen_t typelen = sizeof(type);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &typelen),
      SyscallSucceeds());
  switch (type) {
    case SOCK_STREAM:
      type = SOCK_SEQPACKET;
      break;
    case SOCK_SEQPACKET:
      type = SOCK_STREAM;
      break;
  }

  const FileDescriptor another_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  if (sockets->first_addr()->sa_data[0] != 0) {
    ASSERT_THAT(connect(another_socket.get(), sockets->first_addr(),
                        sockets->first_addr_size()),
                SyscallFailsWithErrno(EPROTOTYPE));
  } else {
    ASSERT_THAT(connect(another_socket.get(), sockets->first_addr(),
                        sockets->first_addr_size()),
                SyscallFailsWithErrno(ECONNREFUSED));
  }

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ConnectNonListening) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, ConnectToFilePath) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "/tmp";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  ASSERT_THAT(
      connect(sockets->second_fd(),
              reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, ConnectToInvalidAbstractPath) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  ASSERT_THAT(
      connect(sockets->second_fd(),
              reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, SelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->first_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, ConnectWithoutListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, Accept) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptValidAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  struct sockaddr_un addr = {};
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(
      accepted = accept(sockets->first_fd(), AsSockAddr(&addr), &addr_len),
      SyscallSucceeds());
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptNegativeAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a negative addr_len, accept returns EINVAL,
  struct sockaddr_un addr = {};
  socklen_t addr_len = -1;
  ASSERT_THAT(accept(sockets->first_fd(), AsSockAddr(&addr), &addr_len),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, AcceptLargePositiveAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a large (positive) addr_len, accept does not return EINVAL.
  int accepted = -1;
  char addr_buf[200];
  socklen_t addr_len = sizeof(addr_buf);
  ASSERT_THAT(accepted = accept(sockets->first_fd(),
                                reinterpret_cast<struct sockaddr*>(addr_buf),
                                &addr_len),
              SyscallSucceeds());
  // addr_len should have been updated by accept().
  EXPECT_LT(addr_len, sizeof(addr_buf));
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptVeryLargePositiveAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a large (positive) addr_len, accept does not return EINVAL.
  int accepted = -1;
  char addr_buf[2000];
  socklen_t addr_len = sizeof(addr_buf);
  ASSERT_THAT(accepted = accept(sockets->first_fd(),
                                reinterpret_cast<struct sockaddr*>(addr_buf),
                                &addr_len),
              SyscallSucceeds());
  // addr_len should have been updated by accept().
  EXPECT_LT(addr_len, sizeof(addr_buf));
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptWithoutBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, AcceptWithoutListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, GetRemoteAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getpeername(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->first_addr_len());
  EXPECT_EQ(0, memcmp(&addr, sockets->first_addr(), sockets->first_addr_len()));
}

TEST_P(AllSocketPairTest, UnboundGetLocalAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getsockname(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, 2);
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BoundGetLocalAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getsockname(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BoundConnector) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, UnboundSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, 0);
}

TEST_P(AllSocketPairTest, BoundSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BindAfterConnectSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BindAfterAcceptSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, AllSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(
            FilesystemUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
