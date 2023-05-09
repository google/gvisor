// Copyright 2022 The gVisor Authors.
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

#include <bits/types/struct_itimerspec.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <iostream>
#include <ostream>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void runForkExecve() {
  auto root_or_error = Open("/", O_RDONLY, 0);
  auto& root = root_or_error.ValueOrDie();

  pid_t child;
  int execve_errno;
  ExecveArray argv = {"/bin/true"};
  ExecveArray envv = {"TEST=123"};
  auto kill_or_error = ForkAndExecveat(root.get(), "/bin/true", argv, envv, 0,
                                       nullptr, &child, &execve_errno);
  ASSERT_EQ(0, execve_errno);
  // Don't kill child, just wait for gracefully exit.
  kill_or_error.ValueOrDie().Release();
  RetryEINTR(waitpid)(child, nullptr, 0);
}

// Creates a simple UDS in the abstract namespace and send one byte from the
// client to the server.
void runSocket() {
  auto path = absl::StrCat(std::string("\0", 1), "trace_test.", getpid(),
                           absl::GetCurrentTimeNanos());

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);

  int parent_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (parent_sock < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([parent_sock] { close(parent_sock); });

  if (bind(parent_sock, reinterpret_cast<struct sockaddr*>(&addr),
           sizeof(addr))) {
    err(1, "bind");
  }
  if (listen(parent_sock, 5) < 0) {
    err(1, "listen");
  }

  pid_t pid = fork();
  if (pid < 0) {
    // Fork error.
    err(1, "fork");
  } else if (pid == 0) {
    // Child.
    close(parent_sock);  // ensure it's not mistakely used in child.

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
      err(1, "socket");
    }
    auto server_closer = absl::MakeCleanup([server] { close(server); });

    if (connect(server, reinterpret_cast<struct sockaddr*>(&addr),
                sizeof(addr)) < 0) {
      err(1, "connect");
    }

    char buf = 'A';
    int bytes = write(server, &buf, sizeof(buf));
    if (bytes != 1) {
      err(1, "write: %d", bytes);
    }
    exit(0);

  } else {
    // Parent.
    int client = RetryEINTR(accept)(parent_sock, nullptr, nullptr);
    if (client < 0) {
      err(1, "accept");
    }
    auto client_closer = absl::MakeCleanup([client] { close(client); });

    char buf;
    int bytes = read(client, &buf, sizeof(buf));
    if (bytes != 1) {
      err(1, "read: %d", bytes);
    }

    // Wait to reap the child.
    RetryEINTR(waitpid)(pid, nullptr, 0);
  }
}

void runReadWrite() {
  const std::string path = "read-write.txt";
  auto fd_or = Open(path, O_RDWR | O_CREAT, 0644);
  if (!fd_or.ok()) {
    err(1, "open(O_CREAT): %s", fd_or.error().ToString().c_str());
  }
  auto cleaup = absl::MakeCleanup([path] { unlink(path.c_str()); });

  auto fd = std::move(fd_or.ValueOrDie());

  // Test different flavors of write.
  char msg[] = "hello world";
  if (WriteFd(fd.get(), msg, ABSL_ARRAYSIZE(msg)) < 0) {
    err(1, "write");
  }
  if (PwriteFd(fd.get(), msg, ABSL_ARRAYSIZE(msg), 10) < 0) {
    err(1, "pwrite");
  }

  struct iovec write_vecs[] = {
      {
          .iov_base = msg,
          .iov_len = ABSL_ARRAYSIZE(msg),
      },
      {
          .iov_base = msg,
          .iov_len = ABSL_ARRAYSIZE(msg) / 2,
      },
  };
  if (writev(fd.get(), write_vecs, ABSL_ARRAYSIZE(write_vecs)) < 0) {
    err(1, "writev");
  }
  if (pwritev(fd.get(), write_vecs, ABSL_ARRAYSIZE(write_vecs), 10) < 0) {
    err(1, "pwritev");
  }
  if (pwritev2(fd.get(), write_vecs, ABSL_ARRAYSIZE(write_vecs), 10,
               RWF_HIPRI) < 0) {
    err(1, "pwritev2");
  }

  // Rewind the file and test different flavors of read.
  if (lseek(fd.get(), 0, SEEK_SET) < 0) {
    err(1, "seek(0)");
  }
  char buf[1024];
  if (ReadFd(fd.get(), buf, ABSL_ARRAYSIZE(buf)) < 0) {
    err(1, "read");
  }
  if (PreadFd(fd.get(), buf, ABSL_ARRAYSIZE(buf), 20) < 0) {
    err(1, "read");
  }

  // Reuse same buffer, since it's not using the result anyways.
  struct iovec read_vecs[] = {
      {
          .iov_base = buf,
          .iov_len = ABSL_ARRAYSIZE(msg),
      },
      {
          .iov_base = buf,
          .iov_len = ABSL_ARRAYSIZE(msg) / 2,
      },
  };
  if (readv(fd.get(), read_vecs, ABSL_ARRAYSIZE(read_vecs)) < 0) {
    err(1, "writev");
  }
  if (preadv(fd.get(), read_vecs, ABSL_ARRAYSIZE(read_vecs), 20) < 0) {
    err(1, "pwritev");
  }
  if (preadv2(fd.get(), read_vecs, ABSL_ARRAYSIZE(read_vecs), 20, RWF_HIPRI) <
      0) {
    err(1, "pwritev2");
  }
}

void runChdir() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int res = chdir(pathname);
  if (res != 0) {
    err(1, "chdir");
  }
  rmdir(pathname);
}

void runFchdir() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int fd = open(pathname, O_DIRECTORY | O_RDONLY);
  int res = fchdir(fd);
  if (res != 0) {
    err(1, "fchdir");
  }
  rmdir(pathname);
  close(fd);
}

void runSetgid() {
  auto get = setgid(0);
  if (get != 0) {
    err(1, "setgid");
  }
}

void runSetuid() {
  auto get = setuid(0);
  if (get != 0) {
    err(1, "setuid");
  }
}

void runSetsid() {
  auto get = setsid();
  // Operation is not permitted so we get an error.
  if (get != -1) {
    err(1, "setsid");
  }
}

void runSetresuid() {
  auto get = setresuid(0, 0, 0);
  if (get != 0) {
    err(1, "setresuid");
  }
}

void runSetresgid() {
  auto get = setresgid(0, 0, 0);
  if (get != 0) {
    err(1, "setresgid");
  }
}

void runChroot() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  if (chroot(pathname)) {
    err(1, "chroot");
  }
}
void runDup() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int fd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (fd < 0) {
    err(1, "open");
  }
  int res = dup(fd);
  if (res < 0) {
    err(1, "dup");
  }
  rmdir(pathname);
}

void runDup2() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int oldfd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (oldfd < 0) {
    err(1, "open");
  }
  int newfd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (newfd < 0) {
    err(1, "open");
  }
  int res = dup2(oldfd, newfd);
  if (res != newfd) {
    err(1, "dup2");
  }
  rmdir(pathname);
}

void runDup3() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int oldfd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (oldfd < 0) {
    err(1, "open");
  }
  int newfd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (newfd < 0) {
    err(1, "open");
  }
  int res = dup3(oldfd, newfd, O_CLOEXEC);
  if (res != newfd) {
    err(1, "dup3");
  }
  rmdir(pathname);
}

void runPrlimit64() {
  struct rlimit setlim;
  setlim.rlim_cur = 0;
  setlim.rlim_max = RLIM_INFINITY;
  int res = prlimit(0, RLIMIT_DATA, &setlim, nullptr);
  if (res != 0) {
    err(1, "prlimit64");
  }
}

void runEventfd() {
  int res = eventfd(0, EFD_NONBLOCK);
  if (res < 0) {
    err(1, "eventfd");
  }
}

void runEventfd2() {
  int res = Eventdfd2Setup(0, EFD_NONBLOCK);
  if (res < 0) {
    err(1, "eventfd2");
  }
}

void runBind() {
  auto path = absl::StrCat(std::string("\0", 1), "trace_test.abc");

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([fd] { close(fd); });

  if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr))) {
    err(1, "bind");
  }
}

void runAccept() {
  auto path = absl::StrCat(std::string("\0", 1), "trace_test.abc");

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);

  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([server] { close(server); });

  if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    err(1, "bind");
  }

  if (listen(server, 5) < 0) {
    err(1, "listen");
  }

  int client = socket(AF_UNIX, SOCK_STREAM, 0);
  if (client < 0) {
    err(1, "socket");
  }
  auto client_closer = absl::MakeCleanup([client] { close(client); });

  if (connect(client, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) <
      0) {
    err(1, "connect");
  }

  int fd = RetryEINTR(accept)(server, nullptr, nullptr);
  if (fd < 0) {
    err(1, "accept");
  }
  close(fd);
}

void runAccept4() {
  auto path = absl::StrCat(std::string("\0", 1), "trace_test.abc");

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);

  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([server] { close(server); });

  if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    err(1, "bind");
  }

  if (listen(server, 5) < 0) {
    err(1, "listen");
  }

  int client = socket(AF_UNIX, SOCK_STREAM, 0);
  if (client < 0) {
    err(1, "socket");
  }
  auto client_closer = absl::MakeCleanup([client] { close(client); });

  if (connect(client, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) <
      0) {
    err(1, "connect");
  }

  int fd = RetryEINTR(accept4)(server, nullptr, nullptr, SOCK_CLOEXEC);
  if (fd < 0) {
    err(1, "accept4");
  }
  close(fd);
}

void runSignalfd4() {
  sigset_t mask;
  sigemptyset(&mask);
  int res = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (res < 0) {
    err(1, "signalfd4");
  }
}

void runFcntl() {
  const auto pathname = "trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int fd = open(pathname, O_DIRECTORY | O_RDONLY);
  if (fd < 0) {
    err(1, "open");
  }
  auto fd_closer = absl::MakeCleanup([fd] { close(fd); });

  int res = fcntl(fd, F_GETFL);
  if (res < 0) {
    err(1, "fcntl");
  }
  rmdir(pathname);
}

void runPipe() {
  int fd[2];
  int res = pipe(fd);
  if (res < 0) {
    err(1, "pipe");
  }
  close(fd[0]);
  close(fd[1]);
}

void runPipe2() {
  int fd[2];
  int res = pipe2(fd, O_CLOEXEC);
  if (res < 0) {
    err(1, "pipe2");
  }
  close(fd[0]);
  close(fd[1]);
}

void runTimerfdCreate() {
  int fd = timerfd_create(CLOCK_REALTIME, 0);
  if (fd < 0) {
    err(1, "timerfd_create");
  }
  close(fd);
}

void runTimerfdSettime() {
  int fd = timerfd_create(CLOCK_REALTIME, 0);
  if (fd < 0) {
    err(1, "timerfd_create");
  }
  auto fd_closer = absl::MakeCleanup([fd] { close(fd); });

  constexpr auto kInitial = absl::Milliseconds(10);
  constexpr auto kInterval = absl::Milliseconds(25);
  const itimerspec val = {absl::ToTimespec(kInitial),
                          absl::ToTimespec(kInterval)};
  int res = timerfd_settime(fd, TFD_TIMER_ABSTIME, &val, 0);
  if (res < 0) {
    err(1, "timerfd_settime");
  }
}

void runTimerfdGettime() {
  int fd = timerfd_create(CLOCK_REALTIME, 0);
  if (fd < 0) {
    err(1, "timerfd_create");
  }
  auto fd_closer = absl::MakeCleanup([fd] { close(fd); });

  itimerspec val;
  int res = timerfd_gettime(fd, &val);
  if (res < 0) {
    err(1, "timerfd_gettime");
  }
}
// signalfd(2), fork(2), and vfork(2) system calls are not supported in arm
// architecture.
#ifdef __x86_64__
void runFork() {
  pid_t pid = syscall(__NR_fork);
  if (pid < 0) {
    err(1, "fork");
  } else if (pid == 0) {
    exit(0);
  }
  RetryEINTR(waitpid)(pid, nullptr, 0);
}

void runVfork() {
  pid_t pid = vfork();
  if (pid < 0) {
    err(1, "vfork");
  } else if (pid == 0) {
    _exit(0);
  }
  RetryEINTR(waitpid)(pid, nullptr, 0);
}

void runSignalfd() {
  sigset_t mask;
  sigemptyset(&mask);
  constexpr int kSizeofKernelSigset = 8;
  int res = syscall(__NR_signalfd, -1, &mask, kSizeofKernelSigset);
  if (res < 0) {
    err(1, "signalfd");
  }
}
#endif

void runClone() {
  Mapping child_stack = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  int child_pid;
  child_pid = clone(
      +[](void*) { return 0; },
      reinterpret_cast<void*>(child_stack.addr() + kPageSize),
      SIGCHLD | CLONE_VFORK | CLONE_FILES, nullptr);

  if (child_pid < 0) {
    err(1, "clone");
  }
  RetryEINTR(waitpid)(child_pid, nullptr, 0);
}

void runInotifyInit() {
  int fd = inotify_init();
  if (fd < 0) {
    err(1, "inotify_init");
  }
  close(fd);
}

void runInotifyInit1() {
  int fd = inotify_init1(IN_NONBLOCK);
  if (fd < 0) {
    err(1, "inotify_init1");
  }
  close(fd);
}

void runInotifyAddWatch() {
  const auto pathname = "timer_trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int fd = inotify_init1(IN_NONBLOCK);
  if (fd < 0) {
    err(1, "inotify_init1");
  }
  auto fd_closer = absl::MakeCleanup([fd] { close(fd); });

  int res = inotify_add_watch(fd, pathname, IN_NONBLOCK);
  if (res < 0) {
    err(1, "inotify_add_watch");
  }
  rmdir(pathname);
}

void runInotifyRmWatch() {
  const auto pathname = "timer_trace_test.abc";
  static constexpr mode_t kDefaultDirMode = 0755;
  int path_or_error = mkdir(pathname, kDefaultDirMode);
  if (path_or_error != 0) {
    err(1, "mkdir");
  }
  int fd = inotify_init1(IN_NONBLOCK);
  if (fd < 0) {
    err(1, "inotify_init1");
  }
  auto fd_closer = absl::MakeCleanup([fd] { close(fd); });

  int wd = inotify_add_watch(fd, pathname, IN_NONBLOCK);
  if (wd < 0) {
    err(1, "inotify_add_watch");
  }
  int res = inotify_rm_watch(fd, wd);
  if (res < 0) {
    err(1, "inotify_rm_watch");
  }
  rmdir(pathname);
}

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  ::gvisor::testing::runForkExecve();
  ::gvisor::testing::runSocket();
  ::gvisor::testing::runReadWrite();
  ::gvisor::testing::runChdir();
  ::gvisor::testing::runFchdir();
  ::gvisor::testing::runSetgid();
  ::gvisor::testing::runSetuid();
  ::gvisor::testing::runSetsid();
  ::gvisor::testing::runSetresuid();
  ::gvisor::testing::runSetresgid();
  ::gvisor::testing::runDup();
  ::gvisor::testing::runDup2();
  ::gvisor::testing::runDup3();
  ::gvisor::testing::runPrlimit64();
  ::gvisor::testing::runEventfd();
  ::gvisor::testing::runEventfd2();
  ::gvisor::testing::runBind();
  ::gvisor::testing::runAccept();
  ::gvisor::testing::runAccept4();
  ::gvisor::testing::runSignalfd4();
  ::gvisor::testing::runFcntl();
  ::gvisor::testing::runPipe();
  ::gvisor::testing::runPipe2();
  ::gvisor::testing::runTimerfdCreate();
  ::gvisor::testing::runTimerfdSettime();
  ::gvisor::testing::runTimerfdGettime();
  ::gvisor::testing::runClone();
  ::gvisor::testing::runInotifyInit();
  ::gvisor::testing::runInotifyInit1();
  ::gvisor::testing::runInotifyAddWatch();
  ::gvisor::testing::runInotifyRmWatch();
// signalfd(2), fork(2), and vfork(2) system calls are not supported in arm
// architecture.
#ifdef __x86_64__
  ::gvisor::testing::runSignalfd();
  ::gvisor::testing::runFork();
  ::gvisor::testing::runVfork();
#endif
  // Run chroot at the end since it changes the root for all other tests.
  ::gvisor::testing::runChroot();
  return 0;
}
