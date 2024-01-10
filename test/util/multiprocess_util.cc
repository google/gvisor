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

#include "test/util/multiprocess_util.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <functional>
#include <string>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// exec_fn wraps a variant of the exec family, e.g. execve or execveat.
PosixErrorOr<Cleanup> ForkAndExecHelper(const std::function<void()>& exec_fn,
                                        const std::function<void()>& fn,
                                        pid_t* child, int* execve_errno) {
  int pfds[2];
  int ret = pipe2(pfds, O_CLOEXEC);
  if (ret < 0) {
    return PosixError(errno, "pipe failed");
  }
  FileDescriptor rfd(pfds[0]);
  FileDescriptor wfd(pfds[1]);

  int parent_stdout = dup(STDOUT_FILENO);
  if (parent_stdout < 0) {
    return PosixError(errno, "dup stdout");
  }
  int parent_stderr = dup(STDERR_FILENO);
  if (parent_stdout < 0) {
    return PosixError(errno, "dup stderr");
  }

  pid_t pid = fork();
  if (pid < 0) {
    return PosixError(errno, "fork failed");
  } else if (pid == 0) {
    // Child.
    rfd.reset();
    if (dup2(parent_stdout, STDOUT_FILENO) < 0) {
      _exit(3);
    }
    if (dup2(parent_stderr, STDERR_FILENO) < 0) {
      _exit(4);
    }
    close(parent_stdout);
    close(parent_stderr);

    // Clean ourself up in case the parent doesn't.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL)) {
      _exit(3);
    }

    if (fn) {
      fn();
    }

    // Call variant of exec function.
    exec_fn();

    int error = errno;
    if (WriteFd(pfds[1], &error, sizeof(error)) != sizeof(error)) {
      // We can't do much if the write fails, but we can at least exit with a
      // different code.
      _exit(2);
    }
    _exit(1);
  }

  // Parent.
  if (child) {
    *child = pid;
  }

  auto cleanup = Cleanup([pid] {
    kill(pid, SIGKILL);
    RetryEINTR(waitpid)(pid, nullptr, 0);
  });

  wfd.reset();

  int read_errno;
  ret = ReadFd(rfd.get(), &read_errno, sizeof(read_errno));
  if (ret == 0) {
    // Other end of the pipe closed, execve must have succeeded.
    read_errno = 0;
  } else if (ret < 0) {
    return PosixError(errno, "read pipe failed");
  } else if (ret != sizeof(read_errno)) {
    return PosixError(EPIPE, absl::StrCat("pipe read wrong size ", ret));
  }

  if (execve_errno) {
    *execve_errno = read_errno;
  }

  return std::move(cleanup);
}

}  // namespace

PosixErrorOr<Cleanup> ForkAndExec(const std::string& filename,
                                  const ExecveArray& argv,
                                  const ExecveArray& envv,
                                  const std::function<void()>& fn, pid_t* child,
                                  int* execve_errno) {
  char* const* argv_data = argv.get();
  char* const* envv_data = envv.get();
  const std::function<void()> exec_fn = [=] {
    execve(filename.c_str(), argv_data, envv_data);
  };
  return ForkAndExecHelper(exec_fn, fn, child, execve_errno);
}

PosixErrorOr<Cleanup> ForkAndExecveat(const int32_t dirfd,
                                      const std::string& pathname,
                                      const ExecveArray& argv,
                                      const ExecveArray& envv, const int flags,
                                      const std::function<void()>& fn,
                                      pid_t* child, int* execve_errno) {
  char* const* argv_data = argv.get();
  char* const* envv_data = envv.get();
  const std::function<void()> exec_fn = [=] {
    syscall(__NR_execveat, dirfd, pathname.c_str(), argv_data, envv_data,
            flags);
  };
  return ForkAndExecHelper(exec_fn, fn, child, execve_errno);
}

PosixErrorOr<int> InForkedProcess(const std::function<void()>& fn) {
  pid_t pid = fork();
  if (pid == 0) {
    fn();
    TEST_CHECK_MSG(!::testing::Test::HasFailure(),
                   "EXPECT*/ASSERT* failed. These are not async-signal-safe "
                   "and must not be called from fn.");
    _exit(0);
  }
  MaybeSave();
  if (pid < 0) {
    return PosixError(errno, "fork failed");
  }

  int status;
  if (waitpid(pid, &status, 0) < 0) {
    return PosixError(errno, "waitpid failed");
  }

  return status;
}

PosixErrorOr<int> InForkedUserMountNamespace(
    const std::function<void()>& parent, const std::function<void()>& child) {
  std::string umap_str = absl::StrFormat("0 %lu 1", geteuid());
  std::string gmap_str = absl::StrFormat("0 %lu 1", getegid());
  int sync_sks[2] = {};
  TEST_CHECK_SUCCESS(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sync_sks));

  pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK_SUCCESS(close(sync_sks[0]));
    TEST_CHECK(unshare(CLONE_NEWNS | CLONE_NEWUSER) == 0);

    // Setup uid and gid maps for child.
    int fd = open("/proc/self/uid_map", O_WRONLY);
    TEST_CHECK(fd > 0);
    TEST_CHECK(write(fd, umap_str.c_str(), umap_str.size()) > 0);
    TEST_CHECK(close(fd) == 0);

    // setgroups isn't implemented in gVisor but is necessary for native
    // tests.
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd > 0) {
      TEST_CHECK(write(fd, "deny", 4) > 0);
      TEST_CHECK(close(fd) == 0);
    }

    fd = open("/proc/self/gid_map", O_WRONLY);
    TEST_CHECK(fd > 0);
    TEST_CHECK(write(fd, gmap_str.c_str(), gmap_str.size()) > 0);
    TEST_CHECK(close(fd) == 0);

    // Wait until uid and gid maps are setup.
    TEST_CHECK(setuid(0) == 0);
    TEST_CHECK(setgid(0) == 0);

    // Mount/user namespace setup is complete. Now run the parent function.
    TEST_CHECK_SUCCESS(shutdown(sync_sks[1], SHUT_WR));
    char s;
    // Wait for the parent function to be complete.
    TEST_CHECK(read(sync_sks[1], &s, 1) == 0);
    TEST_CHECK_SUCCESS(close(sync_sks[1]));
    // Parent function is complete. Now run the child function.
    child();
    TEST_CHECK_MSG(!::testing::Test::HasFailure(),
                   "EXPECT*/ASSERT* failed. These are not async-signal-safe "
                   "and must not be called from fn.");
    _exit(0);
  }
  MaybeSave();
  if (pid < 0) {
    return PosixError(errno, "fork failed");
  }

  close(sync_sks[1]);
  char s;
  // Wait for mount/user namespace setup to be complete.
  TEST_CHECK_SUCCESS(read(sync_sks[0], &s, 1));
  parent();
  // Now start the child function.
  TEST_CHECK_SUCCESS(close(sync_sks[0]));

  int status;
  if (waitpid(pid, &status, 0) < 0) {
    return PosixError(errno, "waitpid failed");
  }
  return status;
}

}  // namespace testing
}  // namespace gvisor
