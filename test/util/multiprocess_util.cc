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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "absl/strings/str_cat.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<Cleanup> ForkAndExec(const std::string& filename,
                                  const ExecveArray& argv,
                                  const ExecveArray& envv,
                                  const std::function<void()>& fn, pid_t* child,
                                  int* execve_errno) {
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

    execve(filename.c_str(), argv.get(), envv.get());
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

PosixErrorOr<int> InForkedProcess(const std::function<void()>& fn) {
  pid_t pid = fork();
  if (pid == 0) {
    fn();
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

}  // namespace testing
}  // namespace gvisor
