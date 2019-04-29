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

#include <sys/wait.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void TestExit(int code) {
  pid_t pid = fork();
  if (pid == 0) {
    _exit(code);
  }

  ASSERT_THAT(pid, SyscallSucceeds());

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == code) << status;
}

TEST(ExitTest, Success) { TestExit(0); }

TEST(ExitTest, Failure) { TestExit(1); }

// This test ensures that a process's file descriptors are closed when it calls
// exit(). In order to test this, the parent tries to read from a pipe whose
// write end is held by the child. While the read is blocking, the child exits,
// which should cause the parent to read 0 bytes due to EOF.
TEST(ExitTest, CloseFds) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  FileDescriptor read_fd(pipe_fds[0]);
  FileDescriptor write_fd(pipe_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    read_fd.reset();

    SleepSafe(absl::Seconds(10));

    _exit(0);
  }

  EXPECT_THAT(pid, SyscallSucceeds());

  write_fd.reset();

  char buf[10];
  EXPECT_THAT(ReadFd(read_fd.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
