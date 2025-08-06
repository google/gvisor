// Copyright 2023 The gVisor Authors.
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

#include <linux/prctl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(SetnsTest, ChangeIPCNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct stat st;
  uint64_t ipcns1, ipcns2, ipcns3;
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/ipc", O_RDONLY));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns1 = st.st_ino;

  // Use unshare(CLONE_NEWIPC) to change into a new IPC namespace.
  ASSERT_THAT(unshare(CLONE_NEWIPC), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns2 = st.st_ino;
  ASSERT_NE(ipcns1, ipcns2);

  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWIPC), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns3 = st.st_ino;
  EXPECT_EQ(ipcns1, ipcns3);
}

TEST(SetnsTest, ChangeUTSNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct stat st;
  uint64_t utsns1, utsns2, utsns3;
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/uts", O_RDONLY));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns1 = st.st_ino;

  // Use unshare(CLONE_NEWUTS) to change into a new UTS namespace.
  ASSERT_THAT(unshare(CLONE_NEWUTS), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns2 = st.st_ino;
  ASSERT_NE(utsns1, utsns2);

  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWUTS), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns3 = st.st_ino;
  EXPECT_EQ(utsns1, utsns3);
}

TEST(SetnsTest, ChangePIDNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sigh = [](int sig) { _exit(5); };
  signal(SIGUSR1, sigh);

  auto child_init_in_pidns = [](void* args) {
    int32_t fd;

    TEST_PCHECK((fd = open("/proc/self/ns/pid", O_RDONLY)) >= 0);
    TEST_PCHECK(setns(fd, 0) == 0);
    TEST_PCHECK(setns(fd, CLONE_NEWPID) == 0);
    close(fd);
    while (1) {
      absl::SleepFor(absl::Seconds(1));
    }
    return 0;
  };

  // Check that a subreaper doesn't affect how pidns is destroyed.
  ASSERT_THAT(prctl(PR_SET_CHILD_SUBREAPER, 1), SyscallSucceeds());

  // Fork a test process in a new PID namespace, because it needs to manipulate
  // with reparented processes.
  struct clone_arg {
    // Reserve some space for clone() to locate arguments and retcode in this
    // place.
    char stack[128] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  pid_t pid;
  ASSERT_THAT(pid = clone(child_init_in_pidns, ca.stack_ptr,
                          CLONE_NEWPID | SIGCHLD, &ca),
              SyscallSucceeds());
  pid_t setns_pid = fork();
  EXPECT_THAT(pid, SyscallSucceeds());
  if (setns_pid == 0) {
    int32_t fd;
    char nspath[PATH_MAX];

    snprintf(nspath, sizeof(nspath), "/proc/%d/ns/pid", pid);

    TEST_PCHECK((fd = open(nspath, O_RDONLY)) >= 0);
    TEST_PCHECK(setns(fd, 0) == 0);
    close(fd);
    pid = fork();
    TEST_PCHECK(pid >= 0);
    if (pid == 0) {
      TEST_PCHECK(kill(1, SIGUSR1) == 0);
      while (1) {
        absl::SleepFor(absl::Seconds(1));
      }
    }
    int status;
    TEST_PCHECK(waitpid(pid, &status, 0) == pid);
    TEST_CHECK(WTERMSIG(status) == SIGKILL);
    _exit(0);
  }
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(setns_pid, &status, 0),
              SyscallSucceedsWithValue(setns_pid));
  EXPECT_EQ(status, 0);
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_EQ(WEXITSTATUS(status), 5);

  ASSERT_THAT(prctl(PR_SET_CHILD_SUBREAPER, 0), SyscallSucceeds());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
