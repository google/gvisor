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

#include <limits.h>
#include <linux/prctl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <utility>

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

namespace gvisor {
namespace testing {
namespace {

struct UserNamespaceChild {
  FileDescriptor nsfd;
  Cleanup cleanup;
};

UserNamespaceChild CreateUserNamespaceChild() {
  int pfd[2];
  TEST_PCHECK(pipe(pfd) == 0);
  FileDescriptor pipe_read(pfd[0]);
  FileDescriptor pipe_write(pfd[1]);

  pid_t child = fork();
  TEST_PCHECK(child >= 0);
  if (child == 0) {
    pipe_read.reset();
    TEST_CHECK_SUCCESS(unshare(CLONE_NEWUSER));
    TEST_CHECK_SUCCESS(write(pipe_write.get(), "R", 1));
    pipe_write.reset();
    pause();
    _exit(0);
  }
  Cleanup cleanup([child] {
    kill(child, SIGKILL);
    int status;
    RetryEINTR(waitpid)(child, &status, 0);
  });
  pipe_write.reset();

  char buf;
  TEST_PCHECK(read(pipe_read.get(), &buf, 1) == 1);

  char nspath[PATH_MAX];
  snprintf(nspath, sizeof(nspath), "/proc/%d/ns/user", child);
  FileDescriptor nsfd = TEST_CHECK_NO_ERRNO_AND_VALUE(Open(nspath, O_RDONLY));

  return {std::move(nsfd), std::move(cleanup)};
}

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

TEST(SetnsTest, ChangeMountNamespaceZeroFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/mnt", O_RDONLY));
  ASSERT_THAT(setns(nsfd.get(), 0), SyscallSucceedsWithValue(0));
}

TEST(SetnsTest, ChangeUserNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  UserNamespaceChild child = CreateUserNamespaceChild();
  EXPECT_THAT(InForkedProcess([&child] {
                TEST_CHECK_SUCCESS(setns(child.nsfd.get(), CLONE_NEWUSER));
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(SetnsTest, ChangeUserNamespaceRejectsCurrentUserNamespace) {
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/user", O_RDONLY));
  EXPECT_THAT(setns(nsfd.get(), CLONE_NEWUSER), SyscallFailsWithErrno(EINVAL));
}

TEST(SetnsTest, ChangeUserNamespaceRejectsMultithreadedCaller) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  UserNamespaceChild child = CreateUserNamespaceChild();

  int nsfd = child.nsfd.get();
  EXPECT_THAT(InForkedProcess([nsfd] {
                int ready_fds[2];
                TEST_PCHECK(pipe(ready_fds) == 0);
                int stop_fds[2];
                TEST_PCHECK(pipe(stop_fds) == 0);
                int done_fds[2];
                TEST_PCHECK(pipe(done_fds) == 0);

                struct ThreadArgs {
                  int ready_read_fd;
                  int ready_write_fd;
                  int stop_read_fd;
                  int stop_write_fd;
                  int done_read_fd;
                  int done_write_fd;
                } args = {ready_fds[0], ready_fds[1], stop_fds[0],
                          stop_fds[1],  done_fds[0],  done_fds[1]};
                struct clone_arg {
                  char stack[1024] __attribute__((aligned(16)));
                  char stack_ptr[0];
                } ca;
                pid_t tid = clone(
                    +[](void* arg) {
                      ThreadArgs* args = static_cast<ThreadArgs*>(arg);
                      TEST_PCHECK(close(args->ready_read_fd) == 0);
                      TEST_PCHECK(close(args->stop_write_fd) == 0);
                      TEST_PCHECK(close(args->done_read_fd) == 0);
                      TEST_PCHECK(write(args->ready_write_fd, "R", 1) == 1);
                      TEST_PCHECK(close(args->ready_write_fd) == 0);
                      char buf;
                      TEST_PCHECK(read(args->stop_read_fd, &buf, 1) == 1);
                      TEST_PCHECK(close(args->stop_read_fd) == 0);
                      TEST_PCHECK(write(args->done_write_fd, "D", 1) == 1);
                      TEST_PCHECK(close(args->done_write_fd) == 0);
                      return 0;
                    },
                    ca.stack_ptr, CLONE_SIGHAND | CLONE_THREAD | CLONE_VM,
                    &args);
                TEST_PCHECK(tid >= 0);
                TEST_PCHECK(close(ready_fds[1]) == 0);
                TEST_PCHECK(close(stop_fds[0]) == 0);
                TEST_PCHECK(close(done_fds[1]) == 0);

                char buf;
                TEST_PCHECK(read(ready_fds[0], &buf, 1) == 1);
                TEST_PCHECK(close(ready_fds[0]) == 0);
                TEST_CHECK_ERRNO(setns(nsfd, CLONE_NEWUSER), EINVAL);
                TEST_PCHECK(write(stop_fds[1], "S", 1) == 1);
                TEST_PCHECK(close(stop_fds[1]) == 0);
                TEST_PCHECK(read(done_fds[0], &buf, 1) == 1);
                TEST_PCHECK(close(done_fds[0]) == 0);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(SetnsTest, ChangeUserNamespaceRejectsSharedFS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  UserNamespaceChild userns_child = CreateUserNamespaceChild();
  int nsfd = userns_child.nsfd.get();

  EXPECT_THAT(
      InForkedProcess([nsfd] {
        int pfd[2];
        TEST_PCHECK(pipe(pfd) == 0);

        struct CloneFSArgs {
          int read_fd;
          int write_fd;
        } args = {pfd[0], pfd[1]};
        struct clone_arg {
          char stack[128] __attribute__((aligned(16)));
          char stack_ptr[0];
        } ca;
        pid_t fs_child = clone(
            +[](void* arg) {
              CloneFSArgs* args = static_cast<CloneFSArgs*>(arg);
              TEST_PCHECK(close(args->write_fd) == 0);
              char buf;
              TEST_PCHECK(read(args->read_fd, &buf, 1) >= 0);
              TEST_PCHECK(close(args->read_fd) == 0);
              _exit(0);
              return 0;
            },
            ca.stack_ptr, CLONE_FS | SIGCHLD, &args);
        TEST_PCHECK(fs_child >= 0);
        TEST_PCHECK(close(pfd[0]) == 0);

        TEST_CHECK_ERRNO(setns(nsfd, CLONE_NEWUSER), EINVAL);

        TEST_PCHECK(close(pfd[1]) == 0);
        int status;
        TEST_PCHECK(RetryEINTR(waitpid)(fs_child, &status, 0) == fs_child);
        TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST(SetnsTest, ChangeUserNamespaceRejectsMissingTargetCapability) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  const FileDescriptor parent_nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/user", O_RDONLY));
  EXPECT_THAT(InForkedProcess([&parent_nsfd] {
                TEST_CHECK_SUCCESS(unshare(CLONE_NEWUSER));
                TEST_CHECK_ERRNO(setns(parent_nsfd.get(), CLONE_NEWUSER),
                                 EPERM);
              }),
              IsPosixErrorOkAndHolds(0));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
