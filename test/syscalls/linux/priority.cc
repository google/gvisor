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

#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

int ioprio_set(int which, int who, int ioprio) {
  return syscall(SYS_ioprio_set, which, who, ioprio);
}

int ioprio_get(int which, int who) {
  return syscall(SYS_ioprio_get, which, who);
}

#ifndef IOPRIO_WHO_PROCESS

#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_WHO_PGRP 2
#define IOPRIO_WHO_USER 3

#define IOPRIO_CLASS_NONE 0
#define IOPRIO_CLASS_RT 1
#define IOPRIO_CLASS_IDLE 3

#define IOPRIO_CLASS_SHIFT 13

#define IOPRIO_PRIO_VALUE(class, data) ((class << IOPRIO_CLASS_SHIFT) | data)

#endif

// These tests are for both the getpriority(2) and setpriority(2) syscalls
// These tests are very rudimentary because getpriority and setpriority
// have not yet been fully implemented.

// Getpriority does something
TEST(GetpriorityTest, Implemented) {
  // "getpriority() can legitimately return the value -1, it is necessary to
  // clear the external variable errno prior to the call"
  errno = 0;
  EXPECT_THAT(getpriority(PRIO_PROCESS, /*who=*/0), SyscallSucceeds());
}

// Invalid which
TEST(GetpriorityTest, InvalidWhich) {
  errno = 0;
  EXPECT_THAT(getpriority(/*which=*/3, /*who=*/0),
              SyscallFailsWithErrno(EINVAL));
}

// Process is found when which=PRIO_PROCESS
TEST(GetpriorityTest, ValidWho) {
  errno = 0;
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()), SyscallSucceeds());
}

// Process is not found when which=PRIO_PROCESS
TEST(GetpriorityTest, InvalidWho) {
  errno = 0;
  // Flaky, but it's tough to avoid a race condition when finding an unused pid
  EXPECT_THAT(getpriority(PRIO_PROCESS, /*who=*/INT_MAX - 1),
              SyscallFailsWithErrno(ESRCH));
}

// Setpriority does something
TEST(SetpriorityTest, Implemented) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // No need to clear errno for setpriority():
  // "The setpriority() call returns 0 if there is no error, or -1 if there is"
  EXPECT_THAT(setpriority(PRIO_PROCESS, /*who=*/0,
                          /*nice=*/16),  // NOLINT(bugprone-argument-comment)
              SyscallSucceeds());
}

// Invalid which
TEST(Setpriority, InvalidWhich) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  EXPECT_THAT(setpriority(/*which=*/3, /*who=*/0,
                          /*nice=*/16),  // NOLINT(bugprone-argument-comment)
              SyscallFailsWithErrno(EINVAL));
}

// Process is found when which=PRIO_PROCESS
TEST(SetpriorityTest, ValidWho) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(),
                          /*nice=*/16),  // NOLINT(bugprone-argument-comment)
              SyscallSucceeds());
}

// niceval is within the range [-20, 19]
TEST(SetpriorityTest, InsideRange) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Set 0 < niceval < 19
  int nice = 12;
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(), nice), SyscallSucceeds());

  errno = 0;
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(nice));

  // Set -20 < niceval < 0
  nice = -12;
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(), nice), SyscallSucceeds());

  errno = 0;
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(nice));
}

// Verify that priority/niceness are exposed via /proc/PID/stat.
TEST(SetpriorityTest, NicenessExposedViaProcfs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  constexpr int kNiceVal = 12;
  ASSERT_THAT(setpriority(PRIO_PROCESS, getpid(), kNiceVal), SyscallSucceeds());

  errno = 0;
  ASSERT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(kNiceVal));

  // Now verify we can read that same value via /proc/self/stat.
  std::string proc_stat;
  ASSERT_NO_ERRNO(GetContents("/proc/self/stat", &proc_stat));
  std::vector<std::string> pieces = absl::StrSplit(proc_stat, ' ');
  ASSERT_GT(pieces.size(), 20);

  int niceness_procfs = 0;
  ASSERT_TRUE(absl::SimpleAtoi(pieces[18], &niceness_procfs));
  EXPECT_EQ(niceness_procfs, kNiceVal);
}

// In the kernel's implementation, values outside the range of [-20, 19] are
// truncated to these minimum and maximum values. See
// https://elixir.bootlin.com/linux/v4.4/source/kernel/sys.c#L190
TEST(SetpriorityTest, OutsideRange) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Set niceval > 19
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(),
                          /*nice=*/100),  // NOLINT(bugprone-argument-comment)
              SyscallSucceeds());

  errno = 0;
  // Test niceval truncated to 19
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(
                  /*maxnice=*/19));  // NOLINT(bugprone-argument-comment)

  // Set niceval < -20
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(),
                          /*nice=*/-100),  // NOLINT(bugprone-argument-comment)
              SyscallSucceeds());

  errno = 0;
  // Test niceval truncated to -20
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(
                  /*minnice=*/-20));  // NOLINT(bugprone-argument-comment)
}

// Process is not found when which=PRIO_PROCESS
TEST(SetpriorityTest, InvalidWho) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Flaky, but it's tough to avoid a race condition when finding an unused pid
  EXPECT_THAT(setpriority(PRIO_PROCESS,
                          /*who=*/INT_MAX - 1,
                          /*nice=*/16),  // NOLINT(bugprone-argument-comment)
              SyscallFailsWithErrno(ESRCH));
}

// Nice succeeds, correctly modifies (or in this case does not
// modify priority of process
TEST(SetpriorityTest, NiceSucceeds) {
  errno = 0;
  const int priority_before = getpriority(PRIO_PROCESS, /*who=*/0);
  ASSERT_THAT(nice(/*inc=*/0), SyscallSucceeds());

  // nice(0) should not change priority
  EXPECT_EQ(priority_before, getpriority(PRIO_PROCESS, /*who=*/0));
}

#ifndef __Fuchsia__  // Fuchsia doesn't support caps.
// Test that setpriority on another task owned by a different UID requires
// CAP_SYS_NICE.
TEST(SetpriorityTest, OtherUidRequiresCapSysNice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  int child_ready[2];
  ASSERT_THAT(pipe(child_ready), SyscallSucceeds());

  pid_t child = fork();
  ASSERT_THAT(child, SyscallSucceeds());

  if (child == 0) {
    constexpr int kUnprivilegedUid = 12345;
    close(child_ready[0]);
    TEST_PCHECK(
        setresuid(kUnprivilegedUid, kUnprivilegedUid, kUnprivilegedUid) == 0);

    char ready = 'r';
    write(child_ready[1], &ready, 1);
    close(child_ready[1]);
    _exit(0);
  }

  close(child_ready[1]);
  char ready;
  ASSERT_THAT(read(child_ready[0], &ready, 1), SyscallSucceedsWithValue(1));
  close(child_ready[0]);

  EXPECT_THAT(setpriority(PRIO_PROCESS, child, 0), SyscallSucceeds());

  AutoCapability cap(CAP_SYS_NICE, false);
  EXPECT_THAT(setpriority(PRIO_PROCESS, child, 0),
              SyscallFailsWithErrno(EPERM));

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}
#endif  // __Fuchsia__

// Threads resulting from clone() maintain parent's priority
// Changes to child priority do not affect parent's priority
TEST(GetpriorityTest, CloneMaintainsPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  constexpr int kParentPriority = 16;
  constexpr int kChildPriority = 14;
  ASSERT_THAT(setpriority(PRIO_PROCESS, getpid(), kParentPriority),
              SyscallSucceeds());

  ScopedThread th([]() {
    // Check that priority equals that of parent thread
    pid_t my_tid;
    EXPECT_THAT(my_tid = syscall(__NR_gettid), SyscallSucceeds());
    EXPECT_THAT(getpriority(PRIO_PROCESS, my_tid),
                SyscallSucceedsWithValue(kParentPriority));

    // Change the child thread's priority
    EXPECT_THAT(setpriority(PRIO_PROCESS, my_tid, kChildPriority),
                SyscallSucceeds());
  });
  th.Join();

  // Check that parent's priority reemained the same even though
  // the child's priority was altered
  EXPECT_EQ(kParentPriority, getpriority(PRIO_PROCESS, syscall(__NR_gettid)));
}

PosixErrorOr<Cleanup> ioPrioCleanup() {
  int old_prio = ioprio_get(IOPRIO_WHO_PROCESS, 0);
  if (old_prio < 0) {
    return PosixError(errno, "ioprio_get() failed");
  }

  return Cleanup([old_prio] { ioprio_set(IOPRIO_WHO_PROCESS, 0, old_prio); });
}

TEST(IoprioTest, BasicSetGet) {
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ioPrioCleanup());

  EXPECT_THAT(
      ioprio_get(IOPRIO_WHO_PROCESS, 0),
      SyscallSucceedsWithValue(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)));

  // Try setting IO class to IDLE
  EXPECT_THAT(ioprio_set(IOPRIO_WHO_PROCESS, 0,
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)),
              SyscallSucceeds());
  EXPECT_THAT(
      ioprio_get(IOPRIO_WHO_PROCESS, 0),
      SyscallSucceedsWithValue(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)));
}

TEST(IoprioTest, ValidWho) {
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ioPrioCleanup());

  EXPECT_THAT(ioprio_set(IOPRIO_WHO_PROCESS, getpid(),
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)),
              SyscallSucceeds());
  EXPECT_THAT(
      ioprio_get(IOPRIO_WHO_PROCESS, getpid()),
      SyscallSucceedsWithValue(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)));
}

TEST(IoprioTest, InvalidClassesAndData) {
  // Using an invalid class
  EXPECT_THAT(ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(5, 0)),
              SyscallFailsWithErrno(EINVAL));

  // Class NONE with non-zero data
  EXPECT_THAT(ioprio_set(IOPRIO_WHO_PROCESS, 0,
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 1)),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IoprioTest, RtRequiresCapability) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ioPrioCleanup());

  EXPECT_THAT(
      ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 4)),
      SyscallSucceeds());

  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  AutoCapability cap_nice(CAP_SYS_NICE, false);

  EXPECT_THAT(
      ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 4)),
      SyscallFailsWithErrno(EPERM));
}

TEST(IoprioTest, ChildPID) {
  pid_t pid = fork();
  ASSERT_THAT(pid, SyscallSucceeds());
  if (pid == 0) {
    while (1) {
      absl::SleepFor(absl::Seconds(60));
    }
  }

  auto cleanup = Cleanup([&pid] {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
  });

  // Child ioprio starts out as 0
  EXPECT_THAT(
      ioprio_get(IOPRIO_WHO_PROCESS, pid),
      SyscallSucceedsWithValue(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)));

  // Parent: try to set child's ioprio
  EXPECT_THAT(ioprio_set(IOPRIO_WHO_PROCESS, pid,
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)),
              SyscallSucceeds());

  EXPECT_THAT(
      ioprio_get(IOPRIO_WHO_PROCESS, pid),
      SyscallSucceedsWithValue(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
