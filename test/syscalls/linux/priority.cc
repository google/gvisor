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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/synchronization/notification.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

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

// Matches Linux kernel/sys.c:sys_setpriority() where reducing priority
// (increasing nice value) does not require CAP_SYS_NICE.
TEST(SetpriorityTest, ReducePrioritySuccessWithoutCapSysNice) {
  // Increase nice value (reduce priority).
  AutoCapability cap(CAP_SYS_NICE, false);

  errno = 0;
  int current_prio = getpriority(PRIO_PROCESS, 0);
  int new_prio = current_prio + 1;
  if (new_prio > 19) {
    new_prio = 19;
  }

  EXPECT_THAT(setpriority(PRIO_PROCESS, 0, new_prio), SyscallSucceeds());
}

// Matches Linux kernel/sys.c:sys_setpriority() where reducing nice value
// (increasing priority) within RLIMIT_NICE does not require CAP_SYS_NICE.
TEST(SetpriorityTest, ReduceNiceWithinLimitSuccessWithoutCapSysNice) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  // Set RLIMIT_NICE to 10 (min nice 10).
  if (rlim.rlim_max < 10) {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));
  }

  struct rlimit new_rlim = {
      .rlim_cur = 10,
      .rlim_max = (rlim.rlim_max < 10) ? 10 : rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  // Set initial nice to 15.
  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 15), SyscallSucceeds());

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Try to set nice to 12. Within limit 10 (12 >= 10).
  EXPECT_THAT(setpriority(PRIO_PROCESS, 0, 12), SyscallSucceeds());
}

// Matches Linux kernel/sys.c:sys_setpriority() where increasing priority
// exceeds RLIMIT_NICE and requires CAP_SYS_NICE.
TEST(SetpriorityTest, IncreasePriorityLimitFailWithoutCapSysNice) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  // Set RLIMIT_NICE to 0 to make it easy to exceed.
  struct rlimit new_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 19), SyscallSucceeds());

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Try to set nice to 18. Exceeds limit 0 (20 - 18 = 2 > 0).
  EXPECT_THAT(setpriority(PRIO_PROCESS, 0, 18),
              SyscallFailsWithErrno(EACCES));
}

// Matches Linux kernel/sys.c:sys_setpriority() where increasing priority
// exceeds RLIMIT_NICE but succeeds with CAP_SYS_NICE.
TEST(SetpriorityTest, IncreasePriorityLimitSuccessWithCapSysNice) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 19), SyscallSucceeds());

  // We need CAP_SYS_NICE.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Try to set nice to 18. Exceeds limit 0, but we have CAP_SYS_NICE.
  EXPECT_THAT(setpriority(PRIO_PROCESS, 0, 18), SyscallSucceeds());
}

// Verify that a process in a non-root user namespace with CAP_SYS_NICE can
// exceed RLIMIT_NICE, while one without it cannot.
TEST(SetpriorityTest, ExceedRlimitNiceInUserNamespace) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  // Set RLIMIT_NICE to 0 to make it easy to exceed.
  struct rlimit new_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  pid_t child_pid = fork();
  ASSERT_THAT(child_pid, SyscallSucceeds());

  if (child_pid == 0) {
    // Enter new user namespace.
    if (unshare(CLONE_NEWUSER) != 0) {
      _exit(77);
    }

    // Now we have CAP_SYS_NICE in the new namespace.

    // Set initial nice to 19 to ensure that setting it to 18 is an increase in priority.
    if (setpriority(PRIO_PROCESS, 0, 19) != 0) {
      _exit(5);
    }

    // Try to set nice to 18. Exceeds limit 0.
    // This should FAIL because we only have CAP_SYS_NICE in our user ns,
    // but Linux requires it in the init user namespace to exceed RLIMIT_NICE.
    if (setpriority(PRIO_PROCESS, 0, 18) == 0) {
      _exit(1);
    }
    if (errno != EACCES) {
      _exit(2);
    }

    // Now drop CAP_SYS_NICE.
    {
      AutoCapability cap(CAP_SYS_NICE, false);
      
      // Try to set nice to 17. Exceeds limit 0. Should FAIL.
      if (setpriority(PRIO_PROCESS, 0, 17) == 0) {
        _exit(3);
      }
      if (errno != EACCES) {
        _exit(4);
      }
    }

    _exit(0);
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0), SyscallSucceedsWithValue(child_pid));
  if (WIFEXITED(status)) {
    int exit_status = WEXITSTATUS(status);
    if (exit_status == 77) {
      GTEST_SKIP() << "unshare(CLONE_NEWUSER) not supported";
    }
    EXPECT_EQ(exit_status, 0);
  } else {
    FAIL() << "Child crashed";
  }
}

// Matches Linux kernel/sys.c:sys_setpriority() where setting priority of
// another user's process requires CAP_SYS_NICE.
TEST(SetpriorityTest, DiffUserFailWithoutCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  const uid_t kOtherUID = 65534; // nobody

  int target_tid = 0;
  absl::Notification notification;
  absl::Notification done;
  bool setuid_ok = false;

  ScopedThread t([&]() {
    target_tid = syscall(SYS_gettid);
    if (syscall(SYS_setuid, kOtherUID) != 0) {
      notification.Notify();
      return;
    }
    setuid_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!setuid_ok) {
    GTEST_SKIP() << "setuid failed, skipping test";
  }

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Attempt to set priority of target.
  EXPECT_THAT(setpriority(PRIO_PROCESS, target_tid, 16),
              SyscallFailsWithErrno(EPERM));

  done.Notify();
}

// Matches Linux kernel/sys.c:sys_setpriority() where setting priority of
// another user's process succeeds with CAP_SYS_NICE.
TEST(SetpriorityTest, DiffUserSuccessWithCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  const uid_t kOtherUID = 65534; // nobody

  int target_tid = 0;
  absl::Notification notification;
  absl::Notification done;
  bool setuid_ok = false;

  ScopedThread t([&]() {
    target_tid = syscall(SYS_gettid);
    if (syscall(SYS_setuid, kOtherUID) != 0) {
      notification.Notify();
      return;
    }
    setuid_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!setuid_ok) {
    GTEST_SKIP() << "setuid failed, skipping test";
  }

  // We need CAP_SYS_NICE.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Attempt to set priority of target.
  EXPECT_THAT(setpriority(PRIO_PROCESS, target_tid, 16), SyscallSucceeds());

  done.Notify();
}

TEST(SetpriorityTest, SameUserSuccessWithoutCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  // Set RLIMIT_NICE to allow resetting nice to 0 even if we inherited a high
  // nice value and lack CAP_SYS_NICE. nice=0 corresponds to rlimit 20.
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = {
      .rlim_cur = 20,
      .rlim_max = (rlim.rlim_max < 20) ? 20 : rlim.rlim_max};
  
  if (rlim.rlim_max < 20) {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));
  }
  
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());
  
  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  // Reset nice value to 0 to avoid inheriting a high nice value from previous tests.
  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 0), SyscallSucceeds());

  int target_tid = 0;
  absl::Notification notification;
  absl::Notification done;

  ScopedThread t([&]() {
    target_tid = syscall(SYS_gettid);
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Attempt to set priority of target.
  EXPECT_THAT(setpriority(PRIO_PROCESS, target_tid, 16), SyscallSucceeds());

  done.Notify();
}

TEST(SetrlimitTest, SetRlimitNiceNonRootSucceeds) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = rlim;
  if (rlim.rlim_cur > 0) {
    new_rlim.rlim_cur = rlim.rlim_cur - 1;
  }

  // Drop capabilities.
  AutoCapability cap1(CAP_SYS_RESOURCE, false);
  AutoCapability cap2(CAP_SYS_NICE, false);

  EXPECT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());
}

TEST(SetrlimitTest, SetRlimitNiceRootSucceeds) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = {
      .rlim_cur = rlim.rlim_cur + 1,
      .rlim_max = rlim.rlim_max + 1,
  };

  // We need CAP_SYS_RESOURCE to increase hard limit.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));

  EXPECT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());
  
  // Restore limit.
  setrlimit(RLIMIT_NICE, &rlim);
}

TEST(SetpriorityTest, PrioUserDiffUserFailWithoutCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  const uid_t kOtherUID = 65534; // nobody

  absl::Notification notification;
  absl::Notification done;
  bool setuid_ok = false;

  ScopedThread t([&]() {
    if (syscall(SYS_setuid, kOtherUID) != 0) {
      notification.Notify();
      return;
    }
    setuid_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!setuid_ok) {
    GTEST_SKIP() << "setuid failed, skipping test";
  }

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Attempt to set priority for another user.
  EXPECT_THAT(setpriority(PRIO_USER, kOtherUID, 16),
              SyscallFailsWithErrno(EPERM));

  done.Notify();
}

TEST(SetpriorityTest, PrioUserDiffUserSuccessWithCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  const uid_t kOtherUID = 65534; // nobody

  absl::Notification notification;
  absl::Notification done;
  bool setuid_ok = false;

  ScopedThread t([&]() {
    if (syscall(SYS_setuid, kOtherUID) != 0) {
      notification.Notify();
      return;
    }
    setuid_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!setuid_ok) {
    GTEST_SKIP() << "setuid failed, skipping test";
  }

  // Attempt to set priority for another user.
  EXPECT_THAT(setpriority(PRIO_USER, kOtherUID, 16), SyscallSucceeds());

  done.Notify();
}

TEST(SetpriorityTest, PrioUserIncreasePriorityLimitFailWithoutCapSysNice) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 19), SyscallSucceeds());

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Try to set nice to 18 for current user.
  EXPECT_THAT(setpriority(PRIO_USER, 0, 18),
              SyscallFailsWithErrno(EACCES));
}

TEST(SetpriorityTest, PrioPgrpIncreasePriorityLimitFailWithoutCapSysNice) {
  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit new_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &new_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  ASSERT_THAT(setpriority(PRIO_PROCESS, 0, 19), SyscallSucceeds());

  // Drop CAP_SYS_NICE.
  AutoCapability cap(CAP_SYS_NICE, false);

  // Try to set nice to 18 for current pgrp.
  EXPECT_THAT(setpriority(PRIO_PGRP, 0, 18),
              SyscallFailsWithErrno(EACCES));
}

TEST(SetpriorityTest, TargetLimitUsedNotCallerLimit) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  struct rlimit rlim;
  ASSERT_THAT(getrlimit(RLIMIT_NICE, &rlim), SyscallSucceeds());

  struct rlimit target_rlim = {
      .rlim_cur = 10,
      .rlim_max = (rlim.rlim_max < 10) ? 10 : rlim.rlim_max,
  };
  if (rlim.rlim_cur < 10) {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));
  }
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &target_rlim), SyscallSucceeds());

  int pipe_c2p[2];
  int pipe_p2c[2];
  ASSERT_THAT(pipe(pipe_c2p), SyscallSucceeds());
  ASSERT_THAT(pipe(pipe_p2c), SyscallSucceeds());

  pid_t child_pid = fork();
  ASSERT_THAT(child_pid, SyscallSucceeds());

  if (child_pid == 0) {
    close(pipe_c2p[0]);
    close(pipe_p2c[1]);

    if (setpriority(PRIO_PROCESS, 0, 15) != 0) {
      _exit(1);
    }

    char c = 'a';
    if (write(pipe_c2p[1], &c, 1) != 1) {
      _exit(2);
    }

    if (read(pipe_p2c[0], &c, 1) != 1) {
      _exit(3);
    }

    _exit(0);
  }

  close(pipe_c2p[1]);
  close(pipe_p2c[0]);

  char c;
  ASSERT_THAT(read(pipe_c2p[0], &c, 1), SyscallSucceedsWithValue(1));

  struct rlimit parent_rlim = {.rlim_cur = 0, .rlim_max = rlim.rlim_max};
  ASSERT_THAT(setrlimit(RLIMIT_NICE, &parent_rlim), SyscallSucceeds());

  auto restore_rlim = Cleanup([&] {
    setrlimit(RLIMIT_NICE, &rlim);
  });

  AutoCapability cap(CAP_SYS_NICE, false);

  EXPECT_THAT(setpriority(PRIO_PROCESS, child_pid, 12), SyscallSucceeds());

  ASSERT_THAT(write(pipe_p2c[1], &c, 1), SyscallSucceedsWithValue(1));

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0), SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST(SetpriorityTest, RealUserMatchEffectiveDiffFailWithoutCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  const uid_t kUID1 = 1000;
  const uid_t kUID2 = 2000;

  int target_tid = 0;
  absl::Notification notification;
  absl::Notification done;
  bool target_ok = false;

  ScopedThread target_thread([&]() {
    target_tid = syscall(SYS_gettid);
    if (syscall(SYS_setresuid, kUID1, kUID1, kUID1) != 0) {
      notification.Notify();
      return;
    }
    target_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!target_ok) {
    GTEST_SKIP() << "Failed to set target UIDs";
  }

  absl::Notification caller_done;
  bool caller_ok = false;
  
  ScopedThread caller_thread([&]() {
    if (syscall(SYS_setresuid, kUID1, kUID2, kUID2) != 0) {
      caller_done.Notify();
      return;
    }
    
    caller_ok = true;
    
    EXPECT_THAT(setpriority(PRIO_PROCESS, target_tid, 16),
                SyscallFailsWithErrno(EPERM));
                
    caller_done.Notify();
  });

  caller_done.WaitForNotification();
  EXPECT_TRUE(caller_ok);

  done.Notify();
}

TEST(SetpriorityTest, RealUserMatchEffectiveDiffSuccessWithCapSysNice) {
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  const uid_t kUID1 = 1000;

  int target_tid = 0;
  absl::Notification notification;
  absl::Notification done;
  bool target_ok = false;

  ScopedThread target_thread([&]() {
    target_tid = syscall(SYS_gettid);
    if (syscall(SYS_setresuid, kUID1, kUID1, kUID1) != 0) {
      notification.Notify();
      return;
    }
    target_ok = true;
    notification.Notify();
    done.WaitForNotification();
  });

  notification.WaitForNotification();
  if (!target_ok) {
    GTEST_SKIP() << "Failed to set target UIDs";
  }

  absl::Notification caller_done;
  bool caller_ok = false;
  
  ScopedThread caller_thread([&]() {
    if (syscall(SYS_setresuid, kUID1, 0, 0) != 0) {
      caller_done.Notify();
      return;
    }
    
    caller_ok = true;
    
    EXPECT_THAT(setpriority(PRIO_PROCESS, target_tid, 16),
                SyscallSucceeds());
                
    caller_done.Notify();
  });

  caller_done.WaitForNotification();
  EXPECT_TRUE(caller_ok);

  done.Notify();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
