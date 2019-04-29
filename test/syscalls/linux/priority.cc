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
#include <unistd.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "test/util/capability_util.h"
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
  EXPECT_THAT(setpriority(PRIO_PROCESS, /*who=*/0, /*nice=*/16),
              SyscallSucceeds());
}

// Invalid which
TEST(Setpriority, InvalidWhich) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  EXPECT_THAT(setpriority(/*which=*/3, /*who=*/0, /*nice=*/16),
              SyscallFailsWithErrno(EINVAL));
}

// Process is found when which=PRIO_PROCESS
TEST(SetpriorityTest, ValidWho) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(), /*nice=*/16),
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
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(), /*nice=*/100),
              SyscallSucceeds());

  errno = 0;
  // Test niceval truncated to 19
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(/*maxnice=*/19));

  // Set niceval < -20
  EXPECT_THAT(setpriority(PRIO_PROCESS, getpid(), /*nice=*/-100),
              SyscallSucceeds());

  errno = 0;
  // Test niceval truncated to -20
  EXPECT_THAT(getpriority(PRIO_PROCESS, getpid()),
              SyscallSucceedsWithValue(/*minnice=*/-20));
}

// Process is not found when which=PRIO_PROCESS
TEST(SetpriorityTest, InvalidWho) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Flaky, but it's tough to avoid a race condition when finding an unused pid
  EXPECT_THAT(setpriority(PRIO_PROCESS,
                          /*who=*/INT_MAX - 1,
                          /*nice=*/16),
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

}  // namespace

}  // namespace testing
}  // namespace gvisor
