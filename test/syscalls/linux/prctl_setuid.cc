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

#include <sched.h>
#include <sys/prctl.h>
#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

DEFINE_int32(scratch_uid, 65534, "scratch UID");
// This flag is used to verify that after an exec PR_GET_KEEPCAPS
// returns 0, the return code will be offset by kPrGetKeepCapsExitBase.
DEFINE_bool(prctl_pr_get_keepcaps, false,
            "If true the test will verify that prctl with pr_get_keepcaps"
            "returns 0. The test will exit with the result of that check.");

// These tests exist seperately from prctl because we need to start
// them as root. Setuid() has the behavior that permissions are fully
// removed if one of the UIDs were 0 before a setuid() call. This
// behavior can be changed by using PR_SET_KEEPCAPS and that is what
// is tested here.
//
// Reference setuid(2):
// The setuid() function checks the effective user ID of
// the caller and if it is the superuser, all process-related user ID's
// are set to uid.  After this has occurred, it is impossible for the
// program to regain root privileges.
//
// Thus, a set-user-ID-root program wishing to temporarily drop root
// privileges, assume the identity of an unprivileged user, and then
// regain root privileges afterward cannot use setuid().  You can
// accomplish this with seteuid(2).
namespace gvisor {
namespace testing {

// Offset added to exit code from test child to distinguish from other abnormal
// exits.
constexpr int kPrGetKeepCapsExitBase = 100;

namespace {

class PrctlKeepCapsSetuidTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // PR_GET_KEEPCAPS will only return 0 or 1 (on success).
    ASSERT_THAT(original_keepcaps_ = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
                SyscallSucceeds());
    ASSERT_TRUE(original_keepcaps_ == 0 || original_keepcaps_ == 1);
  }

  void TearDown() override {
    // Restore PR_SET_KEEPCAPS.
    ASSERT_THAT(prctl(PR_SET_KEEPCAPS, original_keepcaps_, 0, 0, 0),
                SyscallSucceeds());

    // Verify that it was restored.
    ASSERT_THAT(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
                SyscallSucceedsWithValue(original_keepcaps_));
  }

  // The original keep caps value exposed so tests can use it if they need.
  int original_keepcaps_ = 0;
};

// This test will verify that a bad value, eg. not 0 or 1 for
// PR_SET_KEEPCAPS will return EINVAL as required by prctl(2).
TEST_F(PrctlKeepCapsSetuidTest, PrctlBadArgsToKeepCaps) {
  ASSERT_THAT(prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0),
              SyscallFailsWithErrno(EINVAL));
}

// This test will verify that a setuid(2) without PR_SET_KEEPCAPS will cause
// all capabilities to be dropped.
TEST_F(PrctlKeepCapsSetuidTest, SetUidNoKeepCaps) {
  // getuid(2) never fails.
  if (getuid() != 0) {
    SKIP_IF(!IsRunningOnGvisor());
    FAIL() << "User is not root on gvisor platform.";
  }

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting
  // this test. Otherwise, the files are created by root (UID before the
  // test), but cannot be opened by the `uid` set below after the test. After
  // calling setuid(non-zero-UID), there is no way to get root privileges
  // back.
  ScopedThread([] {
    // Start by verifying we have a capability.
    TEST_CHECK(HaveCapability(CAP_SYS_ADMIN).ValueOrDie());

    // Verify that PR_GET_KEEPCAPS is disabled.
    ASSERT_THAT(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
                SyscallSucceedsWithValue(0));

    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. POSIX threads, however, require that
    // all threads have the same UIDs, so using the setuid wrapper sets all
    // threads' real UID.
    EXPECT_THAT(syscall(SYS_setuid, FLAGS_scratch_uid), SyscallSucceeds());

    // Verify that we changed uid.
    EXPECT_THAT(getuid(), SyscallSucceedsWithValue(FLAGS_scratch_uid));

    // Verify we lost the capability in the effective set, this always happens.
    TEST_CHECK(!HaveCapability(CAP_SYS_ADMIN).ValueOrDie());

    // We should have also lost it in the permitted set by the setuid() so
    // SetCapability should fail when we try to add it back to the effective set
    ASSERT_FALSE(SetCapability(CAP_SYS_ADMIN, true).ok());
  });
}

// This test will verify that a setuid with PR_SET_KEEPCAPS will cause
// capabilities to be retained after we switch away from the root user.
TEST_F(PrctlKeepCapsSetuidTest, SetUidKeepCaps) {
  // getuid(2) never fails.
  if (getuid() != 0) {
    SKIP_IF(!IsRunningOnGvisor());
    FAIL() << "User is not root on gvisor platform.";
  }

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting
  // this test. Otherwise, the files are created by root (UID before the
  // test), but cannot be opened by the `uid` set below after the test. After
  // calling setuid(non-zero-UID), there is no way to get root privileges
  // back.
  ScopedThread([] {
    // Start by verifying we have a capability.
    TEST_CHECK(HaveCapability(CAP_SYS_ADMIN).ValueOrDie());

    // Set PR_SET_KEEPCAPS.
    ASSERT_THAT(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), SyscallSucceeds());

    // Verify PR_SET_KEEPCAPS was set before we proceed.
    ASSERT_THAT(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
                SyscallSucceedsWithValue(1));

    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. POSIX threads, however, require that
    // all threads have the same UIDs, so using the setuid wrapper sets all
    // threads' real UID.
    EXPECT_THAT(syscall(SYS_setuid, FLAGS_scratch_uid), SyscallSucceeds());

    // Verify that we changed uid.
    EXPECT_THAT(getuid(), SyscallSucceedsWithValue(FLAGS_scratch_uid));

    // Verify we lost the capability in the effective set, this always happens.
    TEST_CHECK(!HaveCapability(CAP_SYS_ADMIN).ValueOrDie());

    // We lost the capability in the effective set, but it will still
    // exist in the permitted set so we can elevate the capability.
    ASSERT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, true));

    // Verify we got back the capability in the effective set.
    TEST_CHECK(HaveCapability(CAP_SYS_ADMIN).ValueOrDie());
  });
}

// This test will verify that PR_SET_KEEPCAPS is not retained
// across an execve. According to prctl(2):
// "The "keep capabilities" value will  be reset to 0 on subsequent
// calls to execve(2)."
TEST_F(PrctlKeepCapsSetuidTest, NoKeepCapsAfterExec) {
  ASSERT_THAT(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), SyscallSucceeds());

  // Verify PR_SET_KEEPCAPS was set before we proceed.
  ASSERT_THAT(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0), SyscallSucceedsWithValue(1));

  pid_t child_pid = -1;
  int execve_errno = 0;
  // Do an exec and then verify that PR_GET_KEEPCAPS returns 0
  // see the body of main below.
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      "/proc/self/exe", {"/proc/self/exe", "--prctl_pr_get_keepcaps"}, {},
      nullptr, &child_pid, &execve_errno));

  ASSERT_GT(child_pid, 0);
  ASSERT_EQ(execve_errno, 0);

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  ASSERT_TRUE(WIFEXITED(status));
  // PR_SET_KEEPCAPS should have been cleared by the exec.
  // Success should return gvisor::testing::kPrGetKeepCapsExitBase + 0
  ASSERT_EQ(WEXITSTATUS(status), kPrGetKeepCapsExitBase);
}

TEST_F(PrctlKeepCapsSetuidTest, NoKeepCapsAfterNewUserNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  // Fork to avoid changing the user namespace of the original test process.
  pid_t const child_pid = fork();

  if (child_pid == 0) {
    // Verify that the keepcaps flag is set to 0 when we change user namespaces.
    TEST_PCHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
    MaybeSave();

    TEST_PCHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1);
    MaybeSave();

    TEST_PCHECK(unshare(CLONE_NEWUSER) == 0);
    MaybeSave();

    TEST_PCHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0);
    MaybeSave();

    _exit(0);
  }

  int status;
  ASSERT_THAT(child_pid, SyscallSucceeds());
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

// This test will verify that PR_SET_KEEPCAPS and PR_GET_KEEPCAPS work correctly
TEST_F(PrctlKeepCapsSetuidTest, PrGetKeepCaps) {
  // Set PR_SET_KEEPCAPS to the negation of the original.
  ASSERT_THAT(prctl(PR_SET_KEEPCAPS, !original_keepcaps_, 0, 0, 0),
              SyscallSucceeds());

  // Verify it was set.
  ASSERT_THAT(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
              SyscallSucceedsWithValue(!original_keepcaps_));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (FLAGS_prctl_pr_get_keepcaps) {
    return gvisor::testing::kPrGetKeepCapsExitBase +
           prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
  }

  return RUN_ALL_TESTS();
}
