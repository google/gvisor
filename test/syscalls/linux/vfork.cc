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

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/test_util.h"
#include "test/util/time_util.h"

DEFINE_bool(vfork_test_child, false,
            "If true, run the VforkTest child workload.");

namespace gvisor {
namespace testing {

namespace {

// We don't test with raw CLONE_VFORK to avoid interacting with glibc's use of
// TLS.
//
// Even with vfork(2), we must be careful to do little more in the child than
// call execve(2). We use the simplest sleep function possible, though this is
// still precarious, as we're officially only allowed to call execve(2) and
// _exit(2).
constexpr absl::Duration kChildDelay = absl::Seconds(10);

// Exit code for successful child subprocesses. We don't want to use 0 since
// it's too common, and an execve(2) failure causes the child to exit with the
// errno, so kChildExitCode is chosen to be an unlikely errno:
constexpr int kChildExitCode = 118;  // ENOTNAM: Not a XENIX named type file

int64_t MonotonicNow() {
  struct timespec now;
  TEST_PCHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return now.tv_sec * 1000000000ll + now.tv_nsec;
}

TEST(VforkTest, ParentStopsUntilChildExits) {
  const auto test = [] {
    // N.B. Run the test in a single-threaded subprocess because
    // vfork is not safe in a multi-threaded process.

    const int64_t start = MonotonicNow();

    pid_t pid = vfork();
    if (pid == 0) {
      SleepSafe(kChildDelay);
      _exit(kChildExitCode);
    }
    TEST_PCHECK_MSG(pid > 0, "vfork failed");
    MaybeSave();

    const int64_t end = MonotonicNow();

    absl::Duration dur = absl::Nanoseconds(end - start);

    TEST_CHECK(dur >= kChildDelay);

    int status = 0;
    TEST_PCHECK(RetryEINTR(waitpid)(pid, &status, 0));
    TEST_CHECK(WIFEXITED(status));
    TEST_CHECK(WEXITSTATUS(status) == kChildExitCode);
  };

  EXPECT_THAT(InForkedProcess(test), IsPosixErrorOkAndHolds(0));
}

TEST(VforkTest, ParentStopsUntilChildExecves_NoRandomSave) {
  ExecveArray const owned_child_argv = {"/proc/self/exe", "--vfork_test_child"};
  char* const* const child_argv = owned_child_argv.get();

  const auto test = [&] {
    const int64_t start = MonotonicNow();

    pid_t pid = vfork();
    if (pid == 0) {
      SleepSafe(kChildDelay);
      execve(child_argv[0], child_argv, /* envp = */ nullptr);
      _exit(errno);
    }
    // Don't attempt save/restore until after recording end_time,
    // since the test expects an upper bound on the time spent
    // stopped.
    int saved_errno = errno;
    const int64_t end = MonotonicNow();
    errno = saved_errno;
    TEST_PCHECK_MSG(pid > 0, "vfork failed");
    MaybeSave();

    absl::Duration dur = absl::Nanoseconds(end - start);

    // The parent should resume execution after execve, but before
    // the post-execve test child exits.
    TEST_CHECK(dur >= kChildDelay);
    TEST_CHECK(dur <= 2 * kChildDelay);

    int status = 0;
    TEST_PCHECK(RetryEINTR(waitpid)(pid, &status, 0));
    TEST_CHECK(WIFEXITED(status));
    TEST_CHECK(WEXITSTATUS(status) == kChildExitCode);
  };

  EXPECT_THAT(InForkedProcess(test), IsPosixErrorOkAndHolds(0));
}

// A vfork child does not unstop the parent a second time when it exits after
// exec.
TEST(VforkTest, ExecedChildExitDoesntUnstopParent_NoRandomSave) {
  ExecveArray const owned_child_argv = {"/proc/self/exe", "--vfork_test_child"};
  char* const* const child_argv = owned_child_argv.get();

  const auto test = [&] {
    pid_t pid1 = vfork();
    if (pid1 == 0) {
      execve(child_argv[0], child_argv, /* envp = */ nullptr);
      _exit(errno);
    }
    TEST_PCHECK_MSG(pid1 > 0, "vfork failed");
    MaybeSave();

    // pid1 exec'd and is now sleeping.
    SleepSafe(kChildDelay / 2);

    const int64_t start = MonotonicNow();

    pid_t pid2 = vfork();
    if (pid2 == 0) {
      SleepSafe(kChildDelay);
      _exit(kChildExitCode);
    }
    TEST_PCHECK_MSG(pid2 > 0, "vfork failed");
    MaybeSave();

    const int64_t end = MonotonicNow();

    absl::Duration dur = absl::Nanoseconds(end - start);

    // The parent should resume execution only after pid2 exits, not
    // when pid1 exits.
    TEST_CHECK(dur >= kChildDelay);

    int status = 0;
    TEST_PCHECK(RetryEINTR(waitpid)(pid1, &status, 0));
    TEST_CHECK(WIFEXITED(status));
    TEST_CHECK(WEXITSTATUS(status) == kChildExitCode);

    TEST_PCHECK(RetryEINTR(waitpid)(pid2, &status, 0));
    TEST_CHECK(WIFEXITED(status));
    TEST_CHECK(WEXITSTATUS(status) == kChildExitCode);
  };

  EXPECT_THAT(InForkedProcess(test), IsPosixErrorOkAndHolds(0));
}

int RunChild() {
  SleepSafe(kChildDelay);
  return kChildExitCode;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (FLAGS_vfork_test_child) {
    return gvisor::testing::RunChild();
  }

  return RUN_ALL_TESTS();
}
