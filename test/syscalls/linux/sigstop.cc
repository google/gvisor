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

#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

DEFINE_bool(sigstop_test_child, false,
            "If true, run the SigstopTest child workload.");

namespace gvisor {
namespace testing {

namespace {

constexpr absl::Duration kChildStartupDelay = absl::Seconds(5);
constexpr absl::Duration kChildMainThreadDelay = absl::Seconds(10);
constexpr absl::Duration kChildExtraThreadDelay = absl::Seconds(15);
constexpr absl::Duration kPostSIGSTOPDelay = absl::Seconds(20);

// Comparisons on absl::Duration aren't yet constexpr (2017-07-14), so we
// can't just use static_assert.
TEST(SigstopTest, TimesAreRelativelyConsistent) {
  EXPECT_LT(kChildStartupDelay, kChildMainThreadDelay)
      << "Child process will exit before the parent process attempts to stop "
         "it";
  EXPECT_LT(kChildMainThreadDelay, kChildExtraThreadDelay)
      << "Secondary thread in child process will exit before main thread, "
         "causing it to exit with the wrong code";
  EXPECT_LT(kChildExtraThreadDelay, kPostSIGSTOPDelay)
      << "Parent process stops waiting before child process may exit if "
         "improperly stopped, rendering the test ineffective";
}

// Exit codes communicated from the child workload to the parent test process.
constexpr int kChildMainThreadExitCode = 10;
constexpr int kChildExtraThreadExitCode = 11;

TEST(SigstopTest, Correctness) {
  pid_t child_pid = -1;
  int execve_errno = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe", {"/proc/self/exe", "--sigstop_test_child"},
                  {}, nullptr, &child_pid, &execve_errno));

  ASSERT_GT(child_pid, 0);
  ASSERT_EQ(execve_errno, 0);

  // Wait for the child subprocess to start the second thread before stopping
  // it.
  absl::SleepFor(kChildStartupDelay);
  ASSERT_THAT(kill(child_pid, SIGSTOP), SyscallSucceeds());
  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child_pid, &status, WUNTRACED),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFSTOPPED(status));
  EXPECT_EQ(SIGSTOP, WSTOPSIG(status));

  // Sleep for longer than either of the sleeps in the child subprocess,
  // expecting the child to stay alive because it's stopped.
  absl::SleepFor(kPostSIGSTOPDelay);
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, WNOHANG),
              SyscallSucceedsWithValue(0));

  // Resume the child.
  ASSERT_THAT(kill(child_pid, SIGCONT), SyscallSucceeds());

  EXPECT_THAT(RetryEINTR(waitpid)(child_pid, &status, WCONTINUED),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFCONTINUED(status));

  // Expect it to die.
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), kChildMainThreadExitCode);
}

// Like base:SleepFor, but tries to avoid counting time spent stopped due to a
// stop signal toward the sleep.
//
// This is required due to an inconsistency in how nanosleep(2) and stop signals
// interact on Linux. When nanosleep is interrupted, it writes the remaining
// time back to its second timespec argument, so that if nanosleep is
// interrupted by a signal handler then userspace can immediately call nanosleep
// again with that timespec. However, if nanosleep is automatically restarted
// (because it's interrupted by a signal that is not delivered to a handler,
// such as a stop signal), it's restarted based on the timer's former *absolute*
// expiration time (via ERESTART_RESTARTBLOCK => SYS_restart_syscall =>
// hrtimer_nanosleep_restart). This means that time spent stopped is effectively
// counted as time spent sleeping, resulting in less time spent sleeping than
// expected.
//
// Dividing the sleep into multiple smaller sleeps limits the impact of this
// effect to the length of each sleep during which a stop occurs; for example,
// if a sleeping process is only stopped once, SleepIgnoreStopped can
// under-sleep by at most 100ms.
void SleepIgnoreStopped(absl::Duration d) {
  absl::Duration const max_sleep = absl::Milliseconds(100);
  while (d > absl::ZeroDuration()) {
    absl::Duration to_sleep = std::min(d, max_sleep);
    absl::SleepFor(to_sleep);
    d -= to_sleep;
  }
}

void RunChild() {
  // Start another thread that attempts to call exit_group with a different
  // error code, in order to verify that SIGSTOP stops this thread as well.
  ScopedThread t([] {
    SleepIgnoreStopped(kChildExtraThreadDelay);
    exit(kChildExtraThreadExitCode);
  });
  SleepIgnoreStopped(kChildMainThreadDelay);
  exit(kChildMainThreadExitCode);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (FLAGS_sigstop_test_child) {
    gvisor::testing::RunChild();
    return 1;
  }

  return RUN_ALL_TESTS();
}
