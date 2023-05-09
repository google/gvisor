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
#include <time.h>

#include <atomic>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "benchmark/benchmark.h"
#include "test/util/platform_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

// Test that a thread that never yields to the OS does not prevent other threads
// from running.
TEST(ConcurrencyTest, SingleProcessMultithreaded) {
  std::atomic<int> a(0);

  ScopedThread t([&a]() {
    while (!a.load()) {
    }
  });

  absl::SleepFor(absl::Seconds(1));

  // We are still able to execute code in this thread. The other hasn't
  // permanently hung execution in both threads.
  a.store(1);
}

// Test that multiple threads in this process continue to execute in parallel,
// even if an unrelated second process is spawned. Regression test for
// b/32119508.
TEST(ConcurrencyTest, MultiProcessMultithreaded) {
  // In PID 1, start TIDs 1 and 2, and put both to sleep.
  //
  // Start PID 3, which spins for 5 seconds, then exits.
  //
  // TIDs 1 and 2 wake and attempt to Activate, which cannot occur until PID 3
  // exits.
  //
  // Both TIDs 1 and 2 should be woken. If they are not both woken, the test
  // hangs.
  //
  // This is all fundamentally racy. If we are failing to wake all threads, the
  // expectation is that this test becomes flaky, rather than consistently
  // failing.
  //
  // If additional background threads fail to block, we may never schedule the
  // child, at which point this test effectively becomes
  // MultiProcessConcurrency. That's not expected to occur.

  std::atomic<int> a(0);
  ScopedThread t([&a]() {
    // Block so that PID 3 can execute and we can wait on its exit.
    absl::SleepFor(absl::Seconds(1));
    while (!a.load()) {
    }
  });

  pid_t child_pid = fork();
  if (child_pid == 0) {
    struct timespec now;
    TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    // Busy wait without making any blocking syscalls.
    auto end = now.tv_sec + 5;
    while (now.tv_sec < end) {
      TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    }
    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  absl::SleepFor(absl::Seconds(1));

  // If only TID 1 is woken, thread.Join will hang.
  // If only TID 2 is woken, both will hang.
  a.store(1);
  t.Join();

  int status = 0;
  EXPECT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

// Test that multiple processes can execute concurrently, even if one process
// never yields.
TEST(ConcurrencyTest, MultiProcessConcurrency) {
  SKIP_IF(PlatformSupportMultiProcess() == PlatformSupport::NotSupported);

  pid_t child_pid = fork();
  if (child_pid == 0) {
    while (true) {
      int x = 0;
      benchmark::DoNotOptimize(x);  // Don't optimize this loop away.
    }
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  absl::SleepFor(absl::Seconds(5));

  // We are still able to execute code in this process. The other hasn't
  // permanently hung execution in both processes.
  ASSERT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
  int status = 0;

  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  ASSERT_TRUE(WIFSIGNALED(status));
  ASSERT_EQ(WTERMSIG(status), SIGKILL);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
