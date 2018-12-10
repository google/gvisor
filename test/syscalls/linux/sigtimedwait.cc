// Copyright 2018 Google LLC
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
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

// N.B. main() blocks SIGALRM and SIGCHLD on all threads.

constexpr int kAlarmSecs = 12;

void NoopHandler(int sig, siginfo_t* info, void* context) {}

TEST(SigtimedwaitTest, InvalidTimeout) {
  sigset_t mask;
  sigemptyset(&mask);
  struct timespec timeout = {0, 1000000001};
  EXPECT_THAT(sigtimedwait(&mask, nullptr, &timeout),
              SyscallFailsWithErrno(EINVAL));
  timeout = {-1, 0};
  EXPECT_THAT(sigtimedwait(&mask, nullptr, &timeout),
              SyscallFailsWithErrno(EINVAL));
  timeout = {0, -1};
  EXPECT_THAT(sigtimedwait(&mask, nullptr, &timeout),
              SyscallFailsWithErrno(EINVAL));
}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and wait.
TEST(SigtimedwaitTest, AlarmReturnsAlarm_NoRandomSave) {
  struct itimerval itv = {};
  itv.it_value.tv_sec = kAlarmSecs;
  const auto itimer_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_REAL, itv));

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  siginfo_t info = {};
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, &info, nullptr),
              SyscallSucceedsWithValue(SIGALRM));
  EXPECT_EQ(SIGALRM, info.si_signo);
}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and wait.
TEST(SigtimedwaitTest, NullTimeoutReturnsEINTR_NoRandomSave) {
  struct sigaction sa;
  sa.sa_sigaction = NoopHandler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  const auto action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  const auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  struct itimerval itv = {};
  itv.it_value.tv_sec = kAlarmSecs;
  const auto itimer_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_REAL, itv));

  sigset_t mask;
  sigemptyset(&mask);
  EXPECT_THAT(sigtimedwait(&mask, nullptr, nullptr),
              SyscallFailsWithErrno(EINTR));
}

TEST(SigtimedwaitTest, LegitTimeoutReturnsEAGAIN) {
  sigset_t mask;
  sigemptyset(&mask);
  struct timespec timeout = {1, 0};  // 1 second
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &timeout),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(SigtimedwaitTest, ZeroTimeoutReturnsEAGAIN) {
  sigset_t mask;
  sigemptyset(&mask);
  struct timespec timeout = {0, 0};  // 0 second
  EXPECT_THAT(sigtimedwait(&mask, nullptr, &timeout),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(SigtimedwaitTest, KillGeneratedSIGCHLD) {
  EXPECT_THAT(kill(getpid(), SIGCHLD), SyscallSucceeds());

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  struct timespec ts = {5, 0};
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &ts),
              SyscallSucceedsWithValue(SIGCHLD));
}

TEST(SigtimedwaitTest, ChildExitGeneratedSIGCHLD) {
  pid_t pid = fork();
  if (pid == 0) {
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());

  int status;
  EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  struct timespec ts = {5, 0};
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &ts),
              SyscallSucceedsWithValue(SIGCHLD));
}

TEST(SigtimedwaitTest, ChildExitGeneratedSIGCHLDWithHandler) {
  // Setup handler for SIGCHLD, but don't unblock it.
  struct sigaction sa;
  sa.sa_sigaction = NoopHandler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  const auto action_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGCHLD, sa));

  pid_t pid = fork();
  if (pid == 0) {
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  struct timespec ts = {5, 0};
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &ts),
              SyscallSucceedsWithValue(SIGCHLD));

  int status;
  EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;
}

TEST(SigtimedwaitTest, IgnoredUnmaskedSignal) {
  constexpr int kSigno = SIGUSR1;
  constexpr auto kSigtimedwaitSetupTime = absl::Seconds(2);
  constexpr auto kSigtimedwaitTimeout = absl::Seconds(5);
  ASSERT_GT(kSigtimedwaitTimeout, kSigtimedwaitSetupTime);

  // Ensure that kSigno is ignored, and unmasked on this thread.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, mask));

  // Create a thread which will send us kSigno while we are blocked in
  // sigtimedwait.
  pid_t tid = gettid();
  ScopedThread sigthread([&] {
    absl::SleepFor(kSigtimedwaitSetupTime);
    EXPECT_THAT(tgkill(getpid(), tid, kSigno), SyscallSucceeds());
  });

  // sigtimedwait should not observe kSigno since it is ignored and already
  // unmasked, causing it to be dropped before it is enqueued.
  struct timespec timeout_ts = absl::ToTimespec(kSigtimedwaitTimeout);
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &timeout_ts),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(SigtimedwaitTest, IgnoredMaskedSignal) {
  constexpr int kSigno = SIGUSR1;
  constexpr auto kSigtimedwaitSetupTime = absl::Seconds(2);
  constexpr auto kSigtimedwaitTimeout = absl::Seconds(5);
  ASSERT_GT(kSigtimedwaitTimeout, kSigtimedwaitSetupTime);

  // Ensure that kSigno is ignored, and masked on this thread.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, kSigno);
  auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, mask));

  // Create a thread which will send us kSigno while we are blocked in
  // sigtimedwait.
  pid_t tid = gettid();
  ScopedThread sigthread([&] {
    absl::SleepFor(kSigtimedwaitSetupTime);
    EXPECT_THAT(tgkill(getpid(), tid, kSigno), SyscallSucceeds());
  });

  // sigtimedwait should observe kSigno since it is normally masked, causing it
  // to be enqueued despite being ignored.
  struct timespec timeout_ts = absl::ToTimespec(kSigtimedwaitTimeout);
  EXPECT_THAT(RetryEINTR(sigtimedwait)(&mask, nullptr, &timeout_ts),
              SyscallSucceedsWithValue(kSigno));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // These tests depend on delivering SIGALRM/SIGCHLD to the main thread or in
  // sigtimedwait. Block them so that any other threads created by TestInit will
  // also have them blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  sigaddset(&set, SIGCHLD);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
