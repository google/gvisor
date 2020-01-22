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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <atomic>
#include <functional>
#include <iostream>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr char kSIGALRMToMainThread[] = "--itimer_sigarlm_to_main_thread";
constexpr char kSIGPROFFairnessActive[] = "--itimer_sigprof_fairness_active";
constexpr char kSIGPROFFairnessIdle[] = "--itimer_sigprof_fairness_idle";

// Time period to be set for the itimers.
constexpr absl::Duration kPeriod = absl::Milliseconds(25);
// Total amount of time to spend per thread.
constexpr absl::Duration kTestDuration = absl::Seconds(20);
// Amount of spin iterations to perform as the minimum work item per thread.
// Chosen to be sub-millisecond range.
constexpr int kIterations = 10000000;
// Allow deviation in the number of samples.
constexpr double kNumSamplesDeviationRatio = 0.2;

TEST(ItimerTest, ItimervalUpdatedBeforeExpiration) {
  constexpr int kSleepSecs = 10;
  constexpr int kAlarmSecs = 15;
  static_assert(
      kSleepSecs < kAlarmSecs,
      "kSleepSecs must be less than kAlarmSecs for the test to be meaningful");
  constexpr int kMaxRemainingSecs = kAlarmSecs - kSleepSecs;

  // Install a no-op handler for SIGALRM.
  struct sigaction sa = {};
  sigfillset(&sa.sa_mask);
  sa.sa_handler = +[](int signo) {};
  auto const cleanup_sa =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Set an itimer-based alarm for kAlarmSecs from now.
  struct itimerval itv = {};
  itv.it_value.tv_sec = kAlarmSecs;
  auto const cleanup_itimer =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_REAL, itv));

  // After sleeping for kSleepSecs, the itimer value should reflect the elapsed
  // time even if it hasn't expired.
  absl::SleepFor(absl::Seconds(kSleepSecs));
  ASSERT_THAT(getitimer(ITIMER_REAL, &itv), SyscallSucceeds());
  EXPECT_TRUE(
      itv.it_value.tv_sec < kMaxRemainingSecs ||
      (itv.it_value.tv_sec == kMaxRemainingSecs && itv.it_value.tv_usec == 0))
      << "Remaining time: " << itv.it_value.tv_sec << " seconds + "
      << itv.it_value.tv_usec << " microseconds";
}

ABSL_CONST_INIT static thread_local std::atomic_int signal_test_num_samples =
    ATOMIC_VAR_INIT(0);

void SignalTestSignalHandler(int /*signum*/) { signal_test_num_samples++; }

struct SignalTestResult {
  int expected_total;
  int main_thread_samples;
  std::vector<int> worker_samples;
};

std::ostream& operator<<(std::ostream& os, const SignalTestResult& r) {
  os << "{expected_total: " << r.expected_total
     << ", main_thread_samples: " << r.main_thread_samples
     << ", worker_samples: [";
  bool first = true;
  for (int sample : r.worker_samples) {
    if (!first) {
      os << ", ";
    }
    os << sample;
    first = false;
  }
  os << "]}";
  return os;
}

// Starts two worker threads and itimer id and measures the number of signal
// delivered to each thread.
SignalTestResult ItimerSignalTest(int id, clock_t main_clock,
                                  clock_t worker_clock, int signal,
                                  absl::Duration sleep) {
  signal_test_num_samples = 0;

  struct sigaction sa = {};
  sa.sa_handler = &SignalTestSignalHandler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  auto sigaction_cleanup = ScopedSigaction(signal, sa).ValueOrDie();

  int socketfds[2];
  TEST_PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, socketfds) == 0);

  // Do the spinning in the workers.
  std::function<void*(int)> work = [&](int socket_fd) {
    FileDescriptor fd(socket_fd);

    absl::Time finish = Now(worker_clock) + kTestDuration;
    while (Now(worker_clock) < finish) {
      // Blocked on read.
      char c;
      RetryEINTR(read)(fd.get(), &c, 1);
      for (int i = 0; i < kIterations; i++) {
        // Ensure compiler won't optimize this loop away.
        asm("");
      }

      if (sleep != absl::ZeroDuration()) {
        // Sleep so that the entire process is idle for a while.
        absl::SleepFor(sleep);
      }

      // Unblock the other thread.
      RetryEINTR(write)(fd.get(), &c, 1);
    }

    return reinterpret_cast<void*>(signal_test_num_samples.load());
  };

  ScopedThread th1(
      static_cast<std::function<void*()>>(std::bind(work, socketfds[0])));
  ScopedThread th2(
      static_cast<std::function<void*()>>(std::bind(work, socketfds[1])));

  absl::Time start = Now(main_clock);
  // Start the timer.
  struct itimerval timer = {};
  timer.it_value = absl::ToTimeval(kPeriod);
  timer.it_interval = absl::ToTimeval(kPeriod);
  auto cleanup_itimer = ScopedItimer(id, timer).ValueOrDie();

  // Unblock th1.
  //
  // N.B. th2 owns socketfds[1] but can't close it until it unblocks.
  char c = 0;
  TEST_CHECK(write(socketfds[1], &c, 1) == 1);

  SignalTestResult result;

  // Wait for the workers to be done and collect their sample counts.
  result.worker_samples.push_back(reinterpret_cast<int64_t>(th1.Join()));
  result.worker_samples.push_back(reinterpret_cast<int64_t>(th2.Join()));
  cleanup_itimer.Release()();
  result.expected_total = (Now(main_clock) - start) / kPeriod;
  result.main_thread_samples = signal_test_num_samples.load();

  return result;
}

int TestSIGALRMToMainThread() {
  SignalTestResult result =
      ItimerSignalTest(ITIMER_REAL, CLOCK_REALTIME, CLOCK_REALTIME, SIGALRM,
                       absl::ZeroDuration());

  std::cerr << "result: " << result << std::endl;

  // ITIMER_REAL-generated SIGALRMs prefer to deliver to the thread group leader
  // (but don't guarantee it), so we expect to see most samples on the main
  // thread.
  //
  // The number of SIGALRMs delivered to a worker should not exceed 20%
  // of the number of total signals expected (this is somewhat arbitrary).
  const int worker_threshold = result.expected_total / 5;

  //
  // Linux only guarantees timers will never expire before the requested time.
  // Thus, we only check the upper bound and also it at least have one sample.
  TEST_CHECK(result.main_thread_samples <= result.expected_total);
  TEST_CHECK(result.main_thread_samples > 0);
  for (int num : result.worker_samples) {
    TEST_CHECK_MSG(num <= worker_threshold, "worker received too many samples");
  }

  return 0;
}

// Random save/restore is disabled as it introduces additional latency and
// unpredictable distribution patterns.
TEST(ItimerTest, DeliversSIGALRMToMainThread_NoRandomSave) {
  pid_t child;
  int execve_errno;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe", {"/proc/self/exe", kSIGALRMToMainThread},
                  {}, &child, &execve_errno));
  EXPECT_EQ(0, execve_errno);

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));

  // Not required anymore.
  kill.Release();

  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;
}

// Signals are delivered to threads fairly.
//
// sleep indicates how long to sleep worker threads each iteration to make the
// entire process idle.
int TestSIGPROFFairness(absl::Duration sleep) {
  SignalTestResult result =
      ItimerSignalTest(ITIMER_PROF, CLOCK_PROCESS_CPUTIME_ID,
                       CLOCK_THREAD_CPUTIME_ID, SIGPROF, sleep);

  std::cerr << "result: " << result << std::endl;

  // The number of samples on the main thread should be very low as it did
  // nothing.
  TEST_CHECK(result.main_thread_samples < 60);

  // Both workers should get roughly equal number of samples.
  TEST_CHECK(result.worker_samples.size() == 2);

  TEST_CHECK(result.expected_total > 0);

  // In an ideal world each thread would get exactly 50% of the signals,
  // but since that's unlikely to happen we allow for them to get no less than
  // kNumSamplesDeviationRatio of the total observed samples.
  TEST_CHECK_MSG(std::abs(result.worker_samples[0] - result.worker_samples[1]) <
                     ((result.worker_samples[0] + result.worker_samples[1]) *
                      kNumSamplesDeviationRatio),
                 "one worker received disproportionate share of samples");

  return 0;
}

// Random save/restore is disabled as it introduces additional latency and
// unpredictable distribution patterns.
TEST(ItimerTest, DeliversSIGPROFToThreadsRoughlyFairlyActive_NoRandomSave) {
  // TODO(b/143247272): CPU time accounting is inaccurate for the KVM platform.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  pid_t child;
  int execve_errno;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe", {"/proc/self/exe", kSIGPROFFairnessActive},
                  {}, &child, &execve_errno));
  EXPECT_EQ(0, execve_errno);

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));

  // Not required anymore.
  kill.Release();

  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

// Random save/restore is disabled as it introduces additional latency and
// unpredictable distribution patterns.
TEST(ItimerTest, DeliversSIGPROFToThreadsRoughlyFairlyIdle_NoRandomSave) {
  // TODO(b/143247272): CPU time accounting is inaccurate for the KVM platform.
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  pid_t child;
  int execve_errno;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/proc/self/exe", {"/proc/self/exe", kSIGPROFFairnessIdle},
                  {}, &child, &execve_errno));
  EXPECT_EQ(0, execve_errno);

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));

  // Not required anymore.
  kill.Release();

  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor

namespace {
void MaskSIGPIPE() {
  // Always mask SIGPIPE as it's common and tests aren't expected to handle it.
  // We don't take the TestInit() path so we must do this manually.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  TEST_CHECK(sigaction(SIGPIPE, &sa, nullptr) == 0);
}
}  // namespace

int main(int argc, char** argv) {
  // These tests require no background threads, so check for them before
  // TestInit.
  for (int i = 0; i < argc; i++) {
    absl::string_view arg(argv[i]);

    if (arg == gvisor::testing::kSIGALRMToMainThread) {
      MaskSIGPIPE();
      return gvisor::testing::TestSIGALRMToMainThread();
    }
    if (arg == gvisor::testing::kSIGPROFFairnessActive) {
      MaskSIGPIPE();
      return gvisor::testing::TestSIGPROFFairness(absl::ZeroDuration());
    }
    if (arg == gvisor::testing::kSIGPROFFairnessIdle) {
      MaskSIGPIPE();
      // Sleep time > ClockTick (10ms) exercises sleeping gVisor's
      // kernel.cpuClockTicker.
      return gvisor::testing::TestSIGPROFFairness(absl::Milliseconds(25));
    }
  }

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
