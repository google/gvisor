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

#include <signal.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// N.B. Below, main blocks SIGALRM. Test cases must unblock it if they want
// delivery.

void do_nothing_handler(int sig, siginfo_t* siginfo, void* arg) {}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and read.
TEST(AlarmTest, Interrupt_NoRandomSave) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  FileDescriptor read_fd(pipe_fds[0]);
  FileDescriptor write_fd(pipe_fds[1]);

  // Use a signal handler that interrupts but does nothing rather than using the
  // default terminate action.
  struct sigaction sa;
  sa.sa_sigaction = do_nothing_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Actually allow SIGALRM delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  // Alarm in 20 second, which should be well after read blocks below.
  ASSERT_THAT(alarm(20), SyscallSucceeds());

  char buf;
  ASSERT_THAT(read(read_fd.get(), &buf, 1), SyscallFailsWithErrno(EINTR));
}

/* Count of the number of SIGALARMS handled. */
static volatile int alarms_received = 0;

void inc_alarms_handler(int sig, siginfo_t* siginfo, void* arg) {
  alarms_received++;
}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and read.
TEST(AlarmTest, Restart_NoRandomSave) {
  alarms_received = 0;

  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  FileDescriptor read_fd(pipe_fds[0]);
  // Write end closed by thread below.

  struct sigaction sa;
  sa.sa_sigaction = inc_alarms_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Spawn a thread to eventually unblock the read below.
  ScopedThread t([pipe_fds] {
    absl::SleepFor(absl::Seconds(30));
    EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
  });

  // Actually allow SIGALRM delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  // Alarm in 20 second, which should be well after read blocks below, but
  // before it returns.
  ASSERT_THAT(alarm(20), SyscallSucceeds());

  // Read and eventually get an EOF from the writer closing.  If SA_RESTART
  // didn't work, then the alarm would not have fired and we wouldn't increment
  // our alarms_received count in our signal handler, or we would have not
  // restarted the syscall gracefully, which we expect below in order to be
  // able to get the final EOF on the pipe.
  char buf;
  ASSERT_THAT(read(read_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_EQ(alarms_received, 1);

  t.Join();
}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and pause.
TEST(AlarmTest, SaSiginfo_NoRandomSave) {
  // Use a signal handler that interrupts but does nothing rather than using the
  // default terminate action.
  struct sigaction sa;
  sa.sa_sigaction = do_nothing_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Actually allow SIGALRM delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  // Alarm in 20 second, which should be well after pause blocks below.
  ASSERT_THAT(alarm(20), SyscallSucceeds());
  ASSERT_THAT(pause(), SyscallFailsWithErrno(EINTR));
}

// No random save as the test relies on alarm timing. Cooperative save tests
// already cover the save between alarm and pause.
TEST(AlarmTest, SaInterrupt_NoRandomSave) {
  // Use a signal handler that interrupts but does nothing rather than using the
  // default terminate action.
  struct sigaction sa;
  sa.sa_sigaction = do_nothing_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_INTERRUPT;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Actually allow SIGALRM delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  // Alarm in 20 second, which should be well after pause blocks below.
  ASSERT_THAT(alarm(20), SyscallSucceeds());
  ASSERT_THAT(pause(), SyscallFailsWithErrno(EINTR));
}

TEST(AlarmTest, UserModeSpinning) {
  alarms_received = 0;

  struct sigaction sa = {};
  sa.sa_sigaction = inc_alarms_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Actually allow SIGALRM delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGALRM));

  // Alarm in 20 second, which should be well into the loop below.
  ASSERT_THAT(alarm(20), SyscallSucceeds());
  // Make sure that the signal gets delivered even if we are spinning in user
  // mode when it arrives.
  while (!alarms_received) {
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // These tests depend on delivering SIGALRM to the main thread. Block SIGALRM
  // so that any other threads created by TestInit will also have SIGALRM
  // blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
