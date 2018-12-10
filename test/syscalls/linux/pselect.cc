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
#include <sys/select.h>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/base_poll_test.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

struct MaskWithSize {
  sigset_t* mask;
  size_t mask_size;
};

// Linux and glibc have a different idea of the sizeof sigset_t. When calling
// the syscall directly, use what the kernel expects.
unsigned kSigsetSize = SIGRTMAX / 8;

// Linux pselect(2) differs from the glibc wrapper function in that Linux
// updates the timeout with the amount of time remaining. In order to test this
// behavior we need to use the syscall directly.
int syscallPselect6(int nfds, fd_set* readfds, fd_set* writefds,
                    fd_set* exceptfds, struct timespec* timeout,
                    const MaskWithSize* mask_with_size) {
  return syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, timeout,
                 mask_with_size);
}

class PselectTest : public BasePollTest {
 protected:
  void SetUp() override { BasePollTest::SetUp(); }
  void TearDown() override { BasePollTest::TearDown(); }
};

// See that when there are no FD sets, pselect behaves like sleep.
TEST_F(PselectTest, NullFds) {
  struct timespec timeout = absl::ToTimespec(absl::Milliseconds(10));
  ASSERT_THAT(syscallPselect6(0, nullptr, nullptr, nullptr, &timeout, nullptr),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 0);

  timeout = absl::ToTimespec(absl::Milliseconds(10));
  ASSERT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, nullptr),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 0);
}

TEST_F(PselectTest, ClosedFds) {
  fd_set read_set;
  FD_ZERO(&read_set);
  int fd;
  ASSERT_THAT(fd = dup(1), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
  FD_SET(fd, &read_set);
  struct timespec timeout = absl::ToTimespec(absl::Milliseconds(10));
  EXPECT_THAT(
      syscallPselect6(fd + 1, &read_set, nullptr, nullptr, &timeout, nullptr),
      SyscallFailsWithErrno(EBADF));
}

TEST_F(PselectTest, ZeroTimeout) {
  struct timespec timeout = {};
  ASSERT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, nullptr),
              SyscallSucceeds());
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 0);
}

// If random S/R interrupts the pselect, SIGALRM may be delivered before pselect
// restarts, causing the pselect to hang forever.
TEST_F(PselectTest, NoTimeout_NoRandomSave) {
  // When there's no timeout, pselect may never return so set a timer.
  SetTimer(absl::Milliseconds(100));
  // See that we get interrupted by the timer.
  ASSERT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, nullptr, nullptr),
              SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
}

TEST_F(PselectTest, InvalidTimeoutNegative) {
  struct timespec timeout = absl::ToTimespec(absl::Seconds(-1));
  ASSERT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_EQ(timeout.tv_sec, -1);
  EXPECT_EQ(timeout.tv_nsec, 0);
}

TEST_F(PselectTest, InvalidTimeoutNotNormalized) {
  struct timespec timeout = {0, 1000000001};
  ASSERT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, nullptr),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_EQ(timeout.tv_sec, 0);
  EXPECT_EQ(timeout.tv_nsec, 1000000001);
}

TEST_F(PselectTest, EmptySigMaskInvalidMaskSize) {
  struct timespec timeout = {};
  MaskWithSize invalid = {nullptr, 7};
  EXPECT_THAT(syscallPselect6(0, nullptr, nullptr, nullptr, &timeout, &invalid),
              SyscallSucceeds());
}

TEST_F(PselectTest, EmptySigMaskValidMaskSize) {
  struct timespec timeout = {};
  MaskWithSize invalid = {nullptr, 8};
  EXPECT_THAT(syscallPselect6(0, nullptr, nullptr, nullptr, &timeout, &invalid),
              SyscallSucceeds());
}

TEST_F(PselectTest, InvalidMaskSize) {
  struct timespec timeout = {};
  sigset_t sigmask;
  ASSERT_THAT(sigemptyset(&sigmask), SyscallSucceeds());
  MaskWithSize invalid = {&sigmask, 7};
  EXPECT_THAT(syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, &invalid),
              SyscallFailsWithErrno(EINVAL));
}

// Verify that signals blocked by the pselect mask (that would otherwise be
// allowed) do not interrupt pselect.
TEST_F(PselectTest, SignalMaskBlocksSignal) {
  absl::Duration duration(absl::Seconds(30));
  struct timespec timeout = absl::ToTimespec(duration);
  absl::Duration timer_duration(absl::Seconds(10));

  // Call with a mask that blocks SIGALRM. See that pselect is not interrupted
  // (i.e. returns 0) and that upon completion, the timer has fired.
  sigset_t mask;
  ASSERT_THAT(sigprocmask(0, nullptr, &mask), SyscallSucceeds());
  ASSERT_THAT(sigaddset(&mask, SIGALRM), SyscallSucceeds());
  MaskWithSize mask_with_size = {&mask, kSigsetSize};
  SetTimer(timer_duration);
  MaybeSave();
  ASSERT_FALSE(TimerFired());
  ASSERT_THAT(
      syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, &mask_with_size),
      SyscallSucceeds());
  EXPECT_TRUE(TimerFired());
  EXPECT_EQ(absl::DurationFromTimespec(timeout), absl::Duration());
}

// Verify that signals allowed by the pselect mask (that would otherwise be
// blocked) interrupt pselect.
TEST_F(PselectTest, SignalMaskAllowsSignal) {
  absl::Duration duration = absl::Seconds(30);
  struct timespec timeout = absl::ToTimespec(duration);
  absl::Duration timer_duration = absl::Seconds(10);

  sigset_t mask;
  ASSERT_THAT(sigprocmask(0, nullptr, &mask), SyscallSucceeds());

  // Block SIGALRM.
  auto cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, SIGALRM));

  // Call with a mask that unblocks SIGALRM. See that pselect is interrupted.
  MaskWithSize mask_with_size = {&mask, kSigsetSize};
  SetTimer(timer_duration);
  MaybeSave();
  ASSERT_FALSE(TimerFired());
  ASSERT_THAT(
      syscallPselect6(1, nullptr, nullptr, nullptr, &timeout, &mask_with_size),
      SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
  EXPECT_GT(absl::DurationFromTimespec(timeout), absl::Duration());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
