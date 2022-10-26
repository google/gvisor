// Copyright 2019 The gVisor Authors.
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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <functional>
#include <vector>

#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

using ::testing::KilledBySignal;

namespace gvisor {
namespace testing {

namespace {

constexpr int kSigno = SIGUSR1;
constexpr int kSignoMax = 64;  // SIGRTMAX
constexpr int kSignoAlt = SIGUSR2;

class SignalfdTest : public ::testing::TestWithParam<int> {};

TEST_P(SignalfdTest, Basic) {
  int signo = GetParam();
  // Create the signalfd.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signo);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, 0));

  // Deliver the blocked signal.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, signo));
  ASSERT_THAT(tgkill(getpid(), gettid(), signo), SyscallSucceeds());

  // We should now read the signal.
  struct signalfd_siginfo rbuf;
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(rbuf.ssi_signo, signo);
}

TEST_P(SignalfdTest, MaskWorks) {
  int signo = GetParam();
  // Create two signalfds with different masks.
  sigset_t mask1, mask2;
  sigemptyset(&mask1);
  sigemptyset(&mask2);
  sigaddset(&mask1, signo);
  sigaddset(&mask2, kSignoAlt);
  FileDescriptor fd1 = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask1, 0));
  FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask2, 0));

  // Deliver the two signals.
  const auto scoped_sigmask1 =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, signo));
  const auto scoped_sigmask2 =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, kSignoAlt));
  ASSERT_THAT(tgkill(getpid(), gettid(), signo), SyscallSucceeds());
  ASSERT_THAT(tgkill(getpid(), gettid(), kSignoAlt), SyscallSucceeds());

  // We should see the signals on the appropriate signalfds.
  //
  // We read in the opposite order as the signals deliver above, to ensure that
  // we don't happen to read the correct signal from the correct signalfd.
  struct signalfd_siginfo rbuf1, rbuf2;
  ASSERT_THAT(read(fd2.get(), &rbuf2, sizeof(rbuf2)),
              SyscallSucceedsWithValue(sizeof(rbuf2)));
  EXPECT_EQ(rbuf2.ssi_signo, kSignoAlt);
  ASSERT_THAT(read(fd1.get(), &rbuf1, sizeof(rbuf1)),
              SyscallSucceedsWithValue(sizeof(rbuf1)));
  EXPECT_EQ(rbuf1.ssi_signo, signo);
}

TEST(Signalfd, Cloexec) {
  // Exec tests confirm that O_CLOEXEC has the intended effect. We just create a
  // signalfd with the appropriate flag here and assert that the FD has it set.
  sigset_t mask;
  sigemptyset(&mask);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, SFD_CLOEXEC));
  EXPECT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

TEST_P(SignalfdTest, Blocking) {
  int signo = GetParam();
  // Create the signalfd in blocking mode.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signo);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, 0));

  // Shared tid variable.
  absl::Mutex mu;
  bool has_tid = false;
  pid_t tid;

  // Start a thread reading.
  ScopedThread t([&] {
    // Copy the tid and notify the caller.
    {
      absl::MutexLock ml(&mu);
      tid = gettid();
      has_tid = true;
    }

    // Read the signal from the signalfd.
    struct signalfd_siginfo rbuf;
    ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
                SyscallSucceedsWithValue(sizeof(rbuf)));
    EXPECT_EQ(rbuf.ssi_signo, signo);
  });

  // Wait until blocked.
  absl::MutexLock ml(&mu);
  mu.Await(absl::Condition(&has_tid));

  // Deliver the signal to either the waiting thread, or
  // to this thread. N.B. this is a bug in the core gVisor
  // behavior for signalfd, and needs to be fixed.
  //
  // See gvisor.dev/issue/139.
  if (IsRunningOnGvisor()) {
    ASSERT_THAT(tgkill(getpid(), gettid(), signo), SyscallSucceeds());
  } else {
    ASSERT_THAT(tgkill(getpid(), tid, signo), SyscallSucceeds());
  }

  // Ensure that it was received.
  t.Join();
}

TEST_P(SignalfdTest, ThreadGroup) {
  int signo = GetParam();
  // Create the signalfd in blocking mode.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signo);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, 0));

  // Shared variable.
  absl::Mutex mu;
  bool first = false;
  bool second = false;

  // Start a thread reading.
  ScopedThread t([&] {
    // Read the signal from the signalfd.
    struct signalfd_siginfo rbuf;
    ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
                SyscallSucceedsWithValue(sizeof(rbuf)));
    EXPECT_EQ(rbuf.ssi_signo, signo);

    // Wait for the other thread.
    absl::MutexLock ml(&mu);
    first = true;
    mu.Await(absl::Condition(&second));
  });

  // Deliver the signal to the threadgroup.
  ASSERT_THAT(kill(getpid(), signo), SyscallSucceeds());

  // Wait for the first thread to process.
  {
    absl::MutexLock ml(&mu);
    mu.Await(absl::Condition(&first));
  }

  // Deliver to the thread group again (other thread still exists).
  ASSERT_THAT(kill(getpid(), signo), SyscallSucceeds());

  // Ensure that we can also receive it.
  struct signalfd_siginfo rbuf;
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(rbuf.ssi_signo, signo);

  // Mark the test as done.
  {
    absl::MutexLock ml(&mu);
    second = true;
  }

  // The other thread should be joinable.
  t.Join();
}

TEST_P(SignalfdTest, Nonblock) {
  int signo = GetParam();
  // Create the signalfd in non-blocking mode.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signo);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, SFD_NONBLOCK));

  // We should return if we attempt to read.
  struct signalfd_siginfo rbuf;
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Block and deliver the signal.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, signo));
  ASSERT_THAT(tgkill(getpid(), gettid(), signo), SyscallSucceeds());

  // Ensure that a read actually works.
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(rbuf.ssi_signo, signo);

  // Should block again.
  EXPECT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(SignalfdTest, SetMask) {
  int signo = GetParam();
  // Create the signalfd matching nothing.
  sigset_t mask;
  sigemptyset(&mask);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, SFD_NONBLOCK));

  // Block and deliver a signal.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, signo));
  ASSERT_THAT(tgkill(getpid(), gettid(), signo), SyscallSucceeds());

  // We should have nothing.
  struct signalfd_siginfo rbuf;
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Change the signal mask.
  sigaddset(&mask, signo);
  ASSERT_THAT(signalfd(fd.get(), &mask, 0), SyscallSucceeds());

  // We should now have the signal.
  ASSERT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(rbuf.ssi_signo, signo);
}

TEST_P(SignalfdTest, Poll) {
  int signo = GetParam();
  // Create the signalfd.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signo);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, 0));

  // Block the signal, and start a thread to deliver it.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, signo));
  pid_t orig_tid = gettid();
  ScopedThread t([&] {
    absl::SleepFor(absl::Seconds(5));
    ASSERT_THAT(tgkill(getpid(), orig_tid, signo), SyscallSucceeds());
  });

  // Start polling for the signal. We expect that it is not available at the
  // outset, but then becomes available when the signal is sent. We give a
  // timeout of 10000ms (or the delay above + 5 seconds of additional grace
  // time).
  struct pollfd poll_fd = {fd.get(), POLLIN, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));

  // Actually read the signal to prevent delivery.
  struct signalfd_siginfo rbuf;
  EXPECT_THAT(read(fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
}

std::string PrintSigno(::testing::TestParamInfo<int> info) {
  switch (info.param) {
    case kSigno:
      return "kSigno";
    case kSignoMax:
      return "kSignoMax";
    default:
      return absl::StrCat(info.param);
  }
}
INSTANTIATE_TEST_SUITE_P(Signalfd, SignalfdTest,
                         ::testing::Values(kSigno, kSignoMax), PrintSigno);

TEST(Signalfd, Ppoll) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGKILL);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, SFD_CLOEXEC));

  // Ensure that the given ppoll blocks.
  struct pollfd pfd = {};
  pfd.fd = fd.get();
  pfd.events = POLLIN;
  struct timespec timeout = {};
  timeout.tv_sec = 1;
  EXPECT_THAT(RetryEINTR(ppoll)(&pfd, 1, &timeout, &mask),
              SyscallSucceedsWithValue(0));
}

TEST(Signalfd, KillStillKills) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGKILL);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewSignalFD(&mask, SFD_CLOEXEC));

  // Just because there is a signalfd, we shouldn't see any change in behavior
  // for unblockable signals. It's easier to test this with SIGKILL.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, SIGKILL));
  EXPECT_EXIT(tgkill(getpid(), gettid(), SIGKILL), KilledBySignal(SIGKILL), "");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // These tests depend on delivering signals. Block them up front so that all
  // other threads created by TestInit will also have them blocked, and they
  // will not interface with the rest of the test.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, gvisor::testing::kSigno);
  sigaddset(&set, gvisor::testing::kSignoMax);
  sigaddset(&set, gvisor::testing::kSignoAlt);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);

  return gvisor::testing::RunAllTests();
}
