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

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>

#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

void NoopSignalHandler(int sig, siginfo_t* info, void* context) {}

}  // namespace

TEST(PauseTest, OnlyReturnsWhenSignalHandled) {
  struct sigaction sa;
  sigfillset(&sa.sa_mask);

  // Ensure that SIGUSR1 is ignored.
  sa.sa_handler = SIG_IGN;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

  // Register a handler for SIGUSR2.
  sa.sa_sigaction = NoopSignalHandler;
  sa.sa_flags = SA_SIGINFO;
  ASSERT_THAT(sigaction(SIGUSR2, &sa, nullptr), SyscallSucceeds());

  // The child sets their own tid.
  absl::Mutex mu;
  pid_t child_tid = 0;
  bool child_tid_available = false;
  std::atomic<int> sent_signal{0};
  std::atomic<int> waking_signal{0};
  ScopedThread t([&] {
    mu.Lock();
    child_tid = gettid();
    child_tid_available = true;
    mu.Unlock();
    EXPECT_THAT(pause(), SyscallFailsWithErrno(EINTR));
    waking_signal.store(sent_signal.load());
  });
  mu.Lock();
  mu.Await(absl::Condition(&child_tid_available));
  mu.Unlock();

  // Wait a bit to let the child enter pause().
  absl::SleepFor(absl::Seconds(3));

  // The child should not be woken by SIGUSR1.
  sent_signal.store(SIGUSR1);
  ASSERT_THAT(tgkill(getpid(), child_tid, SIGUSR1), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(3));

  // The child should be woken by SIGUSR2.
  sent_signal.store(SIGUSR2);
  ASSERT_THAT(tgkill(getpid(), child_tid, SIGUSR2), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(3));

  EXPECT_EQ(SIGUSR2, waking_signal.load());
}

}  // namespace testing
}  // namespace gvisor
