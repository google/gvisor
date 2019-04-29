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

#include "test/syscalls/linux/base_poll_test.h"

#include <sys/syscall.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

static volatile int timer_fired = 0;
static void SigAlarmHandler(int, siginfo_t*, void*) { timer_fired = 1; }

BasePollTest::BasePollTest() {
  // Register our SIGALRM handler, but save the original so we can restore in
  // the destructor.
  struct sigaction sa = {};
  sa.sa_sigaction = SigAlarmHandler;
  sigfillset(&sa.sa_mask);
  TEST_PCHECK(sigaction(SIGALRM, &sa, &original_alarm_sa_) == 0);
}

BasePollTest::~BasePollTest() {
  ClearTimer();
  TEST_PCHECK(sigaction(SIGALRM, &original_alarm_sa_, nullptr) == 0);
}

void BasePollTest::SetTimer(absl::Duration duration) {
  pid_t tgid = getpid();
  pid_t tid = gettid();
  ClearTimer();

  // Create a new timer thread.
  timer_ = absl::make_unique<TimerThread>(absl::Now() + duration, tgid, tid);
}

bool BasePollTest::TimerFired() const { return timer_fired; }

void BasePollTest::ClearTimer() {
  timer_.reset();
  timer_fired = 0;
}

}  // namespace testing
}  // namespace gvisor
