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

#include "test/util/timer_util.h"

#include "absl/memory/memory.h"

namespace gvisor {
namespace testing {

absl::Time Now(clockid_t id) {
  struct timespec now;
  TEST_PCHECK(clock_gettime(id, &now) == 0);
  return absl::TimeFromTimespec(now);
}

#ifdef __linux__

PosixErrorOr<IntervalTimer> TimerCreate(clockid_t clockid,
                                        const struct sigevent& sev) {
  int timerid;
  int ret = syscall(SYS_timer_create, clockid, &sev, &timerid);
  if (ret < 0) {
    return PosixError(errno, "timer_create");
  }
  if (ret > 0) {
    return PosixError(EINVAL, "timer_create should never return positive");
  }
  MaybeSave();
  return IntervalTimer(timerid);
}

static volatile int timer_fired = 0;
static void SigAlarmHandler(int, siginfo_t*, void*) { timer_fired = 1; }

Alarm::Alarm() {
  // Register our SIGALRM handler, but save the original so we can restore in
  // the destructor.
  struct sigaction sa = {};
  sa.sa_sigaction = SigAlarmHandler;
  sigfillset(&sa.sa_mask);
  TEST_PCHECK(sigaction(SIGALRM, &sa, &original_alarm_sa_) == 0);
}

Alarm::~Alarm() {
  ClearTimer();
  TEST_PCHECK(sigaction(SIGALRM, &original_alarm_sa_, nullptr) == 0);
}

void Alarm::SetTimer(absl::Duration duration) {
  pid_t tgid = getpid();
  pid_t tid = gettid();
  ClearTimer();

  // Create a new timer thread.
  timer_ = absl::make_unique<TimerThread>(absl::Now() + duration, tgid, tid);
}

bool Alarm::TimerFired() const { return timer_fired; }

void Alarm::ClearTimer() {
  timer_.reset();
  timer_fired = 0;
}

#endif  // __linux__

}  // namespace testing
}  // namespace gvisor
