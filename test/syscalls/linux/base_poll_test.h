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

#ifndef GVISOR_TEST_SYSCALLS_BASE_POLL_TEST_H_
#define GVISOR_TEST_SYSCALLS_BASE_POLL_TEST_H_

#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <memory>

#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

// TimerThread is a cancelable timer.
class TimerThread {
 public:
  TimerThread(absl::Time deadline, pid_t tgid, pid_t tid)
      : thread_([=] {
          mu_.Lock();
          mu_.AwaitWithDeadline(absl::Condition(&cancel_), deadline);
          if (!cancel_) {
            TEST_PCHECK(tgkill(tgid, tid, SIGALRM) == 0);
          }
          mu_.Unlock();
        }) {}

  ~TimerThread() { Cancel(); }

  void Cancel() {
    absl::MutexLock ml(&mu_);
    cancel_ = true;
  }

 private:
  mutable absl::Mutex mu_;
  bool cancel_ ABSL_GUARDED_BY(mu_) = false;

  // Must be last to ensure that the destructor for the thread is run before
  // any other member of the object is destroyed.
  ScopedThread thread_;
};

// Base test fixture for poll, select, ppoll, and pselect tests.
//
// This fixture makes use of SIGALRM. The handler is saved in SetUp() and
// restored in TearDown().
class BasePollTest : public ::testing::Test {
 protected:
  BasePollTest();
  ~BasePollTest() override;

  // Sets a timer that will send a signal to the calling thread after
  // `duration`.
  void SetTimer(absl::Duration duration);

  // Returns true if the timer has fired.
  bool TimerFired() const;

  // Stops the pending timer (if any) and clear the "fired" state.
  void ClearTimer();

 private:
  // Thread that implements the timer. If the timer is stopped, timer_ is null.
  //
  // We have to use a thread for this purpose because tests using this fixture
  // expect to be interrupted by the timer signal, but itimers/alarm(2) send
  // thread-group-directed signals, which may be handled by any thread in the
  // test process.
  std::unique_ptr<TimerThread> timer_;

  // The original SIGALRM handler, to restore in destructor.
  struct sigaction original_alarm_sa_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_BASE_POLL_TEST_H_
