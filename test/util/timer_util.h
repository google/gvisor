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

#ifndef GVISOR_TEST_UTIL_TIMER_UTIL_H_
#define GVISOR_TEST_UTIL_TIMER_UTIL_H_

#include <errno.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <sys/time.h>

#include <functional>

#include "gmock/gmock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// From Linux's include/uapi/asm-generic/siginfo.h.
#ifndef sigev_notify_thread_id
#define sigev_notify_thread_id _sigev_un._tid
#endif

// Returns the current time.
absl::Time Now(clockid_t id);

// MonotonicTimer is a simple timer that uses a monotonic clock.
class MonotonicTimer {
 public:
  MonotonicTimer() {}
  absl::Duration Duration() {
    struct timespec ts;
    TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return absl::TimeFromTimespec(ts) - start_;
  }

  void Start() {
    struct timespec ts;
    TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    start_ = absl::TimeFromTimespec(ts);
  }

 protected:
  absl::Time start_;
};

// Sets the given itimer and returns a cleanup function that restores the
// previous itimer when it goes out of scope.
inline PosixErrorOr<Cleanup> ScopedItimer(int which,
                                          struct itimerval const& new_value) {
  struct itimerval old_value;
  int rc = setitimer(which, &new_value, &old_value);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "setitimer failed");
  }
  return Cleanup(std::function<void(void)>([which, old_value] {
    EXPECT_THAT(setitimer(which, &old_value, nullptr), SyscallSucceeds());
  }));
}

#ifdef __linux__

// RAII type for a kernel "POSIX" interval timer. (The kernel provides system
// calls such as timer_create that behave very similarly, but not identically,
// to those described by timer_create(2); in particular, the kernel does not
// implement SIGEV_THREAD. glibc builds POSIX-compliant interval timers based on
// these kernel interval timers.)
//
// Compare implementation to FileDescriptor.
class IntervalTimer {
 public:
  IntervalTimer() = default;

  explicit IntervalTimer(int id) { set_id(id); }

  IntervalTimer(IntervalTimer&& orig) : id_(orig.release()) {}

  IntervalTimer& operator=(IntervalTimer&& orig) {
    if (this == &orig) return *this;
    reset(orig.release());
    return *this;
  }

  IntervalTimer(const IntervalTimer& other) = delete;
  IntervalTimer& operator=(const IntervalTimer& other) = delete;

  ~IntervalTimer() { reset(); }

  int get() const { return id_; }

  int release() {
    int const id = id_;
    id_ = -1;
    return id;
  }

  void reset() { reset(-1); }

  void reset(int id) {
    if (id_ >= 0) {
      TEST_PCHECK(syscall(SYS_timer_delete, id_) == 0);
      MaybeSave();
    }
    set_id(id);
  }

  PosixErrorOr<struct itimerspec> Set(
      int flags, const struct itimerspec& new_value) const {
    struct itimerspec old_value = {};
    if (syscall(SYS_timer_settime, id_, flags, &new_value, &old_value) < 0) {
      return PosixError(errno, "timer_settime");
    }
    MaybeSave();
    return old_value;
  }

  PosixErrorOr<struct itimerspec> Get() const {
    struct itimerspec curr_value = {};
    if (syscall(SYS_timer_gettime, id_, &curr_value) < 0) {
      return PosixError(errno, "timer_gettime");
    }
    MaybeSave();
    return curr_value;
  }

  PosixErrorOr<int> Overruns() const {
    int rv = syscall(SYS_timer_getoverrun, id_);
    if (rv < 0) {
      return PosixError(errno, "timer_getoverrun");
    }
    MaybeSave();
    return rv;
  }

 private:
  void set_id(int id) { id_ = std::max(id, -1); }

  // Kernel timer_t is int; glibc timer_t is void*.
  int id_ = -1;
};

// A wrapper around timer_create(2).
PosixErrorOr<IntervalTimer> TimerCreate(clockid_t clockid,
                                        const struct sigevent& sev);

#endif  // __linux__

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_TIMER_UTIL_H_
