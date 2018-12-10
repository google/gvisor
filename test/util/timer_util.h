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

#ifndef GVISOR_TEST_UTIL_TIMER_UTIL_H_
#define GVISOR_TEST_UTIL_TIMER_UTIL_H_

#include <errno.h>
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

// MonotonicTimer is a simple timer that uses a monotic clock.
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

// Returns the current time.
absl::Time Now(clockid_t id);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_TIMER_UTIL_H_
