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

#endif  // __linux__

}  // namespace testing
}  // namespace gvisor
