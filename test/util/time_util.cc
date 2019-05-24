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

#include "test/util/time_util.h"

#include <sys/syscall.h>
#include <unistd.h>

#include "absl/time/time.h"

namespace gvisor {
namespace testing {

void SleepSafe(absl::Duration duration) {
  if (duration == absl::ZeroDuration()) {
    return;
  }

  struct timespec ts = absl::ToTimespec(duration);
  int ret;
  while (1) {
    ret = syscall(__NR_nanosleep, &ts, &ts);
    if (ret == 0 || (ret <= 0 && errno != EINTR)) {
      break;
    }
  }
}

}  // namespace testing
}  // namespace gvisor
