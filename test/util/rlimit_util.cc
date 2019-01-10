// Copyright 2019 Google LLC
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

#include "test/util/rlimit_util.h"

#include <sys/resource.h>
#include <cerrno>

#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<Cleanup> ScopedSetSoftRlimit(int resource, rlim_t newval) {
  struct rlimit old_rlim;
  if (getrlimit(resource, &old_rlim) != 0) {
    return PosixError(errno, "getrlimit failed");
  }
  struct rlimit new_rlim = old_rlim;
  new_rlim.rlim_cur = newval;
  if (setrlimit(resource, &new_rlim) != 0) {
    return PosixError(errno, "setrlimit failed");
  }
  return Cleanup([resource, old_rlim] {
    TEST_PCHECK(setrlimit(resource, &old_rlim) == 0);
  });
}

}  // namespace testing
}  // namespace gvisor
