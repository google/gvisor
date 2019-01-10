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

#ifndef GVISOR_TEST_UTIL_RLIMIT_UTIL_H_
#define GVISOR_TEST_UTIL_RLIMIT_UTIL_H_

#include <sys/resource.h>
#include <sys/time.h>

#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<Cleanup> ScopedSetSoftRlimit(int resource, rlim_t newval);

}  // namespace testing
}  // namespace gvisor
#endif  // GVISOR_TEST_UTIL_RLIMIT_UTIL_H_
