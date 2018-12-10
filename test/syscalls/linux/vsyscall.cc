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
#include <time.h>

#include "gtest/gtest.h"
#include "test/util/proc_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

time_t vsyscall_time(time_t* t) {
  constexpr uint64_t kVsyscallTimeEntry = 0xffffffffff600400;
  return reinterpret_cast<time_t (*)(time_t*)>(kVsyscallTimeEntry)(t);
}

TEST(VsyscallTest, VsyscallAlwaysAvailableOnGvisor) {
  SKIP_IF(!IsRunningOnGvisor());
  // Vsyscall is always advertised by gvisor.
  EXPECT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));
  // Vsyscall should always works on gvisor.
  time_t t;
  EXPECT_THAT(vsyscall_time(&t), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
