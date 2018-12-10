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
#include <sched.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// In linux, pid is limited to 29 bits because how futex is implemented.
constexpr int kImpossiblePID = (1 << 29) + 1;

TEST(SchedGetparamTest, ReturnsZero) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(getpid(), &param), SyscallSucceeds());
  EXPECT_EQ(param.sched_priority, 0);
  EXPECT_THAT(sched_getparam(/*pid=*/0, &param), SyscallSucceeds());
  EXPECT_EQ(param.sched_priority, 0);
}

TEST(SchedGetparamTest, InvalidPIDReturnsEINVAL) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(/*pid=*/-1, &param),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetparamTest, ImpossiblePIDReturnsESRCH) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(kImpossiblePID, &param),
              SyscallFailsWithErrno(ESRCH));
}

TEST(SchedGetparamTest, NullParamReturnsEINVAL) {
  EXPECT_THAT(sched_getparam(0, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetschedulerTest, ReturnsSchedOther) {
  EXPECT_THAT(sched_getscheduler(getpid()),
              SyscallSucceedsWithValue(SCHED_OTHER));
  EXPECT_THAT(sched_getscheduler(/*pid=*/0),
              SyscallSucceedsWithValue(SCHED_OTHER));
}

TEST(SchedGetschedulerTest, ReturnsEINVAL) {
  EXPECT_THAT(sched_getscheduler(/*pid=*/-1), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetschedulerTest, ReturnsESRCH) {
  EXPECT_THAT(sched_getscheduler(kImpossiblePID), SyscallFailsWithErrno(ESRCH));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
