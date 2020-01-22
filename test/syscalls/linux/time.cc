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

#include <errno.h>
#include <time.h>

#include "gtest/gtest.h"
#include "test/util/proc_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr long kFudgeSeconds = 5;

// Mimics the time(2) wrapper from glibc prior to 2.15.
time_t vsyscall_time(time_t* t) {
  constexpr uint64_t kVsyscallTimeEntry = 0xffffffffff600400;
  return reinterpret_cast<time_t (*)(time_t*)>(kVsyscallTimeEntry)(t);
}

TEST(TimeTest, VsyscallTime_Succeeds) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));

  time_t t1, t2;

  {
    const DisableSave ds;  // Timing assertions.
    EXPECT_THAT(time(&t1), SyscallSucceeds());
    EXPECT_THAT(vsyscall_time(&t2), SyscallSucceeds());
  }

  // Time should be monotonic.
  EXPECT_LE(static_cast<long>(t1), static_cast<long>(t2));

  // Check that it's within kFudge seconds.
  EXPECT_LE(static_cast<long>(t2), static_cast<long>(t1) + kFudgeSeconds);

  // Redo with save.
  EXPECT_THAT(time(&t1), SyscallSucceeds());
  EXPECT_THAT(vsyscall_time(&t2), SyscallSucceeds());

  // Time should be monotonic.
  EXPECT_LE(static_cast<long>(t1), static_cast<long>(t2));
}

TEST(TimeTest, VsyscallTime_InvalidAddressSIGSEGV) {
  EXPECT_EXIT(vsyscall_time(reinterpret_cast<time_t*>(0x1)),
              ::testing::KilledBySignal(SIGSEGV), "");
}

int vsyscall_gettimeofday(struct timeval* tv, struct timezone* tz) {
  constexpr uint64_t kVsyscallGettimeofdayEntry = 0xffffffffff600000;
  return reinterpret_cast<int (*)(struct timeval*, struct timezone*)>(
      kVsyscallGettimeofdayEntry)(tv, tz);
}

TEST(TimeTest, VsyscallGettimeofday_Succeeds) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));

  struct timeval tv1, tv2;
  struct timezone tz1, tz2;

  {
    const DisableSave ds;  // Timing assertions.
    EXPECT_THAT(gettimeofday(&tv1, &tz1), SyscallSucceeds());
    EXPECT_THAT(vsyscall_gettimeofday(&tv2, &tz2), SyscallSucceeds());
  }

  // See above.
  EXPECT_LE(static_cast<long>(tv1.tv_sec), static_cast<long>(tv2.tv_sec));
  EXPECT_LE(static_cast<long>(tv2.tv_sec),
            static_cast<long>(tv1.tv_sec) + kFudgeSeconds);

  // Redo with save.
  EXPECT_THAT(gettimeofday(&tv1, &tz1), SyscallSucceeds());
  EXPECT_THAT(vsyscall_gettimeofday(&tv2, &tz2), SyscallSucceeds());
}

TEST(TimeTest, VsyscallGettimeofday_InvalidAddressSIGSEGV) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsVsyscallEnabled()));

  EXPECT_EXIT(vsyscall_gettimeofday(reinterpret_cast<struct timeval*>(0x1),
                                    reinterpret_cast<struct timezone*>(0x1)),
              ::testing::KilledBySignal(SIGSEGV), "");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
