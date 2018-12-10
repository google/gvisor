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

// This is a very simple sanity test to validate that the sysinfo syscall is
// supported by gvisor and returns sane values.
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SysinfoTest, SysinfoIsCallable) {
  struct sysinfo ignored = {};
  EXPECT_THAT(syscall(SYS_sysinfo, &ignored), SyscallSucceedsWithValue(0));
}

TEST(SysinfoTest, EfaultProducedOnBadAddress) {
  // Validate that we return EFAULT when a bad address is provided.
  // specified by man 2 sysinfo
  EXPECT_THAT(syscall(SYS_sysinfo, nullptr), SyscallFailsWithErrno(EFAULT));
}

TEST(SysinfoTest, TotalRamSaneValue) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  EXPECT_GT(s.totalram, 0);
}

TEST(SysinfoTest, MemunitSet) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  EXPECT_GE(s.mem_unit, 1);
}

TEST(SysinfoTest, UptimeSaneValue) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  EXPECT_GE(s.uptime, 0);
}

TEST(SysinfoTest, UptimeIncreasingValue) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  absl::SleepFor(absl::Seconds(2));
  struct sysinfo s2 = {};
  EXPECT_THAT(sysinfo(&s2), SyscallSucceedsWithValue(0));
  EXPECT_LT(s.uptime, s2.uptime);
}

TEST(SysinfoTest, FreeRamSaneValue) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  EXPECT_GT(s.freeram, 0);
  EXPECT_LT(s.freeram, s.totalram);
}

TEST(SysinfoTest, NumProcsSaneValue) {
  struct sysinfo s = {};
  EXPECT_THAT(sysinfo(&s), SyscallSucceedsWithValue(0));
  EXPECT_GT(s.procs, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
