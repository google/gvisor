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

#include <stdint.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

std::string PrintClockId(::testing::TestParamInfo<clockid_t> info) {
  switch (info.param) {
    case CLOCK_MONOTONIC:
      return "CLOCK_MONOTONIC";
    case CLOCK_BOOTTIME:
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

class MonotonicVDSOClockTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(MonotonicVDSOClockTest, IsCorrect) {
  // The VDSO implementation of clock_gettime() uses the TSC. On KVM, sentry and
  // application TSCs can be very desynchronized; see
  // sentry/platform/kvm/kvm.vCPU.setSystemTime().
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  // Check that when we alternate readings from the clock_gettime syscall and
  // the VDSO's implementation, we observe the combined sequence as being
  // monotonic.
  struct timespec tvdso, tsys;
  absl::Time vdso_time, sys_time;
  ASSERT_THAT(syscall(__NR_clock_gettime, GetParam(), &tsys),
              SyscallSucceeds());
  sys_time = absl::TimeFromTimespec(tsys);
  auto end = absl::Now() + absl::Seconds(10);
  while (absl::Now() < end) {
    ASSERT_THAT(clock_gettime(GetParam(), &tvdso), SyscallSucceeds());
    vdso_time = absl::TimeFromTimespec(tvdso);
    EXPECT_LE(sys_time, vdso_time);
    ASSERT_THAT(syscall(__NR_clock_gettime, GetParam(), &tsys),
                SyscallSucceeds());
    sys_time = absl::TimeFromTimespec(tsys);
    EXPECT_LE(vdso_time, sys_time);
  }
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, MonotonicVDSOClockTest,
                         ::testing::Values(CLOCK_MONOTONIC, CLOCK_BOOTTIME),
                         PrintClockId);

}  // namespace

}  // namespace testing
}  // namespace gvisor
