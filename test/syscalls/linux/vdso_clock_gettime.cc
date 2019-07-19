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
    case CLOCK_REALTIME:
      return "CLOCK_REALTIME";
    case CLOCK_BOOTTIME:
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

class CorrectVDSOClockTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(CorrectVDSOClockTest, IsCorrect) {
  struct timespec tvdso, tsys;
  absl::Time vdso_time, sys_time;
  uint64_t total_calls = 0;

  // It is expected that 82.5% of clock_gettime calls will be less than 100us
  // skewed from the system time.
  // Unfortunately this is not only influenced by the VDSO clock skew, but also
  // by arbitrary scheduling delays and the like. The test is therefore
  // regularly disabled.
  std::map<absl::Duration, std::tuple<double, uint64_t, uint64_t>> confidence =
      {
          {absl::Microseconds(100), std::make_tuple(0.825, 0, 0)},
          {absl::Microseconds(250), std::make_tuple(0.94, 0, 0)},
          {absl::Milliseconds(1), std::make_tuple(0.999, 0, 0)},
      };

  absl::Time start = absl::Now();
  while (absl::Now() < start + absl::Seconds(30)) {
    EXPECT_THAT(clock_gettime(GetParam(), &tvdso), SyscallSucceeds());
    EXPECT_THAT(syscall(__NR_clock_gettime, GetParam(), &tsys),
                SyscallSucceeds());

    vdso_time = absl::TimeFromTimespec(tvdso);

    for (auto const& conf : confidence) {
      std::get<1>(confidence[conf.first]) +=
          (sys_time - vdso_time) < conf.first;
    }

    sys_time = absl::TimeFromTimespec(tsys);

    for (auto const& conf : confidence) {
      std::get<2>(confidence[conf.first]) +=
          (vdso_time - sys_time) < conf.first;
    }

    ++total_calls;
  }

  for (auto const& conf : confidence) {
    EXPECT_GE(std::get<1>(conf.second) / static_cast<double>(total_calls),
              std::get<0>(conf.second));
    EXPECT_GE(std::get<2>(conf.second) / static_cast<double>(total_calls),
              std::get<0>(conf.second));
  }
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, CorrectVDSOClockTest,
                         ::testing::Values(CLOCK_MONOTONIC, CLOCK_REALTIME,
                                           CLOCK_BOOTTIME),
                         PrintClockId);

}  // namespace

}  // namespace testing
}  // namespace gvisor
