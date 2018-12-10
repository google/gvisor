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

#include <sys/time.h>
#include <time.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// clock_getres works regardless of whether or not a timespec is passed.
TEST(ClockGetres, Timespec) {
  struct timespec ts;
  EXPECT_THAT(clock_getres(CLOCK_MONOTONIC, &ts), SyscallSucceeds());
  EXPECT_THAT(clock_getres(CLOCK_MONOTONIC, nullptr), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
