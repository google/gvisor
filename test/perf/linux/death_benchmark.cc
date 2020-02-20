// Copyright 2020 The gVisor Authors.
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

#include <signal.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"

namespace gvisor {
namespace testing {

namespace {

// DeathTest is not so much a microbenchmark as a macrobenchmark. It is testing
// the ability of gVisor (on whatever platform) to execute all the related
// stack-dumping routines associated with EXPECT_EXIT / EXPECT_DEATH.
TEST(DeathTest, ZeroEqualsOne) {
  EXPECT_EXIT({ TEST_CHECK(0 == 1); }, ::testing::KilledBySignal(SIGABRT), "");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
