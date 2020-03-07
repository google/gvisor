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

#include <sched.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Sched_yield(benchmark::State& state) {
  for (auto ignored : state) {
    TEST_CHECK(sched_yield() == 0);
  }
}

BENCHMARK(BM_Sched_yield)->ThreadRange(1, 2000)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
