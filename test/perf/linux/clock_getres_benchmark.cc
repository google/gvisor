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

#include <time.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"

namespace gvisor {
namespace testing {

namespace {

// clock_getres(1) is very nearly a no-op syscall, but it does require copying
// out to a userspace struct. It thus provides a nice small copy-out benchmark.
void BM_ClockGetRes(benchmark::State& state) {
  struct timespec ts;
  for (auto _ : state) {
    clock_getres(CLOCK_MONOTONIC, &ts);
  }
}

BENCHMARK(BM_ClockGetRes);

}  // namespace

}  // namespace testing
}  // namespace gvisor
