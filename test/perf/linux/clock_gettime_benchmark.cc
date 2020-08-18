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

#include <pthread.h>
#include <time.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "benchmark/benchmark.h"

namespace gvisor {
namespace testing {

namespace {

void BM_ClockGettimeThreadCPUTime(benchmark::State& state) {
  clockid_t clockid;
  ASSERT_EQ(0, pthread_getcpuclockid(pthread_self(), &clockid));
  struct timespec tp;

  for (auto _ : state) {
    clock_gettime(clockid, &tp);
  }
}

BENCHMARK(BM_ClockGettimeThreadCPUTime);

void BM_VDSOClockGettime(benchmark::State& state) {
  const clockid_t clock = state.range(0);
  struct timespec tp;
  absl::Time start = absl::Now();

  // Don't benchmark the calibration phase.
  while (absl::Now() < start + absl::Milliseconds(2100)) {
    clock_gettime(clock, &tp);
  }

  for (auto _ : state) {
    clock_gettime(clock, &tp);
  }
}

BENCHMARK(BM_VDSOClockGettime)->Arg(CLOCK_MONOTONIC)->Arg(CLOCK_REALTIME);

}  // namespace

}  // namespace testing
}  // namespace gvisor
