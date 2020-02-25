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

#include <errno.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"

namespace gvisor {
namespace testing {

namespace {

// Sleep for 'param' nanoseconds.
void BM_Sleep(benchmark::State& state) {
  const int nanoseconds = state.range(0);

  for (auto _ : state) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = nanoseconds;

    int ret;
    do {
      ret = syscall(SYS_nanosleep, &ts, &ts);
      if (ret < 0) {
        TEST_CHECK(errno == EINTR);
      }
    } while (ret < 0);
  }
}

BENCHMARK(BM_Sleep)
    ->Arg(0)
    ->Arg(1)
    ->Arg(1000)              // 1us
    ->Arg(1000 * 1000)       // 1ms
    ->Arg(10 * 1000 * 1000)  // 10ms
    ->Arg(50 * 1000 * 1000)  // 50ms
    ->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
