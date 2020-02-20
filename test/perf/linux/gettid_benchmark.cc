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

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Gettid(benchmark::State& state) {
  for (auto _ : state) {
    syscall(SYS_gettid);
  }
}

BENCHMARK(BM_Gettid)->ThreadRange(1, 4000)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
