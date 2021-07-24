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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/temp_path.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Dup(benchmark::State& state) {
  const int size = state.range(0);

  for (auto _ : state) {
    std::vector<int> v;
    for (int i = 0; i < size; i++) {
      int fd = dup(2);
      TEST_CHECK(fd != -1);
      v.push_back(fd);
    }
    for (int i = 0; i < size; i++) {
      int fd = v[i];
      close(fd);
    }
  }
  state.SetItemsProcessed(state.iterations() * size);
}

BENCHMARK(BM_Dup)->Range(1, 1 << 15)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
