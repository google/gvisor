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

void BM_OpenReadClose(benchmark::State& state) {
  const int size = state.range(0);
  std::vector<TempPath> cache;
  for (int i = 0; i < size; i++) {
    auto path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
        GetAbsoluteTestTmpdir(), "some content", 0644));
    cache.emplace_back(std::move(path));
  }

  char buf[1];
  unsigned int seed = 1;
  for (auto _ : state) {
    const int chosen = rand_r(&seed) % size;
    int fd = open(cache[chosen].path().c_str(), O_RDONLY);
    TEST_CHECK(fd != -1);
    TEST_CHECK(read(fd, buf, 1) == 1);
    close(fd);
  }
}

// Gofer dentry cache is 1000 by default. Go over it to force files to be closed
// for real.
BENCHMARK(BM_OpenReadClose)->Range(1000, 16384)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
