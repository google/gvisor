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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Creates a directory containing `files` files, and unlinks all the files.
void BM_Unlink(benchmark::State& state) {
  // Create directory with given files.
  const int file_count = state.range(0);

  // We unlink all files on each iteration, but report this as a "batch"
  // iteration so that reported times are per file.
  TempPath dir;
  while (state.KeepRunningBatch(file_count)) {
    state.PauseTiming();
    // N.B. dir is declared outside the loop so that destruction of the previous
    // iteration's directory occurs here, inside of PauseTiming.
    dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

    std::vector<TempPath> files;
    for (int i = 0; i < file_count; i++) {
      TempPath file =
          ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
      files.push_back(std::move(file));
    }
    state.ResumeTiming();

    while (!files.empty()) {
      // Destructor unlinks.
      files.pop_back();
    }
  }

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_Unlink)->Range(1, 100 * 1000)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
