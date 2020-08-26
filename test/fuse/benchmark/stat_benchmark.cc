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
#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Creates a file in a nested directory hierarchy at least `depth` directories
// deep, and stats that file multiple times.
void BM_Stat(benchmark::State& state) {
  const char* fuse_prefix = getenv("TEST_FUSEPRE");
  ASSERT_NE(fuse_prefix, nullptr);

  // Create nested directories with given depth.
  int depth = state.range(0);
  const TempPath top_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string dir_path = top_dir.path();

  while (depth-- > 0) {
    // Don't use TempPath because it will make paths too long to use.
    //
    // The top_dir destructor will clean up this whole tree.
    dir_path = JoinPath(dir_path, absl::StrCat(depth));
    ASSERT_NO_ERRNO(Mkdir(dir_path, 0755));
  }

  // Create the file that will be stat'd.
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_path));
  std::string file_path = JoinPath(fuse_prefix, file.path());
  struct stat st;
  for (auto _ : state) {
    ASSERT_THAT(stat(file_path.c_str(), &st), SyscallSucceeds());
  }
}

BENCHMARK(BM_Stat)->Range(1, 100)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
