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

void BM_Symlink(benchmark::State& state) {
  char* fuse_prefix = getenv("TEST_FUSEPRE");
  ASSERT_NE(fuse_prefix, nullptr);
  const TempPath top_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string dir_path = top_dir.path();

  const int size = state.range(0);
  std::vector<TempPath> cache;
  for (int i = 0; i < size; i++) {
    auto path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
    cache.emplace_back(std::move(path));
  }

  int index = 0;
  unsigned int seed = 1;
  for (auto t : state) {
    const int chosen = rand_r(&seed) % size;
    const std::string symlink_path = absl::StrCat(fuse_prefix, dir_path, index);
    ASSERT_THAT(symlink(cache[chosen].path().c_str(), symlink_path.c_str()),
                SyscallSucceeds());
    index++;
  }
}

BENCHMARK(BM_Symlink)->Range(1, 128)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
