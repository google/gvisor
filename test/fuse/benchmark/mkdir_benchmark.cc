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

void BM_Mkdir(benchmark::State& state) {
  const char* fuse_prefix = getenv("TEST_FUSEPRE");
  ASSERT_NE(fuse_prefix, nullptr);

  const TempPath top_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string dir_path = top_dir.path();

  int index = 0;
  for (auto t : state) {
    const std::string new_dir_path = absl::StrCat(dir_path, index);
    ASSERT_THAT(mkdir(new_dir_path.c_str(), 0777), SyscallSucceeds());
    index++;
  }
}

BENCHMARK(BM_Mkdir)->Range(1, 128)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
