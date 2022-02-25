// Copyright 2021 The gVisor Authors.
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

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/verity_util.h"

namespace gvisor {
namespace testing {

namespace {

// Creates a file in a nested directory hierarchy at least `depth` directories
// deep, and stats that file multiple times.
void BM_VerityStat(benchmark::State& state) {
  // Create nested directories with given depth.
  int depth = state.range(0);

  // Mount a tmpfs file system to be wrapped by a verity fs.
  TempPath top_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TEST_CHECK(mount("", top_dir.path().c_str(), "tmpfs", 0, "") == 0);
  std::string dir_path = top_dir.path();
  std::string child_path = "";
  std::vector<EnableTarget> targets;

  while (depth-- > 0) {
    // Don't use TempPath because it will make paths too long to use.
    //
    // The top_dir destructor will clean up this whole tree.
    dir_path = JoinPath(dir_path, absl::StrCat(depth));
    ASSERT_NO_ERRNO(Mkdir(dir_path, 0755));
    child_path = JoinPath(child_path, Basename(dir_path));
    targets.emplace_back(EnableTarget(child_path, O_RDONLY));
  }

  // Create the file that will be stat'd.
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_path));

  targets.emplace_back(
      EnableTarget(JoinPath(child_path, Basename(file.path())), O_RDONLY));

  // Reverse the targets because verity should be enabled from the lowest level.
  std::reverse(targets.begin(), targets.end());

  std::string verity_dir =
      TEST_CHECK_NO_ERRNO_AND_VALUE(MountVerity(top_dir.path(), targets));

  struct stat st;
  for (auto _ : state) {
    ASSERT_THAT(stat(JoinPath(verity_dir, targets[0].path).c_str(), &st),
                SyscallSucceeds());
  }
}

BENCHMARK(BM_VerityStat)->Range(1, 100)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
