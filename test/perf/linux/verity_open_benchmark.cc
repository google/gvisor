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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/verity_util.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Open(benchmark::State& state) {
  SKIP_IF(IsRunningWithVFS1());

  const int size = state.range(0);
  std::vector<TempPath> cache;
  std::vector<EnableTarget> targets;

  // Mount a tmpfs file system to be wrapped by a verity fs.
  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TEST_CHECK(mount("", dir.path().c_str(), "tmpfs", 0, "") == 0);

  for (int i = 0; i < size; i++) {
    auto path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
    targets.emplace_back(
        EnableTarget(std::string(Basename(path.path())), O_RDONLY));
    cache.emplace_back(std::move(path));
  }

  std::string verity_dir =
      TEST_CHECK_NO_ERRNO_AND_VALUE(MountVerity(dir.path(), targets));

  unsigned int seed = 1;
  for (auto _ : state) {
    const int chosen = rand_r(&seed) % size;
    int fd = open(JoinPath(verity_dir, targets[chosen].path).c_str(), O_RDONLY);
    TEST_CHECK(fd != -1);
    close(fd);
  }
}

BENCHMARK(BM_Open)->Range(1, 128)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
