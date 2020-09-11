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
#include <sys/stat.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Read(benchmark::State& state) {
  const char* fuse_prefix = getenv("TEST_FUSEPRE");
  ASSERT_NE(fuse_prefix, nullptr);

  const int size = state.range(0);
  const std::string contents(size, 0);
  auto path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), contents, TempPath::kDefaultFileMode));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(fuse_prefix, path.path()), O_RDONLY));

  std::vector<char> buf(size);
  for (auto _ : state) {
    TEST_CHECK(PreadFd(fd.get(), buf.data(), buf.size(), 0) == size);
  }

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_Read)->Range(1, 1 << 26)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
