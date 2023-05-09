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
#include "test/util/logging.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// The maximum file size of the test file, when writes get beyond this point
// they wrap around. This should be large enough to blow away caches.
const uint64_t kMaxFile = 1 << 30;

// Perform writes of various sizes sequentially to one file. Wraps around if it
// goes above a certain maximum file size.
void BM_SeqWrite(benchmark::State& state) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_WRONLY));

  const int size = state.range(0);
  std::vector<char> buf(size);
  RandomizeBuffer(buf.data(), buf.size());

  // Start writes at offset 0.
  uint64_t offset = 0;
  for (auto _ : state) {
    TEST_CHECK(PwriteFd(fd.get(), buf.data(), buf.size(), offset) ==
               ssize_t(buf.size()));
    offset += buf.size();
    // Wrap around if going above the maximum file size.
    if (offset >= kMaxFile) {
      offset = 0;
    }
  }

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_SeqWrite)->Range(1, 1 << 26)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
