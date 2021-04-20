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

void BM_Write(benchmark::State& state) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_WRONLY));

  const int size = state.range(0);
  std::vector<char> buf(size);
  RandomizeBuffer(buf.data(), size);

  for (auto _ : state) {
    TEST_CHECK(PwriteFd(fd.get(), buf.data(), size, 0) == size);
  }

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_Write)->Range(1, 1 << 26)->UseRealTime();

void BM_Append(benchmark::State& state) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY | O_APPEND));

  const char data = 'a';
  for (auto _ : state) {
    TEST_CHECK(WriteFd(fd.get(), &data, 1) == 1);
  }
}

BENCHMARK(BM_Append);

}  // namespace

}  // namespace testing
}  // namespace gvisor
