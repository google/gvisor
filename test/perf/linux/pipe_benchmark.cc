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

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Pipe(benchmark::State& state) {
  int fds[2];
  TEST_CHECK(pipe(fds) == 0);

  const int size = state.range(0);
  std::vector<char> wbuf(size);
  std::vector<char> rbuf(size);
  RandomizeBuffer(wbuf.data(), size);

  ScopedThread t([&] {
    auto const fd = fds[1];
    for (benchmark::IterationCount i = 0; i < state.max_iterations; i++) {
      TEST_CHECK(WriteFd(fd, wbuf.data(), wbuf.size()) == size);
    }
  });

  for (auto _ : state) {
    TEST_CHECK(ReadFd(fds[0], rbuf.data(), rbuf.size()) == size);
  }

  t.Join();

  close(fds[0]);
  close(fds[1]);

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_Pipe)->Range(1, 1 << 20)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
