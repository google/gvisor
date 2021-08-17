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
#include <sys/uio.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Create a 1GB file that will be read from at random positions. This should
// invalid any performance gains from caching.
const uint64_t kFileSize = 1ULL << 30;

// How many bytes to write at once to initialize the file used to read from.
const uint32_t kWriteSize = 65536;

// Largest benchmarked read unit.
const uint32_t kMaxRead = 1UL << 26;

TempPath CreateFile(uint64_t file_size) {
  auto path = TempPath::CreateFile().ValueOrDie();
  FileDescriptor fd = Open(path.path(), O_WRONLY).ValueOrDie();

  // Try to minimize syscalls by using maximum size writev() requests.
  std::vector<char> buffer(kWriteSize);
  RandomizeBuffer(buffer.data(), buffer.size());
  const std::vector<std::vector<struct iovec>> iovecs_list =
      GenerateIovecs(file_size, buffer.data(), buffer.size());
  for (const auto& iovecs : iovecs_list) {
    TEST_CHECK(writev(fd.get(), iovecs.data(), iovecs.size()) >= 0);
  }

  return path;
}

// Global test state, initialized once per process lifetime.
struct GlobalState {
  const TempPath tmpfile;
  explicit GlobalState(TempPath tfile) : tmpfile(std::move(tfile)) {}
};

GlobalState& GetGlobalState() {
  // This gets created only once throughout the lifetime of the process.
  // Use a dynamically allocated object (that is never deleted) to avoid order
  // of destruction of static storage variables issues.
  static GlobalState* const state =
      // The actual file size is the maximum random seek range (kFileSize) + the
      // maximum read size so we can read that number of bytes at the end of the
      // file.
      new GlobalState(CreateFile(kFileSize + kMaxRead));
  return *state;
}

void BM_RandRead(benchmark::State& state) {
  const int size = state.range(0);

  GlobalState& global_state = GetGlobalState();
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(global_state.tmpfile.path(), O_RDONLY));
  std::vector<char> buf(size);

  unsigned int seed = 1;
  for (auto _ : state) {
    TEST_CHECK(PreadFd(fd.get(), buf.data(), buf.size(),
                       rand_r(&seed) % (kFileSize - buf.size())) == size);
  }

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_RandRead)->Range(1, kMaxRead)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
