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
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/verity_util.h"

namespace gvisor {
namespace testing {

namespace {

// Create a 1GB file that will be read from at random positions. This should
// invalid any performance gains from caching.
const uint64_t kFileSize = Megabytes(1024);

// How many bytes to write at once to initialize the file used to read from.
const uint32_t kWriteSize = 65536;

// Largest benchmarked read unit.
const uint32_t kMaxRead = Megabytes(64);

// Global test state, initialized once per process lifetime.
struct GlobalState {
  explicit GlobalState() {
    // Mount a tmpfs file system to be wrapped by a verity fs.
    tmp_dir_ = TempPath::CreateDir().ValueOrDie();
    TEST_CHECK(mount("", tmp_dir_.path().c_str(), "tmpfs", 0, "") == 0);
    file_ = TempPath::CreateFileIn(tmp_dir_.path()).ValueOrDie();
    filename_ = std::string(Basename(file_.path()));

    FileDescriptor fd = Open(file_.path(), O_WRONLY).ValueOrDie();

    // Try to minimize syscalls by using maximum size writev() requests.
    std::vector<char> buffer(kWriteSize);
    RandomizeBuffer(buffer.data(), buffer.size());
    const std::vector<std::vector<struct iovec>> iovecs_list =
        GenerateIovecs(kFileSize + kMaxRead, buffer.data(), buffer.size());
    for (const auto& iovecs : iovecs_list) {
      TEST_CHECK(writev(fd.get(), iovecs.data(), iovecs.size()) >= 0);
    }
    verity_dir_ =
        MountVerity(tmp_dir_.path(), {EnableTarget(filename_, O_RDONLY)})
            .ValueOrDie();
  }
  TempPath tmp_dir_;
  TempPath file_;
  std::string verity_dir_;
  std::string filename_;
};

GlobalState& GetGlobalState() {
  // This gets created only once throughout the lifetime of the process.
  // Use a dynamically allocated object (that is never deleted) to avoid order
  // of destruction of static storage variables issues.
  static GlobalState* const state =
      // The actual file size is the maximum random seek range (kFileSize) + the
      // maximum read size so we can read that number of bytes at the end of the
      // file.
      new GlobalState();
  return *state;
}

void BM_VerityRandRead(benchmark::State& state) {
  const int size = state.range(0);

  GlobalState& global_state = GetGlobalState();
  FileDescriptor verity_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(
      JoinPath(global_state.verity_dir_, global_state.filename_), O_RDONLY));
  std::vector<char> buf(size);

  unsigned int seed = 1;
  for (auto _ : state) {
    TEST_CHECK(PreadFd(verity_fd.get(), buf.data(), buf.size(),
                       rand_r(&seed) % kFileSize) == size);
  }

  state.SetBytesProcessed(static_cast<int64_t>(size) *
                          static_cast<int64_t>(state.iterations()));
}

BENCHMARK(BM_VerityRandRead)->Range(1, kMaxRead)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
