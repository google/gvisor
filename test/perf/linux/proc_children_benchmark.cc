// Copyright 2026 The gVisor Authors.
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

#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

void BM_ProcTaskChildren(benchmark::State& state) {
  std::vector<pid_t> children;
  children.reserve(state.range(0));
  auto reap_children = Cleanup([&] {
    for (pid_t child : children) {
      int status;
      TEST_PCHECK(RetryEINTR(waitpid)(child, &status, 0) == child);
      TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  });

  // These descriptors close before reaping children. Closing the last release
  // writer lets every child exit, including when setup fails.
  int ready[2];
  int release[2];
  TEST_PCHECK(pipe(ready) == 0);
  FileDescriptor ready_read(ready[0]);
  FileDescriptor ready_write(ready[1]);
  TEST_PCHECK(pipe(release) == 0);
  FileDescriptor release_read(release[0]);
  FileDescriptor release_write(release[1]);

  for (int64_t i = 0; i < state.range(0); ++i) {
    pid_t child = fork();
    if (child == 0) {
      ready_read.CloseSignalSafe();
      release_write.CloseSignalSafe();
      const char started = 's';
      if (RetryEINTR(write)(ready_write.get(), &started, 1) != 1) {
        _exit(1);
      }
      ready_write.CloseSignalSafe();
      char done;
      _exit(RetryEINTR(read)(release_read.get(), &done, 1) == 0 ? 0 : 1);
    }
    TEST_PCHECK(child > 0);
    children.push_back(child);
  }
  ready_write.reset();
  release_read.reset();
  for (int64_t i = 0; i < state.range(0); ++i) {
    char started;
    TEST_PCHECK(RetryEINTR(read)(ready_read.get(), &started, 1) == 1);
  }

  const std::string path =
      absl::StrCat("/proc/", getpid(), "/task/", gettid(), "/children");
  char buffer[4096];
  for (auto _ : state) {
    const int fd = RetryEINTR(open)(path.c_str(), O_RDONLY | O_CLOEXEC);
    TEST_PCHECK(fd >= 0);
    ssize_t bytes = RetryEINTR(read)(fd, buffer, sizeof(buffer));
    TEST_PCHECK(bytes >= 0);
    benchmark::DoNotOptimize(bytes);
    TEST_PCHECK(close(fd) == 0 || errno == EINTR);
  }
}

BENCHMARK(BM_ProcTaskChildren)->Arg(0)->Arg(1)->Arg(32)->UseRealTime();

}  // namespace
}  // namespace testing
}  // namespace gvisor
