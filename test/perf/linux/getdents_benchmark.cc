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
#include "benchmark/benchmark.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

#ifndef SYS_getdents64
#if defined(__x86_64__)
#define SYS_getdents64 217
#elif defined(__aarch64__)
#define SYS_getdents64 217
#else
#error "Unknown architecture"
#endif
#endif  // SYS_getdents64

namespace gvisor {
namespace testing {

namespace {

constexpr int kBufferSize = 65536;

PosixErrorOr<TempPath> CreateDirectory(int count,
                                       std::vector<std::string>* files) {
  ASSIGN_OR_RETURN_ERRNO(TempPath dir, TempPath::CreateDir());

  ASSIGN_OR_RETURN_ERRNO(FileDescriptor dfd,
                         Open(dir.path(), O_RDONLY | O_DIRECTORY));

  for (int i = 0; i < count; i++) {
    auto file = NewTempRelPath();
    auto res = MknodAt(dfd, file, S_IFREG | 0644, 0);
    RETURN_IF_ERRNO(res);
    files->push_back(file);
  }

  return std::move(dir);
}

PosixError CleanupDirectory(const TempPath& dir,
                            std::vector<std::string>* files) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor dfd,
                         Open(dir.path(), O_RDONLY | O_DIRECTORY));

  for (auto it = files->begin(); it != files->end(); ++it) {
    auto res = UnlinkAt(dfd, *it, 0);
    RETURN_IF_ERRNO(res);
  }
  return NoError();
}

// Creates a directory containing `files` files, and reads all the directory
// entries from the directory using a single FD.
void BM_GetdentsSameFD(benchmark::State& state) {
  // Create directory with given files.
  const int count = state.range(0);

  // Keep a vector of all of the file TempPaths that is destroyed before dir.
  //
  // Normally, we'd simply allow dir to recursively clean up the contained
  // files, but that recursive cleanup uses getdents, which may be very slow in
  // extreme benchmarks.
  TempPath dir;
  std::vector<std::string> files;
  dir = ASSERT_NO_ERRNO_AND_VALUE(CreateDirectory(count, &files));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY));
  char buffer[kBufferSize];

  // We read all directory entries on each iteration, but report this as a
  // "batch" iteration so that reported times are per file.
  while (state.KeepRunningBatch(count)) {
    ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());

    int ret;
    do {
      ASSERT_THAT(ret = syscall(SYS_getdents64, fd.get(), buffer, kBufferSize),
                  SyscallSucceeds());
    } while (ret > 0);
  }

  ASSERT_NO_ERRNO(CleanupDirectory(dir, &files));

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_GetdentsSameFD)->Range(1, 1 << 12)->UseRealTime();

// Creates a directory containing `files` files, and reads all the directory
// entries from the directory using a new FD each time.
void BM_GetdentsNewFD(benchmark::State& state) {
  // Create directory with given files.
  const int count = state.range(0);

  // Keep a vector of all of the file TempPaths that is destroyed before dir.
  //
  // Normally, we'd simply allow dir to recursively clean up the contained
  // files, but that recursive cleanup uses getdents, which may be very slow in
  // extreme benchmarks.
  TempPath dir;
  std::vector<std::string> files;
  dir = ASSERT_NO_ERRNO_AND_VALUE(CreateDirectory(count, &files));
  char buffer[kBufferSize];

  // We read all directory entries on each iteration, but report this as a
  // "batch" iteration so that reported times are per file.
  while (state.KeepRunningBatch(count)) {
    FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY));

    int ret;
    do {
      ASSERT_THAT(ret = syscall(SYS_getdents64, fd.get(), buffer, kBufferSize),
                  SyscallSucceeds());
    } while (ret > 0);
  }

  ASSERT_NO_ERRNO(CleanupDirectory(dir, &files));

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_GetdentsNewFD)->Range(1, 1 << 12)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
