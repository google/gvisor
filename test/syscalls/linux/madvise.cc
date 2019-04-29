// Copyright 2018 The gVisor Authors.
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
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void ExpectAllMappingBytes(Mapping const& m, char c) {
  auto const v = m.view();
  for (size_t i = 0; i < kPageSize; i++) {
    ASSERT_EQ(v[i], c) << "at offset " << i;
  }
}

// Equivalent to ExpectAllMappingBytes but async-signal-safe and with less
// helpful failure messages.
void CheckAllMappingBytes(Mapping const& m, char c) {
  auto const v = m.view();
  for (size_t i = 0; i < kPageSize; i++) {
    TEST_CHECK_MSG(v[i] == c, "mapping contains wrong value");
  }
}

TEST(MadviseDontneedTest, ZerosPrivateAnonPage) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  ExpectAllMappingBytes(m, 0);
  memset(m.ptr(), 1, m.len());
  ExpectAllMappingBytes(m, 1);
  ASSERT_THAT(madvise(m.ptr(), m.len(), MADV_DONTNEED), SyscallSucceeds());
  ExpectAllMappingBytes(m, 0);
}

TEST(MadviseDontneedTest, ZerosCOWAnonPageInCallerOnly) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  ExpectAllMappingBytes(m, 0);
  memset(m.ptr(), 2, m.len());
  ExpectAllMappingBytes(m, 2);

  // Do madvise in a child process.
  pid_t pid = fork();
  CheckAllMappingBytes(m, 2);
  if (pid == 0) {
    TEST_PCHECK(madvise(m.ptr(), m.len(), MADV_DONTNEED) == 0);
    CheckAllMappingBytes(m, 0);
    _exit(0);
  }

  ASSERT_THAT(pid, SyscallSucceeds());

  int status = 0;
  ASSERT_THAT(waitpid(-1, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  // The child's madvise should not have affected the parent.
  ExpectAllMappingBytes(m, 2);
}

TEST(MadviseDontneedTest, DoesNotModifySharedAnonPage) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  ExpectAllMappingBytes(m, 0);
  memset(m.ptr(), 3, m.len());
  ExpectAllMappingBytes(m, 3);
  ASSERT_THAT(madvise(m.ptr(), m.len(), MADV_DONTNEED), SyscallSucceeds());
  ExpectAllMappingBytes(m, 3);
}

TEST(MadviseDontneedTest, CleansPrivateFilePage) {
  TempPath f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      /* parent = */ GetAbsoluteTestTmpdir(),
      /* content = */ std::string(kPageSize, 4), TempPath::kDefaultFileMode));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDWR));

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0));
  ExpectAllMappingBytes(m, 4);
  memset(m.ptr(), 5, m.len());
  ExpectAllMappingBytes(m, 5);
  ASSERT_THAT(madvise(m.ptr(), m.len(), MADV_DONTNEED), SyscallSucceeds());
  ExpectAllMappingBytes(m, 4);
}

TEST(MadviseDontneedTest, DoesNotModifySharedFilePage) {
  TempPath f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      /* parent = */ GetAbsoluteTestTmpdir(),
      /* content = */ std::string(kPageSize, 6), TempPath::kDefaultFileMode));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDWR));

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0));
  ExpectAllMappingBytes(m, 6);
  memset(m.ptr(), 7, m.len());
  ExpectAllMappingBytes(m, 7);
  ASSERT_THAT(madvise(m.ptr(), m.len(), MADV_DONTNEED), SyscallSucceeds());
  ExpectAllMappingBytes(m, 7);
}

TEST(MadviseDontneedTest, IgnoresPermissions) {
  auto m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  EXPECT_THAT(madvise(m.ptr(), m.len(), MADV_DONTNEED), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
