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
#include "test/util/multiprocess_util.h"
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

TEST(MadviseDontforkTest, AddressLength) {
  auto m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  char *addr = static_cast<char *>(m.ptr());

  // Address must be page aligned.
  EXPECT_THAT(madvise(addr + 1, kPageSize, MADV_DONTFORK),
              SyscallFailsWithErrno(EINVAL));

  // Zero length madvise always succeeds.
  EXPECT_THAT(madvise(addr, 0, MADV_DONTFORK), SyscallSucceeds());

  // Length must not roll over after rounding up.
  size_t badlen = std::numeric_limits<std::size_t>::max() - (kPageSize / 2);
  EXPECT_THAT(madvise(0, badlen, MADV_DONTFORK), SyscallFailsWithErrno(EINVAL));

  // Length need not be page aligned - it is implicitly rounded up.
  EXPECT_THAT(madvise(addr, 1, MADV_DONTFORK), SyscallSucceeds());
  EXPECT_THAT(madvise(addr, kPageSize, MADV_DONTFORK), SyscallSucceeds());
}

TEST(MadviseDontforkTest, DontforkShared) {
  // Mmap two shared file-backed pages and MADV_DONTFORK the second page.
  TempPath f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      /* parent = */ GetAbsoluteTestTmpdir(),
      /* content = */ std::string(kPageSize * 2, 2),
      TempPath::kDefaultFileMode));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDWR));

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0));

  const Mapping ms1 = Mapping(reinterpret_cast<void *>(m.addr()), kPageSize);
  const Mapping ms2 =
      Mapping(reinterpret_cast<void *>(m.addr() + kPageSize), kPageSize);
  m.release();

  ASSERT_THAT(madvise(ms2.ptr(), kPageSize, MADV_DONTFORK), SyscallSucceeds());

  const auto rest = [&] {
    // First page is mapped in child and modifications are visible to parent
    // via the shared mapping.
    TEST_CHECK(IsMapped(ms1.addr()));
    ExpectAllMappingBytes(ms1, 2);
    memset(ms1.ptr(), 1, kPageSize);
    ExpectAllMappingBytes(ms1, 1);

    // Second page must not be mapped in child.
    TEST_CHECK(!IsMapped(ms2.addr()));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));

  ExpectAllMappingBytes(ms1, 1);  // page contents modified by child.
  ExpectAllMappingBytes(ms2, 2);  // page contents unchanged.
}

TEST(MadviseDontforkTest, DontforkAnonPrivate) {
  // Mmap three anonymous pages and MADV_DONTFORK the middle page.
  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  const Mapping mp1 = Mapping(reinterpret_cast<void *>(m.addr()), kPageSize);
  const Mapping mp2 =
      Mapping(reinterpret_cast<void *>(m.addr() + kPageSize), kPageSize);
  const Mapping mp3 =
      Mapping(reinterpret_cast<void *>(m.addr() + 2 * kPageSize), kPageSize);
  m.release();

  ASSERT_THAT(madvise(mp2.ptr(), kPageSize, MADV_DONTFORK), SyscallSucceeds());

  // Verify that all pages are zeroed and memset the first, second and third
  // pages to 1, 2, and 3 respectively.
  ExpectAllMappingBytes(mp1, 0);
  memset(mp1.ptr(), 1, kPageSize);

  ExpectAllMappingBytes(mp2, 0);
  memset(mp2.ptr(), 2, kPageSize);

  ExpectAllMappingBytes(mp3, 0);
  memset(mp3.ptr(), 3, kPageSize);

  const auto rest = [&] {
    // Verify first page is mapped, verify its contents and then modify the
    // page. The mapping is private so the modifications are not visible to
    // the parent.
    TEST_CHECK(IsMapped(mp1.addr()));
    ExpectAllMappingBytes(mp1, 1);
    memset(mp1.ptr(), 11, kPageSize);
    ExpectAllMappingBytes(mp1, 11);

    // Verify second page is not mapped.
    TEST_CHECK(!IsMapped(mp2.addr()));

    // Verify third page is mapped, verify its contents and then modify the
    // page. The mapping is private so the modifications are not visible to
    // the parent.
    TEST_CHECK(IsMapped(mp3.addr()));
    ExpectAllMappingBytes(mp3, 3);
    memset(mp3.ptr(), 13, kPageSize);
    ExpectAllMappingBytes(mp3, 13);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));

  // The fork and COW by child should not affect the parent mappings.
  ExpectAllMappingBytes(mp1, 1);
  ExpectAllMappingBytes(mp2, 2);
  ExpectAllMappingBytes(mp3, 3);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
