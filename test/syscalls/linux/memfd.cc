// Copyright 2019 The gVisor Authors.
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
#include <linux/magic.h>
#include <linux/memfd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/syscall.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// The header sys/memfd.h isn't available on all systems, so redefining some of
// the constants here.
#define F_LINUX_SPECIFIC_BASE 1024

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif /* F_ADD_SEALS */

#ifndef F_GET_SEALS
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif /* F_GET_SEALS */

#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008

using ::testing::StartsWith;

const std::string kMemfdName = "some-memfd";

int memfd_create(const std::string& name, unsigned int flags) {
  return syscall(__NR_memfd_create, name.c_str(), flags);
}

PosixErrorOr<FileDescriptor> MemfdCreate(const std::string& name,
                                         uint32_t flags) {
  int fd = memfd_create(name, flags);
  if (fd < 0) {
    return PosixError(
        errno, absl::StrFormat("memfd_create(\"%s\", %#x)", name, flags));
  }
  MaybeSave();
  return FileDescriptor(fd);
}

// Procfs entries for memfds display the appropriate name.
TEST(MemfdTest, Name) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));
  const std::string proc_name = ASSERT_NO_ERRNO_AND_VALUE(
      ReadLink(absl::StrFormat("/proc/self/fd/%d", memfd.get())));
  EXPECT_THAT(proc_name, StartsWith("/memfd:" + kMemfdName));
}

// Memfds support read/write syscalls.
TEST(MemfdTest, WriteRead) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));

  // Write a random page of data to the memfd via write(2).
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Read back the same data and verify.
  std::vector<char> buf2(kPageSize);
  ASSERT_THAT(lseek(memfd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(read(memfd.get(), buf2.data(), buf2.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(buf, buf2);
}

// Memfds can be mapped and used as usual.
TEST(MemfdTest, Mmap) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));
  const Mapping m1 = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0));

  // Write a random page of data to the memfd via mmap m1.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  memcpy(m1.ptr(), buf.data(), buf.size());

  // Read the data back via a read syscall on the memfd.
  std::vector<char> buf2(kPageSize);
  EXPECT_THAT(read(memfd.get(), buf2.data(), buf2.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(buf, buf2);

  // The same data should be accessible via a new mapping m2.
  const Mapping m2 = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0));
  EXPECT_EQ(0, memcmp(m1.ptr(), m2.ptr(), kPageSize));
}

TEST(MemfdTest, DuplicateFDsShareContent) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));
  const Mapping m1 = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0));
  const FileDescriptor memfd2 = ASSERT_NO_ERRNO_AND_VALUE(memfd.Dup());

  // Write a random page of data to the memfd via mmap m1.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  memcpy(m1.ptr(), buf.data(), buf.size());

  // Read the data back via a read syscall on a duplicate fd.
  std::vector<char> buf2(kPageSize);
  EXPECT_THAT(read(memfd2.get(), buf2.data(), buf2.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(buf, buf2);
}

// File seals are disabled by default on memfds.
TEST(MemfdTest, SealingDisabledByDefault) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));
  EXPECT_THAT(fcntl(memfd.get(), F_GET_SEALS),
              SyscallSucceedsWithValue(F_SEAL_SEAL));
  // Attempting to set any seal should fail.
  EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE),
              SyscallFailsWithErrno(EPERM));
}

// Seals can be retrieved and updated for memfds.
TEST(MemfdTest, SealsGetSet) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  int seals;
  ASSERT_THAT(seals = fcntl(memfd.get(), F_GET_SEALS), SyscallSucceeds());
  // No seals are set yet.
  EXPECT_EQ(0, seals);

  // Set a seal and check that we can get it back.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());
  EXPECT_THAT(fcntl(memfd.get(), F_GET_SEALS),
              SyscallSucceedsWithValue(F_SEAL_WRITE));

  // Set some more seals and verify.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK),
              SyscallSucceeds());
  EXPECT_THAT(
      fcntl(memfd.get(), F_GET_SEALS),
      SyscallSucceedsWithValue(F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK));

  // Attempting to set a seal that is already set is a no-op.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());
  EXPECT_THAT(
      fcntl(memfd.get(), F_GET_SEALS),
      SyscallSucceedsWithValue(F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK));

  // Add remaining seals and verify.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_SEAL), SyscallSucceeds());
  EXPECT_THAT(fcntl(memfd.get(), F_GET_SEALS),
              SyscallSucceedsWithValue(F_SEAL_WRITE | F_SEAL_GROW |
                                       F_SEAL_SHRINK | F_SEAL_SEAL));
}

// F_SEAL_GROW prevents a memfd from being grown using ftruncate.
TEST(MemfdTest, SealGrowWithTruncate) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_GROW), SyscallSucceeds());

  // Try grow the memfd by 1 page.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize * 2),
              SyscallFailsWithErrno(EPERM));

  // Ftruncate calls that don't actually grow the memfd are allowed.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize / 2), SyscallSucceeds());

  // After shrinking, growing back is not allowed.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallFailsWithErrno(EPERM));
}

// F_SEAL_GROW prevents a memfd from being grown using the write syscall.
TEST(MemfdTest, SealGrowWithWrite) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));

  // Initially, writing to the memfd succeeds.
  const std::vector<char> buf(kPageSize);
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Apply F_SEAL_GROW, subsequent writes which extend the memfd should fail.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_GROW), SyscallSucceeds());
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EPERM));

  // However, zero-length writes are ok since they don't grow the memfd.
  EXPECT_THAT(write(memfd.get(), buf.data(), 0), SyscallSucceeds());

  // Writing to existing parts of the memfd is also ok.
  ASSERT_THAT(lseek(memfd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Returning the end of the file and writing still not allowed.
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EPERM));
}

// F_SEAL_GROW causes writes which partially extend off the current EOF to
// partially succeed, up to the page containing the EOF.
TEST(MemfdTest, SealGrowPartialWriteTruncated) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_GROW), SyscallSucceeds());

  // FD offset: 1 page, EOF: 1 page.

  ASSERT_THAT(lseek(memfd.get(), kPageSize * 3 / 4, SEEK_SET),
              SyscallSucceeds());

  // FD offset: 3/4 page. Writing a full page now should only write 1/4 page
  // worth of data. This partially succeeds because the first page is entirely
  // within the file and requires no growth, but attempting to write the final
  // 3/4 page would require growing the file.
  const std::vector<char> buf(kPageSize);
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize / 4));
}

// F_SEAL_GROW causes writes which partially extend off the current EOF to fail
// in its entirety if the only data written would be to the page containing the
// EOF.
TEST(MemfdTest, SealGrowPartialWriteTruncatedSamePage) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize * 3 / 4), SyscallSucceeds());
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_GROW), SyscallSucceeds());

  // EOF: 3/4 page, writing 1/2 page starting at 1/2 page would cause the file
  // to grow. Since this would require only the page containing the EOF to be
  // modified, the write is rejected entirely.
  const std::vector<char> buf(kPageSize / 2);
  EXPECT_THAT(pwrite(memfd.get(), buf.data(), buf.size(), kPageSize / 2),
              SyscallFailsWithErrno(EPERM));

  // However, writing up to EOF is fine.
  EXPECT_THAT(pwrite(memfd.get(), buf.data(), buf.size() / 2, kPageSize / 2),
              SyscallSucceedsWithValue(kPageSize / 4));
}

// F_SEAL_SHRINK prevents a memfd from being shrunk using ftruncate.
TEST(MemfdTest, SealShrink) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_SHRINK),
              SyscallSucceeds());

  // Shrink by half a page.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize / 2),
              SyscallFailsWithErrno(EPERM));

  // Ftruncate calls that don't actually shrink the file are allowed.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallSucceeds());
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize * 2), SyscallSucceeds());

  // After growing, shrinking is still not allowed.
  ASSERT_THAT(ftruncate(memfd.get(), kPageSize), SyscallFailsWithErrno(EPERM));
}

// F_SEAL_WRITE prevents a memfd from being written to through a write
// syscall.
TEST(MemfdTest, SealWriteWithWrite) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const std::vector<char> buf(kPageSize);
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());

  // Attemping to write at the end of the file fails.
  EXPECT_THAT(write(memfd.get(), buf.data(), 1), SyscallFailsWithErrno(EPERM));

  // Attemping to overwrite an existing part of the memfd fails.
  EXPECT_THAT(pwrite(memfd.get(), buf.data(), 1, 0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(pwrite(memfd.get(), buf.data(), buf.size() / 2, kPageSize / 2),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(pwrite(memfd.get(), buf.data(), buf.size(), kPageSize / 2),
              SyscallFailsWithErrno(EPERM));

  // Zero-length writes however do not fail.
  EXPECT_THAT(write(memfd.get(), buf.data(), 0), SyscallSucceeds());
}

// F_SEAL_WRITE prevents a memfd from being written to through an mmap.
TEST(MemfdTest, SealWriteWithMmap) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const std::vector<char> buf(kPageSize);
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());

  // Can't create a shared mapping with writes sealed.
  void* ret = mmap(nullptr, kPageSize, PROT_WRITE, MAP_SHARED, memfd.get(), 0);
  EXPECT_EQ(ret, MAP_FAILED);
  EXPECT_EQ(errno, EPERM);
  ret = mmap(nullptr, kPageSize, PROT_READ, MAP_SHARED, memfd.get(), 0);
  EXPECT_EQ(ret, MAP_FAILED);
  EXPECT_EQ(errno, EPERM);

  // However, private mappings are ok.
  EXPECT_NO_ERRNO(Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                       memfd.get(), 0));
}

// Adding F_SEAL_WRITE fails when there are outstanding writable mappings to a
// memfd.
TEST(MemfdTest, SealWriteWithOutstandingWritbleMapping) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const std::vector<char> buf(kPageSize);
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Attempting to add F_SEAL_WRITE with active shared mapping with any set of
  // permissions fails.

  // Read-only shared mapping.
  {
    const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
        Mmap(nullptr, kPageSize, PROT_READ, MAP_SHARED, memfd.get(), 0));
    EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE),
                SyscallFailsWithErrno(EBUSY));
  }

  // Write-only shared mapping.
  {
    const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
        Mmap(nullptr, kPageSize, PROT_WRITE, MAP_SHARED, memfd.get(), 0));
    EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE),
                SyscallFailsWithErrno(EBUSY));
  }

  // Read-write shared mapping.
  {
    const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
        Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
             memfd.get(), 0));
    EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE),
                SyscallFailsWithErrno(EBUSY));
  }

  // F_SEAL_WRITE can be set with private mappings with any permissions.
  {
    const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
        Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
             memfd.get(), 0));
    EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE),
                SyscallSucceeds());
  }
}

// When applying F_SEAL_WRITE fails due to outstanding writable mappings, any
// additional seals passed to the same add seal call are also rejected.
TEST(MemfdTest, NoPartialSealApplicationWhenWriteSealRejected) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0));

  // Try add some seals along with F_SEAL_WRITE. The seal application should
  // fail since there exists an active shared mapping.
  EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW),
              SyscallFailsWithErrno(EBUSY));

  // None of the seals should be applied.
  EXPECT_THAT(fcntl(memfd.get(), F_GET_SEALS), SyscallSucceedsWithValue(0));
}

// Seals are inode level properties, and apply to all file descriptors referring
// to a memfd.
TEST(MemfdTest, SealsAreInodeLevelProperties) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const FileDescriptor memfd2 = ASSERT_NO_ERRNO_AND_VALUE(memfd.Dup());

  // Add seal through the original memfd, and verify that it appears on the
  // dupped fd.
  ASSERT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());
  EXPECT_THAT(fcntl(memfd2.get(), F_GET_SEALS),
              SyscallSucceedsWithValue(F_SEAL_WRITE));

  // Verify the seal actually applies to both fds.
  std::vector<char> buf(kPageSize);
  EXPECT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(write(memfd2.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EPERM));

  // Seals are enforced on new FDs that are dupped after the seal is already
  // applied.
  const FileDescriptor memfd3 = ASSERT_NO_ERRNO_AND_VALUE(memfd2.Dup());
  EXPECT_THAT(write(memfd3.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EPERM));

  // Try a new seal applied to one of the dupped fds.
  ASSERT_THAT(fcntl(memfd3.get(), F_ADD_SEALS, F_SEAL_GROW), SyscallSucceeds());
  EXPECT_THAT(ftruncate(memfd.get(), kPageSize), SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(ftruncate(memfd2.get(), kPageSize), SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(ftruncate(memfd3.get(), kPageSize), SyscallFailsWithErrno(EPERM));
}

PosixErrorOr<bool> IsTmpfs(const std::string& path) {
  struct statfs stat;
  if (statfs(path.c_str(), &stat)) {
    if (errno == ENOENT) {
      // Nothing at path, don't raise this as an error. Instead, just report no
      // tmpfs at path.
      return false;
    }
    return PosixError(errno,
                      absl::StrFormat("statfs(\"%s\", %#p)", path, &stat));
  }
  return stat.f_type == TMPFS_MAGIC;
}

// Tmpfs files also support seals, but are created with F_SEAL_SEAL.
TEST(MemfdTest, TmpfsFilesHaveSealSeal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs("/tmp")));
  const TempPath tmpfs_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/tmp"));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfs_file.path(), O_RDWR, 0644));
  EXPECT_THAT(fcntl(fd.get(), F_GET_SEALS),
              SyscallSucceedsWithValue(F_SEAL_SEAL));
}

// Can open a memfd from procfs and use as normal.
TEST(MemfdTest, CanOpenFromProcfs) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));

  // Write a random page of data to the memfd via write(2).
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Read back the same data from the fd obtained from procfs and verify.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrFormat("/proc/self/fd/%d", memfd.get()), O_RDWR));
  std::vector<char> buf2(kPageSize);
  EXPECT_THAT(pread(fd.get(), buf2.data(), buf2.size(), 0),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(buf, buf2);
}

// Test that memfd permissions are set up correctly to allow another process to
// open it from procfs.
TEST(MemfdTest, OtherProcessCanOpenFromProcfs) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));
  const auto memfd_path =
      absl::StrFormat("/proc/%d/fd/%d", getpid(), memfd.get());
  const auto rest = [&] {
    int fd = open(memfd_path.c_str(), O_RDWR);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) >= 0);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// Test that only files opened as writable can have seals applied to them.
// Normally there's no way to specify file permissions on memfds, but we can
// obtain a read-only memfd by opening the corresponding procfs fd entry as
// read-only.
TEST(MemfdTest, MemfdMustBeWritableToModifySeals) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, MFD_ALLOW_SEALING));

  // Initially adding a seal works.
  EXPECT_THAT(fcntl(memfd.get(), F_ADD_SEALS, F_SEAL_WRITE), SyscallSucceeds());

  // Re-open the memfd as read-only from procfs.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrFormat("/proc/self/fd/%d", memfd.get()), O_RDONLY));

  // Can't add seals through an unwritable fd.
  EXPECT_THAT(fcntl(fd.get(), F_ADD_SEALS, F_SEAL_GROW),
              SyscallFailsWithErrno(EPERM));
}

// Test that the memfd implementation internally tracks potentially writable
// maps correctly.
TEST(MemfdTest, MultipleWritableAndNonWritableRefsToSameFileRegion) {
  const FileDescriptor memfd =
      ASSERT_NO_ERRNO_AND_VALUE(MemfdCreate(kMemfdName, 0));

  // Populate with a random page of data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(memfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Read-only map to the page. This should cause an initial mapping to be
  // created.
  Mapping m1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, kPageSize, PROT_READ, MAP_PRIVATE, memfd.get(), 0));

  // Create a shared writable map to the page. This should cause the internal
  // mapping to become potentially writable.
  Mapping m2 = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0));

  // Drop the read-only mapping first. If writable-ness isn't tracked correctly,
  // this can cause some misaccounting, which can trigger asserts internally.
  m1.reset();
  m2.reset();
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
