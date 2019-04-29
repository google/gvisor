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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LseekTest, InvalidWhence) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  ASSERT_THAT(lseek(fd.get(), 0, -1), SyscallFailsWithErrno(EINVAL));
}

TEST(LseekTest, NegativeOffset) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  EXPECT_THAT(lseek(fd.get(), -(kFileData.length() + 1), SEEK_CUR),
              SyscallFailsWithErrno(EINVAL));
}

// A 32-bit off_t is not large enough to represent an offset larger than
// maximum file size on standard file systems, so it isn't possible to cause
// overflow.
#ifdef __x86_64__
TEST(LseekTest, Overflow) {
  // HA! Classic Linux. We really should have an EOVERFLOW
  // here, since we're seeking to something that cannot be
  // represented.. but instead we are given an EINVAL.
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));
  EXPECT_THAT(lseek(fd.get(), 0x7fffffffffffffff, SEEK_END),
              SyscallFailsWithErrno(EINVAL));
}
#endif

TEST(LseekTest, Set) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), 6, SEEK_SET), SyscallSucceedsWithValue(6));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[6]);
}

TEST(LseekTest, Cur) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), 3, SEEK_CUR), SyscallSucceedsWithValue(4));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[4]);
}

TEST(LseekTest, End) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), -2, SEEK_END), SyscallSucceedsWithValue(10));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[kFileData.length() - 2]);
}

TEST(LseekTest, InvalidFD) {
  EXPECT_THAT(lseek(-1, 0, SEEK_SET), SyscallFailsWithErrno(EBADF));
}

TEST(LseekTest, DirCurEnd) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/tmp", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

TEST(LseekTest, ProcDir) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(LseekTest, ProcFile) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/meminfo", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallFailsWithErrno(EINVAL));
}

TEST(LseekTest, SysDir) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/sys/devices", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(LseekTest, SeekCurrentDir) {
  // From include/linux/fs.h.
  constexpr loff_t MAX_LFS_FILESIZE = 0x7fffffffffffffff;

  char* dir = get_current_dir_name();
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir, O_RDONLY));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END),
              // Some filesystems (like ext4) allow lseek(SEEK_END) on a
              // directory and return MAX_LFS_FILESIZE, others return EINVAL.
              AnyOf(SyscallSucceedsWithValue(MAX_LFS_FILESIZE),
                    SyscallFailsWithErrno(EINVAL)));
  free(dir);
}

TEST(LseekTest, ProcStatTwice) {
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));

  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_END), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(lseek(fd1.get(), 1000, SEEK_CUR), SyscallSucceeds());
  // Check that just because we moved fd1, fd2 doesn't move.
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const FileDescriptor fd3 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));
  ASSERT_THAT(lseek(fd3.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

TEST(LseekTest, EtcPasswdDup) {
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/etc/passwd", O_RDONLY));
  const FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(fd1.Dup());

  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd1.get(), 1000, SEEK_CUR), SyscallSucceeds());
  // Check that just because we moved fd1, fd2 doesn't move.
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(1000));

  const FileDescriptor fd3 = ASSERT_NO_ERRNO_AND_VALUE(fd1.Dup());
  ASSERT_THAT(lseek(fd3.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(1000));
}

// TODO(magi): Add tests where we have donated in sockets.

}  // namespace

}  // namespace testing
}  // namespace gvisor
