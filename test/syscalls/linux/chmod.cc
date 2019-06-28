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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(ChmodTest, ChmodFileSucceeds) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  ASSERT_THAT(chmod(file.path().c_str(), 0466), SyscallSucceeds());
  EXPECT_THAT(open(file.path().c_str(), O_RDWR), SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, ChmodDirSucceeds) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string fileInDir = NewTempAbsPathInDir(dir.path());

  ASSERT_THAT(chmod(dir.path().c_str(), 0466), SyscallSucceeds());
  EXPECT_THAT(open(fileInDir.c_str(), O_RDONLY), SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodFileSucceeds_NoRandomSave) {
  // Drop capabilities that allow us to file directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0666));
  int fd;
  ASSERT_THAT(fd = open(file.path().c_str(), O_RDWR), SyscallSucceeds());

  {
    const DisableSave ds;  // File permissions are reduced.
    ASSERT_THAT(fchmod(fd, 0444), SyscallSucceeds());
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  EXPECT_THAT(open(file.path().c_str(), O_RDWR), SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodDirSucceeds_NoRandomSave) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int fd;
  ASSERT_THAT(fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY),
              SyscallSucceeds());

  {
    const DisableSave ds;  // File permissions are reduced.
    ASSERT_THAT(fchmod(fd, 0), SyscallSucceeds());
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  EXPECT_THAT(open(dir.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodBadF) {
  ASSERT_THAT(fchmod(-1, 0444), SyscallFailsWithErrno(EBADF));
}

TEST(ChmodTest, FchmodatBadF) {
  ASSERT_THAT(fchmodat(-1, "foo", 0444, 0), SyscallFailsWithErrno(EBADF));
}

TEST(ChmodTest, FchmodatNotDir) {
  ASSERT_THAT(fchmodat(-1, "", 0444, 0), SyscallFailsWithErrno(ENOENT));
}

TEST(ChmodTest, FchmodatFileAbsolutePath) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  ASSERT_THAT(fchmodat(-1, file.path().c_str(), 0444, 0), SyscallSucceeds());
  EXPECT_THAT(open(file.path().c_str(), O_RDWR), SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodatDirAbsolutePath) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int fd;
  ASSERT_THAT(fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  ASSERT_THAT(fchmodat(-1, dir.path().c_str(), 0, 0), SyscallSucceeds());
  EXPECT_THAT(open(dir.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodatFile) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  int parent_fd;
  ASSERT_THAT(
      parent_fd = open(GetAbsoluteTestTmpdir().c_str(), O_RDONLY | O_DIRECTORY),
      SyscallSucceeds());

  ASSERT_THAT(
      fchmodat(parent_fd, std::string(Basename(temp_file.path())).c_str(), 0444,
               0),
      SyscallSucceeds());
  EXPECT_THAT(close(parent_fd), SyscallSucceeds());

  EXPECT_THAT(open(temp_file.path().c_str(), O_RDWR),
              SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodatDir) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int parent_fd;
  ASSERT_THAT(
      parent_fd = open(GetAbsoluteTestTmpdir().c_str(), O_RDONLY | O_DIRECTORY),
      SyscallSucceeds());

  int fd;
  ASSERT_THAT(fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  ASSERT_THAT(
      fchmodat(parent_fd, std::string(Basename(dir.path())).c_str(), 0, 0),
      SyscallSucceeds());
  EXPECT_THAT(close(parent_fd), SyscallSucceeds());

  EXPECT_THAT(open(dir.path().c_str(), O_RDONLY | O_DIRECTORY),
              SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, ChmodDowngradeWritability_NoRandomSave) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0666));

  int fd;
  ASSERT_THAT(fd = open(file.path().c_str(), O_RDWR), SyscallSucceeds());

  const DisableSave ds;  // Permissions are dropped.
  ASSERT_THAT(chmod(file.path().c_str(), 0444), SyscallSucceeds());
  EXPECT_THAT(write(fd, "hello", 5), SyscallSucceedsWithValue(5));

  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(ChmodTest, ChmodFileToNoPermissionsSucceeds) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0666));

  ASSERT_THAT(chmod(file.path().c_str(), 0), SyscallSucceeds());

  EXPECT_THAT(open(file.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(EACCES));
}

TEST(ChmodTest, FchmodDowngradeWritability_NoRandomSave) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  int fd;
  ASSERT_THAT(fd = open(file.path().c_str(), O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());

  const DisableSave ds;  // Permissions are dropped.
  ASSERT_THAT(fchmod(fd, 0444), SyscallSucceeds());
  EXPECT_THAT(write(fd, "hello", 5), SyscallSucceedsWithValue(5));

  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(ChmodTest, FchmodFileToNoPermissionsSucceeds_NoRandomSave) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0666));

  int fd;
  ASSERT_THAT(fd = open(file.path().c_str(), O_RDWR), SyscallSucceeds());

  {
    const DisableSave ds;  // Permissions are dropped.
    ASSERT_THAT(fchmod(fd, 0), SyscallSucceeds());
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  EXPECT_THAT(open(file.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(EACCES));
}

// Verify that we can get a RW FD after chmod, even if a RO fd is left open.
TEST(ChmodTest, ChmodWritableWithOpenFD) {
  // FIXME(b/72455313): broken on hostfs.
  if (IsRunningOnGvisor()) {
    return;
  }

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0444));

  FileDescriptor fd1 = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  ASSERT_THAT(fchmod(fd1.get(), 0644), SyscallSucceeds());

  // This FD is writable, even though fd1 has a read-only reference to the file.
  FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  // fd1 is not writable, but fd2 is.
  char c = 'a';
  EXPECT_THAT(WriteFd(fd1.get(), &c, 1), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(WriteFd(fd2.get(), &c, 1), SyscallSucceedsWithValue(1));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
