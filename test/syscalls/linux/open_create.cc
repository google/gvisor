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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {
TEST(CreateTest, TmpFile) {
  int fd;
  EXPECT_THAT(fd = open(JoinPath(GetAbsoluteTestTmpdir(), "a").c_str(),
                        O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(CreateTest, ExistingFile) {
  int fd;
  EXPECT_THAT(
      fd = open(JoinPath(GetAbsoluteTestTmpdir(), "ExistingFile").c_str(),
                O_RDWR | O_CREAT, 0666),
      SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(
      fd = open(JoinPath(GetAbsoluteTestTmpdir(), "ExistingFile").c_str(),
                O_RDWR | O_CREAT, 0666),
      SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(CreateTest, CreateAtFile) {
  int dirfd;
  EXPECT_THAT(dirfd = open(GetAbsoluteTestTmpdir().c_str(), O_DIRECTORY, 0666),
              SyscallSucceeds());
  EXPECT_THAT(openat(dirfd, "CreateAtFile", O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());
  EXPECT_THAT(close(dirfd), SyscallSucceeds());
}

TEST(CreateTest, HonorsUmask_NoRandomSave) {
  const DisableSave ds;  // file cannot be re-opened as writable.
  TempUmask mask(0222);
  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(GetAbsoluteTestTmpdir(), "UmaskedFile").c_str(),
                O_RDWR | O_CREAT, 0666),
      SyscallSucceeds());
  struct stat statbuf;
  ASSERT_THAT(fstat(fd, &statbuf), SyscallSucceeds());
  EXPECT_EQ(0444, statbuf.st_mode & 0777);
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(CreateTest, CreateExclusively) {
  std::string filename = NewTempAbsPath();

  int fd;
  ASSERT_THAT(fd = open(filename.c_str(), O_CREAT | O_RDWR, 0644),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(open(filename.c_str(), O_CREAT | O_EXCL | O_RDWR, 0644),
              SyscallFailsWithErrno(EEXIST));
}

TEST(CreateTest, CreatWithOTrunc) {
  std::string dirpath = JoinPath(GetAbsoluteTestTmpdir(), "truncd");
  ASSERT_THAT(mkdir(dirpath.c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(open(dirpath.c_str(), O_CREAT | O_TRUNC, 0666),
              SyscallFailsWithErrno(EISDIR));
}

TEST(CreateTest, CreatDirWithOTruncAndReadOnly) {
  std::string dirpath = JoinPath(GetAbsoluteTestTmpdir(), "truncd");
  ASSERT_THAT(mkdir(dirpath.c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(open(dirpath.c_str(), O_CREAT | O_TRUNC | O_RDONLY, 0666),
              SyscallFailsWithErrno(EISDIR));
}

TEST(CreateTest, CreatFileWithOTruncAndReadOnly) {
  std::string dirpath = JoinPath(GetAbsoluteTestTmpdir(), "truncfile");
  int dirfd;
  ASSERT_THAT(dirfd = open(dirpath.c_str(), O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());
  ASSERT_THAT(open(dirpath.c_str(), O_CREAT | O_TRUNC | O_RDONLY, 0666),
              SyscallSucceeds());
  ASSERT_THAT(close(dirfd), SyscallSucceeds());
}

TEST(CreateTest, CreateFailsOnUnpermittedDir) {
  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // always override directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_THAT(open("/foo", O_CREAT | O_RDWR, 0644),
              SyscallFailsWithErrno(EACCES));
}

TEST(CreateTest, CreateFailsOnDirWithoutWritePerms) {
  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // always override directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  auto parent = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0555));
  auto file = JoinPath(parent.path(), "foo");
  ASSERT_THAT(open(file.c_str(), O_CREAT | O_RDWR, 0644),
              SyscallFailsWithErrno(EACCES));
}

// A file originally created RW, but opened RO can later be opened RW.
// Regression test for b/65385065.
TEST(CreateTest, OpenCreateROThenRW) {
  TempPath file(NewTempAbsPath());

  // Create a RW file, but only open it RO.
  FileDescriptor fd1 = ASSERT_NO_ERRNO_AND_VALUE(
      Open(file.path(), O_CREAT | O_EXCL | O_RDONLY, 0644));

  // Now get a RW FD.
  FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  // fd1 is not writable, but fd2 is.
  char c = 'a';
  EXPECT_THAT(WriteFd(fd1.get(), &c, 1), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(WriteFd(fd2.get(), &c, 1), SyscallSucceedsWithValue(1));
}

TEST(CreateTest, ChmodReadToWriteBetweenOpens_NoRandomSave) {
  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // override file read/write permissions. CAP_DAC_READ_SEARCH needs to be
  // cleared for the same reason.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0400));

  const FileDescriptor rfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  // Cannot restore after making permissions more restrictive.
  const DisableSave ds;
  ASSERT_THAT(fchmod(rfd.get(), 0200), SyscallSucceeds());

  EXPECT_THAT(open(file.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(EACCES));

  const FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));

  char c = 'x';
  EXPECT_THAT(write(wfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  c = 0;
  EXPECT_THAT(read(rfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'x');
}

TEST(CreateTest, ChmodWriteToReadBetweenOpens_NoRandomSave) {
  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // override file read/write permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0200));

  const FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));

  // Cannot restore after making permissions more restrictive.
  const DisableSave ds;
  ASSERT_THAT(fchmod(wfd.get(), 0400), SyscallSucceeds());

  EXPECT_THAT(open(file.path().c_str(), O_WRONLY),
              SyscallFailsWithErrno(EACCES));

  const FileDescriptor rfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  char c = 'x';
  EXPECT_THAT(write(wfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  c = 0;
  EXPECT_THAT(read(rfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'x');
}

TEST(CreateTest, CreateWithReadFlagNotAllowedByMode_NoRandomSave) {
  // The only time we can open a file with flags forbidden by its permissions
  // is when we are creating the file. We cannot re-open with the same flags,
  // so we cannot restore an fd obtained from such an operation.
  const DisableSave ds;

  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // override file read/write permissions. CAP_DAC_READ_SEARCH needs to be
  // cleared for the same reason.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  // Create and open a file with read flag but without read permissions.
  const std::string path = NewTempAbsPath();
  const FileDescriptor rfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_CREAT | O_RDONLY, 0222));

  EXPECT_THAT(open(path.c_str(), O_RDONLY), SyscallFailsWithErrno(EACCES));
  const FileDescriptor wfd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));

  char c = 'x';
  EXPECT_THAT(write(wfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  c = 0;
  EXPECT_THAT(read(rfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'x');
}

TEST(CreateTest, CreateWithWriteFlagNotAllowedByMode_NoRandomSave) {
  // The only time we can open a file with flags forbidden by its permissions
  // is when we are creating the file. We cannot re-open with the same flags,
  // so we cannot restore an fd obtained from such an operation.
  const DisableSave ds;

  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // override file read/write permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  // Create and open a file with write flag but without write permissions.
  const std::string path = NewTempAbsPath();
  const FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_CREAT | O_WRONLY, 0444));

  EXPECT_THAT(open(path.c_str(), O_WRONLY), SyscallFailsWithErrno(EACCES));
  const FileDescriptor rfd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));

  char c = 'x';
  EXPECT_THAT(write(wfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  c = 0;
  EXPECT_THAT(read(rfd.get(), &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'x');
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
