// Copyright 2018 Google LLC
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
#include <string.h>
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

mode_t FilePermission(const std::string& path) {
  struct stat buf = {0};
  TEST_CHECK(lstat(path.c_str(), &buf) == 0);
  return buf.st_mode & 0777;
}

// Test that name collisions are checked on the new link path, not the source
// path.
TEST(SymlinkTest, CanCreateSymlinkWithCachedSourceDirent) {
  const std::string srcname = NewTempAbsPath();
  const std::string newname = NewTempAbsPath();
  const std::string basedir = std::string(Dirname(srcname));
  ASSERT_EQ(basedir, Dirname(newname));

  ASSERT_THAT(chdir(basedir.c_str()), SyscallSucceeds());

  // Open the source node to cause the underlying dirent to be cached. It will
  // remain cached while we have the file open.
  int fd;
  ASSERT_THAT(fd = open(srcname.c_str(), O_CREAT | O_RDWR, 0666),
              SyscallSucceeds());
  FileDescriptor fd_closer(fd);

  // Attempt to create a symlink. If the bug exists, this will fail since the
  // dirent link creation code will check for a name collision on the source
  // link name.
  EXPECT_THAT(symlink(std::string(Basename(srcname)).c_str(),
                      std::string(Basename(newname)).c_str()),
              SyscallSucceeds());
}

TEST(SymlinkTest, CanCreateSymlinkFile) {
  const std::string oldname = NewTempAbsPath();
  const std::string newname = NewTempAbsPath();

  int fd;
  ASSERT_THAT(fd = open(oldname.c_str(), O_CREAT | O_RDWR, 0666),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(symlink(oldname.c_str(), newname.c_str()), SyscallSucceeds());
  EXPECT_EQ(FilePermission(newname), 0777);

  auto link = ASSERT_NO_ERRNO_AND_VALUE(ReadLink(newname));
  EXPECT_EQ(oldname, link);

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(oldname.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, CanCreateSymlinkDir) {
  const std::string olddir = NewTempAbsPath();
  const std::string newdir = NewTempAbsPath();

  EXPECT_THAT(mkdir(olddir.c_str(), 0777), SyscallSucceeds());
  EXPECT_THAT(symlink(olddir.c_str(), newdir.c_str()), SyscallSucceeds());
  EXPECT_EQ(FilePermission(newdir), 0777);

  auto link = ASSERT_NO_ERRNO_AND_VALUE(ReadLink(newdir));
  EXPECT_EQ(olddir, link);

  EXPECT_THAT(unlink(newdir.c_str()), SyscallSucceeds());

  ASSERT_THAT(rmdir(olddir.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, CannotCreateSymlinkInReadOnlyDir) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  const std::string olddir = NewTempAbsPath();
  ASSERT_THAT(mkdir(olddir.c_str(), 0444), SyscallSucceeds());

  const std::string newdir = NewTempAbsPathInDir(olddir);
  EXPECT_THAT(symlink(olddir.c_str(), newdir.c_str()),
              SyscallFailsWithErrno(EACCES));

  ASSERT_THAT(rmdir(olddir.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, CannotSymlinkOverExistingFile) {
  const auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const auto newfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  EXPECT_THAT(symlink(oldfile.path().c_str(), newfile.path().c_str()),
              SyscallFailsWithErrno(EEXIST));
}

TEST(SymlinkTest, CannotSymlinkOverExistingDir) {
  const auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const auto newdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(symlink(oldfile.path().c_str(), newdir.path().c_str()),
              SyscallFailsWithErrno(EEXIST));
}

TEST(SymlinkTest, OldnameIsEmpty) {
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(symlink("", newname.c_str()), SyscallFailsWithErrno(ENOENT));
}

TEST(SymlinkTest, OldnameIsDangling) {
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(symlink("/dangling", newname.c_str()), SyscallSucceeds());

  // This is required for S/R random save tests, which pre-run this test
  // in the same TEST_TMPDIR, which means that we need to clean it for any
  // operations exclusively creating files, like symlink above.
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, NewnameCannotExist) {
  const std::string newname =
      JoinPath(GetAbsoluteTestTmpdir(), "thisdoesnotexist", "foo");
  EXPECT_THAT(symlink("/thisdoesnotmatter", newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(SymlinkTest, CanEvaluateLink) {
  const auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // We are going to assert that the symlink inode id is the same as the linked
  // file's inode id. In order for the inode id to be stable across
  // save/restore, it must be kept open. The FileDescriptor type will do that
  // for us automatically.
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  struct stat file_st;
  EXPECT_THAT(fstat(fd.get(), &file_st), SyscallSucceeds());

  const std::string link = NewTempAbsPath();
  EXPECT_THAT(symlink(file.path().c_str(), link.c_str()), SyscallSucceeds());
  EXPECT_EQ(FilePermission(link), 0777);

  auto linkfd = ASSERT_NO_ERRNO_AND_VALUE(Open(link.c_str(), O_RDWR));
  struct stat link_st;
  EXPECT_THAT(fstat(linkfd.get(), &link_st), SyscallSucceeds());

  // Check that in fact newname points to the file we expect.
  EXPECT_EQ(file_st.st_dev, link_st.st_dev);
  EXPECT_EQ(file_st.st_ino, link_st.st_ino);
}

TEST(SymlinkTest, TargetIsNotMapped) {
  const std::string oldname = NewTempAbsPath();
  const std::string newname = NewTempAbsPath();

  int fd;
  // Create the target so that when we read the link, it exists.
  ASSERT_THAT(fd = open(oldname.c_str(), O_CREAT | O_RDWR, 0666),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  // Create a symlink called newname that points to oldname.
  EXPECT_THAT(symlink(oldname.c_str(), newname.c_str()), SyscallSucceeds());

  std::vector<char> buf(1024);
  int linksize;
  // Read the link and assert that the oldname is still the same.
  EXPECT_THAT(linksize = readlink(newname.c_str(), buf.data(), 1024),
              SyscallSucceeds());
  EXPECT_EQ(0, strncmp(oldname.c_str(), buf.data(), linksize));

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(oldname.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, PreadFromSymlink) {
  std::string name = NewTempAbsPath();
  int fd;
  ASSERT_THAT(fd = open(name.c_str(), O_CREAT, 0644), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());

  std::string linkname = NewTempAbsPath();
  ASSERT_THAT(symlink(name.c_str(), linkname.c_str()), SyscallSucceeds());

  ASSERT_THAT(fd = open(linkname.c_str(), O_RDONLY), SyscallSucceeds());

  char buf[1024];
  EXPECT_THAT(pread64(fd, buf, 1024, 0), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(unlink(name.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(linkname.c_str()), SyscallSucceeds());
}

TEST(SymlinkTest, SymlinkAtDegradedPermissions_NoRandomSave) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  int dirfd;
  ASSERT_THAT(dirfd = open(dir.path().c_str(), O_DIRECTORY, 0),
              SyscallSucceeds());

  const DisableSave ds;  // Permissions are dropped.
  EXPECT_THAT(fchmod(dirfd, 0), SyscallSucceeds());

  std::string basename = std::string(Basename(file.path()));
  EXPECT_THAT(symlinkat("/dangling", dirfd, basename.c_str()),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(close(dirfd), SyscallSucceeds());
}

TEST(SymlinkTest, ReadlinkAtDegradedPermissions_NoRandomSave) {
  // Drop capabilities that allow us to override file and directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string oldpath = NewTempAbsPathInDir(dir.path());
  const std::string oldbase = std::string(Basename(oldpath));
  ASSERT_THAT(symlink("/dangling", oldpath.c_str()), SyscallSucceeds());

  int dirfd;
  EXPECT_THAT(dirfd = open(dir.path().c_str(), O_DIRECTORY, 0),
              SyscallSucceeds());

  const DisableSave ds;  // Permissions are dropped.
  EXPECT_THAT(fchmod(dirfd, 0), SyscallSucceeds());

  char buf[1024];
  int linksize;
  EXPECT_THAT(linksize = readlinkat(dirfd, oldbase.c_str(), buf, 1024),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(close(dirfd), SyscallSucceeds());
}

TEST(SymlinkTest, ChmodSymlink) {
  auto target = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newpath = NewTempAbsPath();
  ASSERT_THAT(symlink(target.path().c_str(), newpath.c_str()),
              SyscallSucceeds());
  EXPECT_EQ(FilePermission(newpath), 0777);
  EXPECT_THAT(chmod(newpath.c_str(), 0666), SyscallSucceeds());
  EXPECT_EQ(FilePermission(newpath), 0777);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
