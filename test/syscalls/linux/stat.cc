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
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

#ifndef AT_STATX_FORCE_SYNC
#define AT_STATX_FORCE_SYNC 0x2000
#endif
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif

namespace gvisor {
namespace testing {

namespace {

class StatTest : public FileTest {};

TEST_F(StatTest, FstatatAbs) {
  struct stat st;

  // Check that the stat works.
  EXPECT_THAT(fstatat(AT_FDCWD, test_file_name_.c_str(), &st, 0),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
}

TEST_F(StatTest, FstatatEmptyPath) {
  struct stat st;
  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));

  // Check that the stat works.
  EXPECT_THAT(fstatat(fd.get(), "", &st, AT_EMPTY_PATH), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
}

TEST_F(StatTest, FstatatRel) {
  struct stat st;
  int dirfd;
  auto filename = std::string(Basename(test_file_name_));

  // Open the temporary directory read-only.
  ASSERT_THAT(dirfd = open(GetAbsoluteTestTmpdir().c_str(), O_RDONLY),
              SyscallSucceeds());

  // Check that the stat works.
  EXPECT_THAT(fstatat(dirfd, filename.c_str(), &st, 0), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
  close(dirfd);
}

TEST_F(StatTest, FstatatSymlink) {
  struct stat st;

  // Check that the link is followed.
  EXPECT_THAT(fstatat(AT_FDCWD, "/proc/self", &st, 0), SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_FALSE(S_ISLNK(st.st_mode));

  // Check that the flag works.
  EXPECT_THAT(fstatat(AT_FDCWD, "/proc/self", &st, AT_SYMLINK_NOFOLLOW),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISLNK(st.st_mode));
  EXPECT_FALSE(S_ISDIR(st.st_mode));
}

TEST_F(StatTest, Nlinks) {
  // Skip this test if we are testing overlayfs because overlayfs does not
  // (intentionally) return the correct nlink value for directories.
  // See fs/overlayfs/inode.c:ovl_getattr().
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));

  TempPath basedir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Directory is initially empty, it should contain 2 links (one from itself,
  // one from ".").
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(2));

  // Create a file in the test directory. Files shouldn't increase the link
  // count on the base directory.
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(basedir.path()));
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(2));

  // Create subdirectories. This should increase the link count by 1 per
  // subdirectory.
  TempPath dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(basedir.path()));
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(3));
  TempPath dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(basedir.path()));
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(4));

  // Removing directories should reduce the link count.
  dir1.reset();
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(3));
  dir2.reset();
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(2));

  // Removing files should have no effect on link count.
  file1.reset();
  EXPECT_THAT(Links(basedir.path()), IsPosixErrorOkAndHolds(2));
}

TEST_F(StatTest, BlocksIncreaseOnWrite) {
  struct stat st;

  // Stat the empty file.
  ASSERT_THAT(fstat(test_file_fd_.get(), &st), SyscallSucceeds());

  const int initial_blocks = st.st_blocks;

  // Write to the file, making sure to exceed the block size.
  std::vector<char> buf(2 * st.st_blksize, 'a');
  ASSERT_THAT(write(test_file_fd_.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Stat the file again, and verify that number of allocated blocks has
  // increased.
  ASSERT_THAT(fstat(test_file_fd_.get(), &st), SyscallSucceeds());
  EXPECT_GT(st.st_blocks, initial_blocks);
}

TEST_F(StatTest, PathNotCleaned) {
  TempPath basedir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Create a file in the basedir.
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(basedir.path()));

  // Stating the file directly should succeed.
  struct stat buf;
  EXPECT_THAT(lstat(file.path().c_str(), &buf), SyscallSucceeds());

  // Try to stat the file using a directory that does not exist followed by
  // "..".  If the path is cleaned prior to stating (which it should not be)
  // then this will succeed.
  const std::string bad_path = JoinPath("/does_not_exist/..", file.path());
  EXPECT_THAT(lstat(bad_path.c_str(), &buf), SyscallFailsWithErrno(ENOENT));
}

TEST_F(StatTest, PathCanContainDotDot) {
  TempPath basedir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(basedir.path()));
  const std::string subdir_name = std::string(Basename(subdir.path()));

  // Create a file in the subdir.
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(subdir.path()));
  const std::string file_name = std::string(Basename(file.path()));

  // Stat the file through a path that includes '..' and '.' but still resolves
  // to the file.
  const std::string good_path =
      JoinPath(basedir.path(), subdir_name, "..", subdir_name, ".", file_name);
  struct stat buf;
  EXPECT_THAT(lstat(good_path.c_str(), &buf), SyscallSucceeds());
}

TEST_F(StatTest, PathCanContainEmptyComponent) {
  TempPath basedir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Create a file in the basedir.
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(basedir.path()));
  const std::string file_name = std::string(Basename(file.path()));

  // Stat the file through a path that includes an empty component.  We have to
  // build this ourselves because JoinPath automatically removes empty
  // components.
  const std::string good_path = absl::StrCat(basedir.path(), "//", file_name);
  struct stat buf;
  EXPECT_THAT(lstat(good_path.c_str(), &buf), SyscallSucceeds());
}

TEST_F(StatTest, TrailingSlashNotCleanedReturnsENOTDIR) {
  TempPath basedir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Create a file in the basedir.
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(basedir.path()));

  // Stat the file with an extra "/" on the end of it.  Since file is not a
  // directory, this should return ENOTDIR.
  const std::string bad_path = absl::StrCat(file.path(), "/");
  struct stat buf;
  EXPECT_THAT(lstat(bad_path.c_str(), &buf), SyscallFailsWithErrno(ENOTDIR));
}

TEST_F(StatTest, FstatFileWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  struct stat st;
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_PATH));

  // Stat the directory.
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
}

TEST_F(StatTest, FstatDirWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  struct stat st;
  TempPath tmpdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  FileDescriptor dirfd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(tmpdir.path().c_str(), O_PATH | O_DIRECTORY));

  // Stat the directory.
  ASSERT_THAT(fstat(dirfd.get(), &st), SyscallSucceeds());
}

// fstatat with an O_PATH fd
TEST_F(StatTest, FstatatDirWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  TempPath tmpdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  FileDescriptor dirfd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(tmpdir.path().c_str(), O_PATH | O_DIRECTORY));
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  struct stat st = {};
  EXPECT_THAT(fstatat(dirfd.get(), tmpfile.path().c_str(), &st, 0),
              SyscallSucceeds());
  EXPECT_FALSE(S_ISDIR(st.st_mode));
  EXPECT_TRUE(S_ISREG(st.st_mode));
}

// Test fstatating a symlink directory.
TEST_F(StatTest, FstatatSymlinkDir) {
  // Create a directory and symlink to it.
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const std::string symlink_to_dir = NewTempAbsPath();
  EXPECT_THAT(symlink(dir.path().c_str(), symlink_to_dir.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&symlink_to_dir]() {
    EXPECT_THAT(unlink(symlink_to_dir.c_str()), SyscallSucceeds());
  });

  // Fstatat the link with AT_SYMLINK_NOFOLLOW should return symlink data.
  struct stat st = {};
  EXPECT_THAT(
      fstatat(AT_FDCWD, symlink_to_dir.c_str(), &st, AT_SYMLINK_NOFOLLOW),
      SyscallSucceeds());
  EXPECT_FALSE(S_ISDIR(st.st_mode));
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  // Fstatat the link should return dir data.
  EXPECT_THAT(fstatat(AT_FDCWD, symlink_to_dir.c_str(), &st, 0),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_FALSE(S_ISLNK(st.st_mode));
}

// Test fstatating a symlink directory with trailing slash.
TEST_F(StatTest, FstatatSymlinkDirWithTrailingSlash) {
  // Create a directory and symlink to it.
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string symlink_to_dir = NewTempAbsPath();
  EXPECT_THAT(symlink(dir.path().c_str(), symlink_to_dir.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&symlink_to_dir]() {
    EXPECT_THAT(unlink(symlink_to_dir.c_str()), SyscallSucceeds());
  });

  // Fstatat on the symlink with a trailing slash should return the directory
  // data.
  struct stat st = {};
  EXPECT_THAT(
      fstatat(AT_FDCWD, absl::StrCat(symlink_to_dir, "/").c_str(), &st, 0),
      SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_FALSE(S_ISLNK(st.st_mode));

  // Fstatat on the symlink with a trailing slash with AT_SYMLINK_NOFOLLOW
  // should return the directory data.
  // Symlink to directory with trailing slash will ignore AT_SYMLINK_NOFOLLOW.
  EXPECT_THAT(fstatat(AT_FDCWD, absl::StrCat(symlink_to_dir, "/").c_str(), &st,
                      AT_SYMLINK_NOFOLLOW),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_FALSE(S_ISLNK(st.st_mode));
}

// Test fstatating a symlink directory with a trailing slash
// should return same stat data with fstatating directory.
TEST_F(StatTest, FstatatSymlinkDirWithTrailingSlashSameInode) {
  // Create a directory and symlink to it.
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // We are going to assert that the symlink inode id is the same as the linked
  // dir's inode id. In order for the inode id to be stable across
  // save/restore, it must be kept open. The FileDescriptor type will do that
  // for us automatically.
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY));

  const std::string symlink_to_dir = NewTempAbsPath();
  EXPECT_THAT(symlink(dir.path().c_str(), symlink_to_dir.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&symlink_to_dir]() {
    EXPECT_THAT(unlink(symlink_to_dir.c_str()), SyscallSucceeds());
  });

  // Fstatat on the symlink with a trailing slash should return the directory
  // data.
  struct stat st = {};
  EXPECT_THAT(fstatat(AT_FDCWD, absl::StrCat(symlink_to_dir, "/").c_str(), &st,
                      AT_SYMLINK_NOFOLLOW),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));

  // Dir and symlink should point to same inode.
  struct stat st_dir = {};
  EXPECT_THAT(
      fstatat(AT_FDCWD, dir.path().c_str(), &st_dir, AT_SYMLINK_NOFOLLOW),
      SyscallSucceeds());
  EXPECT_EQ(st.st_ino, st_dir.st_ino);
}

TEST_F(StatTest, LeadingDoubleSlash) {
  // Create a file, and make sure we can stat it.
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  struct stat st;
  ASSERT_THAT(lstat(file.path().c_str(), &st), SyscallSucceeds());

  // Now add an extra leading slash.
  const std::string double_slash_path = absl::StrCat("/", file.path());
  ASSERT_TRUE(absl::StartsWith(double_slash_path, "//"));

  // We should be able to stat the new path, and it should resolve to the same
  // file (same device and inode).
  struct stat double_slash_st;
  ASSERT_THAT(lstat(double_slash_path.c_str(), &double_slash_st),
              SyscallSucceeds());
  EXPECT_EQ(st.st_dev, double_slash_st.st_dev);
  // Inode numbers for gofer-accessed files may change across save/restore.
  if (!IsRunningWithSaveRestore()) {
    EXPECT_EQ(st.st_ino, double_slash_st.st_ino);
  }
}

// Test that a rename doesn't change the underlying file.
TEST_F(StatTest, StatDoesntChangeAfterRename) {
  const TempPath old_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath new_path(NewTempAbsPath());

  struct stat st_old = {};
  struct stat st_new = {};

  ASSERT_THAT(stat(old_file.path().c_str(), &st_old), SyscallSucceeds());
  ASSERT_THAT(rename(old_file.path().c_str(), new_path.path().c_str()),
              SyscallSucceeds());
  ASSERT_THAT(stat(new_path.path().c_str(), &st_new), SyscallSucceeds());

  EXPECT_EQ(st_old.st_nlink, st_new.st_nlink);
  EXPECT_EQ(st_old.st_dev, st_new.st_dev);
  // Inode numbers for gofer-accessed files on which no reference is held may
  // change across save/restore because the information that the gofer client
  // uses to track file identity (9P QID path) is inconsistent between gofer
  // processes, which are restarted across save/restore.
  //
  // Overlay filesystems may synthesize directory inode numbers on the fly.
  if (!IsRunningWithSaveRestore() &&
      !ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir()))) {
    EXPECT_EQ(st_old.st_ino, st_new.st_ino);
  }
  EXPECT_EQ(st_old.st_mode, st_new.st_mode);
  EXPECT_EQ(st_old.st_uid, st_new.st_uid);
  EXPECT_EQ(st_old.st_gid, st_new.st_gid);
  EXPECT_EQ(st_old.st_size, st_new.st_size);
}

// Test link counts with a regular file as the child.
TEST_F(StatTest, LinkCountsWithRegularFileChild) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  struct stat st_parent_before = {};
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_before), SyscallSucceeds());
  EXPECT_EQ(st_parent_before.st_nlink, 2);

  // Adding a regular file doesn't adjust the parent's link count.
  const TempPath child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  struct stat st_parent_after = {};
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_after), SyscallSucceeds());
  EXPECT_EQ(st_parent_after.st_nlink, 2);

  // The child should have a single link from the parent.
  struct stat st_child = {};
  ASSERT_THAT(stat(child.path().c_str(), &st_child), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st_child.st_mode));
  EXPECT_EQ(st_child.st_nlink, 1);

  // Finally unlinking the child should not affect the parent's link count.
  ASSERT_THAT(unlink(child.path().c_str()), SyscallSucceeds());
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_after), SyscallSucceeds());
  EXPECT_EQ(st_parent_after.st_nlink, 2);
}

// This test verifies that inodes remain around when there is an open fd
// after link count hits 0.
//
// It is marked NoSave because we don't support saving unlinked files.
TEST_F(StatTest, ZeroLinksOpenFdRegularFileChild_NoSave) {
  // Setting the enviornment variable GVISOR_GOFER_UNCACHED to any value
  // will prevent this test from running, see the tmpfs lifecycle.
  //
  // We need to support this because when a file is unlinked and we forward
  // the stat to the gofer it would return ENOENT.
  const char* uncached_gofer = getenv("GVISOR_GOFER_UNCACHED");
  SKIP_IF(uncached_gofer != nullptr);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      dir.path(), "hello", TempPath::kDefaultFileMode));

  // The child should have a single link from the parent.
  struct stat st_child_before = {};
  ASSERT_THAT(stat(child.path().c_str(), &st_child_before), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st_child_before.st_mode));
  EXPECT_EQ(st_child_before.st_nlink, 1);
  EXPECT_EQ(st_child_before.st_size, 5);  // Hello is 5 bytes.

  // Open the file so we can fstat after unlinking.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.path(), O_RDONLY));

  // Now a stat should return ENOENT but we should still be able to stat
  // via the open fd and fstat.
  ASSERT_THAT(unlink(child.path().c_str()), SyscallSucceeds());

  // Since the file has no more links stat should fail.
  struct stat st_child_after = {};
  ASSERT_THAT(stat(child.path().c_str(), &st_child_after),
              SyscallFailsWithErrno(ENOENT));

  // Fstat should still allow us to access the same file via the fd.
  struct stat st_child_fd = {};
  ASSERT_THAT(fstat(fd.get(), &st_child_fd), SyscallSucceeds());
  EXPECT_EQ(st_child_before.st_dev, st_child_fd.st_dev);
  EXPECT_EQ(st_child_before.st_ino, st_child_fd.st_ino);
  EXPECT_EQ(st_child_before.st_mode, st_child_fd.st_mode);
  EXPECT_EQ(st_child_before.st_uid, st_child_fd.st_uid);
  EXPECT_EQ(st_child_before.st_gid, st_child_fd.st_gid);
  EXPECT_EQ(st_child_before.st_size, st_child_fd.st_size);

  // TODO(b/34861058): This isn't ideal but since fstatfs(2) will always return
  // OVERLAYFS_SUPER_MAGIC we have no way to know if this fs is backed by a
  // gofer which doesn't support links.
  EXPECT_TRUE(st_child_fd.st_nlink == 0 || st_child_fd.st_nlink == 1);
}

// Test link counts with a directory as the child.
TEST_F(StatTest, LinkCountsWithDirChild) {
  // Skip this test if we are testing overlayfs because overlayfs does not
  // (intentionally) return the correct nlink value for directories.
  // See fs/overlayfs/inode.c:ovl_getattr().
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Before a child is added the two links are "." and the link from the parent.
  struct stat st_parent_before = {};
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_before), SyscallSucceeds());
  EXPECT_EQ(st_parent_before.st_nlink, 2);

  // Create a subdirectory and stat for the parent link counts.
  const TempPath sub_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));

  // The three links are ".", the link from the parent, and the link from
  // the child as "..".
  struct stat st_parent_after = {};
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_after), SyscallSucceeds());
  EXPECT_EQ(st_parent_after.st_nlink, 3);

  // The child will have 1 link from the parent and 1 link which represents ".".
  struct stat st_child = {};
  ASSERT_THAT(stat(sub_dir.path().c_str(), &st_child), SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st_child.st_mode));
  EXPECT_EQ(st_child.st_nlink, 2);

  // Finally delete the child dir and the parent link count should return to 2.
  ASSERT_THAT(rmdir(sub_dir.path().c_str()), SyscallSucceeds());
  ASSERT_THAT(stat(dir.path().c_str(), &st_parent_after), SyscallSucceeds());

  // Now we should only have links from the parent and "." since the subdir
  // has been removed.
  EXPECT_EQ(st_parent_after.st_nlink, 2);
}

// Test statting a child of a non-directory.
TEST_F(StatTest, ChildOfNonDir) {
  // Create a path that has a child of a regular file.
  const std::string filename = JoinPath(test_file_name_, "child");

  // Statting the path should return ENOTDIR.
  struct stat st;
  EXPECT_THAT(lstat(filename.c_str(), &st), SyscallFailsWithErrno(ENOTDIR));
}

// Test lstating a symlink directory.
TEST_F(StatTest, LstatSymlinkDir) {
  // Create a directory and symlink to it.
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string symlink_to_dir = NewTempAbsPath();
  EXPECT_THAT(symlink(dir.path().c_str(), symlink_to_dir.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&symlink_to_dir]() {
    EXPECT_THAT(unlink(symlink_to_dir.c_str()), SyscallSucceeds());
  });

  // Lstat on the symlink should return symlink data.
  struct stat st = {};
  ASSERT_THAT(lstat(symlink_to_dir.c_str(), &st), SyscallSucceeds());
  EXPECT_FALSE(S_ISDIR(st.st_mode));
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  // Lstat on the symlink with a trailing slash should return the directory
  // data.
  ASSERT_THAT(lstat(absl::StrCat(symlink_to_dir, "/").c_str(), &st),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_FALSE(S_ISLNK(st.st_mode));
}

// Verify that we get an ELOOP from too many symbolic links even when there
// are directories in the middle.
TEST_F(StatTest, LstatELOOPPath) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string subdir_base = "subdir";
  ASSERT_THAT(mkdir(JoinPath(dir.path(), subdir_base).c_str(), 0755),
              SyscallSucceeds());

  std::string target = JoinPath(dir.path(), subdir_base, subdir_base);
  std::string dst = JoinPath("..", subdir_base);
  ASSERT_THAT(symlink(dst.c_str(), target.c_str()), SyscallSucceeds());
  auto cleanup = Cleanup(
      [&target]() { EXPECT_THAT(unlink(target.c_str()), SyscallSucceeds()); });

  // Now build a path which is /subdir/subdir/... repeated many times so that
  // we can build a path that is shorter than PATH_MAX but can still cause
  // too many symbolic links. Note: Every other subdir is actually a directory
  // so we're not in a situation where it's a -> b -> a -> b, where a and b
  // are symbolic links.
  std::string path = dir.path();
  std::string subdir_append = absl::StrCat("/", subdir_base);
  do {
    absl::StrAppend(&path, subdir_append);
    // Keep appending /subdir until we would overflow PATH_MAX.
  } while ((path.size() + subdir_append.size()) < PATH_MAX);

  struct stat s = {};
  ASSERT_THAT(lstat(path.c_str(), &s), SyscallFailsWithErrno(ELOOP));
}

TEST(SimpleStatTest, DifferentFilesHaveDifferentDeviceInodeNumberPairs) {
  // TODO(gvisor.dev/issue/1624): This test case fails in VFS1 save/restore
  // tests because VFS1 gofer inode number assignment restarts after
  // save/restore, such that the inodes for file1 and file2 (which are
  // unreferenced and therefore not retained in sentry checkpoints before the
  // calls to lstat()) are assigned the same inode number.
  SKIP_IF(IsRunningWithVFS1() && IsRunningWithSaveRestore());

  TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  TempPath file2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  MaybeSave();
  struct stat st1 = ASSERT_NO_ERRNO_AND_VALUE(Lstat(file1.path()));
  MaybeSave();
  struct stat st2 = ASSERT_NO_ERRNO_AND_VALUE(Lstat(file2.path()));
  EXPECT_FALSE(st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino)
      << "both files have device number " << st1.st_dev << " and inode number "
      << st1.st_ino;
}

// Ensure that inode allocation for anonymous devices work correctly across
// save/restore. In particular, inode numbers should be unique across S/R.
TEST(SimpleStatTest, AnonDeviceAllocatesUniqueInodesAcrossSaveRestore) {
  // Use sockets as a convenient way to create inodes on an anonymous device.
  int fd;
  ASSERT_THAT(fd = socket(AF_UNIX, SOCK_STREAM, 0), SyscallSucceeds());
  FileDescriptor fd1(fd);
  MaybeSave();
  ASSERT_THAT(fd = socket(AF_UNIX, SOCK_STREAM, 0), SyscallSucceeds());
  FileDescriptor fd2(fd);

  struct stat st1;
  struct stat st2;
  ASSERT_THAT(fstat(fd1.get(), &st1), SyscallSucceeds());
  ASSERT_THAT(fstat(fd2.get(), &st2), SyscallSucceeds());

  // The two fds should have different inode numbers.
  EXPECT_NE(st2.st_ino, st1.st_ino);

  // Verify again after another S/R cycle. The inode numbers should remain the
  // same.
  MaybeSave();

  struct stat st1_after;
  struct stat st2_after;
  ASSERT_THAT(fstat(fd1.get(), &st1_after), SyscallSucceeds());
  ASSERT_THAT(fstat(fd2.get(), &st2_after), SyscallSucceeds());

  EXPECT_EQ(st1_after.st_ino, st1.st_ino);
  EXPECT_EQ(st2_after.st_ino, st2.st_ino);
}

#ifndef SYS_statx
#if defined(__x86_64__)
#define SYS_statx 332
#elif defined(__aarch64__)
#define SYS_statx 291
#else
#error "Unknown architecture"
#endif
#endif  // SYS_statx

#ifndef STATX_ALL
#define STATX_ALL 0x00000fffU
#endif  // STATX_ALL

// struct kernel_statx_timestamp is a Linux statx_timestamp struct.
struct kernel_statx_timestamp {
  int64_t tv_sec;
  uint32_t tv_nsec;
  int32_t __reserved;
};

// struct kernel_statx is a Linux statx struct. Old versions of glibc do not
// expose it. See include/uapi/linux/stat.h
struct kernel_statx {
  uint32_t stx_mask;
  uint32_t stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink;
  uint32_t stx_uid;
  uint32_t stx_gid;
  uint16_t stx_mode;
  uint16_t __spare0[1];
  uint64_t stx_ino;
  uint64_t stx_size;
  uint64_t stx_blocks;
  uint64_t stx_attributes_mask;
  struct kernel_statx_timestamp stx_atime;
  struct kernel_statx_timestamp stx_btime;
  struct kernel_statx_timestamp stx_ctime;
  struct kernel_statx_timestamp stx_mtime;
  uint32_t stx_rdev_major;
  uint32_t stx_rdev_minor;
  uint32_t stx_dev_major;
  uint32_t stx_dev_minor;
  uint64_t __spare2[14];
};

int statx(int dirfd, const char* pathname, int flags, unsigned int mask,
          struct kernel_statx* statxbuf) {
  return syscall(SYS_statx, dirfd, pathname, flags, mask, statxbuf);
}

TEST_F(StatTest, StatxAbsPath) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  struct kernel_statx stx;
  EXPECT_THAT(statx(-1, test_file_name_.c_str(), 0, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxRelPathDirFD) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  struct kernel_statx stx;
  auto const dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), O_RDONLY));
  auto filename = std::string(Basename(test_file_name_));

  EXPECT_THAT(statx(dirfd.get(), filename.c_str(), 0, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxRelPathCwd) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  ASSERT_THAT(chdir(GetAbsoluteTestTmpdir().c_str()), SyscallSucceeds());
  auto filename = std::string(Basename(test_file_name_));
  struct kernel_statx stx;
  EXPECT_THAT(statx(AT_FDCWD, filename.c_str(), 0, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxEmptyPath) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));
  struct kernel_statx stx;
  EXPECT_THAT(statx(fd.get(), "", AT_EMPTY_PATH, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxDoesNotRejectExtraneousMaskBits) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  struct kernel_statx stx;
  // Set all mask bits except for STATX__RESERVED.
  uint mask = 0xffffffff & ~0x80000000;
  EXPECT_THAT(statx(-1, test_file_name_.c_str(), 0, mask, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxRejectsReservedMaskBit) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  struct kernel_statx stx;
  // Set STATX__RESERVED in the mask.
  EXPECT_THAT(statx(-1, test_file_name_.c_str(), 0, 0x80000000, &stx),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(StatTest, StatxSymlink) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  std::string parent_dir = GetAbsoluteTestTmpdir();
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent_dir, test_file_name_));
  std::string p = link.path();

  struct kernel_statx stx;
  EXPECT_THAT(statx(AT_FDCWD, p.c_str(), AT_SYMLINK_NOFOLLOW, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISLNK(stx.stx_mode));
  EXPECT_THAT(statx(AT_FDCWD, p.c_str(), 0, STATX_ALL, &stx),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(stx.stx_mode));
}

TEST_F(StatTest, StatxInvalidFlags) {
  SKIP_IF(!IsRunningOnGvisor() && statx(-1, nullptr, 0, 0, nullptr) < 0 &&
          errno == ENOSYS);

  struct kernel_statx stx;
  EXPECT_THAT(statx(AT_FDCWD, test_file_name_.c_str(), 12345, 0, &stx),
              SyscallFailsWithErrno(EINVAL));

  // Sync flags are mutually exclusive.
  EXPECT_THAT(statx(AT_FDCWD, test_file_name_.c_str(),
                    AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC, 0, &stx),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
