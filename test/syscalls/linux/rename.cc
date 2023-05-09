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
#include <stdio.h>

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::AnyOf;

namespace gvisor {
namespace testing {

namespace {

TEST(RenameTest, RootToAnything) {
  ASSERT_THAT(rename("/", "/bin"), SyscallFailsWithErrno(EBUSY));
}

TEST(RenameTest, AnythingToRoot) {
  ASSERT_THAT(rename("/bin", "/"), SyscallFailsWithErrno(EBUSY));
}

TEST(RenameTest, SourceIsAncestorOfTarget) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto subdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  ASSERT_THAT(rename(dir.path().c_str(), subdir.path().c_str()),
              SyscallFailsWithErrno(EINVAL));

  // Try an even deeper directory.
  auto deep_subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(subdir.path()));
  ASSERT_THAT(rename(dir.path().c_str(), deep_subdir.path().c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(RenameTest, TargetIsAncestorOfSource) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto subdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  ASSERT_THAT(rename(subdir.path().c_str(), dir.path().c_str()),
              SyscallFailsWithErrno(ENOTEMPTY));

  // Try an even deeper directory.
  auto deep_subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(subdir.path()));
  ASSERT_THAT(rename(deep_subdir.path().c_str(), dir.path().c_str()),
              SyscallFailsWithErrno(ENOTEMPTY));
}

TEST(RenameTest, FileToSelf) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(rename(f.path().c_str(), f.path().c_str()), SyscallSucceeds());
}

TEST(RenameTest, DirectoryToSelf) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(rename(f.path().c_str(), f.path().c_str()), SyscallSucceeds());
}

TEST(RenameTest, FileToSameDirectory) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  std::string const newpath = NewTempAbsPath();
  ASSERT_THAT(rename(f.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = f.release();
  f.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, FileNameTooLong) {
  auto old_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto new_base = NextTempBasename();
  int padding = (NAME_MAX + 1) - new_base.size();
  new_base.append(padding, 'x');
  auto new_path = JoinPath(Dirname(old_file.path()), new_base);
  ASSERT_THAT(rename(old_file.path().c_str(), new_path.c_str()),
              SyscallFailsWithErrno(ENAMETOOLONG));
}

TEST(RenameTest, RenameAfterWritableFDAndChmod) {
  // Restore will require re-opening the writable FD which will fail.
  const DisableSave ds;
  const std::string data = "hello world\n";
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto wfd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_WRONLY));
  ASSERT_THAT(chmod(f.path().c_str(), 0444), SyscallSucceeds());
  std::string const newpath = NewTempAbsPath();
  ASSERT_THAT(rename(f.path().c_str(), newpath.c_str()), SyscallSucceeds());
  EXPECT_THAT(WriteFd(wfd.get(), data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));
}

TEST(RenameTest, DirectoryToSameDirectory) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string const newpath = NewTempAbsPath();
  ASSERT_THAT(rename(dir.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = dir.release();
  dir.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, FileToParentDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir2.path()));
  std::string const newpath = NewTempAbsPathInDir(dir1.path());
  ASSERT_THAT(rename(f.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = f.release();
  f.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, DirectoryToParentDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir2.path()));
  EXPECT_THAT(IsDirectory(dir3.path()), IsPosixErrorOkAndHolds(true));
  std::string const newpath = NewTempAbsPathInDir(dir1.path());
  ASSERT_THAT(rename(dir3.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = dir3.release();
  dir3.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(IsDirectory(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, FileToChildDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  std::string const newpath = NewTempAbsPathInDir(dir2.path());
  ASSERT_THAT(rename(f.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = f.release();
  f.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, DirectoryToChildDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  std::string const newpath = NewTempAbsPathInDir(dir2.path());
  ASSERT_THAT(rename(dir3.path().c_str(), newpath.c_str()), SyscallSucceeds());
  std::string const oldpath = dir3.release();
  dir3.reset(newpath);
  EXPECT_THAT(Exists(oldpath), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(newpath), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(IsDirectory(newpath), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, DirectoryToOwnChildDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  std::string const newpath = NewTempAbsPathInDir(dir2.path());
  ASSERT_THAT(rename(dir1.path().c_str(), newpath.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(RenameTest, FileOverwritesFile) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      dir.path(), "first", TempPath::kDefaultFileMode));
  auto f2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      dir.path(), "second", TempPath::kDefaultFileMode));
  ASSERT_THAT(rename(f1.path().c_str(), f2.path().c_str()), SyscallSucceeds());
  EXPECT_THAT(Exists(f1.path()), IsPosixErrorOkAndHolds(false));

  f1.release();
  std::string f2_contents;
  ASSERT_NO_ERRNO(GetContents(f2.path(), &f2_contents));
  EXPECT_EQ("first", f2_contents);
}

TEST(RenameTest, DirectoryOverwritesDirectoryLinkCount) {
  // Directory link counts are synthetic on overlay filesystems.
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));

  auto parent1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(Links(parent1.path()), IsPosixErrorOkAndHolds(2));

  auto parent2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(Links(parent2.path()), IsPosixErrorOkAndHolds(2));

  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent1.path()));
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent2.path()));

  EXPECT_THAT(Links(parent1.path()), IsPosixErrorOkAndHolds(3));
  EXPECT_THAT(Links(parent2.path()), IsPosixErrorOkAndHolds(3));

  ASSERT_THAT(rename(dir1.path().c_str(), dir2.path().c_str()),
              SyscallSucceeds());

  EXPECT_THAT(Links(parent1.path()), IsPosixErrorOkAndHolds(2));
  EXPECT_THAT(Links(parent2.path()), IsPosixErrorOkAndHolds(3));
}

TEST(RenameTest, FileDoesNotExist) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string source = JoinPath(dir.path(), "source");
  const std::string dest = JoinPath(dir.path(), "dest");
  ASSERT_THAT(rename(source.c_str(), dest.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(RenameTest, FileDoesNotOverwriteDirectory) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(rename(f.path().c_str(), dir.path().c_str()),
              SyscallFailsWithErrno(EISDIR));
}

TEST(RenameTest, DirectoryDoesNotOverwriteFile) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(rename(dir.path().c_str(), f.path().c_str()),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST(RenameTest, DirectoryOverwritesEmptyDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(rename(dir1.path().c_str(), dir2.path().c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(dir1.path()), IsPosixErrorOkAndHolds(false));
  dir1.release();
  EXPECT_THAT(Exists(JoinPath(dir2.path(), Basename(f.path()))),
              IsPosixErrorOkAndHolds(true));
  f.release();
}

TEST(RenameTest, FailsWithDots) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto dir1_dot = absl::StrCat(dir1.path(), "/.");
  auto dir2_dot = absl::StrCat(dir2.path(), "/.");
  auto dir1_dot_dot = absl::StrCat(dir1.path(), "/..");
  auto dir2_dot_dot = absl::StrCat(dir2.path(), "/..");

  // Try with dot paths in the first argument
  EXPECT_THAT(rename(dir1_dot.c_str(), dir2.path().c_str()),
              SyscallFailsWithErrno(EBUSY));
  EXPECT_THAT(rename(dir1_dot_dot.c_str(), dir2.path().c_str()),
              SyscallFailsWithErrno(EBUSY));

  // Try with dot paths in the second argument
  EXPECT_THAT(rename(dir1.path().c_str(), dir2_dot.c_str()),
              SyscallFailsWithErrno(EBUSY));
  EXPECT_THAT(rename(dir1.path().c_str(), dir2_dot_dot.c_str()),
              SyscallFailsWithErrno(EBUSY));
}

TEST(RenameTest, DirectoryDoesNotOverwriteNonemptyDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir2.path()));
  ASSERT_THAT(rename(dir1.path().c_str(), dir2.path().c_str()),
              SyscallFailsWithErrno(ENOTEMPTY));
}

TEST(RenameTest, FailsWhenOldParentNotWritable) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // dir1 is not writable.
  ASSERT_THAT(chmod(dir1.path().c_str(), 0555), SyscallSucceeds());

  std::string const newpath = NewTempAbsPathInDir(dir2.path());
  EXPECT_THAT(rename(f1.path().c_str(), newpath.c_str()),
              SyscallFailsWithErrno(EACCES));
}

TEST(RenameTest, FailsWhenNewParentNotWritable) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  // dir2 is not writable.
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0555));

  std::string const newpath = NewTempAbsPathInDir(dir2.path());
  EXPECT_THAT(rename(f1.path().c_str(), newpath.c_str()),
              SyscallFailsWithErrno(EACCES));
}

// Equivalent to FailsWhenNewParentNotWritable, but with a destination file
// to overwrite.
TEST(RenameTest, OverwriteFailsWhenNewParentNotWritable) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));

  // dir2 is not writable.
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir2.path()));
  ASSERT_THAT(chmod(dir2.path().c_str(), 0555), SyscallSucceeds());

  EXPECT_THAT(rename(f1.path().c_str(), f2.path().c_str()),
              SyscallFailsWithErrno(EACCES));
}

// If the parent directory of source is not accessible, rename returns EACCES
// because the user cannot determine if source exists.
TEST(RenameTest, FileDoesNotExistWhenNewParentNotExecutable) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  // No execute permission.
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0400));

  const std::string source = JoinPath(dir.path(), "source");
  const std::string dest = JoinPath(dir.path(), "dest");
  ASSERT_THAT(rename(source.c_str(), dest.c_str()),
              SyscallFailsWithErrno(EACCES));
}

TEST(RenameTest, DirectoryWithOpenFdOverwritesEmptyDirectory) {
  auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Get an fd on dir1
  int fd;
  ASSERT_THAT(fd = open(dir1.path().c_str(), O_DIRECTORY), SyscallSucceeds());
  auto close_f = Cleanup([fd] {
    // Close the fd on f.
    EXPECT_THAT(close(fd), SyscallSucceeds());
  });

  EXPECT_THAT(rename(dir1.path().c_str(), dir2.path().c_str()),
              SyscallSucceeds());

  const std::string new_f_path = JoinPath(dir2.path(), Basename(f.path()));

  auto remove_f = Cleanup([&] {
    // Delete f in its new location.
    ASSERT_NO_ERRNO(Delete(new_f_path));
    f.release();
  });

  EXPECT_THAT(Exists(dir1.path()), IsPosixErrorOkAndHolds(false));
  dir1.release();
  EXPECT_THAT(Exists(new_f_path), IsPosixErrorOkAndHolds(true));
}

TEST(RenameTest, FileWithOpenFd) {
  TempPath root_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root_dir.path()));
  TempPath dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root_dir.path()));
  TempPath dir3 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root_dir.path()));

  // Create file in dir1.
  constexpr char kContents[] = "foo";
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      dir1.path(), kContents, TempPath::kDefaultFileMode));

  // Get fd on file.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDWR));

  // Move f to dir2.
  const std::string path2 = NewTempAbsPathInDir(dir2.path());
  ASSERT_THAT(rename(f.path().c_str(), path2.c_str()), SyscallSucceeds());

  // Read f's kContents.
  char buf[sizeof(kContents)];
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(kContents), 0),
              SyscallSucceedsWithValue(sizeof(kContents) - 1));
  EXPECT_EQ(absl::string_view(buf, sizeof(buf) - 1), kContents);

  // Move f to dir3.
  const std::string path3 = NewTempAbsPathInDir(dir3.path());
  ASSERT_THAT(rename(path2.c_str(), path3.c_str()), SyscallSucceeds());

  // Read f's kContents.
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(kContents), 0),
              SyscallSucceedsWithValue(sizeof(kContents) - 1));
  EXPECT_EQ(absl::string_view(buf, sizeof(buf) - 1), kContents);
}

// Tests that calling rename with file path ending with . or .. causes EBUSY.
TEST(RenameTest, PathEndingWithDots) {
  TempPath root_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root_dir.path()));
  TempPath dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root_dir.path()));

  // Try to move dir1 into dir2 but mess up the paths.
  auto dir1Dot = JoinPath(dir1.path(), ".");
  auto dir2Dot = JoinPath(dir2.path(), ".");
  auto dir1DotDot = JoinPath(dir1.path(), "..");
  auto dir2DotDot = JoinPath(dir2.path(), "..");
  ASSERT_THAT(rename(dir1.path().c_str(), dir2Dot.c_str()),
              SyscallFailsWithErrno(EBUSY));
  ASSERT_THAT(rename(dir1.path().c_str(), dir2DotDot.c_str()),
              SyscallFailsWithErrno(EBUSY));
  ASSERT_THAT(rename(dir1Dot.c_str(), dir2.path().c_str()),
              SyscallFailsWithErrno(EBUSY));
  ASSERT_THAT(rename(dir1DotDot.c_str(), dir2.path().c_str()),
              SyscallFailsWithErrno(EBUSY));
}

// Calling rename with file path ending with . or .. causes EBUSY in sysfs.
TEST(RenameTest, SysfsPathEndingWithDots) {
  // If a non-root user tries to rename inside /sys then we get EPERM.
  SKIP_IF(geteuid() != 0);
  ASSERT_THAT(rename("/sys/devices/system/cpu/online", "/sys/."),
              SyscallFailsWithErrno(EBUSY));
  ASSERT_THAT(rename("/sys/devices/system/cpu/online", "/sys/.."),
              SyscallFailsWithErrno(EBUSY));
}

TEST(RenameTest, SysfsFileToSelf) {
  // If a non-root user tries to rename inside /sys then we get EPERM.
  SKIP_IF(geteuid() != 0);
  std::string const path = "/sys/devices/system/cpu/online";
  EXPECT_THAT(rename(path.c_str(), path.c_str()), SyscallSucceeds());
}

TEST(RenameTest, SysfsDirectoryToSelf) {
  // If a non-root user tries to rename inside /sys then we get EPERM.
  SKIP_IF(geteuid() != 0);
  std::string const path = "/sys/devices";
  EXPECT_THAT(rename(path.c_str(), path.c_str()), SyscallSucceeds());
}

#ifndef SYS_renameat2
#if defined(__x86_64__)
#define SYS_renameat2 316
#elif defined(__aarch64__)
#define SYS_renameat2 276
#else
#error "Unknown architecture"
#endif
#endif  // SYS_renameat2

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif  // RENAME_NOREPLACE

int renameat2(int olddirfd, const char* oldpath, int newdirfd,
              const char* newpath, unsigned int flags) {
  return syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

TEST(Renameat2Test, NoReplaceSuccess) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  std::string const newpath = NewTempAbsPath();
  // renameat2 may fail with ENOSYS (if the syscall is unsupported) or EINVAL
  // (if flags are unsupported), or succeed (if RENAME_NOREPLACE is operating
  // correctly).
  EXPECT_THAT(
      renameat2(AT_FDCWD, f.path().c_str(), AT_FDCWD, newpath.c_str(),
                RENAME_NOREPLACE),
      AnyOf(SyscallFailsWithErrno(AnyOf(ENOSYS, EINVAL)), SyscallSucceeds()));
}

TEST(Renameat2Test, NoReplaceExisting) {
  auto f1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  // renameat2 may fail with ENOSYS (if the syscall is unsupported), EINVAL (if
  // flags are unsupported), or EEXIST (if RENAME_NOREPLACE is operating
  // correctly).
  EXPECT_THAT(renameat2(AT_FDCWD, f1.path().c_str(), AT_FDCWD,
                        f2.path().c_str(), RENAME_NOREPLACE),
              SyscallFailsWithErrno(AnyOf(ENOSYS, EINVAL, EEXIST)));
}

TEST(Renameat2Test, NoReplaceDot) {
  auto d1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto d2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // renameat2 may fail with ENOSYS (if the syscall is unsupported), EINVAL (if
  // flags are unsupported), or EEXIST (if RENAME_NOREPLACE is operating
  // correctly).
  EXPECT_THAT(
      renameat2(AT_FDCWD, d1.path().c_str(), AT_FDCWD,
                absl::StrCat(d2.path(), "/.").c_str(), RENAME_NOREPLACE),
      SyscallFailsWithErrno(AnyOf(ENOSYS, EINVAL, EEXIST)));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
