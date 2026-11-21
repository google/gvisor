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
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(int32_t, scratch_uid, 65534, "scratch UID");

namespace gvisor {
namespace testing {

namespace {

// IsSameFile returns true if both filenames have the same device and inode.
bool IsSameFile(const std::string& f1, const std::string& f2) {
  // Inode numbers for gofer-accessed files on which no reference is held may
  // change across save/restore because the information that the gofer client
  // uses to track file identity (path) is inconsistent between gofer
  // processes, which are restarted across save/restore.
  DisableSave ds;
  // Use lstat rather than stat, so that symlinks are not followed.
  struct stat stat1 = {};
  EXPECT_THAT(lstat(f1.c_str(), &stat1), SyscallSucceeds());
  struct stat stat2 = {};
  EXPECT_THAT(lstat(f2.c_str(), &stat2), SyscallSucceeds());

  return stat1.st_dev == stat2.st_dev && stat1.st_ino == stat2.st_ino;
}

TEST(LinkTest, CanCreateLinkFile) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();

  // Get the initial link count.
  uint64_t initial_link_count =
      ASSERT_NO_ERRNO_AND_VALUE(Links(oldfile.path()));

  EXPECT_THAT(link(oldfile.path().c_str(), newname.c_str()), SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));

  // Link count should be incremented.
  EXPECT_THAT(Links(oldfile.path()),
              IsPosixErrorOkAndHolds(initial_link_count + 1));

  // Delete the link.
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());

  // Link count should be back to initial.
  EXPECT_THAT(Links(oldfile.path()),
              IsPosixErrorOkAndHolds(initial_link_count));
}

TEST(LinkTest, HardlinkChangeMode) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();
  constexpr uint32_t kMode = S_IRUSR;
  struct stat stat1 = {};
  struct stat stat2 = {};
  FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(oldfile.path(), O_PATH));

  ASSERT_THAT(
      linkat(AT_FDCWD, oldfile.path().c_str(), AT_FDCWD, newname.c_str(), 0),
      SyscallSucceeds());

  EXPECT_THAT(chmod(oldfile.path().c_str(), kMode), SyscallSucceeds());
  EXPECT_THAT(lstat(newname.c_str(), &stat1), SyscallSucceeds());
  EXPECT_THAT(lstat(oldfile.path().c_str(), &stat2), SyscallSucceeds());

  // Expect both names to report the same device and inode numbers, even with
  // save/restore enabled in this test, since they refer to the same host file.
  // Do not use IsSameFile() here because it disables save/restore.

  EXPECT_EQ(stat1.st_dev, stat2.st_dev);
  EXPECT_EQ(stat1.st_ino, stat2.st_ino);
  EXPECT_EQ(kMode, (stat1.st_mode & S_IRWXU));
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, PermissionDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FOWNER)));

  // In Linux, the constraints checked by this test are only enforced by
  // fs/namei.c:may_linkat() => safe_hardlink_source() when
  // sysctl_protected_hardlinks is enabled.
  if (auto maybe_protected_hardlinks =
          GetContents("/proc/sys/fs/protected_hardlinks");
      maybe_protected_hardlinks.ok()) {
    if (auto protected_hardlinks = maybe_protected_hardlinks.ValueOrDie();
        !protected_hardlinks.empty() && protected_hardlinks[0] == '0') {
      GTEST_SKIP() << "protected_hardlinks is disabled";
    }
  }

  // Make the file "unsafe" to link by making it only readable, but not
  // writable.
  const auto unwriteable_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0400));
  const std::string special_path = NewTempAbsPath();
  ASSERT_THAT(mkfifo(special_path.c_str(), 0666), SyscallSucceeds());
  const auto setuid_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0666 | S_ISUID));

  const std::string newname = NewTempAbsPath();

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting this
  // test. Otherwise, the files are created by root (UID before the test), but
  // cannot be opened by the `uid` set below after the test. After calling
  // setuid(non-zero-UID), there is no way to get root privileges back.
  ScopedThread([&] {
    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. POSIX threads, however, require that all
    // threads have the same UIDs, so using the setuid wrapper sets all threads'
    // real UID.
    // Also drops capabilities.
    EXPECT_THAT(syscall(SYS_setuid, absl::GetFlag(FLAGS_scratch_uid)),
                SyscallSucceeds());

    EXPECT_THAT(link(unwriteable_file.path().c_str(), newname.c_str()),
                SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(link(special_path.c_str(), newname.c_str()),
                SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(link(setuid_file.path().c_str(), newname.c_str()),
                SyscallFailsWithErrno(EPERM));
  });
}

TEST(LinkTest, CannotLinkDirectory) {
  auto olddir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string newdir = NewTempAbsPath();

  EXPECT_THAT(link(olddir.path().c_str(), newdir.c_str()),
              SyscallFailsWithErrno(EPERM));

  EXPECT_THAT(rmdir(olddir.path().c_str()), SyscallSucceeds());
}

TEST(LinkTest, CannotLinkWithSlash) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  // Put a final "/" on newname.
  const std::string newname = absl::StrCat(NewTempAbsPath(), "/");

  EXPECT_THAT(link(oldfile.path().c_str(), newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, OldnameIsEmpty) {
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link("", newname.c_str()), SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, OldnameDoesNotExist) {
  const std::string oldname = NewTempAbsPath();
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link(oldname.c_str(), newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, NewnameCannotExist) {
  const std::string newname =
      JoinPath(GetAbsoluteTestTmpdir(), "thisdoesnotexist", "foo");
  EXPECT_THAT(link("/thisdoesnotmatter", newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, WithOldDirFD) {
  const std::string oldname_parent = NewTempAbsPath();
  const std::string oldname_base = "child";
  const std::string oldname = JoinPath(oldname_parent, oldname_base);
  const std::string newname = NewTempAbsPath();

  // Create oldname_parent directory, and get an FD.
  ASSERT_THAT(mkdir(oldname_parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor oldname_parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(oldname_parent, O_DIRECTORY | O_RDONLY));

  // Create oldname file.
  const FileDescriptor oldname_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(oldname, O_CREAT | O_RDWR, 0666));

  // Link oldname to newname, using oldname_parent_fd.
  EXPECT_THAT(linkat(oldname_parent_fd.get(), oldname_base.c_str(), AT_FDCWD,
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldname, newname));

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(oldname.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(oldname_parent.c_str()), SyscallSucceeds());
}

TEST(LinkTest, BogusFlags) {
  ASSERT_THAT(linkat(1, "foo", 2, "bar", 3), SyscallFailsWithErrno(EINVAL));
}

TEST(LinkTest, WithNewDirFD) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname_parent = NewTempAbsPath();
  const std::string newname_base = "child";
  const std::string newname = JoinPath(newname_parent, newname_base);

  // Create newname_parent directory, and get an FD.
  EXPECT_THAT(mkdir(newname_parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor newname_parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(newname_parent, O_DIRECTORY | O_RDONLY));

  // Link newname to oldfile, using newname_parent_fd.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), newname_parent_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(newname_parent.c_str()), SyscallSucceeds());
}

TEST(LinkTest, RelPathsWithNonDirFDs) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Create a file that will be passed as the directory fd for old/new names.
  const std::string filename = NewTempAbsPath();
  const FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT | O_RDWR, 0666));

  // Using file_fd as olddirfd will fail.
  EXPECT_THAT(linkat(file_fd.get(), "foo", AT_FDCWD, "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));

  // Using file_fd as newdirfd will fail.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), file_fd.get(), "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST(LinkTest, AbsPathsWithNonDirFDs) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();

  // Create a file that will be passed as the directory fd for old/new names.
  const std::string filename = NewTempAbsPath();
  const FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT | O_RDWR, 0666));

  // Using file_fd as the dirfds is OK as long as paths are absolute.
  EXPECT_THAT(linkat(file_fd.get(), oldfile.path().c_str(), file_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));
}

TEST(LinkTest, NewDirFDWithOpath) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname_parent = NewTempAbsPath();
  const std::string newname_base = "child";
  const std::string newname = JoinPath(newname_parent, newname_base);

  // Create newname_parent directory, and get an FD.
  EXPECT_THAT(mkdir(newname_parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor newname_parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(newname_parent, O_DIRECTORY | O_PATH));

  // Link newname to oldfile, using newname_parent_fd.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), newname_parent_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));
}

TEST(LinkTest, RelPathsNonDirFDsWithOpath) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Create a file that will be passed as the directory fd for old/new names.
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor file_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_PATH));

  // Using file_fd as olddirfd will fail.
  EXPECT_THAT(linkat(file_fd.get(), "foo", AT_FDCWD, "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));

  // Using file_fd as newdirfd will fail.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), file_fd.get(), "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST(LinkTest, AbsPathsNonDirFDsWithOpath) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();

  // Create a file that will be passed as the directory fd for old/new names.
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor file_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_PATH));

  // Using file_fd as the dirfds is OK as long as paths are absolute.
  EXPECT_THAT(linkat(file_fd.get(), oldfile.path().c_str(), file_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());
  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));
}

TEST(LinkTest, LinkDoesNotFollowSymlinks) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  EXPECT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink.
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link(oldsymlink.c_str(), newname.c_str()), SyscallSucceeds());

  // The link should not have resolved the symlink, so newname and oldsymlink
  // are the same.
  EXPECT_TRUE(IsSameFile(oldsymlink, newname));
  EXPECT_FALSE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, LinkatDoesNotFollowSymlinkByDefault) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  EXPECT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink.
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(
      linkat(AT_FDCWD, oldsymlink.c_str(), AT_FDCWD, newname.c_str(), 0),
      SyscallSucceeds());

  // The link should not have resolved the symlink, so newname and oldsymlink
  // are the same.
  EXPECT_TRUE(IsSameFile(oldsymlink, newname));
  EXPECT_FALSE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, LinkatWithSymlinkFollow) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  ASSERT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink, and pass AT_SYMLINK_FOLLOW flag.
  const std::string newname = NewTempAbsPath();
  ASSERT_THAT(linkat(AT_FDCWD, oldsymlink.c_str(), AT_FDCWD, newname.c_str(),
                     AT_SYMLINK_FOLLOW),
              SyscallSucceeds());

  // The link should have resolved the symlink, so oldfile and newname are the
  // same.
  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));
  EXPECT_FALSE(IsSameFile(oldsymlink, newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, KernfsAcrossFilesystem) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(link(file.path().c_str(), "/sys/newfile"),
              SyscallFailsWithErrno(::testing::AnyOf(EROFS, EXDEV)));
}

// A test for a relaxed linkat(AT_EMPTY_PATH) where the need for
// CAP_DAC_READ_SEARCH is excused if the creds struct has not changed. See
// https://github.com/torvalds/linux/commit/42bd2af5950456d, which first
// appears in Linux 6.10.
TEST(LinkTest, LinkAtWithEmptyPathNeedsNoCapForSameCreds) {
  if (!IsRunningOnGvisor()) {
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 10)) {
      GTEST_SKIP() << "Kernel version is too old";
    }
  }

  // Drop the cap before opening the fd.
  AutoCapability cap(CAP_DAC_READ_SEARCH, false);

  auto old_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto old_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(old_file.path(), O_RDONLY));
  int old_fd_raw = old_fd.get();
  auto new_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto new_dir_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(new_dir.path(), O_RDONLY));
  int new_dir_fd_raw = new_dir_fd.get();

  // linkat(AT_EMPTY_PATH) should succeed for a dirfd we just opened,
  // even though we don't have CAP_DAC_READ_SEARCH, because our creds struct
  // remained the same.
  constexpr char kOldCredsNoCap[] = "old_creds_no_cap";
  ASSERT_THAT(
      linkat(old_fd_raw, "", new_dir_fd_raw, kOldCredsNoCap, AT_EMPTY_PATH),
      SyscallSucceeds());
  ASSERT_THAT(unlinkat(new_dir_fd_raw, kOldCredsNoCap, 0), SyscallSucceeds());
}

TEST(LinkTest, LinkAtWithEmptyPathNeedsCapDacReadSearch) {
  // The Linux commit 42bd2af5950456d described above appears only in 6.10.
  if (!IsRunningOnGvisor()) {
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 10)) {
      GTEST_SKIP() << "Kernel version is too old";
    }
  }
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_READ_SEARCH)));

  auto old_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto old_file_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(old_file.path(), O_RDONLY));
  int old_file_fd_raw = old_file_fd.get();
  auto new_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto new_dir_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(new_dir.path(), O_RDONLY));
  int new_dir_fd_raw = new_dir_fd.get();

  // Toggling CAP_DAC_READ_SEARCH forces the creds struct of this task to change
  // since we opened the fd, but linkat(AT_EMPTY_PATH) should succeed because we
  // still have the cap. See
  // https://github.com/torvalds/linux/commit/42bd2af5950456d.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, true));
  constexpr char kNewCredsWithCap[] = "new_creds_with_cap";
  ASSERT_THAT(linkat(old_file_fd_raw, "", new_dir_fd_raw, kNewCredsWithCap,
                     AT_EMPTY_PATH),
              SyscallSucceeds());
  auto cleanup1 = Cleanup([&] {
    ASSERT_THAT(unlinkat(new_dir_fd_raw, kNewCredsWithCap, 0),
                SyscallSucceeds());
  });

  // Once the cap is dropped, linkat(AT_EMPTY_PATH) should fail with ENOENT.
  AutoCapability cap(CAP_DAC_READ_SEARCH, false);
  constexpr char kNewCredsNoCap[] = "new_creds_no_cap";
  ASSERT_THAT(linkat(old_file_fd_raw, "", new_dir_fd_raw, kNewCredsNoCap,
                     AT_EMPTY_PATH),
              SyscallFailsWithErrno(ENOENT));

  // In this forked process, the creds struct is decidedly different from the
  // fd-creator's creds struct, so we do need CAP_DAC_READ_SEARCH to succeed.
  // But it's not enough to possess the cap in one's own userns.
  constexpr char kNewCredsWithCapButInDiffUserns[] =
      "new_creds_with_cap_in_wrong_userns";
  ASSERT_THAT(InForkedProcess([&] {
                // unshare to gain CAP_DAC_READ_SEARCH in a new userns.
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER));
                // But the linkat should still fail with ENOENT for we still
                // lack CAP_DAC_READ_SEARCH in the userns in which the fd was
                // opened.
                TEST_CHECK_ERRNO(
                    syscall(SYS_linkat, old_file_fd_raw, "", new_dir_fd_raw,
                            kNewCredsWithCapButInDiffUserns, AT_EMPTY_PATH),
                    ENOENT);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(LinkTest, LinkAtWithEmptyPathNeedsNoCapForAtFcwd) {
  // The Linux commit 42bd2af5950456d described above appears only in 6.10.
  if (!IsRunningOnGvisor()) {
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 10)) {
      GTEST_SKIP() << "Kernel version is too old";
    }
  }
  AutoCapability cap(CAP_DAC_READ_SEARCH, false);

  auto old_dir = GetAbsoluteTestTmpdir();
  auto old_dir_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(old_dir, O_RDONLY));
  int old_dir_fd_raw = old_dir_fd.get();
  auto old_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(old_dir));
  const char* old_file_path = old_file.path().c_str();

  std::string old_file_rel_path =
      std::string(absl::StripPrefix(old_file_path, old_dir));
  if (!old_file_rel_path.empty() && old_file_rel_path[0] == '/') {
    old_file_rel_path.erase(0, 1);
  }

  auto new_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto new_dir_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(new_dir.path(), O_RDONLY));
  int new_dir_fd_raw = new_dir_fd.get();

  // If we try to linkat with olddirfd=AT_FDCWD, it should succeed, because
  // the AT_EMPTY_PATH cap checks are triggered only if the olddirfd is not
  // AT_FDCWD (If they were triggered, our lack of CAP_DAC_READ_SEARCH would
  // have caused a failure).
  EXPECT_THAT(
      InForkedProcess([&] {
        // Change the cwd to old_dir (in a forked process to avoid
        // affecting the test process's cwd).
        TEST_CHECK_SUCCESS(RetryEINTR(syscall)(SYS_fchdir, old_dir_fd_raw));

        constexpr char kAtFdcwdNewCredsNoCap[] = "at_fdcwd_new_creds_no_cap";
        int res;
        while (true) {
          // linkat() skips the AT_EMPTY_PATH check if the olddirfd
          // is AT_FDCWD or if the oldpath is absolute: so we use a
          // relative oldpath.
          res = syscall(SYS_linkat, AT_FDCWD, old_file_rel_path.c_str(),
                        new_dir_fd_raw, kAtFdcwdNewCredsNoCap, AT_EMPTY_PATH);
          if (res == -1 && errno == EINTR) {
            // Slow FSes like FUSE may return EINTR, unless we check if the link
            // was created by way of an fstat(), we might encounter an EEXIST if
            // we retry blindly.
            struct stat st;
            if (fstatat(new_dir_fd_raw, kAtFdcwdNewCredsNoCap, &st, 0) == 0) {
              res = 0;
              break;
            }
            continue;  // Retry on EINTR.
          }
          break;
        }
        TEST_CHECK_SUCCESS(res);
      }),
      IsPosixErrorOkAndHolds(0));
}

// Removing one name of a hard-linked file must not leave the file pinned
// under the removed name. For example, an NFS client renames a file that is
// unlinked while it has an open file description for that name to .nfsXXXX in
// the same directory, and keeps it until that file description is closed;
// meanwhile, rmdir(2) of the directory fails with ENOTEMPTY.
TEST(LinkTest, RmdirAfterUnlinkingHardLink) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir1 = JoinPath(parent.path(), "dir1");
  const std::string dir2 = JoinPath(parent.path(), "dir2");
  const std::string name1 = JoinPath(dir1, "file");
  const std::string name2 = JoinPath(dir2, "file");
  ASSERT_NO_ERRNO(Mkdir(dir1));
  ASSERT_NO_ERRNO(Mkdir(dir2));
  ASSERT_NO_ERRNO(CreateWithContents(name1, "data"));
  // Instantiate the file via name1 and read it, so that any cached host state
  // for the file was obtained via name1.
  EXPECT_THAT(GetContents(name1), IsPosixErrorOkAndHolds("data"));
  ASSERT_THAT(link(name1.c_str(), name2.c_str()), SyscallSucceeds());
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("data"));

  ASSERT_THAT(unlink(name1.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir1.c_str()), SyscallSucceeds());
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("data"));

  ASSERT_THAT(unlink(name2.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir2.c_str()), SyscallSucceeds());
}

// As above, but the removed name's dentry is evicted from the sentry's dentry
// cache before the name is removed, while the other name stays in use. The
// file's host state must not stay pinned to the evicted name.
TEST(LinkTest, RmdirAfterUnlinkingEvictedHardLink) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir1 = JoinPath(parent.path(), "dir1");
  const std::string dir2 = JoinPath(parent.path(), "dir2");
  const std::string dir3 = JoinPath(parent.path(), "dir3");
  const std::string name1 = JoinPath(dir1, "file");
  const std::string name2 = JoinPath(dir2, "file");
  ASSERT_NO_ERRNO(Mkdir(dir1));
  ASSERT_NO_ERRNO(Mkdir(dir2));
  ASSERT_NO_ERRNO(Mkdir(dir3));
  ASSERT_NO_ERRNO(CreateWithContents(name1, "data"));
  EXPECT_THAT(GetContents(name1), IsPosixErrorOkAndHolds("data"));
  ASSERT_THAT(link(name1.c_str(), name2.c_str()), SyscallSucceeds());
  // Keep name2 in use, so that only name1 can be evicted.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name2, O_RDONLY));

  // Look up more files than gofer mounts cache by default (1000), so that
  // name1 is evicted where such a cache exists.
  {
    const DisableSave ds;
    for (int i = 0; i < 1500; i++) {
      const std::string name = JoinPath(dir3, absl::StrCat(i));
      ASSERT_NO_ERRNO_AND_VALUE(Open(name, O_CREAT | O_RDONLY, 0644));
    }
  }

  ASSERT_THAT(unlink(name1.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir1.c_str()), SyscallSucceeds());
  char buf[4];
  ASSERT_THAT(PreadFd(fd.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(absl::string_view(buf, sizeof(buf)), "data");
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("data"));
}

// As above, but the file remains open via the removed name. The open file
// description must keep working, and refer to the same file as the surviving
// name.
//
// We need to disable S/R because gofer-backed filesystems restore a file that
// is open but unlinked by copying its data into a new file, which is no longer
// a link of the surviving name.
TEST(LinkTest, UnlinkHardLinkWhileOpen) {
  const DisableSave ds;
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir1 = JoinPath(parent.path(), "dir1");
  const std::string dir2 = JoinPath(parent.path(), "dir2");
  const std::string name1 = JoinPath(dir1, "file");
  const std::string name2 = JoinPath(dir2, "file");
  ASSERT_NO_ERRNO(Mkdir(dir1));
  ASSERT_NO_ERRNO(Mkdir(dir2));
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(name1, O_CREAT | O_RDWR, 0644));
  ASSERT_THAT(WriteFd(fd.get(), "data", 4), SyscallSucceedsWithValue(4));
  ASSERT_THAT(link(name1.c_str(), name2.c_str()), SyscallSucceeds());

  ASSERT_THAT(unlink(name1.c_str()), SyscallSucceeds());
  ASSERT_THAT(PwriteFd(fd.get(), "DATA", 4, 0), SyscallSucceedsWithValue(4));
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("DATA"));
  ASSERT_NO_ERRNO(SetContents(name2, "more"));
  char buf[4];
  ASSERT_THAT(PreadFd(fd.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(absl::string_view(buf, sizeof(buf)), "more");
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_nlink, 1u);

  // Removing the last name leaves the open file usable.
  ASSERT_THAT(unlink(name2.c_str()), SyscallSucceeds());
  ASSERT_THAT(PreadFd(fd.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(absl::string_view(buf, sizeof(buf)), "more");
  fd.reset();
  EXPECT_THAT(rmdir(dir1.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir2.c_str()), SyscallSucceeds());
}

// Replacing one name of a hard-linked file by rename(2) must leave the file
// reachable via its other name.
TEST(LinkTest, RenameOverHardLink) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string name1 = JoinPath(parent.path(), "file1");
  const std::string name2 = JoinPath(parent.path(), "file2");
  const std::string other = JoinPath(parent.path(), "other");
  ASSERT_NO_ERRNO(CreateWithContents(name1, "data"));
  EXPECT_THAT(GetContents(name1), IsPosixErrorOkAndHolds("data"));
  ASSERT_THAT(link(name1.c_str(), name2.c_str()), SyscallSucceeds());
  ASSERT_NO_ERRNO(CreateWithContents(other, "other"));

  ASSERT_THAT(rename(other.c_str(), name1.c_str()), SyscallSucceeds());
  EXPECT_THAT(GetContents(name1), IsPosixErrorOkAndHolds("other"));
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("data"));
}

// A synthetic file (here, a bound Unix socket) replacing one name of a
// hard-linked file by rename(2) must leave the file reachable via its other
// name, and its former directory removable.
TEST(LinkTest, RenameSocketOverHardLink) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir1 = JoinPath(parent.path(), "dir1");
  const std::string dir2 = JoinPath(parent.path(), "dir2");
  const std::string name1 = JoinPath(dir1, "file");
  const std::string name2 = JoinPath(dir2, "file");
  const std::string sock_path = JoinPath(parent.path(), "sock");
  ASSERT_NO_ERRNO(Mkdir(dir1));
  ASSERT_NO_ERRNO(Mkdir(dir2));
  ASSERT_NO_ERRNO(CreateWithContents(name1, "data"));
  EXPECT_THAT(GetContents(name1), IsPosixErrorOkAndHolds("data"));
  ASSERT_THAT(link(name1.c_str(), name2.c_str()), SyscallSucceeds());

  const int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(sock_fd, SyscallSucceeds());
  FileDescriptor sock(sock_fd);
  {
    // The test temporary directory path may be too long for sun_path, so bind
    // the socket by a name relative to parent.
    const std::string old_cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
    ASSERT_THAT(chdir(parent.path().c_str()), SyscallSucceeds());
    const auto restore_cwd = Cleanup(
        [&] { EXPECT_THAT(chdir(old_cwd.c_str()), SyscallSucceeds()); });
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "sock", sizeof(addr.sun_path) - 1);
    ASSERT_THAT(bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr),
                     sizeof(addr)),
                SyscallSucceeds());
  }

  ASSERT_THAT(rename(sock_path.c_str(), name1.c_str()), SyscallSucceeds());
  struct stat st;
  ASSERT_THAT(lstat(name1.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISSOCK(st.st_mode));
  EXPECT_THAT(GetContents(name2), IsPosixErrorOkAndHolds("data"));

  ASSERT_THAT(unlink(name1.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir1.c_str()), SyscallSucceeds());
  ASSERT_THAT(unlink(name2.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(dir2.c_str()), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
