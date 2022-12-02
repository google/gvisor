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
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <functional>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Contains;
using ::testing::Pair;

TEST(MountTest, MountBadFilesystem) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Linux expects a valid target before it checks the file system name.
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", dir.path().c_str(), "foobar", 0, ""),
              SyscallFailsWithErrno(ENODEV));
}

TEST(MountTest, MountInvalidTarget) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = NewTempAbsPath();
  EXPECT_THAT(mount("", dir.c_str(), "tmpfs", 0, ""),
              SyscallFailsWithErrno(ENOENT));
}

TEST(MountTest, MountPermDenied) {
  // Clear CAP_SYS_ADMIN.
  AutoCapability cap(CAP_SYS_ADMIN, false);

  // Linux expects a valid target before checking capability.
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", dir.path().c_str(), "", 0, ""),
              SyscallFailsWithErrno(EPERM));
}

TEST(MountTest, UmountPermDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "", 0));

  // Drop privileges in another thread, so we can still unmount the mounted
  // directory.
  ScopedThread([&]() {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_THAT(umount(dir.path().c_str()), SyscallFailsWithErrno(EPERM));
  });
}

TEST(MountTest, MountOverBusy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));

  // Should be able to mount over a busy directory.
  ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "", 0));
}

TEST(MountTest, OpenFileBusy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, "mode=0700", 0));
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));

  // An open file should prevent unmounting.
  EXPECT_THAT(umount(dir.path().c_str()), SyscallFailsWithErrno(EBUSY));
}

TEST(MountTest, UmountNoFollow) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto const mountPoint = NewTempAbsPathInDir(dir.path());
  ASSERT_THAT(mkdir(mountPoint.c_str(), 0777), SyscallSucceeds());

  // Create a symlink in dir which will point to the actual mountpoint.
  const std::string symlinkInDir = NewTempAbsPathInDir(dir.path());
  EXPECT_THAT(symlink(mountPoint.c_str(), symlinkInDir.c_str()),
              SyscallSucceeds());

  // Create a symlink to the dir.
  const std::string symlinkToDir = NewTempAbsPath();
  EXPECT_THAT(symlink(dir.path().c_str(), symlinkToDir.c_str()),
              SyscallSucceeds());

  // Should fail with ELOOP when UMOUNT_NOFOLLOW is specified and the last
  // component is a symlink.
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", mountPoint, "tmpfs", 0, "mode=0700", 0));
  EXPECT_THAT(umount2(symlinkInDir.c_str(), UMOUNT_NOFOLLOW),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(unlink(symlinkInDir.c_str()), SyscallSucceeds());

  // UMOUNT_NOFOLLOW should only apply to the last path component. A symlink in
  // non-last path component should be just fine.
  EXPECT_THAT(umount2(JoinPath(symlinkToDir, Basename(mountPoint)).c_str(),
                      UMOUNT_NOFOLLOW),
              SyscallSucceeds());
  mount.Release();
}

TEST(MountTest, UmountDetach) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // structure:
  //
  // dir (mount point)
  //   subdir
  //   file
  //
  // We show that we can walk around in the mount after detach-unmount dir.
  //
  // We show that even though dir is unreachable from outside the mount, we can
  // still reach dir's (former) parent!
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const struct stat before = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  auto mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "mode=0700",
                                      /* umountflags= */ MNT_DETACH));
  const struct stat after = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  EXPECT_FALSE(before.st_dev == after.st_dev && before.st_ino == after.st_ino)
      << "mount point has device number " << before.st_dev
      << " and inode number " << before.st_ino << " before and after mount";

  // Create files in the new mount.
  constexpr char kContents[] = "no no no";
  auto const subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  auto const file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), kContents, 0777));

  auto const dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(subdir.path(), O_RDONLY | O_DIRECTORY));
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  // Unmount the tmpfs.
  mount.Release()();

  // Inode numbers for gofer-accessed files may change across save/restore.
  //
  // For overlayfs, if xino option is not enabled and if all overlayfs layers do
  // not belong to the same filesystem then "the value of st_ino for directory
  // objects may not be persistent and could change even while the overlay
  // filesystem is mounted."  -- Documentation/filesystems/overlayfs.txt
  if (!IsRunningWithSaveRestore() &&
      !ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(dir.path()))) {
    const struct stat after2 = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
    EXPECT_EQ(before.st_ino, after2.st_ino);
  }

  // Can still read file after unmounting.
  std::vector<char> buf(sizeof(kContents));
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()), SyscallSucceeds());

  // Walk to dir.
  auto const mounted_dir = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt(dir_fd.get(), "..", O_DIRECTORY | O_RDONLY));
  // Walk to dir/file.
  auto const fd_again = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt(mounted_dir.get(), std::string(Basename(file.path())), O_RDONLY));

  std::vector<char> buf2(sizeof(kContents));
  EXPECT_THAT(ReadFd(fd_again.get(), buf2.data(), buf2.size()),
              SyscallSucceeds());
  EXPECT_EQ(buf, buf2);

  // Walking outside the unmounted realm should still work, too!
  auto const dir_parent = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt(mounted_dir.get(), "..", O_DIRECTORY | O_RDONLY));
}

TEST(MountTest, UmountMountsStackedOnDot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  // Verify that unmounting at "." properly unmounts the mount at the top of
  // mount stack.
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TEST_CHECK_SUCCESS(chdir(dir.path().c_str()));
  const struct stat before = ASSERT_NO_ERRNO_AND_VALUE(Stat("."));

  TEST_CHECK_SUCCESS(mount("", dir.path().c_str(), "tmpfs", 0, "mode=0700"));
  TEST_CHECK_SUCCESS(mount("", dir.path().c_str(), "tmpfs", 0, "mode=0700"));

  // Unmount the second mount at "."
  TEST_CHECK_SUCCESS(umount2(".", MNT_DETACH));

  // Unmount the first mount at "."; this will fail if umount does not resolve
  // "." to the topmost mount.
  TEST_CHECK_SUCCESS(umount2(".", MNT_DETACH));
  const struct stat after2 = ASSERT_NO_ERRNO_AND_VALUE(Stat("."));
  EXPECT_TRUE(before.st_dev == after2.st_dev && before.st_ino == after2.st_ino);
}

TEST(MountTest, ActiveSubmountBusy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, "mode=0700", 0));

  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), "tmpfs", 0, "", 0));

  // Since dir now has an active submount, should not be able to unmount.
  EXPECT_THAT(umount(dir.path().c_str()), SyscallFailsWithErrno(EBUSY));
}

TEST(MountTest, MountTmpfs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // NOTE(b/129868551): Inode IDs are only stable across S/R if we have an open
  // FD for that inode. Since we are going to compare inode IDs below, get a
  // FileDescriptor for this directory here, which will be closed automatically
  // at the end of the test.
  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY, O_RDONLY));

  const struct stat before = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));

  {
    auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", dir.path(), "tmpfs", 0, "mode=0700", 0));

    const struct stat s = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
    EXPECT_EQ(s.st_mode, S_IFDIR | 0700);
    EXPECT_FALSE(before.st_dev == s.st_dev && before.st_ino == s.st_ino)
        << "mount point has device number " << before.st_dev
        << " and inode number " << before.st_ino << " before and after mount";

    EXPECT_NO_ERRNO(Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));
  }

  // Now that dir is unmounted again, we should have the old inode back.
  //
  // Inode numbers for gofer-accessed files may change across save/restore.
  //
  // For overlayfs, if xino option is not enabled and if all overlayfs layers do
  // not belong to the same filesystem then "the value of st_ino for directory
  // objects may not be persistent and could change even while the overlay
  // filesystem is mounted."  -- Documentation/filesystems/overlayfs.txt
  if (!IsRunningWithSaveRestore() &&
      !ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(dir.path()))) {
    const struct stat after = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
    EXPECT_EQ(before.st_ino, after.st_ino);
  }
}

TEST(MountTest, MountTmpfsMagicValIgnored) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", MS_MGC_VAL, "mode=0700", 0));
}

// Passing nullptr to data is equivalent to "".
TEST(MountTest, NullData) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), "tmpfs", 0, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(umount2(dir.path().c_str(), 0), SyscallSucceeds());
}

TEST(MountTest, MountReadonly) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", MS_RDONLY, "mode=0777", 0));

  const struct stat s = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  EXPECT_EQ(s.st_mode, S_IFDIR | 0777);

  EXPECT_THAT(access(dir.path().c_str(), W_OK), SyscallFailsWithErrno(EROFS));

  std::string const filename = JoinPath(dir.path(), "foo");
  EXPECT_THAT(open(filename.c_str(), O_RDWR | O_CREAT, 0777),
              SyscallFailsWithErrno(EROFS));
}

PosixErrorOr<absl::Time> ATime(absl::string_view file) {
  struct stat s = {};
  if (stat(std::string(file).c_str(), &s) == -1) {
    return PosixError(errno, "stat failed");
  }
  return absl::TimeFromTimespec(s.st_atim);
}

TEST(MountTest, MountNoAtime) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", MS_NOATIME, "mode=0777", 0));

  std::string const contents = "No no no, don't follow the instructions!";
  auto const file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), contents, 0777));

  absl::Time const before = ASSERT_NO_ERRNO_AND_VALUE(ATime(file.path()));

  // Reading from the file should change the atime, but the MS_NOATIME flag
  // should prevent that.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  char buf[100];
  int read_n;
  ASSERT_THAT(read_n = read(fd.get(), buf, sizeof(buf)), SyscallSucceeds());
  EXPECT_EQ(std::string(buf, read_n), contents);

  absl::Time const after = ASSERT_NO_ERRNO_AND_VALUE(ATime(file.path()));

  // Expect that atime hasn't changed.
  EXPECT_EQ(before, after);
}

TEST(MountTest, MountNoExec) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", MS_NOEXEC, "mode=0777", 0));

  std::string const contents = "No no no, don't follow the instructions!";
  auto const file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), contents, 0777));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {}, {}, nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, EACCES);
}

TEST(MountTest, RenameRemoveMountPoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir_parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_parent.path()));
  auto const new_dir = NewTempAbsPath();

  auto const mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "", 0));

  ASSERT_THAT(rename(dir.path().c_str(), new_dir.c_str()),
              SyscallFailsWithErrno(EBUSY));

  ASSERT_THAT(rmdir(dir.path().c_str()), SyscallFailsWithErrno(EBUSY));
}

TEST(MountTest, MountInfo) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", MS_NOEXEC, "mode=0123", 0));
  const std::vector<ProcMountsEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountsEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.fstype, "tmpfs");
      auto mopts = ParseMountOptions(e.mount_opts);
      EXPECT_THAT(mopts, AnyOf(Contains(Pair("mode", "0123")),
                               Contains(Pair("mode", "123"))));
    }
  }

  const std::vector<ProcMountInfoEntry> mountinfo =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());

  for (auto const& e : mountinfo) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.fstype, "tmpfs");
      auto mopts = ParseMountOptions(e.super_opts);
      EXPECT_THAT(mopts, AnyOf(Contains(Pair("mode", "0123")),
                               Contains(Pair("mode", "123"))));
    }
  }
}

TEST(MountTest, TmpfsSizeRoundUpSinglePageSize) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize / 2);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to 1 Page Size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, kPageSize);

  // Grow to size beyond tmpfs allocated bytes.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize + 1),
              SyscallFailsWithErrno(ENOSPC));
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, kPageSize);
}

TEST(MountTest, TmpfsSizeAllocationMultiplePages) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto page_multiple = 2;
  auto size = kPageSize * page_multiple;
  auto tmpfs_size_opt = absl::StrCat("size=", size);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Ensure fallocate does not allow partial allocations.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, size + 1),
              SyscallFailsWithErrno(ENOSPC));
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to multiple of page size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, size), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, size);

  // Grow to beyond tmpfs size bytes.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, size + 1),
              SyscallFailsWithErrno(ENOSPC));
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, size);
}

TEST(MountTest, TmpfsSizeMoreThanSinglePgSZMultipleFiles) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const page_multiple = 10;
  auto const size = kPageSize * page_multiple;
  auto tmpfs_size_opt = absl::StrCat("size=", size);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  for (int i = 0; i < page_multiple; i++) {
    auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(
        JoinPath(dir.path(), absl::StrCat("foo_", i)), O_CREAT | O_RDWR, 0777));
    // Create buffer & Grow to 100 bytes.
    struct stat buf;
    ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
    ASSERT_THAT(fallocate(fd.get(), 0, 0, 100), SyscallSucceeds());
    ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
    EXPECT_EQ(buf.st_size, 100);
  }
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), absl::StrCat("foo_", page_multiple + 1)),
           O_CREAT | O_RDWR, 0777));
  // Grow to beyond tmpfs size bytes after exhausting the size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize),
              SyscallFailsWithErrno(ENOSPC));
}

TEST(MountTest, TmpfsSizeFtruncate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
  struct stat status;
  ASSERT_THAT(fstat(fd.get(), &status), SyscallSucceeds());
  EXPECT_EQ(status.st_size, kPageSize);

  ASSERT_THAT(ftruncate(fd.get(), kPageSize + 1), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &status), SyscallSucceeds());
  EXPECT_EQ(status.st_size, kPageSize + 1);

  ASSERT_THAT(ftruncate(fd.get(), 0), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &status), SyscallSucceeds());
  EXPECT_EQ(status.st_size, 0);

  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &status), SyscallSucceeds());
  EXPECT_EQ(status.st_size, kPageSize);
}

// Test shows directory does not take up any pages.
TEST(MountTest, TmpfsDirectoryAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir_parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir_parent.path(), "tmpfs", 0, tmpfs_size_opt, 0));

  auto const dir_tmp =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_parent.path()));

  // Creating only 1 regular file allocates 1 page size.
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir_parent.path(), "foo"), O_CREAT | O_RDWR, 0777));

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to 1 Page Size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, kPageSize);

  // Grow to beyond 1 Page Size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize + 1),
              SyscallFailsWithErrno(ENOSPC));
}

// Tests memory allocation for symlinks.
TEST(MountTest, TmpfsSymlinkAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir_parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir_parent.path(), "tmpfs", 0, tmpfs_size_opt, 0));

  const int target_size = 128;
  auto target = std::string(target_size - 1, 'a');
  auto pathname = JoinPath(dir_parent.path(), "foo1");
  EXPECT_THAT(symlink(target.c_str(), pathname.c_str()), SyscallSucceeds());

  target = std::string(target_size, 'a');
  pathname = absl::StrCat(dir_parent.path(), "/foo2");
  EXPECT_THAT(symlink(target.c_str(), pathname.c_str()), SyscallSucceeds());

  target = std::string(target_size, 'a');
  pathname = absl::StrCat(dir_parent.path(), "/foo3");
  EXPECT_THAT(symlink(target.c_str(), pathname.c_str()),
              SyscallFailsWithErrno(ENOSPC));

  target = std::string(target_size - 1, 'a');
  pathname = absl::StrCat(dir_parent.path(), "/foo4");
  EXPECT_THAT(symlink(target.c_str(), pathname.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(pathname.c_str()), SyscallSucceeds());
}

// Tests memory unallocation for symlinks.
TEST(MountTest, TmpfsSymlinkUnallocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir_parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir_parent.path(), "tmpfs", 0, tmpfs_size_opt, 0));

  const int target_size = 128;
  auto pathname = JoinPath(dir_parent.path(), "foo1");
  auto target = std::string(target_size, 'a');
  EXPECT_THAT(symlink(target.c_str(), pathname.c_str()), SyscallSucceeds());
  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(pathname, O_CREAT | O_RDWR, 0777));
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize),
              SyscallFailsWithErrno(ENOSPC));
  EXPECT_THAT(unlink(pathname.c_str()), SyscallSucceeds());
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
}

// Tests memory allocation for Hard Links is not double allocated.
TEST(MountTest, TmpfsHardLinkAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  const std::string fileOne = JoinPath(dir.path(), "foo1");
  const std::string fileTwo = JoinPath(dir.path(), "foo2");
  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(fileOne, O_CREAT | O_RDWR, 0777));
  EXPECT_THAT(link(fileOne.c_str(), fileTwo.c_str()), SyscallSucceeds());

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to 1 Page Size.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, kPageSize);

  // Grow to size beyond tmpfs allocated bytes.
  ASSERT_THAT(fallocate(fd.get(), 0, 0, kPageSize + 1),
              SyscallFailsWithErrno(ENOSPC));
  ASSERT_THAT(fstat(fd.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, kPageSize);
  EXPECT_THAT(unlink(fileTwo.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(fileOne.c_str()), SyscallSucceeds());
}

// Tests memory allocation for empty size.
TEST(MountTest, TmpfsEmptySizeAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir.path().c_str(), "tmpfs", 0, "size"),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, TmpfsUnlinkRegularFileAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  const int kTruncateSize = 2 * kPageSize;
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  const std::string fileOne = JoinPath(dir.path(), "foo1");
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fileOne, O_CREAT | O_RDWR, 0777));
  EXPECT_THAT(unlink(fileOne.c_str()), SyscallSucceeds());
  EXPECT_THAT(ftruncate(fd.get(), kTruncateSize), SyscallSucceeds());
}

TEST(MountTest, TmpfsSizePartialWriteSinglePage) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));

  const std::string fileOne = JoinPath(dir.path(), "foo1");
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fileOne, O_CREAT | O_RDWR, 0777));
  lseek(fd.get(), kPageSize - 2, SEEK_SET);
  char buf[4];
  EXPECT_THAT(write(fd.get(), buf, 4), SyscallSucceedsWithValue(2));
  EXPECT_THAT(write(fd.get(), buf, 4), SyscallFailsWithErrno(ENOSPC));
}

TEST(MountTest, TmpfsSizePartialWriteMultiplePages) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", 3 * kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));

  const std::string fileOne = JoinPath(dir.path(), "foo1");
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fileOne, O_CREAT | O_RDWR, 0777));
  lseek(fd.get(), kPageSize, SEEK_SET);
  std::vector<char> buf(kPageSize + 2);
  EXPECT_THAT(write(fd.get(), buf.data(), 4), SyscallSucceedsWithValue(4));
  struct stat status;
  ASSERT_THAT(fstat(fd.get(), &status), SyscallSucceeds());
  EXPECT_EQ(status.st_size, kPageSize + 4);
  EXPECT_THAT(write(fd.get(), buf.data(), 1), SyscallSucceedsWithValue(1));

  // Writing with size exactly until the end of page boundary.
  EXPECT_THAT(write(fd.get(), buf.data(), kPageSize - 5),
              SyscallSucceedsWithValue(kPageSize - 5));

  EXPECT_THAT(write(fd.get(), buf.data(), 1), SyscallSucceedsWithValue(1));
  // Writing with size more than page end & having extra page available as well.
  EXPECT_THAT(write(fd.get(), buf.data(), kPageSize + 1),
              SyscallSucceedsWithValue(kPageSize + 1));

  // Writing with size more than page end & having no page available.
  EXPECT_THAT(write(fd.get(), buf.data(), kPageSize + 1),
              SyscallSucceedsWithValue(kPageSize - 2));
  EXPECT_THAT(write(fd.get(), buf.data(), 1), SyscallFailsWithErrno(ENOSPC));
}

TEST(MountTest, TmpfsSizeMmap) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, tmpfs_size_opt, 0));
  const std::string fileOne = JoinPath(dir.path(), "foo");
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fileOne, O_CREAT | O_RDWR, 0777));
  EXPECT_THAT(ftruncate(fd.get(), 2 * kPageSize), SyscallSucceeds());
  void* addr = mmap(NULL, 2 * kPageSize, PROT_READ, MAP_PRIVATE, fd.get(), 0);
  EXPECT_NE(addr, MAP_FAILED);
  // Access memory so that the first page to page fault occurs and is allocated.
  char data = ((char*)addr)[kPageSize - 2];
  EXPECT_EQ(data, 0);
  std::vector<char> in(kPageSize + 2);
  // Access memory such that it causes the second page to page fault. The page
  // fault should fail due to hitting tmpfs size limit which should cause
  // SIGBUS signal.
  EXPECT_EXIT(memcpy(in.data(), reinterpret_cast<char*>(addr), kPageSize + 2),
              ::testing::KilledBySignal(SIGBUS), "");
  EXPECT_THAT(munmap(addr, 2 * kPageSize), SyscallSucceeds());
}

TEST(MountTest, SimpleBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path(), "tmpfs", 0, "mode=0123", 0));
  auto const child1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const child2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const bind_mount = Mount(dir1.path(), dir2.path(), "", MS_BIND, "", 0);

  // Write to child1 in dir1.
  const std::string filename = "foo.txt";
  const std::string contents = "barbaz";
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(child1.path(), filename),
                                     contents, O_WRONLY));
  // Verify both directories have the same nodes.
  std::vector<std::string> child_names = {std::string(Basename(child1.path())),
                                          std::string(Basename(child2.path()))};
  ASSERT_NO_ERRNO(DirContains(dir1.path(), child_names, {}));
  ASSERT_NO_ERRNO(DirContains(dir2.path(), child_names, {}));

  const std::string dir1_filepath =
      JoinPath(dir1.path(), Basename(child1.path()), filename);
  const std::string dir2_filepath =
      JoinPath(dir2.path(), Basename(child1.path()), filename);

  std::string output;
  ASSERT_NO_ERRNO(GetContents(dir1_filepath, &output));
  ASSERT_EQ(output, contents);
  ASSERT_NO_ERRNO(GetContents(dir2_filepath, &output));
  ASSERT_EQ(output, contents);
}

TEST(MountTest, BindToSelf) {
  // Test that we can turn a normal directory into a mount with MS_BIND.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const std::vector<ProcMountsEntry> mounts_before =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountsEntries());
  for (const auto& e : mounts_before) {
    ASSERT_NE(e.mount_point, dir.path());
  }

  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir.path(), dir.path(), "", MS_BIND, "", 0));

  const std::vector<ProcMountsEntry> mounts_after =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountsEntries());
  bool found = false;
  for (const auto& e : mounts_after) {
    if (e.mount_point == dir.path()) {
      found = true;
    }
  }
  ASSERT_TRUE(found);
}

TEST(MountTest, MaxMounts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", parent.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto const dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  ASSERT_THAT(
      mount(dir.path().c_str(), dir.path().c_str(), nullptr, MS_BIND, nullptr),
      SyscallSucceeds());
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, ""),
              SyscallSucceeds());

  // Each bind mount doubles the number of mounts in the peer group. The number
  // of binds we can do before failing is log2(max_mounts-num_current_mounts).
  int mount_max = 10000;
  bool mount_max_exists =
      ASSERT_NO_ERRNO_AND_VALUE(Exists("/proc/sys/fs/mount-max"));
  if (mount_max_exists) {
    std::string mount_max_string;
    ASSERT_NO_ERRNO(GetContents("/proc/sys/fs/mount-max", &mount_max_string));
    ASSERT_TRUE(absl::SimpleAtoi(mount_max_string, &mount_max));
  }

  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  int num_binds = static_cast<int>(std::log2(mount_max - mounts.size()));

  for (int i = 0; i < num_binds; i++) {
    ASSERT_THAT(mount(dir.path().c_str(), dir.path().c_str(), nullptr, MS_BIND,
                      nullptr),
                SyscallSucceeds());
  }
  ASSERT_THAT(
      mount(dir.path().c_str(), dir.path().c_str(), nullptr, MS_BIND, nullptr),
      SyscallFailsWithErrno(ENOSPC));
  umount2(parent.path().c_str(), MNT_DETACH);
}

// Tests that it is possible to make a shared mount.
TEST(MountTest, MakeShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      break;
    }
  }
}

// Tests that shared mounts have different group IDs.
TEST(MountTest, MakeMultipleShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  std::string optional1, optional2;
  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir1.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      optional1 = e.optional;
    } else if (e.mount_point == dir2.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      optional2 = e.optional;
    }
  }
  EXPECT_NE(optional1, optional2);
}

// Tests that shared mounts reused group IDs from deleted groups.
TEST(MountTest, ReuseGroupIDs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string reused_optional;
  {
    auto const mount2 =
        ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), "tmpfs", 0, "", 0));
    ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
                SyscallSucceeds());

    const std::vector<ProcMountInfoEntry> mounts =
        ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
    for (const auto& e : mounts) {
      if (e.mount_point == dir2.path()) {
        EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
        reused_optional = e.optional;
      }
    }
  }

  // Check that created a new shared mount reuses the ID 2.
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir2.path()) {
      EXPECT_EQ(e.optional, reused_optional);
      break;
    }
  }
}

// Tests that a child mount inherits the propagation type of its parent.
TEST(MountTest, InerheritPropagation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), "tmpfs", 0, "", 0));

  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir2.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      break;
    }
  }
}

// Tests that it is possible to make a mount private again after it is shared.
TEST(MountTest, MakePrivate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_PRIVATE, 0),
              SyscallSucceeds());

  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.optional, "");
      break;
    }
  }
}

TEST(MountTest, ArgumentsAreIgnored) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // These mounts should not fail even though string arguments are passed as
  // NULL.
  ASSERT_THAT(
      mount(dir.path().c_str(), dir.path().c_str(), NULL, MS_BIND, NULL),
      SyscallSucceeds());
  ASSERT_THAT(mount(NULL, dir.path().c_str(), NULL, MS_SHARED, NULL),
              SyscallSucceeds());
  const std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      break;
    }
  }
}

TEST(MountTest, MultiplePropagationFlagsFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "tmpfs", 0, "", 0));
  EXPECT_THAT(mount("", dir.path().c_str(), "", MS_SHARED | MS_PRIVATE, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, SetMountPropagationOfStackedMounts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), "tmpfs", 0, "", 0));

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  int parent_mount_id;
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      parent_mount_id = e.id;
    }
  }
  // Only the topmost mount on the stack should be shared.
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  mounts = ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path() && e.id != parent_mount_id) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
    }
    if (e.mount_point == dir.path() && e.id == parent_mount_id) {
      EXPECT_EQ(e.optional, "");
    }
  }
}

TEST(MountTest, MakePeer) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), "tmpfs", 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  std::string optional1, optional2;
  for (const auto& e : mounts) {
    if (e.mount_point == dir1.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      optional1 = e.optional;
    }
    if (e.mount_point == dir2.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      optional2 = e.optional;
    }
  }
  ASSERT_EQ(optional1, optional2);
}

TEST(MountTest, PropagateMountEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), "tmpfs", 0, "", 0));
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  // This mount should propagate to dir2.
  auto const child_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", child_dir.path().c_str(), "tmpfs", 0, "", 0));

  const std::string child_path1 =
      JoinPath(dir1.path(), Basename(child_dir.path()));
  const std::string child_path2 =
      JoinPath(dir2.path(), Basename(child_dir.path()));

  std::string child_opt1, child_opt2, parent_optional;
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == child_path1) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      child_opt1 = e.optional;
    }
    if (e.mount_point == child_path2) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      child_opt2 = e.optional;
    }
    if (e.mount_point == dir1.path() || e.mount_point == dir2.path()) {
      EXPECT_TRUE(absl::StrContains(e.optional, "shared:"));
      parent_optional = e.optional;
    }
  }
  // Should be in the same peer group.
  ASSERT_EQ(child_opt1, child_opt2);
  ASSERT_NE(child_opt1, parent_optional);
}

TEST(MountTest, PropagateUmountEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), "tmpfs", 0, "", 0));
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  // This mount will propagate to dir2. Once the block ends it will be
  // unmounted, which should also propagate to dir2.
  {
    auto const child_mnt = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", child_dir.path().c_str(), "tmpfs", 0, "", 0));
  }

  const std::string child_path1 =
      JoinPath(dir1.path(), Basename(child_dir.path()));
  const std::string child_path2 =
      JoinPath(dir2.path(), Basename(child_dir.path()));

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    ASSERT_NE(e.mount_point, child_path1);
    ASSERT_NE(e.mount_point, child_path2);
  }
}

TEST(MountTest, UmountIgnoresPeersWithChildren) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir1.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", child_dir.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto const grandchild_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(child_dir.path()));
  ASSERT_THAT(mount("", grandchild_dir.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());

  const std::string child_path1 =
      JoinPath(dir1.path(), Basename(child_dir.path()));
  const std::string child_path2 =
      JoinPath(dir2.path(), Basename(child_dir.path()));
  ASSERT_THAT(mount("", child_path2.c_str(), "", MS_PRIVATE, 0),
              SyscallSucceeds());
  const std::string grandchild_path2 =
      JoinPath(child_path2, Basename(grandchild_dir.path()));
  ASSERT_THAT(umount2(grandchild_path2.c_str(), MNT_DETACH), SyscallSucceeds());

  // This umount event should not propagate to the peer at dir1 because its
  // child mount still has its own child mount.
  ASSERT_THAT(umount2(child_path2.c_str(), MNT_DETACH), SyscallSucceeds());
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  bool found = false;
  for (const auto& e : mounts) {
    ASSERT_NE(e.mount_point, child_path2);
    if (e.mount_point == child_path1) {
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
}

TEST(MountTest, BindSharedOnShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir4 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // Dir 1 and 2 are part of peer group 'A', dir 3 and 4 are part of peer group
  // 'B'.
  ASSERT_THAT(mount("", dir1.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto const dir5 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir3.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir3.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount(dir3.path().c_str(), dir4.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  const std::string dir5_path2 = JoinPath(dir2.path(), Basename(dir5.path()));

  // Bind peer group 'A' to peer group 'B'.
  ASSERT_THAT(mount(dir4.path().c_str(), dir5.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  // The new mounts should all be peers with the old ones.
  // Optional string should be in the format shared:x.

  std::string opt1, opt2, opt3, opt4;
  for (const auto& e : mounts) {
    if (e.mount_point == dir3.path()) {
      opt1 = e.optional;
    }
    if (e.mount_point == dir4.path()) {
      opt2 = e.optional;
    }
    if (e.mount_point == dir5.path()) {
      opt3 = e.optional;
    }
    if (e.mount_point == dir5_path2) {
      opt4 = e.optional;
    }
  }
  ASSERT_EQ(opt1, opt2);
  ASSERT_EQ(opt2, opt3);
  ASSERT_EQ(opt3, opt4);
  ASSERT_TRUE(absl::StrContains(opt1, "shared:"));
}

TEST(MountTest, BindSharedOnPrivate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir1.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir4 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir3.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir3.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount(dir3.path().c_str(), dir4.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  // bind to private mount.
  ASSERT_THAT(mount(dir3.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  std::string opt1, opt2, opt3;
  for (const auto& e : mounts) {
    if (e.mount_point == dir1.path()) {
      ASSERT_EQ(e.optional, "");
    }
    if (e.mount_point == dir2.path()) {
      opt1 = e.optional;
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
    }
    if (e.mount_point == dir3.path()) {
      opt2 = e.optional;
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
    }
    if (e.mount_point == dir4.path()) {
      opt3 = e.optional;
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
    }
  }
  ASSERT_EQ(opt1, opt2);
  ASSERT_EQ(opt2, opt3);
}

TEST(MountTest, BindPeerGroupsWithChildren) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir1.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir2.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  // dir3 and dir4 are child mounts of dir1.
  auto const dir3 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir3.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto const dir4 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir4.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  const std::string dir3_path2 = JoinPath(dir2.path(), Basename(dir3.path()));
  const std::string dir4_path2 = JoinPath(dir2.path(), Basename(dir4.path()));

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  std::string opt1, opt2, opt3;
  for (const auto& e : mounts) {
    if (e.mount_point == dir1.path()) {
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
      opt1 = e.optional;
    }
    if (e.mount_point == dir3.path()) {
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
      opt2 = e.optional;
    }
    if (e.mount_point == dir4.path()) {
      ASSERT_TRUE(absl::StrContains(e.optional, "shared:"));
      opt3 = e.optional;
    }
    ASSERT_NE(e.mount_point, dir3_path2);
    ASSERT_NE(e.mount_point, dir4_path2);
  }
  ASSERT_NE(opt1, opt2);
  ASSERT_NE(opt2, opt3);
  ASSERT_NE(opt3, opt1);
}

TEST(MountTest, BindParentToChild) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, ""),
              SyscallSucceeds());
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(
      mount(dir1.path().c_str(), child_dir.path().c_str(), "", MS_BIND, ""),
      SyscallSucceeds());

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  std::string opt1, opt2, opt3;
  for (const auto& e : mounts) {
    if (e.mount_point == dir1.path()) {
      opt1 = e.optional;
    }
    if (e.mount_point == dir2.path()) {
      opt2 = e.optional;
    }
    if (e.mount_point == child_dir.path()) {
      opt3 = e.optional;
    }
  }
  ASSERT_TRUE(absl::StrContains(opt1, "shared:"));
  ASSERT_EQ(opt1, opt2);
  ASSERT_EQ(opt2, opt3);
}

TEST(MountTest, MountInfoHasRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", parent.path(), "tmpfs", 0, "mode=0123", 0));
  auto const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  auto const bind_mount = Mount(child.path(), child.path(), "", MS_BIND, "", 0);
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == child.path()) {
      ASSERT_EQ(e.root, JoinPath("/", Basename(child.path())));
    }
    if (e.mount_point == parent.path()) {
      ASSERT_EQ(e.root, "/");
    }
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
