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
#include <linux/magic.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
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
#include "absl/container/flat_hash_map.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
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

constexpr char kTmpfs[] = "tmpfs";

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
  EXPECT_THAT(mount("", dir.c_str(), kTmpfs, 0, ""),
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
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));

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
  ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));
}

TEST(MountTest, OpenFileBusy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "mode=0700", 0));
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
      Mount("", mountPoint, kTmpfs, 0, "mode=0700", 0));
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
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "mode=0700",
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

TEST(MountTest, MMapWithExecProtFailsOnNoExecFile) {
  // Skips the test if test does not have needed capability to create the volume
  // mount.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto ret = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_NOEXEC, "", 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "random1", 0777));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDWR));
  ASSERT_THAT(reinterpret_cast<uintptr_t>(
                  mmap(0, kPageSize, PROT_EXEC, MAP_PRIVATE, fd.get(), 0)),
              SyscallFailsWithErrno(EPERM));
}

TEST(MountTest, MMapWithExecProtSucceedsOnExecutableVolumeFile) {
  // Capability is needed to create tmpfs.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto ret = ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "random1", 0777));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDWR));

  void* address = mmap(0, kPageSize, PROT_EXEC, MAP_PRIVATE, fd.get(), 0);
  EXPECT_NE(address, MAP_FAILED);

  MunmapSafe(address, kPageSize);
}

TEST(MountTest, MMapWithoutNoExecProtSucceedsOnNoExecFile) {
  // Capability is needed to create tmpfs.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto ret = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_NOEXEC, "", 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "random1", 0777));
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDWR));

  void* address =
      mmap(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0);
  EXPECT_NE(address, MAP_FAILED);

  MunmapSafe(address, kPageSize);
}

TEST(MountTest, MProtectWithNoExecProtFailsOnNoExecFile) {
  // Capability is needed to create tmpfs.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto ret = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_NOEXEC, "", 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "random1", 0777));
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDWR));

  void* address =
      mmap(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0);
  EXPECT_NE(address, MAP_FAILED);

  ASSERT_THAT(mprotect(address, kPageSize, PROT_EXEC),
              SyscallFailsWithErrno(EACCES));

  MunmapSafe(address, kPageSize);
}

TEST(MountTest, UmountMountsStackedOnDot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  // Verify that unmounting at "." properly unmounts the mount at the top of
  // mount stack.
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TEST_CHECK_SUCCESS(chdir(dir.path().c_str()));
  const struct stat before = ASSERT_NO_ERRNO_AND_VALUE(Stat("."));

  TEST_CHECK_SUCCESS(mount("", dir.path().c_str(), kTmpfs, 0, "mode=0700"));
  TEST_CHECK_SUCCESS(mount("", dir.path().c_str(), kTmpfs, 0, "mode=0700"));

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
      Mount("", dir.path(), kTmpfs, 0, "mode=0700", 0));

  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), kTmpfs, 0, "", 0));

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
        Mount("", dir.path(), kTmpfs, 0, "mode=0700", 0));

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
      Mount("", dir.path(), kTmpfs, MS_MGC_VAL, "mode=0700", 0));
}

// Passing nullptr to data is equivalent to "".
TEST(MountTest, NullData) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), kTmpfs, 0, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(umount2(dir.path().c_str(), 0), SyscallSucceeds());
}

TEST(MountTest, MountReadonly) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_RDONLY, "mode=0777", 0));

  const struct stat s = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  EXPECT_EQ(s.st_mode, S_IFDIR | 0777);

  EXPECT_THAT(access(dir.path().c_str(), W_OK), SyscallFailsWithErrno(EROFS));

  std::string const filename = JoinPath(dir.path(), "foo");
  EXPECT_THAT(open(filename.c_str(), O_RDWR | O_CREAT, 0777),
              SyscallFailsWithErrno(EROFS));
}

TEST(MountTest, BindMountReadonly) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const bindDir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir.path(), bindDir.path(), "", MS_BIND, "", 0));

  std::string const filename = JoinPath(bindDir.path(), "foo");
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_RDWR | O_CREAT, 0644));
  char msg[] = "hello world";
  EXPECT_THAT(pwrite64(fd.get(), msg, strlen(msg), 0),
              SyscallSucceedsWithValue(strlen(msg)));
  fd.reset();
  EXPECT_THAT(mount(dir.path().c_str(), bindDir.path().c_str(), NULL,
                    MS_BIND | MS_RDONLY | MS_REMOUNT, NULL),
              SyscallSucceeds());

  EXPECT_THAT(access(bindDir.path().c_str(), W_OK),
              SyscallFailsWithErrno(EROFS));

  EXPECT_THAT(open(filename.c_str(), O_RDWR), SyscallFailsWithErrno(EROFS));
  EXPECT_THAT(open(filename.c_str(), O_RDWR | O_TRUNC),
              SyscallFailsWithErrno(EROFS));
  EXPECT_THAT(open(filename.c_str(), O_RDONLY | O_TRUNC),
              SyscallFailsWithErrno(EROFS));
  const struct stat s = ASSERT_NO_ERRNO_AND_VALUE(Stat(filename));
  EXPECT_EQ(s.st_size, strlen(msg));
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
      Mount("", dir.path(), kTmpfs, MS_NOATIME, "mode=0777", 0));

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

TEST(MountTest, MountWithStrictAtime) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      "", dir.path(), kTmpfs, MS_NOATIME | MS_STRICTATIME, "mode=0777", 0));

  std::string const contents = "No no no, don't follow the instructions!";
  auto const file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), contents, 0777));

  absl::Time const before = ASSERT_NO_ERRNO_AND_VALUE(ATime(file.path()));

  absl::SleepFor(absl::Milliseconds(100));

  // MS_STRICTATIME should override MS_NOATIME and update the file's atime.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  char buf[100];
  int read_n;
  ASSERT_THAT(read_n = read(fd.get(), buf, sizeof(buf)), SyscallSucceeds());
  EXPECT_EQ(std::string(buf, read_n), contents);

  absl::Time const after = ASSERT_NO_ERRNO_AND_VALUE(ATime(file.path()));

  // The after atime is expected to be larger than the before atime.
  EXPECT_LT(before, after);
}

TEST(MountTest, MountNoExec) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_NOEXEC, "mode=0777", 0));

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
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));

  ASSERT_THAT(rename(dir.path().c_str(), new_dir.c_str()),
              SyscallFailsWithErrno(EBUSY));

  ASSERT_THAT(rmdir(dir.path().c_str()), SyscallFailsWithErrno(EBUSY));
}

TEST(MountTest, MountInfo) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, MS_NOEXEC, "mode=0123", 0));
  const std::vector<ProcMountsEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountsEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.fstype, kTmpfs);
      auto mopts = ParseMountOptions(e.mount_opts);
      EXPECT_THAT(mopts, AnyOf(Contains(Pair("mode", "0123")),
                               Contains(Pair("mode", "123"))));
    }
  }

  const std::vector<ProcMountInfoEntry> mountinfo =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());

  for (auto const& e : mountinfo) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.fstype, kTmpfs);
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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir_parent.path(), kTmpfs, 0, tmpfs_size_opt, 0));

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
      Mount("", dir_parent.path(), kTmpfs, 0, tmpfs_size_opt, 0));

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
      Mount("", dir_parent.path(), kTmpfs, 0, tmpfs_size_opt, 0));

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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
  ASSERT_THAT(mount("", dir.path().c_str(), kTmpfs, 0, "size"),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, TmpfsUnlinkRegularFileAllocCheck) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto tmpfs_size_opt = absl::StrCat("size=", kPageSize);
  const int kTruncateSize = 2 * kPageSize;
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));

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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));

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
      Mount("", dir.path(), kTmpfs, 0, tmpfs_size_opt, 0));
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
      Mount("", dir1.path(), kTmpfs, 0, "mode=0123", 0));
  auto const child1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const child2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const bind_mount = Mount(dir1.path(), dir2.path(), "", MS_BIND, "", 0);

  // Write to child1 in dir1.
  const std::string filename = "foo.txt";
  const std::string contents = "barbaz";
  ASSERT_NO_ERRNO(
      CreateWithContents(JoinPath(child1.path(), filename), contents, 0666));
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
  EXPECT_EQ(output, contents);
  ASSERT_NO_ERRNO(GetContents(dir2_filepath, &output));
  EXPECT_EQ(output, contents);
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
  ASSERT_THAT(mount("", parent.path().c_str(), kTmpfs, 0, ""),
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

TEST(MountTest, PropagateToSameMountpointStacksMounts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir.path().c_str(), dir.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  ASSERT_THAT(mount(child.path().c_str(), child.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  std::string dir2_child_path = JoinPath(dir2.path(), Basename(child.path()));
  ASSERT_THAT(
      mount(dir2_child_path.c_str(), dir2_child_path.c_str(), "", MS_BIND, 0),
      SyscallSucceeds());

  // Check that mounts at the child mount point have distinct parents.
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  uint64_t parent_id = 0;
  for (auto& minfo : mounts) {
    if (minfo.mount_point == child.path()) {
      if (parent_id == 0) {
        parent_id = minfo.parent_id;
      } else {
        EXPECT_NE(parent_id, minfo.parent_id);
      }
    }
  }
}

TEST(MountTest, UmountReparentsCoveredMounts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  ASSERT_THAT(mount("", child.path().c_str(), kTmpfs, 0, 0), SyscallSucceeds());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  std::string dir2_child_path = JoinPath(dir2.path(), Basename(child.path()));
  ASSERT_THAT(mount("", dir2_child_path.c_str(), kTmpfs, 0, 0),
              SyscallSucceeds());

  umount2(dir2_child_path.c_str(), MNT_DETACH);

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[child.path()].empty());
  EXPECT_NE(optionals[child.path()][0].shared, 0);
  EXPECT_TRUE(optionals[dir2_child_path].empty());
}

// Tests that it is possible to make a shared mount.
TEST(MountTest, MakeShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir.path()].empty());
  EXPECT_NE(optionals[dir.path()][0].shared, 0);
}

// Tests that shared mounts have different group IDs.
TEST(MountTest, MakeMultipleShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  EXPECT_NE(optionals[dir1.path()][0].shared, optionals[dir2.path()][0].shared);
}

// Tests that shared mounts reused group IDs from deleted groups.
TEST(MountTest, ReuseGroupIDs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int reused_group_id;
  {
    auto const mount2 =
        ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), kTmpfs, 0, "", 0));
    ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
                SyscallSucceeds());
    auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
    ASSERT_FALSE(optionals[dir2.path()].empty());
    reused_group_id = optionals[dir2.path()][0].shared;
  }

  // Check that created a new shared mount reuses the ID 2.
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  EXPECT_EQ(reused_group_id, optionals[dir2.path()][0].shared);
}

// Tests that a child mount inherits the propagation type of its parent.
TEST(MountTest, InerheritPropagation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount1 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir1.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const mount2 =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir2.path(), kTmpfs, 0, "", 0));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  EXPECT_NE(optionals[dir2.path()][0].shared, 0);
}

// Tests that it is possible to make a mount private again after it is shared.
TEST(MountTest, MakePrivate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_PRIVATE, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir.path()].empty());
  EXPECT_EQ(optionals[dir.path()][0].shared, 0);
}

TEST(MountTest, ArgumentsAreIgnored) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // These mounts should not fail even though string arguments are passed as
  // NULL.
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir.path(), dir.path(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount(NULL, dir.path().c_str(), NULL, MS_SHARED, NULL),
              SyscallSucceeds());
  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir.path()].empty());
  EXPECT_NE(optionals[dir.path()][0].shared, 0);
}

TEST(MountTest, MultiplePropagationFlagsFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));
  EXPECT_THAT(mount("", dir.path().c_str(), "", MS_SHARED | MS_PRIVATE, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, SetMountPropagationOfStackedMounts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), kTmpfs, 0, "", 0));
  // Only the topmost mount on the stack should be shared.
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path().c_str(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir.path()].empty());
  EXPECT_EQ(optionals[dir.path()][0].shared, 0);
  EXPECT_NE(optionals[dir.path()][1].shared, 0);
}

TEST(MountTest, MakePeer) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", 0));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir1.path(), dir2.path(), "", MS_BIND, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  EXPECT_EQ(optionals[dir1.path()][0].shared, optionals[dir2.path()][0].shared);
  EXPECT_NE(optionals[dir1.path()][0].shared, 0);
}

TEST(MountTest, PropagateMountEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir1.path(), dir2.path(), "", MS_BIND, "", MNT_DETACH));
  // This mount should propagate to dir2.
  auto const child_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", child_dir.path().c_str(), kTmpfs, 0, "", MNT_DETACH));

  const std::string child_path1 =
      JoinPath(dir1.path(), Basename(child_dir.path()));
  const std::string child_path2 =
      JoinPath(dir2.path(), Basename(child_dir.path()));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  ASSERT_FALSE(optionals[child_path1].empty());
  ASSERT_FALSE(optionals[child_path2].empty());
  EXPECT_EQ(optionals[dir1.path()][0].shared, optionals[dir2.path()][0].shared);
  EXPECT_NE(optionals[dir1.path()][0].shared, 0);
  EXPECT_EQ(optionals[child_path1][0].shared, optionals[child_path2][0].shared);
  EXPECT_NE(optionals[child_path1][0].shared, 0);
}

TEST(MountTest, PropagateUmountEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir1.path(), dir2.path(), "", MS_BIND, "", MNT_DETACH));
  // This mount will propagate to dir2. Once the block ends it will be
  // unmounted, which should also propagate to dir2.
  {
    auto const child_mnt = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", child_dir.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  }

  const std::string child_path1 =
      JoinPath(dir1.path(), Basename(child_dir.path()));
  const std::string child_path2 =
      JoinPath(dir2.path(), Basename(child_dir.path()));

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    EXPECT_NE(e.mount_point, child_path1);
    EXPECT_NE(e.mount_point, child_path2);
  }
}

TEST(MountTest, PropagateChildUmountEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  TempPath const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir1.path().c_str(), kTmpfs, 0, ""), SyscallSucceeds());

  TempPath const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", child.path().c_str(), kTmpfs, 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(mount("", child.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());

  TempPath const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(child.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());
  ASSERT_THAT(mount("", child.path().c_str(), kTmpfs, 0, ""),
              SyscallSucceeds());
  ASSERT_THAT(umount2(dir1.path().c_str(), MNT_DETACH), SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  EXPECT_EQ(optionals[dir2.path()].size(), 1);

  ASSERT_EQ(umount2(dir2.path().c_str(), MNT_DETACH), 0);
}

TEST(MountTest, UmountIgnoresPeersWithChildren) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", dir1.path().c_str(), kTmpfs, 0, ""), SyscallSucceeds());
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, 0),
              SyscallSucceeds());

  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", child_dir.path().c_str(), kTmpfs, 0, ""),
              SyscallSucceeds());
  auto const grandchild_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(child_dir.path()));
  ASSERT_THAT(mount("", grandchild_dir.path().c_str(), kTmpfs, 0, ""),
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
  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  EXPECT_EQ(optionals[child_path2].size(), 0);
  EXPECT_EQ(optionals[child_path1].size(), 1);

  ASSERT_THAT(umount2(dir1.path().c_str(), MNT_DETACH), SyscallSucceeds());
  ASSERT_THAT(umount2(dir2.path().c_str(), MNT_DETACH), SyscallSucceeds());
}

TEST(MountTest, BindSharedOnShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir4 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // Dir 1 and 2 are part of peer group 'A', dir 3 and 4 are part of peer group
  // 'B'.
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const dir5 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const mnt3 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir3.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir3.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const mnt4 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir3.path().c_str(), dir4.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  const std::string dir5_path2 = JoinPath(dir2.path(), Basename(dir5.path()));

  // Bind peer group 'A' to peer group 'B'.
  auto const mnt5 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir4.path().c_str(), dir5.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  ASSERT_FALSE(optionals[dir3.path()].empty());
  ASSERT_FALSE(optionals[dir4.path()].empty());
  ASSERT_FALSE(optionals[dir5.path()].empty());
  ASSERT_FALSE(optionals[dir5_path2].empty());
  EXPECT_EQ(optionals[dir3.path()][0].shared, optionals[dir4.path()][0].shared);
  EXPECT_EQ(optionals[dir4.path()][0].shared, optionals[dir5.path()][0].shared);
  EXPECT_EQ(optionals[dir5.path()][0].shared, optionals[dir5_path2][0].shared);
  EXPECT_NE(optionals[dir3.path()][0].shared, 0);
}

TEST(MountTest, BindSharedOnPrivate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir4 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt3 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir3.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir3.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const mnt4 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir3.path().c_str(), dir4.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  // bind to private mount.
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir3.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  ASSERT_FALSE(optionals[dir3.path()].empty());
  ASSERT_FALSE(optionals[dir4.path()].empty());
  EXPECT_EQ(optionals[dir1.path()][0].shared, 0);
  EXPECT_EQ(optionals[dir2.path()][0].shared, optionals[dir3.path()][0].shared);
  EXPECT_EQ(optionals[dir3.path()][0].shared, optionals[dir4.path()][0].shared);
}

TEST(MountTest, BindPeerGroupsWithChildren) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir2.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir2.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  // dir3 and dir4 are child mounts of dir1.
  auto const dir3 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const mnt3 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir3.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const dir4 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const mnt4 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir4.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  auto const mnt5 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  const std::string dir3_path2 = JoinPath(dir2.path(), Basename(dir3.path()));
  const std::string dir4_path2 = JoinPath(dir2.path(), Basename(dir4.path()));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  ASSERT_FALSE(optionals[dir3.path()].empty());

  EXPECT_NE(optionals[dir1.path()][0].shared, optionals[dir3.path()][0].shared);
  EXPECT_NE(optionals[dir3.path()][0].shared, optionals[dir4.path()][0].shared);
  EXPECT_NE(optionals[dir4.path()][0].shared, optionals[dir1.path()][0].shared);
  EXPECT_EQ(optionals[dir3_path2].size(), 0);
  EXPECT_EQ(optionals[dir4_path2].size(), 0);
}

TEST(MountTest, BindParentToChild) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir1.path()));
  auto const mnt3 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir1.path().c_str(), child_dir.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_FALSE(optionals[dir1.path()].empty());
  ASSERT_FALSE(optionals[dir2.path()].empty());
  ASSERT_FALSE(optionals[child_dir.path()].empty());

  EXPECT_EQ(optionals[dir1.path()][0].shared, optionals[dir2.path()][0].shared);
  EXPECT_EQ(optionals[dir2.path()][0].shared,
            optionals[child_dir.path()][0].shared);
  EXPECT_NE(optionals[dir1.path()][0].shared, 0);
}

TEST(MountTest, MountInfoHasRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", parent.path(), kTmpfs, 0, "mode=0123", 0));
  auto const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  auto const bind_mount = Mount(child.path(), child.path(), "", MS_BIND, "", 0);
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (const auto& e : mounts) {
    if (e.mount_point == child.path()) {
      EXPECT_EQ(e.root, JoinPath("/", Basename(child.path())))
          << "Offending mount ID is: " << e.id;
    }
    if (e.mount_point == parent.path()) {
      EXPECT_EQ(e.root, "/") << "Offending mount ID is: " << e.id;
    }
  }
}

TEST(MountTest, DeadMountsAreDecRefd) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  DisableSave ds;
  std::string home = NewTempAbsPath();
  ASSERT_NO_ERRNO(Mkdir(home));
  ASSERT_THAT(chdir(home.c_str()), SyscallSucceeds());
  constexpr char dirpath[] = "./file";

  for (int i = 0; i < 10; ++i) {
    const auto rest = [&] {
      mkdir(dirpath, 0);
      mount(dirpath, ".", 0, MS_BIND, 0);
      rmdir(dirpath);
      mkdir(dirpath, 0);
      mount(dirpath, ".", 0, MS_BIND, 0);
    };
    EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
  }
}

TEST(MountTest, UmountSharedBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  std::string home = NewTempAbsPath();
  ASSERT_NO_ERRNO(Mkdir(home));
  ASSERT_THAT(chdir(home.c_str()), SyscallSucceeds());
  constexpr char dirpath[] = "./file";

  ASSERT_THAT(mkdir(dirpath, 0), SyscallSucceeds());
  ASSERT_THAT(mount(dirpath, dirpath, 0, MS_BIND, 0), SyscallSucceeds());
  ASSERT_THAT(mount(0, dirpath, 0, MS_SHARED, 0), SyscallSucceeds());
  ASSERT_THAT(mount(dirpath, dirpath, 0, MS_BIND, 0), SyscallSucceeds());
  ASSERT_THAT(mount(0, dirpath, 0, MS_SHARED, 0), SyscallSucceeds());
  ASSERT_THAT(umount2(dirpath, MNT_DETACH), SyscallSucceeds());
  ASSERT_THAT(umount2(dirpath, MNT_DETACH), SyscallSucceeds());
}

TEST(MountTest, MakeSlave) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SLAVE, 0), SyscallSucceeds());
  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_NE(optionals[dir1.path()][0].shared, 0);
  ASSERT_NE(optionals[dir2.path()][0].master, 0);
}

TEST(MountTest, MakeSharedSlave) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SHARED, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_NE(optionals[dir1.path()][0].shared, 0);
  ASSERT_NE(optionals[dir2.path()][0].shared, 0);
  ASSERT_NE(optionals[dir2.path()][0].master, 0);
}

TEST(MountTest, PrivateMasterUnslaves) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const base_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", base.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", base.path().c_str(), "", MS_PRIVATE, 0),
              SyscallSucceeds());

  auto const dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base.path()));
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base.path()));
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SHARED, 0),
              SyscallSucceeds());

  ASSERT_THAT(mount(0, dir1.path().c_str(), 0, MS_PRIVATE, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_EQ(optionals[dir1.path()][0].shared, 0);
  ASSERT_EQ(optionals[dir2.path()][0].master, 0);
  ASSERT_NE(optionals[dir2.path()][0].shared, 0);
}

TEST(MountTest, SlaveMaster) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt1 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir1.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dir1.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir1.path().c_str(), dir2.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_SHARED, 0),
              SyscallSucceeds());
  auto const dir3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt3 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dir2.path().c_str(), dir3.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount(0, dir3.path().c_str(), 0, MS_SLAVE, 0), SyscallSucceeds());

  ASSERT_THAT(mount(0, dir2.path().c_str(), 0, MS_PRIVATE, 0),
              SyscallSucceeds());

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_NE(optionals[dir1.path()][0].shared, 0);
  ASSERT_EQ(optionals[dir2.path()][0].shared, 0);
  ASSERT_EQ(optionals[dir2.path()][0].master, 0);
  ASSERT_EQ(optionals[dir3.path()][0].master, optionals[dir1.path()][0].shared);
}

TEST(MountTest, BindSharedToSlave) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const src = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const src_mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), src.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", src.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dst_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst_master.path().c_str(), dst_master.path().c_str(), "", MS_BIND,
            "", MNT_DETACH));
  ASSERT_THAT(mount("", dst_master.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dst = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst_master.path().c_str(), dst.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));
  ASSERT_THAT(mount("", dst.path().c_str(), "", MS_SLAVE, 0),
              SyscallSucceeds());

  auto const dst_mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), dst.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());

  ASSERT_EQ(optionals[src.path()][0].shared, optionals[dst.path()][1].shared);
  ASSERT_EQ(optionals[dst.path()][0].master,
            optionals[dst_master.path()][0].shared);
}

TEST(MountTest, BindSlaveToShared) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const src = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const src_mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), src.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", src.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const src_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const src_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(src.path().c_str(), src_master.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));
  ASSERT_THAT(mount("", src.path().c_str(), "", MS_SLAVE, 0),
              SyscallSucceeds());

  auto const dst = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dst.path().c_str(), dst.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dst.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dst_peer = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_peer_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst.path().c_str(), dst_peer.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));

  auto const dst_mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), dst.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_EQ(optionals[dst.path()][1].shared,
            optionals[dst_peer.path()][1].shared);
  ASSERT_EQ(optionals[dst.path()][1].master,
            optionals[dst_peer.path()][1].master);
  ASSERT_EQ(optionals[dst.path()][1].master,
            optionals[src_master.path()][0].shared);
}

TEST(MountTest, BindSlaveToSlave) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const src = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const src_mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), src.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", src.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const src_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const src_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(src.path().c_str(), src_master.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));
  ASSERT_THAT(mount("", src.path().c_str(), "", MS_SLAVE, 0),
              SyscallSucceeds());

  auto const dst = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      dst.path().c_str(), dst.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", dst.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dst_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst.path().c_str(), dst_master.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));
  ASSERT_THAT(mount("", dst.path().c_str(), "", MS_SLAVE, 0),
              SyscallSucceeds());

  auto const dst_mnt2 = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      src.path().c_str(), dst.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_EQ(optionals[dst.path()][1].master, optionals[src.path()][0].master);
}

// Test that mounting on a slave mount does not propagate to the master.
TEST(MountTest, SlavePropagationEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dst_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst_master.path().c_str(), dst_master.path().c_str(), "", MS_BIND,
            "", MNT_DETACH));
  ASSERT_THAT(mount("", dst_master.path().c_str(), "", MS_SHARED, 0),
              SyscallSucceeds());
  auto const dst = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dst_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dst_master.path().c_str(), dst.path().c_str(), "", MS_BIND, "",
            MNT_DETACH));
  ASSERT_THAT(mount("", dst.path().c_str(), "", MS_SLAVE, 0),
              SyscallSucceeds());
  auto const child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dst_master.path()));

  const std::string master_child_path =
      JoinPath(dst_master.path(), Basename(child.path()));
  const std::string slave_child_path =
      JoinPath(dst.path(), Basename(child.path()));
  auto const slave_child_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", slave_child_path.c_str(), kTmpfs, 0, "", MNT_DETACH));

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  ASSERT_EQ(optionals[child.path()].size(), 0);
}

// We are building a propagation tree that looks like this:
/*
    A <--> B <--> C <---> D
   /|\           /|       |\
  / F G         J K       H I
 /
E<-->O
    /|\
   M L N
*/
// Propagating mount events across this tree should cover most propagation
// cases.
TEST(MountTest, LargeTreePropagationEvent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // 15 total mounts that should all get propagated to if we mount on A.
  auto const a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const c = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const d = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const e = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const g = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const h = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const i = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const j = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const k = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const l = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const m = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const n = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const o = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), a.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());

  // Place E, F, and G in A's peer group, then make them slaves.
  auto const e_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), e.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const f_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), f.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const g_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), g.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", e.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", f.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", g.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());

  // Add B to A's shared group.
  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), b.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  // Add C to A's shared group and place J and K in C's peer group, then make
  // them slaves.
  auto const c_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), c.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const j_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(c.path().c_str(), j.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const k_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(c.path().c_str(), k.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", j.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", k.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());

  // Add D to A's shared group and place H and I in Ds peer group, then make
  // them slaves.
  auto const d_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path().c_str(), d.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const h_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(d.path().c_str(), h.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const i_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(d.path().c_str(), i.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", h.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", i.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());

  // Make E shared and create a group with O.
  ASSERT_THAT(mount("", e.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());
  auto const o_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(e.path().c_str(), o.path().c_str(), "", MS_BIND, "", MNT_DETACH));

  // Add M, L and N to K's shared group and make them slaves of O.
  auto const m_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(o.path().c_str(), m.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const l_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(o.path().c_str(), l.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  auto const n_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(o.path().c_str(), n.path().c_str(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", m.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", l.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", n.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());

  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());

  ASSERT_THAT(mount("", a.path().c_str(), kTmpfs, 0, ""), SyscallSucceeds());

  std::vector<ProcMountInfoEntry> mounts_after_mount =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  ASSERT_EQ(mounts_after_mount.size(), mounts.size() + 15);

  auto optionals = ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());

  // A, B, C, and D are all mounted over and in a peer group.
  ASSERT_NE(optionals[a.path()][1].shared, 0);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[b.path()][1].shared);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[c.path()][1].shared);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[d.path()][1].shared);

  // E, F, G, H, I, J, K are all mounted over and slave to A's peer group.
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[e.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[f.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[g.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[h.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[i.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[j.path()][1].master);
  ASSERT_EQ(optionals[a.path()][1].shared, optionals[k.path()][1].master);

  // E and O are all mounted over and in a peer group.
  ASSERT_EQ(optionals[e.path()][1].shared, optionals[o.path()][1].shared);

  // L, M, and N are all mounted over and slaves to E's peer group.
  ASSERT_EQ(optionals[e.path()][1].shared, optionals[l.path()][1].master);
  ASSERT_EQ(optionals[e.path()][1].shared, optionals[m.path()][1].master);
  ASSERT_EQ(optionals[e.path()][1].shared, optionals[n.path()][1].master);

  ASSERT_THAT(umount2(a.path().c_str(), MNT_DETACH), SyscallSucceeds());
  std::vector<ProcMountInfoEntry> mounts_after_umount =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  ASSERT_EQ(mounts_after_umount.size(), mounts.size());
}

TEST(MountTest, MaxMountsWithSlave) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const parent_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", parent.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));
  auto const a =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  auto const b =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  auto const c =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));

  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", a.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));
  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());

  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), b.path(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", b.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());
  ASSERT_THAT(mount("", b.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());

  auto const c_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(b.path(), c.path(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", c.path().c_str(), "", MS_SLAVE, 0), SyscallSucceeds());

  auto const d = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  auto const e = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));

  int mount_max = 10000;
  bool mount_max_exists =
      ASSERT_NO_ERRNO_AND_VALUE(Exists("/proc/sys/fs/mount-max"));
  if (mount_max_exists) {
    std::string mount_max_string;
    ASSERT_NO_ERRNO(GetContents("/proc/sys/fs/mount-max", &mount_max_string));
    ASSERT_TRUE(absl::SimpleAtoi(mount_max_string, &mount_max));
  }

  // Each bind mount doubles the number of mounts in the propagation tree
  // starting with 3. The number of binds we can do before failing is
  // log2((max_mounts-num_current_mounts)/3).
  std::vector<ProcMountInfoEntry> mounts =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  int num_binds = static_cast<int>(std::log2((mount_max - mounts.size()) / 3));

  for (int i = 0; i < num_binds; i++) {
    ASSERT_THAT(
        mount(d.path().c_str(), d.path().c_str(), nullptr, MS_BIND, nullptr),
        SyscallSucceeds());
    ASSERT_THAT(mount("", d.path().c_str(), "", MS_SHARED, 0),
                SyscallSucceeds());
  }
  for (int i = 0; i < 2; i++) {
    EXPECT_THAT(
        mount(d.path().c_str(), d.path().c_str(), nullptr, MS_BIND, nullptr),
        SyscallFailsWithErrno(ENOSPC));
  }
}

TEST(MountTest, SetPropagationRecursive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", a.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));
  const auto b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", b.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));
  const auto c = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(b.path()));
  auto const c_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", c.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));
  const auto d = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(c.path()));
  auto const d_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", d.path(), kTmpfs, 0, "mode=0123", MNT_DETACH));

  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SHARED | MS_REC, 0),
              SyscallSucceeds());
  absl::flat_hash_map<std::string, std::vector<MountOptional>> optionals =
      ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  EXPECT_NE(optionals[a.path()][0].shared, 0);
  EXPECT_NE(optionals[b.path()][0].shared, 0);
  EXPECT_NE(optionals[c.path()][0].shared, 0);
  EXPECT_NE(optionals[d.path()][0].shared, 0);
}

TEST(MountTest, SetSlaveRecursive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const auto a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), a.path(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());
  const auto a_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const a_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), a_master.path(), "", MS_BIND, "", MNT_DETACH));

  const auto b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), b.path(), "", MS_BIND, "", MNT_DETACH));
  const auto b_master = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const b_master_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(b.path(), b_master.path(), "", MS_BIND, "", MNT_DETACH));

  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SLAVE | MS_REC, 0),
              SyscallSucceeds());

  absl::flat_hash_map<std::string, std::vector<MountOptional>> optionals =
      ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  EXPECT_EQ(optionals[a.path()][0].master,
            optionals[a_master.path()][0].shared);
  EXPECT_EQ(optionals[b.path()][0].master,
            optionals[b_master.path()][0].shared);
}

TEST(MountTest, RecursiveBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const auto a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), a.path(), "", MS_BIND, "", MNT_DETACH));
  const auto b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(b.path(), b.path(), "", MS_BIND, "", MNT_DETACH));
  const auto c = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(b.path()));
  const auto d = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const d_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), d.path(), "", MS_BIND | MS_REC, "", MNT_DETACH));

  // Write to child1 in dir1.
  const std::string filename = "foo.txt";
  const std::string contents = "barbaz";
  ASSERT_NO_ERRNO(
      CreateWithContents(JoinPath(c.path(), filename), contents, 0666));
  // Verify both directories have the same nodes.
  const std::string path =
      JoinPath(d.path(), Basename(b.path()), Basename(c.path()), filename);

  std::string output;
  ASSERT_NO_ERRNO(GetContents(path, &output));
  EXPECT_EQ(output, contents);
}

TEST(MountTest, MaxRecursiveBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const auto a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), a.path(), "", MS_BIND, "", MNT_DETACH));
  const auto b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));

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
    ASSERT_THAT(mount(a.path().c_str(), b.path().c_str(), nullptr,
                      MS_BIND | MS_REC, nullptr),
                SyscallSucceeds());
  }
  ASSERT_THAT(mount(a.path().c_str(), b.path().c_str(), nullptr,
                    MS_BIND | MS_REC, nullptr),
              SyscallFailsWithErrno(ENOSPC));
}

TEST(MountTest, RecursiveBindPropagation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const auto parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const parent_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(parent.path(), parent.path(), "", MS_BIND, "", MNT_DETACH));
  const auto a =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const auto b =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const auto c =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));

  auto const a_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("test", a.path(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount("", a.path().c_str(), "", MS_SHARED, 0), SyscallSucceeds());

  auto const b_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), b.path(), "", MS_BIND, "", MNT_DETACH));
  auto const c_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(a.path(), c.path(), "", MS_BIND, "", MNT_DETACH));

  const auto d =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  auto const d_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(d.path(), d.path(), "", MS_BIND, "", MNT_DETACH));

  const auto e = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(d.path()));
  auto const e_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(e.path(), e.path(), "", MS_BIND, "", MNT_DETACH));

  auto const f_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(d.path(), f.path(), "", MS_BIND | MS_REC, "", MNT_DETACH));

  absl::flat_hash_map<std::string, std::vector<MountOptional>> optionals =
      ASSERT_NO_ERRNO_AND_VALUE(MountOptionals());
  auto b_e_path = JoinPath(b.path(), Basename(f.path()), Basename(e.path()));
  ASSERT_FALSE(optionals[b_e_path].empty());
  auto c_e_path = JoinPath(c.path(), Basename(f.path()), Basename(e.path()));
  ASSERT_FALSE(optionals[c_e_path].empty());
}

TEST(MountTest, MountNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "mode=0700", 0));
  auto const file_path = JoinPath(dir.path(), "foo");
  EXPECT_NO_ERRNO(Open(file_path, O_CREAT | O_RDWR, 0777));

  pid_t child = fork();
  if (child == 0) {
    // Create a new mount namespace and umount the test mount from it.
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(access(file_path.c_str(), F_OK) == 0);
    TEST_PCHECK(umount2(dir.path().c_str(), MNT_DETACH) == 0);
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Check that the test mount is still here.
  EXPECT_NO_ERRNO(Open(file_path, O_RDWR));
}

TEST(MountTest, MountNamespaceSetns) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "mode=0700", MNT_DETACH));
  auto const file_path = JoinPath(dir.path(), "foo");
  EXPECT_NO_ERRNO(Open(file_path, O_CREAT | O_RDWR, 0777));
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/mnt", O_RDONLY));

  pid_t child = fork();
  if (child == 0) {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(umount2(dir.path().c_str(), MNT_DETACH) == 0);
    TEST_PCHECK(setns(nsfd.get(), CLONE_NEWNS) == 0);
    TEST_PCHECK(access(file_path.c_str(), F_OK) == 0);
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST(MountTest, MountNamespacePropagation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "mode=0700", MNT_DETACH));
  auto child_dir = JoinPath(dir.path(), "test");
  auto const file_path = JoinPath(child_dir, "foo");
  auto const file2_path = JoinPath(child_dir, "boo");

  ASSERT_THAT(mount(NULL, dir.path().c_str(), NULL, MS_SHARED, NULL),
              SyscallSucceeds());
  ASSERT_THAT(mkdir(child_dir.c_str(), 0700), SyscallSucceeds());
  ASSERT_THAT(mount("child", child_dir.c_str(), kTmpfs, 0, NULL),
              SyscallSucceeds());
  EXPECT_NO_ERRNO(Open(file_path, O_CREAT | O_RDWR, 0777));

  pid_t child = fork();
  if (child == 0) {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(access(file_path.c_str(), F_OK) == 0);
    // The test mount has to be umounted from the second mount namespace too.
    TEST_PCHECK(umount2(child_dir.c_str(), MNT_DETACH) == 0);
    // The new mount has to be propagated to the second mount namespace.
    TEST_PCHECK(mount("test2", child_dir.c_str(), kTmpfs, 0, NULL) == 0);
    TEST_PCHECK(mknod(file2_path.c_str(), 0777 | S_IFREG, 0) == 0);
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Check that the test mount is still here.
  EXPECT_NO_ERRNO(Open(file2_path, O_RDWR));
  EXPECT_THAT(umount2(child_dir.c_str(), MNT_DETACH), SyscallSucceeds());
}

TEST(MountTest, MountNamespaceSlavesNewUserNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const Cleanup dir_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount(NULL, dir.path().c_str(), NULL, MS_SHARED, NULL),
              SyscallSucceeds());
  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  const std::string file_path = JoinPath(child_dir.path(), "foo");
  const std::string file2_path = JoinPath(child_dir.path(), "boo");

  const std::function<void()> parent = [&] {
    TEST_CHECK_SUCCESS(
        mount("child", child_dir.path().c_str(), kTmpfs, 0, NULL));
    TEST_CHECK_SUCCESS(open(file_path.c_str(), O_CREAT | O_RDWR, 0777));
  };
  const std::function<void()> child = [&] {
    TEST_CHECK_SUCCESS(access(JoinPath(child_dir.path(), "foo").c_str(), F_OK));

    // These mount operations will not propagate to the other namespace
    // because it is a slave mount.
    TEST_CHECK_SUCCESS(umount2(child_dir.path().c_str(), MNT_DETACH));
    TEST_CHECK_SUCCESS(
        mount("test2", child_dir.path().c_str(), kTmpfs, 0, NULL));
    TEST_CHECK_SUCCESS(mknod(file2_path.c_str(), 0777 | S_IFREG, 0));

    TEST_CHECK_SUCCESS(umount2(child_dir.path().c_str(), MNT_DETACH));
    // This should fail because the mount is locked.
    TEST_CHECK_ERRNO(umount2(child_dir.path().c_str(), MNT_DETACH), EINVAL);

    // Check that there is a master entry in mountinfo.
    int fd = open("/proc/self/mountinfo", O_RDONLY);
    TEST_CHECK(fd >= 0);
    char child_mountinfo[0x8000];
    int size = 0;
    while (true) {
      int ret =
          read(fd, child_mountinfo + size, sizeof(child_mountinfo) - size);
      TEST_CHECK(ret != -1);
      size += ret;
      if (ret == 0) {
        break;
      }
    }
    TEST_CHECK(absl::StrContains(child_mountinfo, "master:"));
  };
  EXPECT_THAT(InForkedUserMountNamespace(parent, child),
              IsPosixErrorOkAndHolds(0));

  // Check that the test mount is still here.
  EXPECT_EQ(Open(file2_path, O_RDWR).error().errno_value(), ENOENT);
  EXPECT_THAT(umount2(child_dir.path().c_str(), MNT_DETACH), SyscallSucceeds());
}

TEST(MountTest, LockedMountStopsNonRecBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const Cleanup dir_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), kTmpfs, 0, "", MNT_DETACH));
  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  const Cleanup child_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", child_dir.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  const std::string foo_dir = JoinPath(dir.path(), "foo");

  const std::function<void()> child_fn = [&] {
    TEST_CHECK_SUCCESS(mkdir(foo_dir.c_str(), 0700));
    TEST_CHECK_ERRNO(
        mount(dir.path().c_str(), foo_dir.c_str(), "", MS_BIND, ""), EINVAL);
    TEST_CHECK_SUCCESS(
        mount(dir.path().c_str(), foo_dir.c_str(), "", MS_BIND | MS_REC, ""));
  };
  EXPECT_THAT(InForkedUserMountNamespace([] {}, child_fn),
              IsPosixErrorOkAndHolds(0));
}

// This test checks that a mount tree that propagates from a more privileged
// mount namespace cannot be partially unmounted. It must be unmounted as a
// single unit as described in point 4 of the notes in
// https://man7.org/linux/man-pages/man7/mount_namespaces.7.html. This test
// also checks that unmounting a propagated mount tree does not reveal the
// contents of overmounted filesystems from the more privileged mount namespace.
TEST(MountTest, UmountPropagatedSubtreeFromPrivilegedNS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(GetAbsoluteTestTmpdir())));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const Cleanup dir_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir.path(), dir.path(), "", MS_BIND, "", MNT_DETACH));
  ASSERT_THAT(mount(NULL, dir.path().c_str(), NULL, MS_SHARED, NULL),
              SyscallSucceeds());

  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  const TempPath sibling_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  const Cleanup child_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", child_dir.path(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(mount(NULL, child_dir.path().c_str(), NULL, MS_PRIVATE, NULL),
              SyscallSucceeds());

  const TempPath grandchild_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(child_dir.path()));
  ASSERT_THAT(open(JoinPath(grandchild_dir.path(), "foo").c_str(),
                   O_CREAT | O_RDWR, 0777),
              SyscallSucceeds());
  const Cleanup grandchild_mnt = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", grandchild_dir.path(), kTmpfs, 0, "", MNT_DETACH));
  ASSERT_THAT(
      mount(NULL, grandchild_dir.path().c_str(), NULL, MS_PRIVATE, NULL),
      SyscallSucceeds());
  const std::string grandsibling_dir =
      JoinPath(sibling_dir.path(), Basename(grandchild_dir.path()));

  const std::function<void()> parent = [&] {
    TEST_CHECK_SUCCESS(mount(child_dir.path().c_str(),
                             sibling_dir.path().c_str(), "", MS_BIND | MS_REC,
                             ""));
    TEST_CHECK_SUCCESS(
        mount("", sibling_dir.path().c_str(), "", MS_PRIVATE | MS_REC, ""));
  };
  // You can umount an entire subtree that propagated from a more privileged
  // mount namespace, but can't umount only part of the subtree.
  const std::string file_path =
      JoinPath(Basename(grandchild_dir.path()), "foo");
  const std::function<void()> child = [&] {
    TEST_CHECK_ERRNO(umount2(grandsibling_dir.c_str(), MNT_DETACH), EINVAL);
    int dirfd = open(sibling_dir.path().c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(dirfd >= 0);
    TEST_CHECK_SUCCESS(umount2(sibling_dir.path().c_str(), MNT_DETACH));
    // Check to ensure you cannot access an overmounted file with openat after
    // the mount unit has been destroyed.
    TEST_CHECK_ERRNO(openat(dirfd, file_path.c_str(), O_RDONLY), ENOENT);
  };
  EXPECT_THAT(InForkedUserMountNamespace(parent, child),
              IsPosixErrorOkAndHolds(0));
}

TEST(MountTest, MountFailsOnPseudoFilesystemMountpoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, 0));
  std::string path = absl::StrCat("/proc/self/fd/", fd.get());
  EXPECT_THAT(mount("test", path.c_str(), kTmpfs, 0, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, ChangeMountFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const auto flag = MS_NODEV;
  const auto dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto mount_cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(dir1.path(), dir2.path(), kTmpfs, MS_BIND, "", 0));

  struct statfs st;
  EXPECT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), kTmpfs,
                    MS_REMOUNT | MS_BIND | flag, ""),
              SyscallSucceeds());
  EXPECT_THAT(statfs(dir2.path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.f_flags & flag, flag);
  // Resets mount flags.
  EXPECT_THAT(mount(dir1.path().c_str(), dir2.path().c_str(), kTmpfs,
                    MS_REMOUNT | MS_BIND, ""),
              SyscallSucceeds());
  ASSERT_THAT(statfs(dir2.path().c_str(), &st), SyscallSucceeds());
  ASSERT_EQ(st.f_flags & flag, 0);
}

TEST(MountTest, RemountUnmounted) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), kTmpfs, MS_REMOUNT, ""),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, DetachedMountBindFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath path1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Cleanup mount_cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", path1.path().c_str(), kTmpfs, 0, "", MNT_DETACH));
  mount_cleanup.Release();
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path1.path().c_str(), O_RDONLY));
  std::string fd_path = absl::Substitute("/proc/self/fd/$0", fd.get());
  ASSERT_THAT(umount2(path1.path().c_str(), MNT_DETACH), SyscallSucceeds());
  const TempPath path2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount(fd_path.c_str(), path2.path().c_str(), "", MS_BIND, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MountTest, MountProc) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Mount procfs with a NULL source to a temporary directory.
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount(NULL, dir.path().c_str(), "proc", 0, NULL),
              SyscallSucceeds());
  auto cleanup = Cleanup([&dir] {
    EXPECT_THAT(umount2(dir.path().c_str(), 0), SyscallSucceeds());
  });

  // Verify that /proc/self/mountinfo describes the device as "none".
  const std::vector<ProcMountInfoEntry> mountinfo =
      ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntries());
  for (auto const& e : mountinfo) {
    if (e.mount_point == dir.path()) {
      EXPECT_EQ(e.fstype, "proc");
      EXPECT_EQ(e.mount_source, "none");
    }
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
