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
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

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
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN))) {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
  }

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
  EXPECT_NE(before.st_ino, after.st_ino);

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

  const struct stat after2 = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  EXPECT_EQ(before.st_ino, after2.st_ino);

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
    EXPECT_NE(s.st_ino, before.st_ino);

    EXPECT_NO_ERRNO(Open(JoinPath(dir.path(), "foo"), O_CREAT | O_RDWR, 0777));
  }

  // Now that dir is unmounted again, we should have the old inode back.
  const struct stat after = ASSERT_NO_ERRNO_AND_VALUE(Stat(dir.path()));
  EXPECT_EQ(before.st_ino, after.st_ino);
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

}  // namespace

}  // namespace testing
}  // namespace gvisor
