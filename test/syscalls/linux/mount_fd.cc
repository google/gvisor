// Copyright 2026 The gVisor Authors.
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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// Syscall Definitions/Constants

#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x1
#endif

#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG 0x0
#define FSCONFIG_SET_STRING 0x1
#define FSCONFIG_SET_BINARY 0x2
#define FSCONFIG_SET_PATH 0x3
#define FSCONFIG_SET_PATH_EMPTY 0x4
#define FSCONFIG_SET_FD 0x5
#define FSCONFIG_CMD_CREATE 0x6
#define FSCONFIG_CMD_RECONFIGURE 0x7
#define FSCONFIG_CMD_CREATE_EXCL 0x8
#endif

#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x1
#endif

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#define MOUNT_ATTR_NOSUID 0x00000002
#define MOUNT_ATTR_NODEV 0x00000004
#define MOUNT_ATTR_NOEXEC 0x00000008
#define MOUNT_ATTR__ATIME 0x00000070
#define MOUNT_ATTR_RELATIME 0x00000000
#define MOUNT_ATTR_NOATIME 0x00000010
#define MOUNT_ATTR_STRICTATIME 0x00000020
#define MOUNT_ATTR_NODIRATIME 0x00000080
#endif

#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS 0x00000001
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define MOVE_MOUNT_T_SYMLINKS 0x00000010
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#define MOVE_MOUNT__MASK 0x00000077
#endif

#ifndef ST_RDONLY
#define ST_RDONLY 0x1
#endif
#ifndef ST_NODEV
#define ST_NODEV 0x4
#endif
#ifndef ST_NOEXEC
#define ST_NOEXEC 0x8
#endif

#ifndef SYS_fsopen
#if defined(__x86_64__)
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#elif defined(__aarch64__)
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#else
#error "Unknown architecture"
#endif
#endif

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

inline int fsopen(const char* fsname, unsigned int flags) {
  return syscall(SYS_fsopen, fsname, flags);
}
inline int fsconfig(int fd, unsigned int cmd, const char* key,
                    const void* value, int aux) {
  return syscall(SYS_fsconfig, fd, cmd, key, value, aux);
}
inline int fsmount(int fsfd, unsigned int flags, unsigned int attr_flags) {
  return syscall(SYS_fsmount, fsfd, flags, attr_flags);
}
inline int move_mount(int from_dirfd, const char* from_pathname, int to_dirfd,
                      const char* to_pathname, unsigned int flags) {
  return syscall(SYS_move_mount, from_dirfd, from_pathname, to_dirfd,
                 to_pathname, flags);
}
inline int open_tree(int dirfd, const char* pathname, unsigned int flags) {
  return syscall(SYS_open_tree, dirfd, pathname, flags);
}

namespace gvisor {
namespace testing {

namespace {

constexpr char kTmpfs[] = "tmpfs";

// fsopen(2) tests

TEST(FsOpenTest, FsOpenSuccess) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fd1 = fsopen(kTmpfs, 0);
  ASSERT_THAT(fd1, SyscallSucceeds());
  EXPECT_THAT(close(fd1), SyscallSucceeds());

  int fd2 = fsopen(kTmpfs, FSOPEN_CLOEXEC);
  ASSERT_THAT(fd2, SyscallSucceeds());
  EXPECT_THAT(close(fd2), SyscallSucceeds());
}

TEST(FsOpenTest, FsOpenInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  EXPECT_THAT(fsopen(kTmpfs, -1), SyscallFailsWithErrno(EINVAL));
}

TEST(FsOpenTest, FsOpenPermDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Drop privileges in another thread to verify CAP_SYS_ADMIN check.
  ScopedThread([&]() {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_THAT(fsopen(kTmpfs, 0), SyscallFailsWithErrno(EPERM));
  });
}

// fsconfig(2) tests

TEST(FsConfigTest, FsConfigSetSource) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
}

TEST(FsConfigTest, FsConfigSetParams) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_FLAG, "ro", NULL, 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "mode", "755", 0),
              SyscallSucceeds());
}

TEST(FsConfigTest, FsConfigSetSourceTwice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "src1", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "src2", 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FsConfigTest, FsConfigCreateWithoutSource) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
}

TEST(FsConfigTest, FsConfigBadFilesystem) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  // Note: Skipped on Linux because Linux fails immediately at fsopen() time
  // with ENODEV. Currently on gVisor, fsopen() succeeds and the ENODEV failure
  // occurs during fsconfig(FSCONFIG_CMD_CREATE).
  SKIP_IF(!IsRunningOnGvisor());

  int fsfd = fsopen("invalid_fs_name", 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "src", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallFailsWithErrno(ENODEV));
}

TEST(FsConfigTest, FsConfigCreateSuccess) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
}

TEST(FsConfigTest, FsConfigCreateTwice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallFailsWithErrno(EBUSY));
}

TEST(FsConfigTest, FsConfigUnsupportedCmds) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  // Note: Skipped on Linux because gVisor currently does not support
  // FSCONFIG_CMD_CREATE_EXCL (returns EINVAL).
  SKIP_IF(!IsRunningOnGvisor());

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE_EXCL, NULL, NULL, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FsConfigTest, FsConfigReconfigureSucceeds) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd =
      fsmount(fsfd, FSMOUNT_CLOEXEC, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_FLAG, "ro", NULL, 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "nr_inodes", "12345", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0),
              SyscallSucceeds());

	// TODO(gvisor.dev/issues/13450): once reconfiguration is properly supported
  // on underlying filesystems, this test should be updated.
  struct statfs st;
  ASSERT_THAT(fstatfs(mntfd, &st), SyscallSucceeds());
  EXPECT_NE(st.f_files, 12345);
  EXPECT_NE(st.f_flags & ST_RDONLY, ST_RDONLY);
}

TEST(FsConfigTest, FsConfigUnsupportedTypes) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  // Note: Skipped on Linux because gVisor currently does not support
  // BINARY, FD, or PATH parameter types (returns EINVAL).
  SKIP_IF(!IsRunningOnGvisor());

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_BINARY, "key", "val", 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_FD, "key", NULL, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_PATH, "key", "val", 0),
              SyscallFailsWithErrno(EINVAL));
}

// fsmount(2) tests

TEST(FsMountTest, FsMountSuccess) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "nr_inodes", "12345", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_FLAG, "ro", NULL, 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd =
      fsmount(fsfd, FSMOUNT_CLOEXEC, MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  struct statfs st;
  ASSERT_THAT(fstatfs(mntfd, &st), SyscallSucceeds());
  EXPECT_EQ(st.f_files, 12345);
  EXPECT_EQ(st.f_flags & (ST_NODEV | ST_NOEXEC | ST_RDONLY),
            ST_NODEV | ST_NOEXEC | ST_RDONLY);
}

TEST(FsMountTest, FsMountBeforeCreate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsmount(fsfd, 0, 0), SyscallFailsWithErrno(EINVAL));
}

TEST(FsMountTest, FsMountTwice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  EXPECT_THAT(fsmount(fsfd, 0, 0), SyscallFailsWithErrno(EBUSY));
}

TEST(FsMountTest, FsMountInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  EXPECT_THAT(fsmount(fsfd, -1, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fsmount(fsfd, 0, -1), SyscallFailsWithErrno(EINVAL));
}

TEST(FsMountTest, FsMountDetachedUsage) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  // Verify that detached mount FD acts as a valid root dirfd before attachment.
  EXPECT_THAT(mkdirat(mntfd, "subdir", 0755), SyscallSucceeds());

  int filefd = openat(mntfd, "file", O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(filefd, SyscallSucceeds());
  EXPECT_THAT(close(filefd), SyscallSucceeds());
}

// move_mount(2) tests

TEST(MoveMountTest, MoveMountAttachSuccess) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  // Pre-move creation: Create files and directories in detached mntfd.
  EXPECT_THAT(mkdirat(mntfd, "pre_move_dir", 0755), SyscallSucceeds());
  int filefd = openat(mntfd, "pre_move_file", O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(filefd, SyscallSucceeds());
  EXPECT_THAT(close(filefd), SyscallSucceeds());

  // Create a mountpoint on the existing root filesystem
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Move the detached mount onto the new mount directory.
  EXPECT_THAT(move_mount(mntfd, "", AT_FDCWD, dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt.Release()();

  // Verify that pre-move contents are fully preserved and accessible at target.
  EXPECT_THAT(access(JoinPath(dir.path(), "pre_move_dir").c_str(), F_OK),
              SyscallSucceeds());
  EXPECT_THAT(access(JoinPath(dir.path(), "pre_move_file").c_str(), F_OK),
              SyscallSucceeds());

  EXPECT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
}

TEST(MoveMountTest, MoveMountFromAttached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });

  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "my_source", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());

  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // First attach to dir1.
  EXPECT_THAT(move_mount(mntfd, "", AT_FDCWD, dir1.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt.Release()();

  // Now move from dir1 to dir2.
  EXPECT_THAT(move_mount(AT_FDCWD, dir1.path().c_str(), AT_FDCWD,
                         dir2.path().c_str(), 0),
              SyscallSucceeds());

  EXPECT_THAT(umount(dir2.path().c_str()), SyscallSucceeds());
}

TEST(MoveMountTest, MoveMountOntoDetached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Create first detached mount mntfd1.
  int fsfd1 = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd1, SyscallSucceeds());
  auto cleanup_fs1 = Cleanup([&]() { close(fsfd1); });
  EXPECT_THAT(fsconfig(fsfd1, FSCONFIG_SET_STRING, "source", "src1", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd1, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd1 = fsmount(fsfd1, 0, 0);
  ASSERT_THAT(mntfd1, SyscallSucceeds());
  auto cleanup_mnt1 = Cleanup([&]() { close(mntfd1); });

  EXPECT_THAT(mkdirat(mntfd1, "submnt", 0755), SyscallSucceeds());

  // Create second detached mount mntfd2.
  int fsfd2 = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd2, SyscallSucceeds());
  auto cleanup_fs2 = Cleanup([&]() { close(fsfd2); });
  EXPECT_THAT(fsconfig(fsfd2, FSCONFIG_SET_STRING, "source", "src2", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd2, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd2 = fsmount(fsfd2, 0, 0);
  ASSERT_THAT(mntfd2, SyscallSucceeds());
  auto cleanup_mnt2 = Cleanup([&]() { close(mntfd2); });

  // Move mntfd2 onto submnt of mntfd1.
  EXPECT_THAT(move_mount(mntfd2, "", mntfd1, "submnt", MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt2.Release()();

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(move_mount(mntfd1, "", AT_FDCWD, dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt1.Release()();

  EXPECT_THAT(umount(JoinPath(dir.path(), "submnt").c_str()),
              SyscallSucceeds());
  EXPECT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
}

TEST(MoveMountTest, MoveMountSubmountToFs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // To move a mount out of an anonymous mount namespace, it must be
  // the *root* of that namespace.

  // Create first detached mount mntfd1.
  int fsfd1 = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd1, SyscallSucceeds());
  auto cleanup_fs1 = Cleanup([&]() { close(fsfd1); });
  EXPECT_THAT(fsconfig(fsfd1, FSCONFIG_SET_STRING, "source", "src1", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd1, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd1 = fsmount(fsfd1, 0, 0);
  ASSERT_THAT(mntfd1, SyscallSucceeds());
  auto cleanup_mnt1 = Cleanup([&]() { close(mntfd1); });

  EXPECT_THAT(mkdirat(mntfd1, "submnt", 0755), SyscallSucceeds());

  // Create second detached mount mntfd2.
  int fsfd2 = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd2, SyscallSucceeds());
  auto cleanup_fs2 = Cleanup([&]() { close(fsfd2); });
  EXPECT_THAT(fsconfig(fsfd2, FSCONFIG_SET_STRING, "source", "src2", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd2, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd2 = fsmount(fsfd2, 0, 0);
  ASSERT_THAT(mntfd2, SyscallSucceeds());
  auto cleanup_mnt2 = Cleanup([&]() { close(mntfd2); });

  // Move mntfd2 onto submnt of mntfd1.
  EXPECT_THAT(move_mount(mntfd2, "", mntfd1, "submnt", MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt2.Release()();

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Attempt to move *only* the submount (submnt of mntfd1) onto the real tree
  // (which should fail).
  EXPECT_THAT(move_mount(mntfd1, "submnt", AT_FDCWD, dir.path().c_str(), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MoveMountTest, MoveMountWithoutEmptyPath) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "src", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // Omit MOVE_MOUNT_F_EMPTY_PATH when passing mntfd and "".
  EXPECT_THAT(move_mount(mntfd, "", AT_FDCWD, dir.path().c_str(), 0),
              SyscallFailsWithErrno(ENOENT));
}

TEST(MoveMountTest, MoveMountLoop) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(fsfd, SyscallSucceeds());
  auto cleanup_fs = Cleanup([&]() { close(fsfd); });
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "src", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int mntfd = fsmount(fsfd, 0, 0);
  ASSERT_THAT(mntfd, SyscallSucceeds());
  auto cleanup_mnt = Cleanup([&]() { close(mntfd); });

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(move_mount(mntfd, "", AT_FDCWD, dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_mnt.Release();
  close(mntfd);

  EXPECT_THAT(mkdir(JoinPath(dir.path(), "child").c_str(), 0755),
              SyscallSucceeds());

  // Attempt to move parent mount under its own child directory.
  EXPECT_THAT(move_mount(AT_FDCWD, dir.path().c_str(), AT_FDCWD,
                         JoinPath(dir.path(), "child").c_str(), 0),
              SyscallFailsWithErrno(ELOOP));

  EXPECT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
}

// open_tree(2) tests

TEST(OpenTreeTest, OpenTreeNoCloneSuccess) {
  // No capability needed without OPEN_TREE_CLONE.
  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int fd = open_tree(AT_FDCWD, dir.path().c_str(), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  auto cleanup = Cleanup([&]() { close(fd); });

  // Returned fd is a path fd usable as a dirfd.
  struct stat st;
  EXPECT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
}

TEST(OpenTreeTest, OpenTreeCloneRequiresCapSysAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  ScopedThread([&]() {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_THAT(open_tree(AT_FDCWD, dir.path().c_str(), OPEN_TREE_CLONE),
                SyscallFailsWithErrno(EPERM));
  });
}

TEST(OpenTreeTest, OpenTreeRecursiveRequiresClone) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(open_tree(AT_FDCWD, dir.path().c_str(), AT_RECURSIVE),
              SyscallFailsWithErrno(EINVAL));
}

TEST(OpenTreeTest, OpenTreeInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // A high bit that isn't a known open_tree flag on Linux or gVisor.
  EXPECT_THAT(open_tree(AT_FDCWD, dir.path().c_str(), 1u << 30),
              SyscallFailsWithErrno(EINVAL));
}

TEST(OpenTreeTest, OpenTreeCloneNonRecursiveOnAttached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Create and attach the parent tmpfs via the new mount API.
  int parent_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(parent_fsfd, SyscallSucceeds());
  auto cleanup_parent_fs = Cleanup([&]() { close(parent_fsfd); });
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_SET_STRING, "source", "parent", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int parent_mntfd = fsmount(parent_fsfd, 0, 0);
  ASSERT_THAT(parent_mntfd, SyscallSucceeds());
  auto cleanup_parent_mnt = Cleanup([&]() { close(parent_mntfd); });

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(move_mount(parent_mntfd, "", AT_FDCWD, dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_parent_mnt.Release()();

  // Create the submount mountpoint, then attach a child tmpfs onto it.
  std::string sub_path = JoinPath(dir.path(), "sub");
  ASSERT_THAT(mkdir(sub_path.c_str(), 0755), SyscallSucceeds());

  int child_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(child_fsfd, SyscallSucceeds());
  auto cleanup_child_fs = Cleanup([&]() { close(child_fsfd); });
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_SET_STRING, "source", "child", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int child_mntfd = fsmount(child_fsfd, 0, 0);
  ASSERT_THAT(child_mntfd, SyscallSucceeds());
  auto cleanup_child_mnt = Cleanup([&]() { close(child_mntfd); });

  EXPECT_THAT(move_mount(child_mntfd, "", AT_FDCWD, sub_path.c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_child_mnt.Release()();
  auto cleanup_child_umount = Cleanup([&]() { umount(sub_path.c_str()); });
  auto cleanup_parent_umount = Cleanup([&]() { umount(dir.path().c_str()); });

  int markerfd =
      open(JoinPath(sub_path, "marker_sub").c_str(), O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(markerfd, SyscallSucceeds());
  EXPECT_THAT(close(markerfd), SyscallSucceeds());

  // Clone parent without AT_RECURSIVE: the submount and its contents should
  // not be visible in the clone, though the (now-empty) mountpoint dir is.
  int treefd = open_tree(AT_FDCWD, dir.path().c_str(), OPEN_TREE_CLONE);
  ASSERT_THAT(treefd, SyscallSucceeds());
  auto cleanup_tree = Cleanup([&]() { close(treefd); });

  EXPECT_THAT(faccessat(treefd, "sub", F_OK, 0), SyscallSucceeds());
  EXPECT_THAT(faccessat(treefd, "sub/marker_sub", F_OK, 0),
              SyscallFailsWithErrno(ENOENT));
}

TEST(OpenTreeTest, OpenTreeCloneNonRecursiveOnDetached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Create the parent tmpfs as a detached mount.
  int parent_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(parent_fsfd, SyscallSucceeds());
  auto cleanup_parent_fs = Cleanup([&]() { close(parent_fsfd); });
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_SET_STRING, "source", "parent", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int parent_mntfd = fsmount(parent_fsfd, 0, 0);
  ASSERT_THAT(parent_mntfd, SyscallSucceeds());
  auto cleanup_parent_mnt = Cleanup([&]() { close(parent_mntfd); });

  // Create the submount mountpoint inside the detached parent and attach a
  // child tmpfs there (still all detached).
  ASSERT_THAT(mkdirat(parent_mntfd, "sub", 0755), SyscallSucceeds());

  int child_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(child_fsfd, SyscallSucceeds());
  auto cleanup_child_fs = Cleanup([&]() { close(child_fsfd); });
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_SET_STRING, "source", "child", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int child_mntfd = fsmount(child_fsfd, 0, 0);
  ASSERT_THAT(child_mntfd, SyscallSucceeds());
  auto cleanup_child_mnt = Cleanup([&]() { close(child_mntfd); });

  EXPECT_THAT(
      move_mount(child_mntfd, "", parent_mntfd, "sub", MOVE_MOUNT_F_EMPTY_PATH),
      SyscallSucceeds());
  cleanup_child_mnt.Release()();

  int markerfd = openat(parent_mntfd, "sub/marker_sub", O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(markerfd, SyscallSucceeds());
  EXPECT_THAT(close(markerfd), SyscallSucceeds());

  // Clone parent without AT_RECURSIVE.
  int treefd = open_tree(parent_mntfd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE);
  ASSERT_THAT(treefd, SyscallSucceeds());
  auto cleanup_tree = Cleanup([&]() { close(treefd); });

  EXPECT_THAT(faccessat(treefd, "sub", F_OK, 0), SyscallSucceeds());
  EXPECT_THAT(faccessat(treefd, "sub/marker_sub", F_OK, 0),
              SyscallFailsWithErrno(ENOENT));
}

TEST(OpenTreeTest, OpenTreeCloneRecursiveOnAttached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Create and attach the parent tmpfs.
  int parent_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(parent_fsfd, SyscallSucceeds());
  auto cleanup_parent_fs = Cleanup([&]() { close(parent_fsfd); });
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_SET_STRING, "source", "parent", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int parent_mntfd = fsmount(parent_fsfd, 0, 0);
  ASSERT_THAT(parent_mntfd, SyscallSucceeds());
  auto cleanup_parent_mnt = Cleanup([&]() { close(parent_mntfd); });

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(move_mount(parent_mntfd, "", AT_FDCWD, dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_parent_mnt.Release()();

  // Mount a child tmpfs at parent/sub.
  std::string sub_path = JoinPath(dir.path(), "sub");
  ASSERT_THAT(mkdir(sub_path.c_str(), 0755), SyscallSucceeds());

  int child_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(child_fsfd, SyscallSucceeds());
  auto cleanup_child_fs = Cleanup([&]() { close(child_fsfd); });
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_SET_STRING, "source", "child", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int child_mntfd = fsmount(child_fsfd, 0, 0);
  ASSERT_THAT(child_mntfd, SyscallSucceeds());
  auto cleanup_child_mnt = Cleanup([&]() { close(child_mntfd); });

  EXPECT_THAT(move_mount(child_mntfd, "", AT_FDCWD, sub_path.c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_child_mnt.Release()();
  auto cleanup_child_umount = Cleanup([&]() { umount(sub_path.c_str()); });
  auto cleanup_parent_umount = Cleanup([&]() { umount(dir.path().c_str()); });

  int markerfd =
      open(JoinPath(sub_path, "marker_sub").c_str(), O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(markerfd, SyscallSucceeds());
  EXPECT_THAT(close(markerfd), SyscallSucceeds());

  // Clone parent with AT_RECURSIVE: the submount is carried along.
  int treefd =
      open_tree(AT_FDCWD, dir.path().c_str(), OPEN_TREE_CLONE | AT_RECURSIVE);
  ASSERT_THAT(treefd, SyscallSucceeds());
  auto cleanup_tree = Cleanup([&]() { close(treefd); });

  EXPECT_THAT(faccessat(treefd, "sub/marker_sub", F_OK, 0), SyscallSucceeds());

  // The cloned tree is itself a detached mount; verify it can be attached
  // via move_mount, with the submount still present at the new location.
  auto const dst_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(move_mount(treefd, "", AT_FDCWD, dst_dir.path().c_str(),
                         MOVE_MOUNT_F_EMPTY_PATH),
              SyscallSucceeds());
  cleanup_tree.Release()();
  EXPECT_THAT(access(JoinPath(dst_dir.path(), "sub/marker_sub").c_str(), F_OK),
              SyscallSucceeds());
  EXPECT_THAT(umount(JoinPath(dst_dir.path(), "sub").c_str()),
              SyscallSucceeds());
  EXPECT_THAT(umount(dst_dir.path().c_str()), SyscallSucceeds());
}

TEST(OpenTreeTest, OpenTreeCloneRecursiveOnDetached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Create the parent tmpfs as a detached mount.
  int parent_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(parent_fsfd, SyscallSucceeds());
  auto cleanup_parent_fs = Cleanup([&]() { close(parent_fsfd); });
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_SET_STRING, "source", "parent", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(parent_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int parent_mntfd = fsmount(parent_fsfd, 0, 0);
  ASSERT_THAT(parent_mntfd, SyscallSucceeds());
  auto cleanup_parent_mnt = Cleanup([&]() { close(parent_mntfd); });

  ASSERT_THAT(mkdirat(parent_mntfd, "sub", 0755), SyscallSucceeds());

  int child_fsfd = fsopen(kTmpfs, 0);
  ASSERT_THAT(child_fsfd, SyscallSucceeds());
  auto cleanup_child_fs = Cleanup([&]() { close(child_fsfd); });
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_SET_STRING, "source", "child", 0),
              SyscallSucceeds());
  EXPECT_THAT(fsconfig(child_fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0),
              SyscallSucceeds());
  int child_mntfd = fsmount(child_fsfd, 0, 0);
  ASSERT_THAT(child_mntfd, SyscallSucceeds());
  auto cleanup_child_mnt = Cleanup([&]() { close(child_mntfd); });

  EXPECT_THAT(
      move_mount(child_mntfd, "", parent_mntfd, "sub", MOVE_MOUNT_F_EMPTY_PATH),
      SyscallSucceeds());
  cleanup_child_mnt.Release()();

  int markerfd = openat(parent_mntfd, "sub/marker_sub", O_CREAT | O_RDWR, 0644);
  ASSERT_THAT(markerfd, SyscallSucceeds());
  EXPECT_THAT(close(markerfd), SyscallSucceeds());

  // Clone parent with AT_RECURSIVE on the detached mountfd.
  int treefd = open_tree(parent_mntfd, "",
                         AT_EMPTY_PATH | OPEN_TREE_CLONE | AT_RECURSIVE);
  ASSERT_THAT(treefd, SyscallSucceeds());
  auto cleanup_tree = Cleanup([&]() { close(treefd); });

  EXPECT_THAT(faccessat(treefd, "sub/marker_sub", F_OK, 0), SyscallSucceeds());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
