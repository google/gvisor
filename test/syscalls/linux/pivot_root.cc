// Copyright 2021 The gVisor Authors.
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
#include <stddef.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(PivotRootTest, Success) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_SUCCESS(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, CreatesNewRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));
  auto file_in_new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(new_root.path()));
  const std::string file_in_new_root_path = file_in_new_root.path();
  const std::string file_in_new_root_new_path =
      absl::StrCat("/", Basename(file_in_new_root_path));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    // pivot_root and switch into new_root.
    TEST_CHECK_SUCCESS(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()));
    TEST_CHECK_SUCCESS(chdir("/"));
    // Should not be able to stat file by its full path.
    char buf[1024];
    struct stat statbuf;
    TEST_CHECK_ERRNO(stat(file_in_new_root_path.c_str(), &statbuf), ENOENT);
    // Should be able to stat file at new rooted path.
    TEST_CHECK_SUCCESS(stat(file_in_new_root_new_path.c_str(), &statbuf));
    // getcwd should return "/".
    TEST_CHECK_SUCCESS(syscall(__NR_getcwd, buf, sizeof(buf)));
    TEST_CHECK_SUCCESS(strcmp(buf, "/") == 0);
    // Statting '.', '..', '/', and '/..' all return the same dev and inode.
    struct stat statbuf_dot;
    TEST_CHECK_SUCCESS(stat(".", &statbuf_dot));
    struct stat statbuf_dotdot;
    TEST_CHECK_SUCCESS(stat("..", &statbuf_dotdot));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_dotdot.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_dotdot.st_ino);
    struct stat statbuf_slash;
    TEST_CHECK_SUCCESS(stat("/", &statbuf_slash));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_slash.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_slash.st_ino);
    struct stat statbuf_slashdotdot;
    TEST_CHECK_SUCCESS(stat("/..", &statbuf_slashdotdot));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_slashdotdot.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_slashdotdot.st_ino);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, MovesOldRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));

  const std::string old_root_new_path =
      absl::StrCat("/", Basename(put_old_path));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    struct stat statbuf_oldroot;
    TEST_CHECK_SUCCESS(stat("/", &statbuf_oldroot));
    // pivot_root and switch into new_root.
    TEST_CHECK_SUCCESS(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()));
    TEST_CHECK_SUCCESS(chdir("/"));
    // Should not be able to stat file by its full path.
    struct stat statbuf;
    TEST_CHECK_ERRNO(stat(put_old_path.c_str(), &statbuf), ENOENT);
    // Should be able to chdir to old root.
    TEST_CHECK_SUCCESS(chdir(old_root_new_path.c_str()));
    // Statting the root dir from before pivot_root and the put_old location
    // should return the same inode and device.
    struct stat statbuf_dot;
    TEST_CHECK_SUCCESS(stat(".", &statbuf_dot));
    TEST_CHECK(statbuf_dot.st_ino == statbuf_oldroot.st_ino);
    TEST_CHECK(statbuf_dot.st_dev == statbuf_oldroot.st_dev);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, ChangesCwdForAllProcesses) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));
  const std::string old_root_new_path =
      absl::StrCat("/", Basename(put_old_path));

  struct stat statbuf_newroot;
  TEST_CHECK_SUCCESS(stat(new_root.path().c_str(), &statbuf_newroot));
  // Change cwd to the root path.
  chdir(root.path().c_str());
  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_SUCCESS(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
  // pivot_root should change the cwd/root directory all threads and processes
  // in the current mount namespace if they pointed the old root.
  struct stat statbuf_cwd_after_syscall;
  EXPECT_THAT(stat(".", &statbuf_cwd_after_syscall), SyscallSucceeds());
  EXPECT_EQ(statbuf_cwd_after_syscall.st_ino, statbuf_newroot.st_ino);
  EXPECT_EQ(statbuf_cwd_after_syscall.st_dev, statbuf_newroot.st_dev);
}

TEST(PivotRootTest, DotDot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));

  auto file_in_new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(new_root.path()));
  const std::string file_in_new_root_path =
      std::string(Basename(file_in_new_root.path()));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_SUCCESS(chdir(new_root_path.c_str()));
    // pivot_root should be able to stack put_old ontop of new_root. This allows
    // users to pivot_root without creating a temp directory.
    TEST_CHECK_SUCCESS(syscall(__NR_pivot_root, ".", "."));
    TEST_CHECK_SUCCESS(umount2(".", MNT_DETACH));
    struct stat statbuf;
    TEST_CHECK_SUCCESS(stat(file_in_new_root_path.c_str(), &statbuf));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, NotDir) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto file2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(
      syscall(__NR_pivot_root, file1.path().c_str(), file2.path().c_str()),
      SyscallFailsWithErrno(ENOTDIR));
  EXPECT_THAT(
      syscall(__NR_pivot_root, file1.path().c_str(), dir.path().c_str()),
      SyscallFailsWithErrno(ENOTDIR));
  EXPECT_THAT(
      syscall(__NR_pivot_root, dir.path().c_str(), file2.path().c_str()),
      SyscallFailsWithErrno(ENOTDIR));
}

TEST(PivotRootTest, NotExist) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(syscall(__NR_pivot_root, "/foo/bar", "/bar/baz"),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(syscall(__NR_pivot_root, dir.path().c_str(), "/bar/baz"),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(syscall(__NR_pivot_root, "/foo/bar", dir.path().c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(PivotRootTest, WithoutCapability) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETPCAP)));

  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string new_root_path = new_root.path();
  EXPECT_THAT(mount("", new_root_path.c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root_path));
  const std::string put_old_path = put_old.path();

  AutoCapability cap(CAP_SYS_ADMIN, false);
  EXPECT_THAT(
      syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
      SyscallFailsWithErrno(EPERM));
}

TEST(PivotRootTest, NewRootOnRootMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path().c_str()));
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));

  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EBUSY);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, NewRootNotAMountpoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  // Make sure new_root is on a separate mount, otherwise this is the same
  // as the NewRootOnRootMount test.
  auto mountpoint =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path().c_str()));
  EXPECT_THAT(mount("", mountpoint.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string mountpoint_path =
      absl::StrCat("/", Basename(mountpoint.path()));
  auto new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(mountpoint.path()));
  const std::string new_root_path =
      absl::StrCat(mountpoint_path, "/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, PutOldNotUnderNewRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto put_old = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string put_old_path = absl::StrCat("/", Basename(put_old.path()));
  EXPECT_THAT(mount("", put_old.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, CurrentRootNotAMountPoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path =
      absl::StrCat("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      absl::StrCat(new_root_path, "/", Basename(put_old.path()));

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, OnRootFS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string new_root_path = new_root.path();
  EXPECT_THAT(mount("", new_root_path.c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root_path));
  const std::string put_old_path = put_old.path();

  const auto rest = [&] {
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, OnSharedNewRootParent) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path = JoinPath("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      JoinPath(new_root_path, "/", Basename(put_old.path()));

  // Fails because parent has propagation type shared.
  EXPECT_THAT(mount(nullptr, root.path().c_str(), nullptr, MS_SHARED, nullptr),
              SyscallSucceeds());
  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, OnSharedNewRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path = JoinPath("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      JoinPath(new_root_path, "/", Basename(put_old.path()));

  // Fails because new_root has propagation type shared.
  EXPECT_THAT(
      mount(nullptr, new_root.path().c_str(), nullptr, MS_SHARED, nullptr),
      SyscallSucceeds());
  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(PivotRootTest, OnSharedPutOldMountpoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("", root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  EXPECT_THAT(mount("", new_root.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  const std::string new_root_path = JoinPath("/", Basename(new_root.path()));
  auto put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(new_root.path()));
  const std::string put_old_path =
      JoinPath(new_root_path, "/", Basename(put_old.path()));

  // Fails because put_old is a mountpoint and has propagation type shared.
  EXPECT_THAT(mount("", put_old.path().c_str(), "tmpfs", 0, "mode=0700"),
              SyscallSucceeds());
  EXPECT_THAT(
      mount(nullptr, put_old.path().c_str(), nullptr, MS_SHARED, nullptr),
      SyscallSucceeds());
  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.path().c_str()));
    TEST_CHECK_ERRNO(
        syscall(__NR_pivot_root, new_root_path.c_str(), put_old_path.c_str()),
        EINVAL);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
