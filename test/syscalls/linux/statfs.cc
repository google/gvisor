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
#include <linux/magic.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif
#ifndef _LINUX_STATFS_H
#define _LINUX_STATFS_H
#define ST_RDONLY 0x0001
#define ST_NOSUID 0x0002
#define ST_NODEV 0x0004
#define ST_NOEXEC 0x0008
#define ST_NOATIME 0x0400
#define ST_NOSYMFOLLOW 0x2000
#endif

TEST(StatfsTest, CannotStatBadPath) {
  auto temp_file = NewTempAbsPath();

  struct statfs st;
  EXPECT_THAT(statfs(temp_file.c_str(), &st), SyscallFailsWithErrno(ENOENT));
}

TEST(StatfsTest, TempPath) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  struct statfs st;
  EXPECT_THAT(statfs(temp_file.path().c_str(), &st), SyscallSucceeds());
  EXPECT_GT(st.f_namelen, 0);
}

TEST(StatfsTest, InternalDevShm) {
  struct statfs st;
  EXPECT_THAT(statfs("/dev/shm", &st), SyscallSucceeds());

  EXPECT_GT(st.f_namelen, 0);
  // This assumes that /dev/shm is tmpfs.
  // Note: We could be an overlay on some configurations.
  EXPECT_TRUE(st.f_type == TMPFS_MAGIC || st.f_type == OVERLAYFS_SUPER_MAGIC);
}

TEST(StatFsTest, MountFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // From mount flags to statfs flags.
  const std::map<int64_t, int64_t> flags = {
      {MS_NOEXEC, ST_NOEXEC}, {MS_NOATIME, ST_NOATIME},
      {MS_NODEV, ST_NODEV},   {MS_NOSUID, ST_NOSUID},
      {MS_RDONLY, ST_RDONLY}, {MS_NOSYMFOLLOW, ST_NOSYMFOLLOW}};

  for (const auto& [mount_flag, statfs_flag] : flags) {
    auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", dir.path(), "tmpfs", mount_flag, "mode=0777", 0));
    struct statfs st;
    EXPECT_THAT(statfs(dir.path().c_str(), &st), SyscallSucceeds());
    EXPECT_TRUE((st.f_flags & statfs_flag) == statfs_flag);
  }
}

TEST(FstatfsTest, CannotStatBadFd) {
  struct statfs st;
  EXPECT_THAT(fstatfs(-1, &st), SyscallFailsWithErrno(EBADF));
}

TEST(FstatfsTest, TempPath) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_RDONLY));

  struct statfs st;
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
  EXPECT_GT(st.f_namelen, 0);
}

TEST(FstatfsTest, CanStatFileWithOpath) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_PATH));

  struct statfs st;
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
}

TEST(FstatfsTest, InternalDevShm) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/shm", O_RDONLY));

  struct statfs st;
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
  EXPECT_GT(st.f_namelen, 0);
  // This assumes that /dev/shm is tmpfs.
  // Note: We could be an overlay on some configurations.
  EXPECT_TRUE(st.f_type == TMPFS_MAGIC || st.f_type == OVERLAYFS_SUPER_MAGIC);
}

// Tests that the number of blocks free in the filesystem, as reported by
// statfs(2) updates appropriately when pages are allocated.
TEST(FstatfsTest, BlocksFree) {
  const std::string file_path = NewTempAbsPath();
  const std::string dir = std::string(Dirname(file_path));
  struct statfs st_before;
  EXPECT_THAT(statfs(dir.c_str(), &st_before), SyscallSucceeds());
  // Only test for tmpfs. Passthru gofer does not expose host filesystem
  // statfs(2) results. It always returns 0 for blocks free.
  SKIP_IF(st_before.f_type != TMPFS_MAGIC);

  ASSERT_NO_ERRNO(CreateWithContents(file_path, "abcd"));
  struct statfs st_after;
  EXPECT_THAT(statfs(dir.c_str(), &st_after), SyscallSucceeds());
  EXPECT_GT(st_before.f_bfree, st_after.f_bfree);
  EXPECT_GT(st_before.f_bavail, st_after.f_bavail);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
