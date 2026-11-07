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

#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// DirentIno returns the directory entry inode number of name in dir.
ino_t DirentIno(const std::string& dir, const std::string& name) {
  DIR* dp = opendir(dir.c_str());
  EXPECT_NE(dp, nullptr) << dir;
  if (dp == nullptr) {
    return 0;
  }
  auto close_dir = Cleanup([dp] { EXPECT_EQ(closedir(dp), 0); });
  while (struct dirent* ent = readdir(dp)) {
    if (name == ent->d_name) {
      return ent->d_ino;
    }
  }
  ADD_FAILURE() << name << " is missing from " << dir;
  return 0;
}

// Mounts an overlay whose layers share one tmpfs and checks that the mount
// publishes one device number, that a directory entry inode matches stat, and
// that copy-up does not change a file's device and inode numbers.
TEST(OverlayInode, StableIdentity) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto umount_base = Cleanup(
      [&base] { EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds()); });

  const std::string lower = JoinPath(base.path(), "lower");
  const std::string upper = JoinPath(base.path(), "upper");
  const std::string work = JoinPath(base.path(), "work");
  const std::string merged = JoinPath(base.path(), "merged");
  for (const std::string& dir : {lower, upper, work, merged}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }
  const std::string sub = JoinPath(lower, "sub");
  ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
  const std::string lower_file = JoinPath(sub, "file");
  {
    const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
        Open(lower_file, O_CREAT | O_WRONLY | O_TRUNC, 0644));
    ASSERT_THAT(write(created.get(), "a", 1), SyscallSucceedsWithValue(1));
  }

  const std::string opts =
      absl::StrCat("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
  ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
              SyscallSucceeds());
  auto umount_merged = Cleanup(
      [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

  const std::string merged_sub = JoinPath(merged, "sub");
  const std::string merged_file = JoinPath(merged_sub, "file");
  struct stat dir_stat;
  struct stat file_stat;
  ASSERT_THAT(stat(merged_sub.c_str(), &dir_stat), SyscallSucceeds());
  ASSERT_THAT(stat(merged_file.c_str(), &file_stat), SyscallSucceeds());
  EXPECT_EQ(dir_stat.st_dev, file_stat.st_dev);
  EXPECT_EQ(DirentIno(merged, "sub"), dir_stat.st_ino);
  EXPECT_EQ(DirentIno(merged_sub, "file"), file_stat.st_ino);

  const FileDescriptor append =
      ASSERT_NO_ERRNO_AND_VALUE(Open(merged_file, O_WRONLY | O_APPEND, 0));
  ASSERT_THAT(write(append.get(), "b", 1), SyscallSucceedsWithValue(1));
  struct stat after;
  ASSERT_THAT(stat(merged_file.c_str(), &after), SyscallSucceeds());
  EXPECT_EQ(file_stat.st_dev, after.st_dev);
  EXPECT_EQ(file_stat.st_ino, after.st_ino);
  EXPECT_EQ(dir_stat.st_dev, after.st_dev);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
