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

#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/verity_util.h"

namespace gvisor {
namespace testing {

namespace {

const char kSymlink[] = "verity_symlink";

class SymlinkTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Verity is implemented in VFS2.
    SKIP_IF(IsRunningWithVFS1());

    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    // Mount a tmpfs file system, to be wrapped by a verity fs.
    tmpfs_dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", tmpfs_dir_.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());

    // Create a new file in the tmpfs mount.
    file_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateFileWith(tmpfs_dir_.path(), kContents, 0777));
    filename_ = Basename(file_.path());

    // Create a symlink to the file.
    ASSERT_THAT(symlink(file_.path().c_str(),
                        JoinPath(tmpfs_dir_.path(), kSymlink).c_str()),
                SyscallSucceeds());
  }

  TempPath tmpfs_dir_;
  TempPath file_;
  std::string filename_;
};

TEST_F(SymlinkTest, Success) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_,
                  {EnableTarget(kSymlink, O_RDONLY | O_NOFOLLOW)}));

  char buf[256];
  EXPECT_THAT(
      readlink(JoinPath(verity_dir, kSymlink).c_str(), buf, sizeof(buf)),
      SyscallSucceeds());
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, kSymlink).c_str(), O_RDONLY, 0777));
  EXPECT_THAT(ReadFd(verity_fd.get(), buf, sizeof(kContents)),
              SyscallSucceeds());
}

TEST_F(SymlinkTest, DeleteLink) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_,
                  {EnableTarget(kSymlink, O_RDONLY | O_NOFOLLOW)}));

  ASSERT_THAT(unlink(JoinPath(tmpfs_dir_.path(), kSymlink).c_str()),
              SyscallSucceeds());
  char buf[256];
  EXPECT_THAT(
      readlink(JoinPath(verity_dir, kSymlink).c_str(), buf, sizeof(buf)),
      SyscallFailsWithErrno(EIO));
  EXPECT_THAT(open(JoinPath(verity_dir, kSymlink).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(SymlinkTest, ModifyLink) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_,
                  {EnableTarget(kSymlink, O_RDONLY | O_NOFOLLOW)}));

  ASSERT_THAT(unlink(JoinPath(tmpfs_dir_.path(), kSymlink).c_str()),
              SyscallSucceeds());

  std::string newlink = "newlink";
  ASSERT_THAT(symlink(JoinPath(tmpfs_dir_.path(), newlink).c_str(),
                      JoinPath(tmpfs_dir_.path(), kSymlink).c_str()),
              SyscallSucceeds());
  char buf[256];
  EXPECT_THAT(
      readlink(JoinPath(verity_dir, kSymlink).c_str(), buf, sizeof(buf)),
      SyscallFailsWithErrno(EIO));
  EXPECT_THAT(open(JoinPath(verity_dir, kSymlink).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
