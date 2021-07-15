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
#include <time.h>

#include <iomanip>
#include <sstream>

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

class IoctlTest : public ::testing::Test {
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
  }

  TempPath tmpfs_dir_;
  TempPath file_;
  std::string filename_;
};

TEST_F(IoctlTest, Enable) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir_.path();
  auto const verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()),
      SyscallSucceeds());

  // Confirm that the verity flag is absent.
  int flag = 0;
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir.path(), filename_), O_RDONLY, 0777));
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_GETFLAGS, &flag), SyscallSucceeds());
  EXPECT_EQ(flag & FS_VERITY_FL, 0);

  // Enable the file and confirm that the verity flag is present.
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_GETFLAGS, &flag), SyscallSucceeds());
  EXPECT_EQ(flag & FS_VERITY_FL, FS_VERITY_FL);
}

TEST_F(IoctlTest, Measure) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir_.path();
  auto const verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()),
      SyscallSucceeds());

  // Confirm that the file cannot be measured.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir.path(), filename_), O_RDONLY, 0777));
  uint8_t digest_array[sizeof(struct fsverity_digest) + kMaxDigestSize] = {0};
  struct fsverity_digest* digest =
      reinterpret_cast<struct fsverity_digest*>(digest_array);
  digest->digest_size = kMaxDigestSize;
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_MEASURE_VERITY, digest),
              SyscallFailsWithErrno(ENODATA));

  // Enable the file and confirm that the file can be measured.
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_MEASURE_VERITY, digest),
              SyscallSucceeds());
  EXPECT_EQ(digest->digest_size, kDefaultDigestSize);
}

TEST_F(IoctlTest, Mount) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Make sure the file can be open and read in the mounted verity fs.
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));
  char buf[sizeof(kContents)];
  EXPECT_THAT(ReadFd(verity_fd.get(), buf, sizeof(kContents)),
              SyscallSucceeds());
}

TEST_F(IoctlTest, NonExistingFile) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Confirm that opening a non-existing file in the verity-enabled directory
  // triggers the expected error instead of verification failure.
  EXPECT_THAT(
      open(JoinPath(verity_dir, filename_ + "abc").c_str(), O_RDONLY, 0777),
      SyscallFailsWithErrno(ENOENT));
}

TEST_F(IoctlTest, ModifiedFile) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Modify the file and check verification failure upon reading from it.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(tmpfs_dir_.path(), filename_), O_RDWR, 0777));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), sizeof(kContents) - 1));

  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));
  char buf[sizeof(kContents)];
  EXPECT_THAT(pread(verity_fd.get(), buf, 16, 0), SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, ModifiedMerkle) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Modify the Merkle file and check verification failure upon opening the
  // corresponding file.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(MerklePath(JoinPath(tmpfs_dir_.path(), filename_)), O_RDWR, 0777));
  auto stat = ASSERT_NO_ERRNO_AND_VALUE(Fstat(fd.get()));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), stat.st_size));

  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, ModifiedDirMerkle) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Modify the Merkle file for the parent directory and check verification
  // failure upon opening the corresponding file.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(MerkleRootPath(JoinPath(tmpfs_dir_.path(), "root")), O_RDWR, 0777));
  auto stat = ASSERT_NO_ERRNO_AND_VALUE(Fstat(fd.get()));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), stat.st_size));

  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, Stat) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  struct stat st;
  EXPECT_THAT(stat(JoinPath(verity_dir, filename_).c_str(), &st),
              SyscallSucceeds());
}

TEST_F(IoctlTest, ModifiedStat) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  EXPECT_THAT(chmod(JoinPath(tmpfs_dir_.path(), filename_).c_str(), 0644),
              SyscallSucceeds());
  struct stat st;
  EXPECT_THAT(stat(JoinPath(verity_dir, filename_).c_str(), &st),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, DeleteFile) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  EXPECT_THAT(unlink(JoinPath(tmpfs_dir_.path(), filename_).c_str()),
              SyscallSucceeds());
  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, DeleteMerkle) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  EXPECT_THAT(
      unlink(MerklePath(JoinPath(tmpfs_dir_.path(), filename_)).c_str()),
      SyscallSucceeds());
  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, RenameFile) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  std::string new_file_name = "renamed-" + filename_;
  EXPECT_THAT(rename(JoinPath(tmpfs_dir_.path(), filename_).c_str(),
                     JoinPath(tmpfs_dir_.path(), new_file_name).c_str()),
              SyscallSucceeds());
  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

TEST_F(IoctlTest, RenameMerkle) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  std::string new_file_name = "renamed-" + filename_;
  EXPECT_THAT(
      rename(MerklePath(JoinPath(tmpfs_dir_.path(), filename_)).c_str(),
             MerklePath(JoinPath(tmpfs_dir_.path(), new_file_name)).c_str()),
      SyscallSucceeds());
  EXPECT_THAT(open(JoinPath(verity_dir, filename_).c_str(), O_RDONLY, 0777),
              SyscallFailsWithErrno(EIO));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
