// Copyright 2020 The gVisor Authors.
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
#include <sys/mount.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class MountTest : public FuseTest {
 protected:
  void CheckFUSECreateFile(std::string_view test_file_path) {
    std::string_view test_file_name = Basename(test_file_path.data());
    const mode_t mode = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;
    // Ensure the file doesn't exist.
    struct fuse_out_header out_header = {
        .len = sizeof(struct fuse_out_header),
        .error = -ENOENT,
    };
    auto iov_out = FuseGenerateIovecs(out_header);
    SetServerResponse(FUSE_LOOKUP, iov_out);

    // creat(2) is equal to open(2) with open_flags O_CREAT | O_WRONLY |
    // O_TRUNC.
    const mode_t new_mask = S_IWGRP | S_IWOTH;
    const int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
    out_header.error = 0;
    out_header.len = sizeof(struct fuse_out_header) +
                     sizeof(struct fuse_entry_out) +
                     sizeof(struct fuse_open_out);
    struct fuse_entry_out entry_payload = DefaultEntryOut(mode & ~new_mask, 2);
    struct fuse_open_out out_payload = {
        .fh = 1,
        .open_flags = open_flags,
    };
    iov_out = FuseGenerateIovecs(out_header, entry_payload, out_payload);
    SetServerResponse(FUSE_CREATE, iov_out);

    int fd;
    TempUmask mask(new_mask);
    EXPECT_THAT(fd = creat(test_file_path.data(), mode), SyscallSucceeds());
    EXPECT_THAT(fcntl(fd, F_GETFL),
                SyscallSucceedsWithValue(open_flags & O_ACCMODE));

    struct fuse_in_header in_header;
    struct fuse_create_in in_payload;
    std::vector<char> name(test_file_name.size() + 1);
    auto iov_in = FuseGenerateIovecs(in_header, in_payload, name);

    // Skip the request of FUSE_LOOKUP.
    SkipServerActualRequest();

    // Get the first FUSE_CREATE.
    GetServerActualRequest(iov_in);
    EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload) +
                                 test_file_name.size() + 1);
    EXPECT_EQ(in_header.opcode, FUSE_CREATE);
    EXPECT_EQ(in_payload.flags, open_flags);
    EXPECT_EQ(in_payload.mode, mode & ~new_mask);
    EXPECT_EQ(in_payload.umask, new_mask);
    EXPECT_EQ(std::string(name.data()), test_file_name);

    EXPECT_THAT(close(fd), SyscallSucceeds());
    // Skip the FUSE_RELEASE.
    SkipServerActualRequest();
  }
};

TEST(FuseMount, Success) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_WRONLY));
  std::string mopts =
      absl::StrFormat("fd=%d,user_id=%d,group_id=%d,rootmode=0777", fd.get(),
                      getuid(), getgid());

  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const auto mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "fuse", 0, mopts, 0));
}

TEST(FuseMount, SuccessFstype) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_WRONLY));
  std::string mopts =
      absl::StrFormat("fd=%d,user_id=%d,group_id=%d,rootmode=0777", fd.get(),
                      getuid(), getgid());

  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "fuse.testfs", 0, mopts, 0));
}

TEST(FuseMount, FDNotParsable) {
  int devfd;
  EXPECT_THAT(devfd = open("/dev/fuse", O_RDWR), SyscallSucceeds());
  std::string mount_opts = "fd=thiscantbeparsed";
  TempPath mount_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("fuse", mount_dir.path().c_str(), "fuse",
                    MS_NODEV | MS_NOSUID, mount_opts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, NoDevice) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, ""),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, ClosedFD) {
  FileDescriptor f = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_WRONLY));
  int fd = f.release();
  close(fd);
  std::string mopts = absl::StrCat("fd=", std::to_string(fd));

  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, mopts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, BadFD) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  std::string mopts = absl::StrCat("fd=", std::to_string(fd.get()));

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, mopts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(MountTest, ReuseFD) {
  std::string mopts =
      absl::StrFormat("fd=%d,user_id=%d,group_id=%d,rootmode=0777", dev_fd_,
                      getuid(), getgid());

  const std::string test_file1_path =
      JoinPath(mount_point_.path().c_str(), "testfile1");
  CheckFUSECreateFile(test_file1_path);

  auto mount_point1 = std::move(mount_point_);

  auto dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  MountFuse(dev_fd_, dir2, mopts.c_str());

  std::string test_file2_path =
      JoinPath(mount_point_.path().c_str(), "testfile2");
  CheckFUSECreateFile(test_file2_path);

  EXPECT_THAT(umount(mount_point1.path().c_str()), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
