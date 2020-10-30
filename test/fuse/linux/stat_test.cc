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
#include <linux/fuse.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_fd_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class StatTest : public FuseFdTest {
 public:
  void SetUp() override {
    FuseFdTest::SetUp();
    test_file_path_ = JoinPath(mount_point_.path(), test_file_);
  }

 protected:
  bool StatsAreEqual(struct stat expected, struct stat actual) {
    // Device number will be dynamically allocated by kernel, we cannot know in
    // advance.
    actual.st_dev = expected.st_dev;
    return memcmp(&expected, &actual, sizeof(struct stat)) == 0;
  }

  const std::string test_file_ = "testfile";
  const mode_t expected_mode = S_IFREG | S_IRUSR | S_IWUSR;
  const uint64_t fh = 23;

  std::string test_file_path_;
};

TEST_F(StatTest, StatNormal) {
  // Set up fixture.
  struct fuse_attr attr = DefaultFuseAttr(expected_mode, 1);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
  };
  struct fuse_attr_out out_payload = {
      .attr = attr,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_GETATTR, iov_out);

  // Make syscall.
  struct stat stat_buf;
  EXPECT_THAT(stat(mount_point_.path().c_str(), &stat_buf), SyscallSucceeds());

  // Check filesystem operation result.
  struct stat expected_stat = {
      .st_ino = attr.ino,
#ifdef __aarch64__
      .st_mode = expected_mode,
      .st_nlink = attr.nlink,
#else
      .st_nlink = attr.nlink,
      .st_mode = expected_mode,
#endif
      .st_uid = attr.uid,
      .st_gid = attr.gid,
      .st_rdev = attr.rdev,
      .st_size = static_cast<off_t>(attr.size),
      .st_blksize = attr.blksize,
      .st_blocks = static_cast<blkcnt_t>(attr.blocks),
      .st_atim = (struct timespec){.tv_sec = static_cast<int>(attr.atime),
                                   .tv_nsec = attr.atimensec},
      .st_mtim = (struct timespec){.tv_sec = static_cast<int>(attr.mtime),
                                   .tv_nsec = attr.mtimensec},
      .st_ctim = (struct timespec){.tv_sec = static_cast<int>(attr.ctime),
                                   .tv_nsec = attr.ctimensec},
  };
  EXPECT_TRUE(StatsAreEqual(stat_buf, expected_stat));

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_getattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_GETATTR);
  EXPECT_EQ(in_payload.getattr_flags, 0);
  EXPECT_EQ(in_payload.fh, 0);
}

TEST_F(StatTest, StatNotFound) {
  // Set up fixture.
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = -ENOENT,
  };
  auto iov_out = FuseGenerateIovecs(out_header);
  SetServerResponse(FUSE_GETATTR, iov_out);

  // Make syscall.
  struct stat stat_buf;
  EXPECT_THAT(stat(mount_point_.path().c_str(), &stat_buf),
              SyscallFailsWithErrno(ENOENT));

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_getattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_GETATTR);
  EXPECT_EQ(in_payload.getattr_flags, 0);
  EXPECT_EQ(in_payload.fh, 0);
}

TEST_F(StatTest, FstatNormal) {
  // Set up fixture.
  SetServerInodeLookup(test_file_);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenPath(test_file_path_, O_RDONLY, fh));
  auto close_fd = CloseFD(fd);

  struct fuse_attr attr = DefaultFuseAttr(expected_mode, 2);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
  };
  struct fuse_attr_out out_payload = {
      .attr = attr,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_GETATTR, iov_out);

  // Make syscall.
  struct stat stat_buf;
  EXPECT_THAT(fstat(fd.get(), &stat_buf), SyscallSucceeds());

  // Check filesystem operation result.
  struct stat expected_stat = {
      .st_ino = attr.ino,
#ifdef __aarch64__
      .st_mode = expected_mode,
      .st_nlink = attr.nlink,
#else
      .st_nlink = attr.nlink,
      .st_mode = expected_mode,
#endif
      .st_uid = attr.uid,
      .st_gid = attr.gid,
      .st_rdev = attr.rdev,
      .st_size = static_cast<off_t>(attr.size),
      .st_blksize = attr.blksize,
      .st_blocks = static_cast<blkcnt_t>(attr.blocks),
      .st_atim = (struct timespec){.tv_sec = static_cast<int>(attr.atime),
                                   .tv_nsec = attr.atimensec},
      .st_mtim = (struct timespec){.tv_sec = static_cast<int>(attr.mtime),
                                   .tv_nsec = attr.mtimensec},
      .st_ctim = (struct timespec){.tv_sec = static_cast<int>(attr.ctime),
                                   .tv_nsec = attr.ctimensec},
  };
  EXPECT_TRUE(StatsAreEqual(stat_buf, expected_stat));

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_getattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_GETATTR);
  EXPECT_EQ(in_payload.getattr_flags, 0);
  EXPECT_EQ(in_payload.fh, 0);
}

TEST_F(StatTest, StatByFileHandle) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, expected_mode, 0);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenPath(test_file_path_, O_RDONLY, fh));
  auto close_fd = CloseFD(fd);

  struct fuse_attr attr = DefaultFuseAttr(expected_mode, 2, 0);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
  };
  struct fuse_attr_out out_payload = {
      .attr = attr,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_GETATTR, iov_out);

  // Make syscall.
  std::vector<char> buf(1);
  // Since this is an empty file, it won't issue FUSE_READ. But a FUSE_GETATTR
  // will be issued before read completes.
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_getattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_GETATTR);
  EXPECT_EQ(in_payload.getattr_flags, FUSE_GETATTR_FH);
  EXPECT_EQ(in_payload.fh, fh);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
