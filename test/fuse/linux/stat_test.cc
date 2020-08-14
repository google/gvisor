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
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class StatTest : public FuseTest {
 public:
  bool StatsAreEqual(struct stat expected, struct stat actual) {
    // device number will be dynamically allocated by kernel, we cannot know
    // in advance
    actual.st_dev = expected.st_dev;
    return memcmp(&expected, &actual, sizeof(struct stat)) == 0;
  }
};

TEST_F(StatTest, StatNormal) {
  // Set up fixture.
  mode_t expected_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
  struct timespec atime = {.tv_sec = 1595436289, .tv_nsec = 134150844};
  struct timespec mtime = {.tv_sec = 1595436290, .tv_nsec = 134150845};
  struct timespec ctime = {.tv_sec = 1595436291, .tv_nsec = 134150846};
  struct fuse_attr attr = {
      .ino = 1,
      .size = 512,
      .blocks = 4,
      .atime = static_cast<uint64_t>(atime.tv_sec),
      .mtime = static_cast<uint64_t>(mtime.tv_sec),
      .ctime = static_cast<uint64_t>(ctime.tv_sec),
      .atimensec = static_cast<uint32_t>(atime.tv_nsec),
      .mtimensec = static_cast<uint32_t>(mtime.tv_nsec),
      .ctimensec = static_cast<uint32_t>(ctime.tv_nsec),
      .mode = expected_mode,
      .nlink = 2,
      .uid = 1234,
      .gid = 4321,
      .rdev = 12,
      .blksize = 4096,
  };
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
  };
  struct fuse_attr_out out_payload = {
      .attr = attr,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_GETATTR, iov_out);

  // Do integration test.
  struct stat stat_buf;
  EXPECT_THAT(stat(mount_point_.path().c_str(), &stat_buf), SyscallSucceeds());

  // Check filesystem operation result.
  struct stat expected_stat = {
      .st_ino = attr.ino,
      .st_nlink = attr.nlink,
      .st_mode = expected_mode,
      .st_uid = attr.uid,
      .st_gid = attr.gid,
      .st_rdev = attr.rdev,
      .st_size = static_cast<off_t>(attr.size),
      .st_blksize = attr.blksize,
      .st_blocks = static_cast<blkcnt_t>(attr.blocks),
      .st_atim = atime,
      .st_mtim = mtime,
      .st_ctim = ctime,
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

  // Do integration test.
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

}  // namespace

}  // namespace testing
}  // namespace gvisor
