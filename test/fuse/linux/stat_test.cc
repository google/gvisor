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

#include <string>
#include <vector>

#include "fuse_base.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class StatTest : public FuseTest {
 public:
  bool CompareRequest(void* expected_mem, size_t expected_len, void* real_mem,
                      size_t real_len) {
    if (expected_len != real_len){
      std::cerr << "expect header len " << expected_len << " but got "
                << real_len << std::endl;
      return false;
    };
    struct fuse_in_header* real_header =
        reinterpret_cast<fuse_in_header*>(real_mem);

    if (real_header->opcode != FUSE_GETATTR) {
      std::cerr << "expect header opcode " << FUSE_GETATTR << " but got "
                << real_header->opcode << std::endl;
      return false;
    }
    return true;
  }

  bool StatsAreEqual(struct stat expected, struct stat actual) {
    // device number will be dynamically allocated by kernel, we cannot know
    // in advance
    actual.st_dev = expected.st_dev;
    return memcmp(&expected, &actual, sizeof(struct stat)) == 0;
  }
};

TEST_F(StatTest, StatNormal) {
  struct iovec iov_in[2];
  struct iovec iov_out[2];

  mode_t expected_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
  struct timespec atime = {.tv_sec = 1595436289, .tv_nsec = 134150844};
  struct timespec mtime = {.tv_sec = 1595436290, .tv_nsec = 134150845};
  struct timespec ctime = {.tv_sec = 1595436291, .tv_nsec = 134150846};
  struct fuse_out_header out_header = {
      .len = 120,
      .error = 0,
      .unique = 4,
  };
  struct fuse_attr_out out_payload = {
      .attr_valid_nsec = 2,
      .attr =
          (struct fuse_attr){
              .ino = 1,
              .size = 512,
              .blocks = 4,
              .atime = uint64_t(atime.tv_sec),
              .mtime = uint64_t(mtime.tv_sec),
              .ctime = uint64_t(ctime.tv_sec),
              .atimensec = uint32_t(atime.tv_nsec),
              .mtimensec = uint32_t(mtime.tv_nsec),
              .ctimensec = uint32_t(ctime.tv_nsec),
              .mode = expected_mode,
              .nlink = 2,
              .uid = 1234,
              .gid = 4321,
              .rdev = 12,
              .blksize = 4096,
          },
  };
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;
  iov_out[1].iov_len = sizeof(out_payload);
  iov_out[1].iov_base = &out_payload;

  SetServerResponse(FUSE_GETATTR, iov_out, 2);

  struct stat stat_buf;
  EXPECT_THAT(stat(kMountPoint, &stat_buf), SyscallSucceeds());

  struct stat expected_stat = {
      .st_ino = 1,
      .st_nlink = 2,
      .st_mode = expected_mode,
      .st_uid = 1234,
      .st_gid = 4321,
      .st_rdev = 12,
      .st_size = 512,
      .st_blksize = 4096,
      .st_blocks = 4,
      .st_atim = atime,
      .st_mtim = mtime,
      .st_ctim = ctime,
  };
  EXPECT_TRUE(StatsAreEqual(stat_buf, expected_stat));

  // Check if the request sent is what we wanted.
  struct fuse_in_header expected_header = {
      .len = sizeof(struct fuse_in_header) + sizeof(struct fuse_getattr_in),
      .opcode = FUSE_GETATTR,
      .unique = 4,
      .nodeid = 1,
      .uid = 0,
      .gid = 0,
      .pid = 4,
      .padding = 0,
  };
  struct fuse_getattr_in expected_payload = {0};

  struct fuse_in_header actual_header;
  struct fuse_getattr_in actual_payload;
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_in, actual_header, actual_payload);

  GetServerActualRequest(iov_in, 2);
  EXPECT_TRUE(CompareRequest(&expected_header, expected_header.len, &actual_header, actual_header.len));
}

TEST_F(StatTest, StatNotFound) {
  struct iovec iov_in[2];
  struct iovec iov_out[2];

  struct fuse_in_header in_header = {
      .len = sizeof(struct fuse_in_header) + sizeof(struct fuse_getattr_in),
      .opcode = FUSE_GETATTR,
      .unique = 4,
  };
  struct fuse_getattr_in in_payload = {0};
  iov_in[0].iov_len = sizeof(in_header);
  iov_in[0].iov_base = &in_header;
  iov_in[1].iov_len = sizeof(in_payload);
  iov_in[1].iov_base = &in_payload;

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = -2,
      .unique = 4,
  };
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;

  SetServerResponse(FUSE_GETATTR, iov_out, 1);

  struct stat stat_buf;
  EXPECT_THAT(stat(kMountPoint, &stat_buf), SyscallFailsWithErrno(ENOENT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
