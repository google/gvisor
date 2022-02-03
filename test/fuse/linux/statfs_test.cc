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
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <iostream>
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

#define FUSE_SUPER_MAGIC 0x65735546

class StatfsTest : public FuseFdTest {
 public:
  void SetUp() override { FuseFdTest::SetUp(); }

 protected:
  const mode_t dir_mode_ = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
  bool StatsfsAreEqual(struct statfs expected, struct statfs actual) {
    return memcmp(&expected, &actual, sizeof(struct statfs)) == 0;
  }

  const mode_t expected_mode = S_IFREG | S_IRUSR | S_IWUSR;
  const uint64_t fh = 23;
};

TEST_F(StatfsTest, StatfsNormal) {
  SetServerInodeLookup(mount_point_.path(), dir_mode_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_statfs_out),
  };
  struct fuse_statfs_out out_payload = {
      .st =
          fuse_kstatfs{
              .blocks = 0x6000,
              .bfree = 0x6000,
              .bavail = 0x6000,
              .bsize = 4096,
              .namelen = 0x10000,
          },
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_STATFS, iov_out);

  // Make syscall.
  struct statfs st;
  EXPECT_THAT(statfs(mount_point_.path().c_str(), &st), SyscallSucceeds());

  // Check filesystem operation result.
  struct statfs expected_stat = {
      .f_type = FUSE_SUPER_MAGIC,
      .f_bsize = out_payload.st.bsize,
      .f_blocks = out_payload.st.blocks,
      .f_bfree = out_payload.st.bfree,
      .f_bavail = out_payload.st.bavail,
      .f_namelen = out_payload.st.namelen,
  };
  EXPECT_TRUE(StatsfsAreEqual(st, expected_stat));

  // Check FUSE request.
  struct fuse_in_header in_header;
  auto iov_in = FuseGenerateIovecs(in_header);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_STATFS);
}

TEST_F(StatfsTest, NotFound) {
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = -ENOENT,
  };
  auto iov_out = FuseGenerateIovecs(out_header);
  SetServerResponse(FUSE_STATFS, iov_out);

  // Make syscall.
  struct statfs statfs_buf;
  EXPECT_THAT(statfs(mount_point_.path().c_str(), &statfs_buf),
              SyscallFailsWithErrno(ENOENT));

  // Check FUSE request.
  struct fuse_in_header in_header;
  auto iov_in = FuseGenerateIovecs(in_header);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.opcode, FUSE_STATFS);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
