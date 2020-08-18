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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/fuse.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"
#include "test/util/fuse_util.h"

#include "fuse_base.h"

namespace gvisor {
namespace testing {

namespace {

class MknodTest : public FuseTest {
 protected:
  const std::string test_file_name_ = "testFile";
   
};

TEST_F(MknodTest, RegularFile) {
    const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_name_);
  struct fuse_out_header out_header = {
    .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  const mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFREG | perms, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_MKNOD, iov_out);

  const mode_t newUmask = 0077;
  umask(newUmask);
  ASSERT_THAT(mknod(test_file_path.c_str(), perms, 0), SyscallSucceeds());
  struct fuse_in_header in_header;
  struct fuse_mknod_in in_payload;
  std::vector<char> actualFileName (test_file_name_.length() + 1);
  auto iov_in = FuseGenerateIovecs(in_header, in_payload, actualFileName);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload) + test_file_name_.length() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_MKNOD);
  EXPECT_EQ(in_payload.mode & 0777, perms & ~newUmask);
  EXPECT_EQ(0, memcmp(actualFileName.data(), test_file_name_.c_str(), test_file_name_.length() + 1));
}

TEST_F(MknodTest, FileTypeError) {
    const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_name_);
  struct fuse_out_header out_header = {
    .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  const mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  // server return directory instead of regular file should cause an error. 
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFDIR | perms, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_MKNOD, iov_out);

  ASSERT_THAT(mknod(test_file_path.c_str(), perms, 0), SyscallFailsWithErrno(EIO));
  SkipServerActualRequest();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor