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

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fuse_util.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class MkdirTest : public FuseTest {
 protected:
  const std::string test_dir_ = "test_dir";
  const mode_t perms_ = S_IRWXU | S_IRWXG | S_IRWXO;
};

TEST_F(MkdirTest, CreateDir) {
  const std::string test_dir_path_ =
      JoinPath(mount_point_.path().c_str(), test_dir_);
  const mode_t new_umask = 0077;

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFDIR | perms_, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_MKDIR, iov_out);
  TempUmask mask(new_umask);
  ASSERT_THAT(mkdir(test_dir_path_.c_str(), 0777), SyscallSucceeds());

  struct fuse_in_header in_header;
  struct fuse_mkdir_in in_payload;
  std::vector<char> actual_dir(test_dir_.length() + 1);
  auto iov_in = FuseGenerateIovecs(in_header, in_payload, actual_dir);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len,
            sizeof(in_header) + sizeof(in_payload) + test_dir_.length() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_MKDIR);
  EXPECT_EQ(in_payload.mode & 0777, perms_ & ~new_umask);
  EXPECT_EQ(in_payload.umask, new_umask);
  EXPECT_EQ(std::string(actual_dir.data()), test_dir_);
}

TEST_F(MkdirTest, FileTypeError) {
  const std::string test_dir_path_ =
      JoinPath(mount_point_.path().c_str(), test_dir_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFREG | perms_, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_MKDIR, iov_out);
  ASSERT_THAT(mkdir(test_dir_path_.c_str(), 0777), SyscallFailsWithErrno(EIO));
  SkipServerActualRequest();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
