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
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class SymlinkTest : public FuseTest {
 protected:
  const std::string target_file_ = "target_file_";
  const std::string symlink_ = "symlink_";
  const mode_t perms_ = S_IRWXU | S_IRWXG | S_IRWXO;
};

TEST_F(SymlinkTest, CreateSymLink) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), symlink_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFLNK | perms_, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SYMLINK, iov_out);
  ASSERT_THAT(symlink(target_file_.c_str(), symlink_path.c_str()),
              SyscallSucceeds());

  struct fuse_in_header in_header;
  std::vector<char> actual_target_file(target_file_.length() + 1);
  std::vector<char> actual_symlink(symlink_.length() + 1);
  auto iov_in =
      FuseGenerateIovecs(in_header, actual_symlink, actual_target_file);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len,
            sizeof(in_header) + symlink_.length() + target_file_.length() + 2);
  EXPECT_EQ(in_header.opcode, FUSE_SYMLINK);
  EXPECT_EQ(std::string(actual_target_file.data()), target_file_);
  EXPECT_EQ(std::string(actual_symlink.data()), symlink_);
}

TEST_F(SymlinkTest, FileTypeError) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), symlink_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFREG | perms_, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SYMLINK, iov_out);
  ASSERT_THAT(symlink(target_file_.c_str(), symlink_path.c_str()),
              SyscallFailsWithErrno(EIO));
  SkipServerActualRequest();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
