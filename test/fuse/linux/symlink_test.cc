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
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

#include "fuse_base.h"

namespace gvisor {
namespace testing {

namespace {

class SymlinkTest : public FuseTest {
 protected:
  const std::string target_file_ = "target_file_";
  const std::string symlink_name_ = "symlink_name_";
};

TEST_F(SymlinkTest, CreateSymLink) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), symlink_name_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  const mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  struct fuse_entry_out out_payload = DefaultEntryOut(S_IFLNK | perms, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SYMLINK, iov_out);

  ASSERT_THAT(symlink(target_file_.c_str(), symlink_path.c_str()),
              SyscallSucceeds());
  struct fuse_in_header in_header;
  std::vector<char> actual_target_file(target_file_.length() + 1);
  std::vector<char> actual_symlink_name(symlink_name_.length() + 1);
  auto iov_in =
      FuseGenerateIovecs(in_header, actual_symlink_name, actual_target_file);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + symlink_name_.length() +
                               target_file_.length() + 2);
  EXPECT_EQ(in_header.opcode, FUSE_SYMLINK);
  EXPECT_EQ(0, memcmp(actual_target_file.data(), target_file_.c_str(),
                      target_file_.length() + 1));
  EXPECT_EQ(0, memcmp(actual_symlink_name.data(), symlink_name_.c_str(),
                      symlink_name_.length() + 1));
}

TEST_F(SymlinkTest, FileTypeError) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), symlink_name_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out out_payload =
      DefaultEntryOut(S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 5);
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SYMLINK, iov_out);

  ASSERT_THAT(symlink(target_file_.c_str(), symlink_path.c_str()),
              SyscallFailsWithErrno(EIO));
  SkipServerActualRequest();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
