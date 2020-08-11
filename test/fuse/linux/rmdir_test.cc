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

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class RmDirTest : public FuseTest {
 protected:
  const std::string test_dir_name_ = "test_dir";
  const mode_t test_dir_mode_ = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
};

TEST_F(RmDirTest, NormalRmDir) {
  const std::string test_dir_path_ =
      JoinPath(mount_point_.path().c_str(), test_dir_name_);

  SetServerInodeLookup(test_dir_name_, test_dir_mode_);

  // RmDir code.
  struct fuse_out_header rmdir_header = {
      .len = sizeof(struct fuse_out_header),
  };

  auto iov_out = FuseGenerateIovecs(rmdir_header);
  SetServerResponse(FUSE_RMDIR, iov_out);

  ASSERT_THAT(rmdir(test_dir_path_.c_str()), SyscallSucceeds());

  struct fuse_in_header in_header;
  std::vector<char> actual_dirname(test_dir_name_.length() + 1);
  auto iov_in = FuseGenerateIovecs(in_header, actual_dirname);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + test_dir_name_.length() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_RMDIR);
  EXPECT_EQ(std::string(actual_dirname.data()), test_dir_name_);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
