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
#include <sys/mount.h>
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

class UnlinkTest : public FuseTest {
 protected:
  const std::string test_file_ = "test_file";
};

TEST_F(UnlinkTest, RegularFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
  };
  auto iov_out = FuseGenerateIovecs(out_header);
  SetServerResponse(FUSE_UNLINK, iov_out);

  ASSERT_THAT(unlink(test_file_path.c_str()), SyscallSucceeds());
  struct fuse_in_header in_header;
  std::vector<char> unlinked_file(test_file_.length() + 1);
  auto iov_in = FuseGenerateIovecs(in_header, unlinked_file);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + test_file_.length() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_UNLINK);
  EXPECT_EQ(std::string(unlinked_file.data()), test_file_);
}

TEST_F(UnlinkTest, NoFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = -ENOENT,
  };
  auto iov_out = FuseGenerateIovecs(out_header);
  SetServerResponse(FUSE_UNLINK, iov_out);

  ASSERT_THAT(unlink(test_file_path.c_str()), SyscallFailsWithErrno(ENOENT));
  SkipServerActualRequest();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
