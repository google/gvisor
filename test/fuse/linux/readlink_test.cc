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

class ReadlinkTest : public FuseTest {
 protected:
  const std::string test_file_ = "test_file_";
  const mode_t perms_ = S_IRWXU | S_IRWXG | S_IRWXO;
};

TEST_F(ReadlinkTest, ReadSymLink) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, S_IFLNK | perms_);

  struct fuse_out_header out_header = {
      .len = static_cast<uint32_t>(sizeof(struct fuse_out_header)) +
             static_cast<uint32_t>(test_file_.length()) + 1,
  };
  std::string link = test_file_;
  auto iov_out = FuseGenerateIovecs(out_header, link);
  SetServerResponse(FUSE_READLINK, iov_out);
  const std::string actual_link =
      ASSERT_NO_ERRNO_AND_VALUE(ReadLink(symlink_path));

  struct fuse_in_header in_header;
  auto iov_in = FuseGenerateIovecs(in_header);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header));
  EXPECT_EQ(in_header.opcode, FUSE_READLINK);
  EXPECT_EQ(0, memcmp(actual_link.c_str(), link.data(), link.size()));

  // next readlink should have link cached, so shouldn't have new request to
  // server.
  uint32_t recieved_before = GetServerTotalReceivedBytes();
  ASSERT_NO_ERRNO(ReadLink(symlink_path));
  EXPECT_EQ(GetServerTotalReceivedBytes(), recieved_before);
}

TEST_F(ReadlinkTest, NotSymlink) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, S_IFREG | perms_);

  std::vector<char> buf(PATH_MAX + 1);
  ASSERT_THAT(readlink(test_file_path.c_str(), buf.data(), PATH_MAX),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
