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

class ReadlinkTest : public FuseTest {
 protected:
  const std::string target_file_ = "target_file_";
};

TEST_F(ReadlinkTest, ReadSymLink) {
  const std::string symlink_path =
      JoinPath(mount_point_.path().c_str(), target_file_);

  struct fuse_out_header entry_out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  const mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  struct fuse_entry_out entry_out_payload = DefaultEntryOut(S_IFLNK | perms, 5);
  auto iov_out = FuseGenerateIovecs(entry_out_header, entry_out_payload);
  SetServerResponse(FUSE_SYMLINK, iov_out);
  ASSERT_THAT(symlink(target_file_.c_str(), symlink_path.c_str()),
              SyscallSucceeds());
  SkipServerActualRequest();

  struct fuse_out_header out_header = {
      .len = static_cast<uint32_t>(sizeof(struct fuse_out_header)) +
             static_cast<uint32_t>(target_file_.length()) + 1,
  };
  std::vector<char> link(target_file_.begin(), target_file_.end());
  link.push_back(0);
  iov_out = FuseGenerateIovecs(out_header, link);
  SetServerResponse(FUSE_READLINK, iov_out);
  const std::string actual_link =
      ASSERT_NO_ERRNO_AND_VALUE(ReadLink(symlink_path));
  EXPECT_EQ(0, memcmp(actual_link.c_str(), link.data(), link.size()));
  struct fuse_in_header in_header;
  auto iov_in = FuseGenerateIovecs(in_header);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header));
  EXPECT_EQ(in_header.opcode, FUSE_READLINK);

  // next readlink should have link cached, so shouldn't have new request to
  // test server.
  uint32_t recieved_before = GetServerTotalReceivedBytes();
  ASSERT_NO_ERRNO(ReadLink(symlink_path));
  uint32_t recieved_after = GetServerTotalReceivedBytes();
  EXPECT_EQ(recieved_before, recieved_after);
}

TEST_F(ReadlinkTest, NotSymlink) {
  const std::string testFilePath =
      JoinPath(mount_point_.path().c_str(), "test_file");

  // prepare the file for testing.
  struct fuse_out_header entry_out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out entry_out_payload =
      DefaultEntryOut(S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 5);
  auto iov_out = FuseGenerateIovecs(entry_out_header, entry_out_payload);
  SetServerResponse(FUSE_MKNOD, iov_out);
  ASSERT_THAT(mknod(testFilePath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO, 0),
              SyscallSucceeds());
  SkipServerActualRequest();

  std::vector<char> buf(PATH_MAX + 1);
  ASSERT_THAT(readlink(testFilePath.c_str(), buf.data(), PATH_MAX),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor