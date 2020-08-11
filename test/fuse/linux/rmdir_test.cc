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
#include "test/util/fs_util.h"

#include "fuse_base.h"

namespace gvisor {
namespace testing {

namespace {

class RmDirTest : public FuseTest {};

TEST_F(RmDirTest, NormalRmDir) {
  const std::string dir_name = "dir";
  const std::string dir_path = JoinPath(kMountPoint, dir_name);
  struct iovec iov_in[3];
  struct iovec iov_out[2];

  struct fuse_out_header mkdir_header = {
    .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  struct fuse_entry_out mkdir_payload = DefaultEntryOut(S_IFDIR | perms, 5);

  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, mkdir_header, mkdir_payload);
  SetServerResponse(FUSE_MKDIR, iov_out, 2);

  ASSERT_THAT(mkdir(dir_path.c_str(), 0777), SyscallSucceeds());
  SkipServerActualRequest();

  // RmDir code.
  struct fuse_out_header rmdir_header = {
    .len = sizeof(struct fuse_out_header),
  };

  SET_IOVEC_WITH_HEADER(iov_out, rmdir_header);
  SetServerResponse(FUSE_RMDIR, iov_out, 1);

  ASSERT_THAT(rmdir(dir_path.c_str()), SyscallSucceeds());

  struct fuse_in_header in_header;
  char actual_dirname[dir_name.length() + 1];
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_in, in_header, actual_dirname);
  GetServerActualRequest(iov_in, 2);

  EXPECT_EQ(in_header.len, sizeof(in_header) + dir_name.length() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_RMDIR);
  EXPECT_EQ(0, memcmp(actual_dirname, dir_name.c_str(), dir_name.length() + 1));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
