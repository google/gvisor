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

class ReleaseTest : public FuseTest {
 protected:
  const std::string test_file_ = "test_file";
};

TEST_F(ReleaseTest, RegularFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = O_RDWR,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path, O_RDWR));
  SkipServerActualRequest();
  ASSERT_THAT(close(fd.release()), SyscallSucceeds());

  struct fuse_in_header in_header;
  struct fuse_release_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_RELEASE);
  EXPECT_EQ(in_payload.flags, O_RDWR);
  EXPECT_EQ(in_payload.fh, 1);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
