// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class OpenTest : public FuseTest {
  // OpenTest doesn't care the release request when close a fd,
  // so doesn't check leftover requests when tearing down.
  void TearDown() { UnmountFuse(); }

 protected:
  const std::string test_file_ = "test_file";
  const mode_t regular_file_ = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;

  struct fuse_open_out out_payload_ = {
      .fh = 1,
      .open_flags = O_RDWR,
  };
};

TEST_F(OpenTest, RegularFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, regular_file_);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload_);
  SetServerResponse(FUSE_OPEN, iov_out);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), O_RDWR));

  struct fuse_in_header in_header;
  struct fuse_open_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_OPEN);
  EXPECT_EQ(in_payload.flags, O_RDWR);
  EXPECT_THAT(fcntl(fd.get(), F_GETFL), SyscallSucceedsWithValue(O_RDWR));
}

TEST_F(OpenTest, SetNoOpen) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);
  SetServerInodeLookup(test_file_, regular_file_);

  // ENOSYS indicates open is not implemented.
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
      .error = -ENOSYS,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload_);
  SetServerResponse(FUSE_OPEN, iov_out);
  ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), O_RDWR));
  SkipServerActualRequest();

  // check open doesn't send new request.
  uint32_t recieved_before = GetServerTotalReceivedBytes();
  ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), O_RDWR));
  EXPECT_EQ(GetServerTotalReceivedBytes(), recieved_before);
}

TEST_F(OpenTest, OpenFail) {
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
      .error = -ENOENT,
  };

  auto iov_out = FuseGenerateIovecs(out_header, out_payload_);
  SetServerResponse(FUSE_OPENDIR, iov_out);
  ASSERT_THAT(open(mount_point_.path().c_str(), O_RDWR),
              SyscallFailsWithErrno(ENOENT));

  struct fuse_in_header in_header;
  struct fuse_open_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_OPENDIR);
  EXPECT_EQ(in_payload.flags, O_RDWR);
}

TEST_F(OpenTest, DirectoryFlagOnRegularFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_);

  SetServerInodeLookup(test_file_, regular_file_);
  ASSERT_THAT(open(test_file_path.c_str(), O_RDWR | O_DIRECTORY),
              SyscallFailsWithErrno(ENOTDIR));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
