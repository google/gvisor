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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"
#include "test/util/fuse_util.h"
#include "test/util/fs_util.h"

#include "fuse_base.h"

namespace gvisor {
namespace testing {

namespace {

class OpenTest : public FuseTest {};

TEST_F(OpenTest, RegularFile) {
  const std::string testFilePath = JoinPath(kMountPoint, "testFile");
  struct iovec iov_in[3];
  struct iovec iov_out[2];

  // prepare the file for testing.
  struct fuse_out_header entry_out_header = {
    .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out entry_out_payload = DefaultEntryOut(S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 5);
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, entry_out_header, entry_out_payload);
  SetServerResponse(FUSE_MKNOD, iov_out, 2);
  ASSERT_THAT(mknod(testFilePath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO, 0), SyscallSucceeds());
  SkipServerActualRequest();

  const int openFlag = O_RDWR;
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = openFlag,
  };
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out, 2);

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(testFilePath.c_str(), openFlag));
  struct fuse_in_header in_header;
  struct fuse_open_in in_payload;
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_in, in_header, in_payload);

  GetServerActualRequest(iov_in, 2);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_OPEN);
  EXPECT_EQ(in_payload.flags, openFlag);
  EXPECT_THAT(fcntl(fd.get(), F_GETFL), SyscallSucceedsWithValue(openFlag));
}

TEST_F(OpenTest, OpenFail) {
  struct iovec iov_in[2];
  struct iovec iov_out[2];
  const int openFlag = O_RDWR;
  const int32_t testError = ENOENT;

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
      .error = -testError,
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = openFlag,
  };

  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, out_header, out_payload);
  SetServerResponse(FUSE_OPENDIR, iov_out, 2);

  ASSERT_THAT(open(kMountPoint, openFlag), SyscallFailsWithErrno(testError));
  struct fuse_in_header in_header;
  struct fuse_open_in in_payload;
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_in, in_header, in_payload);

  GetServerActualRequest(iov_in, 2);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_OPENDIR);
  EXPECT_EQ(in_payload.flags, openFlag);
}

TEST_F(OpenTest, SetNoOpen) {
  const std::string testFilePath = JoinPath(kMountPoint, "testFile");
  struct iovec iov_in[3];
  struct iovec iov_out[2];

  // prepare the file for testing.
  struct fuse_out_header entry_out_header = {
    .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out entry_out_payload = DefaultEntryOut(S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 5);
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, entry_out_header, entry_out_payload);
  SetServerResponse(FUSE_MKNOD, iov_out, 2);
  ASSERT_THAT(mknod(testFilePath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO, 0), SyscallSucceeds());
  SkipServerActualRequest();

  const int openFlag = O_RDWR;
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
      .error = -ENOSYS,
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = openFlag,
  };

  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out, 2);

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(testFilePath.c_str(), openFlag));
  struct fuse_in_header in_header;
  struct fuse_open_in in_payload;
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_in, in_header, in_payload);

  GetServerActualRequest(iov_in, 2);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_OPEN);
  EXPECT_EQ(in_payload.flags, openFlag);
  EXPECT_THAT(fcntl(fd.get(), F_GETFL), SyscallSucceedsWithValue(openFlag));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
