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
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class CreateTest : public FuseTest {
 protected:
  const std::string test_file_name_ = "test_file";
  const mode_t mode = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;
};

TEST_F(CreateTest, CreateFile) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_name_);

  // Ensure the file doesn't exist.
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = -ENOENT,
  };
  auto iov_out = FuseGenerateIovecs(out_header);
  SetServerResponse(FUSE_LOOKUP, iov_out);

  // creat(2) is equal to open(2) with open_flags O_CREAT | O_WRONLY | O_TRUNC.
  const mode_t new_mask = S_IWGRP | S_IWOTH;
  const int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
  out_header.error = 0;
  out_header.len = sizeof(struct fuse_out_header) +
                   sizeof(struct fuse_entry_out) + sizeof(struct fuse_open_out);
  struct fuse_entry_out entry_payload = DefaultEntryOut(mode & ~new_mask, 2);
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = open_flags,
  };
  iov_out = FuseGenerateIovecs(out_header, entry_payload, out_payload);
  SetServerResponse(FUSE_CREATE, iov_out);

  // kernfs generates a successive FUSE_OPEN after the file is created. Linux's
  // fuse kernel module will not send this FUSE_OPEN after creat(2).
  out_header.len =
      sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out);
  iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out);

  int fd;
  TempUmask mask(new_mask);
  EXPECT_THAT(fd = creat(test_file_path.c_str(), mode), SyscallSucceeds());
  EXPECT_THAT(fcntl(fd, F_GETFL),
              SyscallSucceedsWithValue(open_flags & O_ACCMODE));

  struct fuse_in_header in_header;
  struct fuse_create_in in_payload;
  std::vector<char> name(test_file_name_.size() + 1);
  auto iov_in = FuseGenerateIovecs(in_header, in_payload, name);

  // Skip the request of FUSE_LOOKUP.
  SkipServerActualRequest();

  // Get the first FUSE_CREATE.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload) +
                               test_file_name_.size() + 1);
  EXPECT_EQ(in_header.opcode, FUSE_CREATE);
  EXPECT_EQ(in_payload.flags, open_flags);
  EXPECT_EQ(in_payload.mode, mode & ~new_mask);
  EXPECT_EQ(in_payload.umask, new_mask);
  EXPECT_EQ(std::string(name.data()), test_file_name_);

  // Get the successive FUSE_OPEN.
  struct fuse_open_in in_payload_open;
  iov_in = FuseGenerateIovecs(in_header, in_payload_open);
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload_open));
  EXPECT_EQ(in_header.opcode, FUSE_OPEN);
  EXPECT_EQ(in_payload_open.flags, open_flags & O_ACCMODE);

  EXPECT_THAT(close(fd), SyscallSucceeds());
  // Skip the FUSE_RELEASE.
  SkipServerActualRequest();
}

TEST_F(CreateTest, CreateFileAlreadyExists) {
  const std::string test_file_path =
      JoinPath(mount_point_.path().c_str(), test_file_name_);

  const int open_flags = O_CREAT | O_EXCL;

  SetServerInodeLookup(test_file_name_);

  EXPECT_THAT(open(test_file_path.c_str(), mode, open_flags),
              SyscallFailsWithErrno(EEXIST));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
