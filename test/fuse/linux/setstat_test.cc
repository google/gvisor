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
#include <utime.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_fd_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class SetStatTest : public FuseFdTest {
 public:
  void SetUp() override {
    FuseFdTest::SetUp();
    test_dir_path_ = JoinPath(mount_point_.path(), test_dir_);
    test_file_path_ = JoinPath(mount_point_.path(), test_file_);
  }

 protected:
  const uint64_t fh = 23;
  const std::string test_dir_ = "testdir";
  const std::string test_file_ = "testfile";
  const mode_t test_dir_mode_ = S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR;
  const mode_t test_file_mode_ = S_IFREG | S_IRUSR | S_IWUSR | S_IXUSR;

  std::string test_dir_path_;
  std::string test_file_path_;
};

TEST_F(SetStatTest, ChmodDir) {
  // Set up fixture.
  SetServerInodeLookup(test_dir_, test_dir_mode_);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  mode_t set_mode = S_IRGRP | S_IWGRP | S_IXGRP;
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(set_mode, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(chmod(test_dir_path_.c_str(), set_mode), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_MODE);
  EXPECT_EQ(in_payload.mode, S_IFDIR | set_mode);
}

TEST_F(SetStatTest, ChownDir) {
  // Set up fixture.
  SetServerInodeLookup(test_dir_, test_dir_mode_);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(test_dir_mode_, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(chown(test_dir_path_.c_str(), 1025, 1025), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_UID | FATTR_GID);
  EXPECT_EQ(in_payload.uid, 1025);
  EXPECT_EQ(in_payload.gid, 1025);
}

TEST_F(SetStatTest, TruncateFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(S_IFREG | S_IRUSR | S_IWUSR, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(truncate(test_file_path_.c_str(), 321), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_SIZE);
  EXPECT_EQ(in_payload.size, 321);
}

TEST_F(SetStatTest, UtimeFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(S_IFREG | S_IRUSR | S_IWUSR, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  time_t expected_atime = 1597159766, expected_mtime = 1597159765;
  struct utimbuf times = {
      .actime = expected_atime,
      .modtime = expected_mtime,
  };
  EXPECT_THAT(utime(test_file_path_.c_str(), &times), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_ATIME | FATTR_MTIME);
  EXPECT_EQ(in_payload.atime, expected_atime);
  EXPECT_EQ(in_payload.mtime, expected_mtime);
}

TEST_F(SetStatTest, UtimesFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(test_file_mode_, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  struct timeval expected_times[2] = {
      {
          .tv_sec = 1597159766,
          .tv_usec = 234945,
      },
      {
          .tv_sec = 1597159765,
          .tv_usec = 232341,
      },
  };
  EXPECT_THAT(utimes(test_file_path_.c_str(), expected_times),
              SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_ATIME | FATTR_MTIME);
  EXPECT_EQ(in_payload.atime, expected_times[0].tv_sec);
  EXPECT_EQ(in_payload.atimensec, expected_times[0].tv_usec * 1000);
  EXPECT_EQ(in_payload.mtime, expected_times[1].tv_sec);
  EXPECT_EQ(in_payload.mtimensec, expected_times[1].tv_usec * 1000);
}

TEST_F(SetStatTest, FtruncateFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenPath(test_file_path_, O_RDWR, fh));
  auto close_fd = CloseFD(fd);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(test_file_mode_, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(ftruncate(fd.get(), 321), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_SIZE | FATTR_FH);
  EXPECT_EQ(in_payload.fh, fh);
  EXPECT_EQ(in_payload.size, 321);
}

TEST_F(SetStatTest, FchmodFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenPath(test_file_path_, O_RDWR, fh));
  auto close_fd = CloseFD(fd);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  mode_t set_mode = S_IROTH | S_IWOTH | S_IXOTH;
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(set_mode, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(fchmod(fd.get(), set_mode), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_MODE | FATTR_FH);
  EXPECT_EQ(in_payload.fh, fh);
  EXPECT_EQ(in_payload.mode, S_IFREG | set_mode);
}

TEST_F(SetStatTest, FchownFile) {
  // Set up fixture.
  SetServerInodeLookup(test_file_, test_file_mode_);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenPath(test_file_path_, O_RDWR, fh));
  auto close_fd = CloseFD(fd);

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
      .error = 0,
  };
  struct fuse_attr_out out_payload = {
      .attr = DefaultFuseAttr(S_IFREG | S_IRUSR | S_IWUSR | S_IXUSR, 2),
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_SETATTR, iov_out);

  // Make syscall.
  EXPECT_THAT(fchown(fd.get(), 1025, 1025), SyscallSucceeds());

  // Check FUSE request.
  struct fuse_in_header in_header;
  struct fuse_setattr_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);

  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_SETATTR);
  EXPECT_EQ(in_header.uid, 0);
  EXPECT_EQ(in_header.gid, 0);
  EXPECT_EQ(in_payload.valid, FATTR_UID | FATTR_GID | FATTR_FH);
  EXPECT_EQ(in_payload.fh, fh);
  EXPECT_EQ(in_payload.uid, 1025);
  EXPECT_EQ(in_payload.gid, 1025);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
