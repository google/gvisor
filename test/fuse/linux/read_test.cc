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

#include "fuse_base.h"

namespace gvisor {
namespace testing {

namespace {

class ReadTest : public FuseTest {
 void TearDown() { UnmountFuse(); }

 protected:
  const std::string test_file = "test_file";
  const std::string test_file_path = JoinPath(kMountPoint, test_file);
};

TEST_F(ReadTest, ReadWhole) {
  // Open to get a fd.
  SetServerInodeLookup(test_file, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);
  const int open_flag = O_RDWR;
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = open_flag,
  };
  auto iov_out_open = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out_open);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), open_flag));

  // Can replace with SkipServerActualRequest() after mergerd.
  struct fuse_in_header in_header_open;
  struct fuse_open_in in_payload_open;
  auto iov_in_open = FuseGenerateIovecs(in_header_open, in_payload_open);
  GetServerActualRequest(iov_in_open);

  EXPECT_EQ(in_header_open.len, sizeof(in_header_open) + sizeof(in_payload_open));
  EXPECT_EQ(in_header_open.opcode, FUSE_OPEN);

  // Prepare for the read.
  const int n_read = 5;
  std::string data = std::string(n_read, 'a');
  struct fuse_out_header read_out_header = {
    .len = static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size() + 1),
  };
  auto iov_out_read = FuseGenerateIovecs(read_out_header, data);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read the whole "file".
  char buf[n_read+1];
  EXPECT_THAT(read(fd.get(), buf, n_read), SyscallSucceedsWithValue(n_read));
  buf[n_read] = '\0';

  // Check the read request.
  struct fuse_in_header in_header;
  struct fuse_read_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_READ);
  EXPECT_EQ(in_payload.offset, 0);
  EXPECT_STREQ(buf, data.c_str());
}

TEST_F(ReadTest, ReadPartial) {
  // Open to get a fd.
  SetServerInodeLookup(test_file, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);
  const int open_flag = O_RDWR;
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = open_flag,
  };
  auto iov_out_open = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out_open);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), open_flag));

  // Can replace with SkipServerActualRequest() after mergerd.
  struct fuse_in_header in_header_open;
  struct fuse_open_in in_payload_open;
  auto iov_in_open = FuseGenerateIovecs(in_header_open, in_payload_open);
  GetServerActualRequest(iov_in_open);

  EXPECT_EQ(in_header_open.len, sizeof(in_header_open) + sizeof(in_payload_open));
  EXPECT_EQ(in_header_open.opcode, FUSE_OPEN);

  // Prepare for the read.
  const int n_data = 10;
  std::string data = std::string(n_data, 'a');
  // Note: due to read ahead, current read implementation will treat any
  // response that is longer than requested as correct (i.e. not reach the EOF).
  // Therefore, the test below should make sure the size to read does not exceed
  // n_data.
  struct fuse_out_header read_out_header = {
    .len = static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size() + 1),
  };
  auto iov_out_read = FuseGenerateIovecs(read_out_header, data);
  struct fuse_in_header in_header;
  struct fuse_read_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  char buf[n_data+1];

  // Read 1 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf, 1), SyscallSucceedsWithValue(1));

  // Check the 1-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_READ);
  EXPECT_EQ(in_payload.offset, 0);

  // Read 3 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf, 3), SyscallSucceedsWithValue(3));

  // Check the 3-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_payload.offset, 1);

  // Read 5 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf, 5), SyscallSucceedsWithValue(5));

  // Check the 5-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_payload.offset, 4);
}

TEST_F(ReadTest, PRead) {
  // Open to get a fd.
  SetServerInodeLookup(test_file, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);
  const int open_flag = O_RDWR;
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = 1,
      .open_flags = open_flag,
  };
  auto iov_out_open = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out_open);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_path.c_str(), open_flag));

  // Can replace with SkipServerActualRequest() after mergerd.
  struct fuse_in_header in_header_open;
  struct fuse_open_in in_payload_open;
  auto iov_in_open = FuseGenerateIovecs(in_header_open, in_payload_open);
  GetServerActualRequest(iov_in_open);

  EXPECT_EQ(in_header_open.len, sizeof(in_header_open) + sizeof(in_payload_open));
  EXPECT_EQ(in_header_open.opcode, FUSE_OPEN);

  // Prepare for the read.
  const int n_read = 5;
  std::string data = std::string(n_read, 'a');
  struct fuse_out_header read_out_header = {
    .len = static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size() + 1),
  };
  auto iov_out_read = FuseGenerateIovecs(read_out_header, data);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read some bytes.
  char buf[n_read+1];
  const int offset_read = 123;
  EXPECT_THAT(pread(fd.get(), buf, n_read, offset_read), SyscallSucceedsWithValue(n_read));
  buf[n_read] = '\0';

  // Check the read request.
  struct fuse_in_header in_header;
  struct fuse_read_in in_payload;
  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_READ);
  EXPECT_EQ(in_payload.offset, offset_read);
  EXPECT_STREQ(buf, data.c_str());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor 