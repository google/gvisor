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

class ReadTest : public FuseTest {
  void SetUp() override {
    FuseTest::SetUp();
    test_file_path_ = JoinPath(mount_point_.path().c_str(), test_file_);
  }

  // TearDown overrides the parent's function
  // to skip checking the unconsumed release request at the end.
  void TearDown() override { UnmountFuse(); }

 protected:
  const std::string test_file_ = "test_file";
  const mode_t test_file_mode_ = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;
  const uint64_t test_fh_ = 1;
  const uint32_t open_flag_ = O_RDWR;

  std::string test_file_path_;

  PosixErrorOr<FileDescriptor> OpenTestFile(const std::string &path,
                                            uint64_t size = 512) {
    SetServerInodeLookup(test_file_, test_file_mode_, size);

    struct fuse_out_header out_header_open = {
        .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
    };
    struct fuse_open_out out_payload_open = {
        .fh = test_fh_,
        .open_flags = open_flag_,
    };
    auto iov_out_open = FuseGenerateIovecs(out_header_open, out_payload_open);
    SetServerResponse(FUSE_OPEN, iov_out_open);

    auto res = Open(path.c_str(), open_flag_);
    if (res.ok()) {
      SkipServerActualRequest();
    }
    return res;
  }
};

class ReadTestSmallMaxRead : public ReadTest {
  void SetUp() override {
    MountFuse(mountOpts);
    SetUpFuseServer();
    test_file_path_ = JoinPath(mount_point_.path().c_str(), test_file_);
  }

 protected:
  constexpr static char mountOpts[] =
      "rootmode=755,user_id=0,group_id=0,max_read=4096";
  // 4096 is hard-coded as the max_read in mount options.
  const int size_fragment = 4096;
};

TEST_F(ReadTest, ReadWhole) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the read.
  const int n_read = 5;
  std::vector<char> data(n_read);
  RandomizeBuffer(data.data(), data.size());
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read the whole "file".
  std::vector<char> buf(n_read);
  EXPECT_THAT(read(fd.get(), buf.data(), n_read),
              SyscallSucceedsWithValue(n_read));

  // Check the read request.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_header_read.len,
            sizeof(in_header_read) + sizeof(in_payload_read));
  EXPECT_EQ(in_header_read.opcode, FUSE_READ);
  EXPECT_EQ(in_payload_read.offset, 0);
  EXPECT_EQ(buf, data);
}

TEST_F(ReadTest, ReadPartial) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the read.
  const int n_data = 10;
  std::vector<char> data(n_data);
  RandomizeBuffer(data.data(), data.size());
  // Note: due to read ahead, current read implementation will treat any
  // response that is longer than requested as correct (i.e. not reach the EOF).
  // Therefore, the test below should make sure the size to read does not exceed
  // n_data.
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);

  std::vector<char> buf(n_data);

  // Read 1 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf.data(), 1), SyscallSucceedsWithValue(1));

  // Check the 1-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_header_read.len,
            sizeof(in_header_read) + sizeof(in_payload_read));
  EXPECT_EQ(in_header_read.opcode, FUSE_READ);
  EXPECT_EQ(in_payload_read.offset, 0);

  // Read 3 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf.data(), 3), SyscallSucceedsWithValue(3));

  // Check the 3-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_payload_read.offset, 1);

  // Read 5 bytes.
  SetServerResponse(FUSE_READ, iov_out_read);
  EXPECT_THAT(read(fd.get(), buf.data(), 5), SyscallSucceedsWithValue(5));

  // Check the 5-byte read request.
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_payload_read.offset, 4);
}

TEST_F(ReadTest, PRead) {
  const int file_size = 512;
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_, file_size));

  // Prepare for the read.
  const int n_read = 5;
  std::vector<char> data(n_read);
  RandomizeBuffer(data.data(), data.size());
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read some bytes.
  std::vector<char> buf(n_read);
  const int offset_read = file_size >> 1;
  EXPECT_THAT(pread(fd.get(), buf.data(), n_read, offset_read),
              SyscallSucceedsWithValue(n_read));

  // Check the read request.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_header_read.len,
            sizeof(in_header_read) + sizeof(in_payload_read));
  EXPECT_EQ(in_header_read.opcode, FUSE_READ);
  EXPECT_EQ(in_payload_read.offset, offset_read);
  EXPECT_EQ(buf, data);
}

TEST_F(ReadTest, ReadZero) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Issue the read.
  std::vector<char> buf;
  EXPECT_THAT(read(fd.get(), buf.data(), 0), SyscallSucceedsWithValue(0));
}

TEST_F(ReadTest, ReadShort) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the short read.
  const int n_read = 5;
  std::vector<char> data(n_read >> 1);
  RandomizeBuffer(data.data(), data.size());
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read the whole "file".
  std::vector<char> buf(n_read);
  EXPECT_THAT(read(fd.get(), buf.data(), n_read),
              SyscallSucceedsWithValue(data.size()));

  // Check the read request.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_header_read.len,
            sizeof(in_header_read) + sizeof(in_payload_read));
  EXPECT_EQ(in_header_read.opcode, FUSE_READ);
  EXPECT_EQ(in_payload_read.offset, 0);
  std::vector<char> short_buf(buf.begin(), buf.begin() + data.size());
  EXPECT_EQ(short_buf, data);
}

TEST_F(ReadTest, ReadShortEOF) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the short read.
  struct fuse_out_header out_header_read = {
      .len = static_cast<uint32_t>(sizeof(struct fuse_out_header)),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read);
  SetServerResponse(FUSE_READ, iov_out_read);

  // Read the whole "file".
  const int n_read = 10;
  std::vector<char> buf(n_read);
  EXPECT_THAT(read(fd.get(), buf.data(), n_read), SyscallSucceedsWithValue(0));

  // Check the read request.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);
  GetServerActualRequest(iov_in);

  EXPECT_EQ(in_payload_read.fh, test_fh_);
  EXPECT_EQ(in_header_read.len,
            sizeof(in_header_read) + sizeof(in_payload_read));
  EXPECT_EQ(in_header_read.opcode, FUSE_READ);
  EXPECT_EQ(in_payload_read.offset, 0);
}

TEST_F(ReadTestSmallMaxRead, ReadSmallMaxRead) {
  const int n_fragment = 10;
  const int n_read = size_fragment * n_fragment;

  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_, n_read));

  // Prepare for the read.
  std::vector<char> data(size_fragment);
  RandomizeBuffer(data.data(), data.size());
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);

  for (int i = 0; i < n_fragment; ++i) {
    SetServerResponse(FUSE_READ, iov_out_read);
  }

  // Read the whole "file".
  std::vector<char> buf(n_read);
  EXPECT_THAT(read(fd.get(), buf.data(), n_read),
              SyscallSucceedsWithValue(n_read));

  ASSERT_EQ(GetServerNumUnsentResponses(), 0);
  ASSERT_EQ(GetServerNumUnconsumedRequests(), n_fragment);

  // Check each read segment.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);

  for (int i = 0; i < n_fragment; ++i) {
    GetServerActualRequest(iov_in);
    EXPECT_EQ(in_payload_read.fh, test_fh_);
    EXPECT_EQ(in_header_read.len,
              sizeof(in_header_read) + sizeof(in_payload_read));
    EXPECT_EQ(in_header_read.opcode, FUSE_READ);
    EXPECT_EQ(in_payload_read.offset, i * size_fragment);
    EXPECT_EQ(in_payload_read.size, size_fragment);

    auto it = buf.begin() + i * size_fragment;
    EXPECT_EQ(std::vector<char>(it, it + size_fragment), data);
  }
}

TEST_F(ReadTestSmallMaxRead, ReadSmallMaxReadShort) {
  const int n_fragment = 10;
  const int n_read = size_fragment * n_fragment;

  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_, n_read));

  // Prepare for the read.
  std::vector<char> data(size_fragment);
  RandomizeBuffer(data.data(), data.size());
  struct fuse_out_header out_header_read = {
      .len =
          static_cast<uint32_t>(sizeof(struct fuse_out_header) + data.size()),
  };
  auto iov_out_read = FuseGenerateIovecs(out_header_read, data);

  for (int i = 0; i < n_fragment - 1; ++i) {
    SetServerResponse(FUSE_READ, iov_out_read);
  }

  // The last fragment is a short read.
  std::vector<char> half_data(data.begin(), data.begin() + (data.size() >> 1));
  struct fuse_out_header out_header_read_short = {
      .len = static_cast<uint32_t>(sizeof(struct fuse_out_header) +
                                   half_data.size()),
  };
  auto iov_out_read_short =
      FuseGenerateIovecs(out_header_read_short, half_data);
  SetServerResponse(FUSE_READ, iov_out_read_short);

  // Read the whole "file".
  std::vector<char> buf(n_read);
  EXPECT_THAT(read(fd.get(), buf.data(), n_read),
              SyscallSucceedsWithValue(n_read - (data.size() >> 1)));

  ASSERT_EQ(GetServerNumUnsentResponses(), 0);
  ASSERT_EQ(GetServerNumUnconsumedRequests(), n_fragment);

  // Check each read segment.
  struct fuse_in_header in_header_read;
  struct fuse_read_in in_payload_read;
  auto iov_in = FuseGenerateIovecs(in_header_read, in_payload_read);

  for (int i = 0; i < n_fragment; ++i) {
    GetServerActualRequest(iov_in);
    EXPECT_EQ(in_payload_read.fh, test_fh_);
    EXPECT_EQ(in_header_read.len,
              sizeof(in_header_read) + sizeof(in_payload_read));
    EXPECT_EQ(in_header_read.opcode, FUSE_READ);
    EXPECT_EQ(in_payload_read.offset, i * size_fragment);
    EXPECT_EQ(in_payload_read.size, size_fragment);

    auto it = buf.begin() + i * size_fragment;
    if (i != n_fragment - 1) {
      EXPECT_EQ(std::vector<char>(it, it + data.size()), data);
    } else {
      EXPECT_EQ(std::vector<char>(it, it + half_data.size()), half_data);
    }
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
