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

class WriteTest : public FuseTest {
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

class WriteTestSmallMaxWrite : public WriteTest {
  void SetUp() override {
    MountFuse();
    SetUpFuseServer(&fuse_init_payload);
    test_file_path_ = JoinPath(mount_point_.path().c_str(), test_file_);
  }

 protected:
  const static uint32_t max_write_ = 4096;
  constexpr static struct fuse_init_out fuse_init_payload = {
      .major = 7,
      .max_write = max_write_,
  };

  const uint32_t size_fragment = max_write_;
};

TEST_F(WriteTest, WriteNormal) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the write.
  const int n_write = 10;
  struct fuse_out_header out_header_write = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out),
  };
  struct fuse_write_out out_payload_write = {
      .size = n_write,
  };
  auto iov_out_write = FuseGenerateIovecs(out_header_write, out_payload_write);
  SetServerResponse(FUSE_WRITE, iov_out_write);

  // Issue the write.
  std::vector<char> buf(n_write);
  RandomizeBuffer(buf.data(), buf.size());
  EXPECT_THAT(write(fd.get(), buf.data(), n_write),
              SyscallSucceedsWithValue(n_write));

  // Check the write request.
  struct fuse_in_header in_header_write;
  struct fuse_write_in in_payload_write;
  std::vector<char> payload_buf(n_write);
  auto iov_in_write =
      FuseGenerateIovecs(in_header_write, in_payload_write, payload_buf);
  GetServerActualRequest(iov_in_write);

  EXPECT_EQ(in_payload_write.fh, test_fh_);
  EXPECT_EQ(in_header_write.len,
            sizeof(in_header_write) + sizeof(in_payload_write));
  EXPECT_EQ(in_header_write.opcode, FUSE_WRITE);
  EXPECT_EQ(in_payload_write.offset, 0);
  EXPECT_EQ(in_payload_write.size, n_write);
  EXPECT_EQ(buf, payload_buf);
}

TEST_F(WriteTest, WriteShort) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the write.
  const int n_write = 10, n_written = 5;
  struct fuse_out_header out_header_write = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out),
  };
  struct fuse_write_out out_payload_write = {
      .size = n_written,
  };
  auto iov_out_write = FuseGenerateIovecs(out_header_write, out_payload_write);
  SetServerResponse(FUSE_WRITE, iov_out_write);

  // Issue the write.
  std::vector<char> buf(n_write);
  RandomizeBuffer(buf.data(), buf.size());
  EXPECT_THAT(write(fd.get(), buf.data(), n_write),
              SyscallSucceedsWithValue(n_written));

  // Check the write request.
  struct fuse_in_header in_header_write;
  struct fuse_write_in in_payload_write;
  std::vector<char> payload_buf(n_write);
  auto iov_in_write =
      FuseGenerateIovecs(in_header_write, in_payload_write, payload_buf);
  GetServerActualRequest(iov_in_write);

  EXPECT_EQ(in_payload_write.fh, test_fh_);
  EXPECT_EQ(in_header_write.len,
            sizeof(in_header_write) + sizeof(in_payload_write));
  EXPECT_EQ(in_header_write.opcode, FUSE_WRITE);
  EXPECT_EQ(in_payload_write.offset, 0);
  EXPECT_EQ(in_payload_write.size, n_write);
  EXPECT_EQ(buf, payload_buf);
}

TEST_F(WriteTest, WriteShortZero) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Prepare for the write.
  const int n_write = 10;
  struct fuse_out_header out_header_write = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out),
  };
  struct fuse_write_out out_payload_write = {
      .size = 0,
  };
  auto iov_out_write = FuseGenerateIovecs(out_header_write, out_payload_write);
  SetServerResponse(FUSE_WRITE, iov_out_write);

  // Issue the write.
  std::vector<char> buf(n_write);
  RandomizeBuffer(buf.data(), buf.size());
  EXPECT_THAT(write(fd.get(), buf.data(), n_write), SyscallFailsWithErrno(EIO));

  // Check the write request.
  struct fuse_in_header in_header_write;
  struct fuse_write_in in_payload_write;
  std::vector<char> payload_buf(n_write);
  auto iov_in_write =
      FuseGenerateIovecs(in_header_write, in_payload_write, payload_buf);
  GetServerActualRequest(iov_in_write);

  EXPECT_EQ(in_payload_write.fh, test_fh_);
  EXPECT_EQ(in_header_write.len,
            sizeof(in_header_write) + sizeof(in_payload_write));
  EXPECT_EQ(in_header_write.opcode, FUSE_WRITE);
  EXPECT_EQ(in_payload_write.offset, 0);
  EXPECT_EQ(in_payload_write.size, n_write);
  EXPECT_EQ(buf, payload_buf);
}

TEST_F(WriteTest, WriteZero) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_));

  // Issue the write.
  std::vector<char> buf(0);
  EXPECT_THAT(write(fd.get(), buf.data(), 0), SyscallSucceedsWithValue(0));
}

TEST_F(WriteTest, PWrite) {
  const int file_size = 512;
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_, file_size));

  // Prepare for the write.
  const int n_write = 10;
  struct fuse_out_header out_header_write = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out),
  };
  struct fuse_write_out out_payload_write = {
      .size = n_write,
  };
  auto iov_out_write = FuseGenerateIovecs(out_header_write, out_payload_write);
  SetServerResponse(FUSE_WRITE, iov_out_write);

  // Issue the write.
  std::vector<char> buf(n_write);
  RandomizeBuffer(buf.data(), buf.size());
  const int offset_write = file_size >> 1;
  EXPECT_THAT(pwrite(fd.get(), buf.data(), n_write, offset_write),
              SyscallSucceedsWithValue(n_write));

  // Check the write request.
  struct fuse_in_header in_header_write;
  struct fuse_write_in in_payload_write;
  std::vector<char> payload_buf(n_write);
  auto iov_in_write =
      FuseGenerateIovecs(in_header_write, in_payload_write, payload_buf);
  GetServerActualRequest(iov_in_write);

  EXPECT_EQ(in_payload_write.fh, test_fh_);
  EXPECT_EQ(in_header_write.len,
            sizeof(in_header_write) + sizeof(in_payload_write));
  EXPECT_EQ(in_header_write.opcode, FUSE_WRITE);
  EXPECT_EQ(in_payload_write.offset, offset_write);
  EXPECT_EQ(in_payload_write.size, n_write);
  EXPECT_EQ(buf, payload_buf);
}

TEST_F(WriteTestSmallMaxWrite, WriteSmallMaxWrie) {
  const int n_fragment = 10;
  const int n_write = size_fragment * n_fragment;

  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenTestFile(test_file_path_, n_write));

  // Prepare for the write.
  struct fuse_out_header out_header_write = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_write_out),
  };
  struct fuse_write_out out_payload_write = {
      .size = size_fragment,
  };
  auto iov_out_write = FuseGenerateIovecs(out_header_write, out_payload_write);

  for (int i = 0; i < n_fragment; ++i) {
    SetServerResponse(FUSE_WRITE, iov_out_write);
  }

  // Issue the write.
  std::vector<char> buf(n_write);
  RandomizeBuffer(buf.data(), buf.size());
  EXPECT_THAT(write(fd.get(), buf.data(), n_write),
              SyscallSucceedsWithValue(n_write));

  ASSERT_EQ(GetServerNumUnsentResponses(), 0);
  ASSERT_EQ(GetServerNumUnconsumedRequests(), n_fragment);

  // Check the write request.
  struct fuse_in_header in_header_write;
  struct fuse_write_in in_payload_write;
  std::vector<char> payload_buf(size_fragment);
  auto iov_in_write =
      FuseGenerateIovecs(in_header_write, in_payload_write, payload_buf);

  for (int i = 0; i < n_fragment; ++i) {
    GetServerActualRequest(iov_in_write);

    EXPECT_EQ(in_payload_write.fh, test_fh_);
    EXPECT_EQ(in_header_write.len,
              sizeof(in_header_write) + sizeof(in_payload_write));
    EXPECT_EQ(in_header_write.opcode, FUSE_WRITE);
    EXPECT_EQ(in_payload_write.offset, i * size_fragment);
    EXPECT_EQ(in_payload_write.size, size_fragment);

    auto it = buf.begin() + i * size_fragment;
    EXPECT_EQ(std::vector<char>(it, it + size_fragment), payload_buf);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor