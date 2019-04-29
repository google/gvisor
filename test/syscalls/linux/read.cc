// Copyright 2018 The gVisor Authors.
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

#include <fcntl.h>
#include <unistd.h>
#include <vector>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class ReadTest : public ::testing::Test {
  void SetUp() override {
    name_ = NewTempAbsPath();
    int fd;
    ASSERT_THAT(fd = open(name_.c_str(), O_CREAT, 0644), SyscallSucceeds());
    ASSERT_THAT(close(fd), SyscallSucceeds());
  }

  void TearDown() override { unlink(name_.c_str()); }

 public:
  std::string name_;
};

TEST_F(ReadTest, ZeroBuffer) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());

  char msg[] = "hello world";
  EXPECT_THAT(PwriteFd(fd, msg, strlen(msg), 0),
              SyscallSucceedsWithValue(strlen(msg)));

  char buf[10];
  EXPECT_THAT(ReadFd(fd, buf, 0), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(ReadTest, EmptyFileReturnsZeroAtEOF) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());

  char eof_buf[10];
  EXPECT_THAT(ReadFd(fd, eof_buf, 10), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(ReadTest, EofAfterRead) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());

  // Write some bytes to be read.
  constexpr char kMessage[] = "hello world";
  EXPECT_THAT(PwriteFd(fd, kMessage, sizeof(kMessage), 0),
              SyscallSucceedsWithValue(sizeof(kMessage)));

  // Read all of the bytes at once.
  char buf[sizeof(kMessage)];
  EXPECT_THAT(ReadFd(fd, buf, sizeof(kMessage)),
              SyscallSucceedsWithValue(sizeof(kMessage)));

  // Read again with a non-zero buffer and expect EOF.
  char eof_buf[10];
  EXPECT_THAT(ReadFd(fd, eof_buf, 10), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(ReadTest, DevNullReturnsEof) {
  int fd;
  ASSERT_THAT(fd = open("/dev/null", O_RDONLY), SyscallSucceeds());
  std::vector<char> buf(1);
  EXPECT_THAT(ReadFd(fd, buf.data(), 1), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

const int kReadSize = 128 * 1024;

// Do not allow random save as it could lead to partial reads.
TEST_F(ReadTest, CanReadFullyFromDevZero_NoRandomSave) {
  int fd;
  ASSERT_THAT(fd = open("/dev/zero", O_RDONLY), SyscallSucceeds());

  std::vector<char> buf(kReadSize, 1);
  EXPECT_THAT(ReadFd(fd, buf.data(), kReadSize),
              SyscallSucceedsWithValue(kReadSize));
  EXPECT_THAT(close(fd), SyscallSucceeds());
  EXPECT_EQ(std::vector<char>(kReadSize, 0), buf);
}

TEST_F(ReadTest, ReadDirectoryFails) {
  const FileDescriptor file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), O_RDONLY));
  std::vector<char> buf(1);
  EXPECT_THAT(ReadFd(file.get(), buf.data(), 1), SyscallFailsWithErrno(EISDIR));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
