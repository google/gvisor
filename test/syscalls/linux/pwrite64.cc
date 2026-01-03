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

#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class Pwrite64 : public ::testing::Test {
  void SetUp() override {
    name_ = NewTempAbsPath();
    int fd;
    ASSERT_THAT(fd = open(name_.c_str(), O_CREAT, 0644), SyscallSucceeds());
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  void TearDown() override { unlink(name_.c_str()); }

 public:
  std::string name_;
};

TEST_F(Pwrite64, AppendOnly) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), 0),
              SyscallSucceedsWithValue(buf.size()));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, InvalidArgs) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), -1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, Overflow) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), 0x7fffffffffffffffull),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, Pwrite64WithOpath) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  std::vector<char> buf(1);
  EXPECT_THAT(PwriteFd(fd.get(), buf.data(), 1, 0),
              SyscallFailsWithErrno(EBADF));
}

// Test that pwrite64 with a nullptr buffer fails with EFAULT.
TEST_F(Pwrite64, NullBuffer) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());
  EXPECT_THAT(pwrite64(fd, nullptr, 1, 0), SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

// Test that pwrite64 with zero length and nullptr buffer succeeds.
TEST_F(Pwrite64, ZeroLengthNullBuffer) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());
  EXPECT_THAT(pwrite64(fd, nullptr, 0, 0), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

// Test that pwrite64 to a closed fd fails with EBADF.
TEST_F(Pwrite64, ClosedFd) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(pwrite64(fd, buf, sizeof(buf), 0), SyscallFailsWithErrno(EBADF));
}

// Test that pwrite64 to a read-only fd fails with EBADF.
TEST_F(Pwrite64, ReadOnlyFd) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDONLY), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(pwrite64(fd, buf, sizeof(buf), 0), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

// Test that pwrite64 does not change file offset.
TEST_F(Pwrite64, DoesNotChangeOffset) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_RDWR), SyscallSucceeds());

  // Set initial offset.
  const off_t initial_offset = 50;
  ASSERT_THAT(lseek(fd, initial_offset, SEEK_SET),
              SyscallSucceedsWithValue(initial_offset));

  char buf[16] = "test data";
  EXPECT_THAT(pwrite64(fd, buf, sizeof(buf), 100),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Offset should remain unchanged.
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR),
              SyscallSucceedsWithValue(initial_offset));

  EXPECT_THAT(close(fd), SyscallSucceeds());
}

// Test that pwrite64 to a pipe fails with ESPIPE.
TEST_F(Pwrite64, Pipe) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(pwrite64(pipe_fds[1], buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

// Test that pwrite64 to a socket fails with ESPIPE.
TEST_F(Pwrite64, Socket) {
  int sock_fds[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(pwrite64(sock_fds[0], buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(sock_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(sock_fds[1]), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
