// Copyright 2018 Google LLC
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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class Pread64Test : public ::testing::Test {
  void SetUp() override {
    name_ = NewTempAbsPath();
    ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_CREAT, 0644));
  }

  void TearDown() override { unlink(name_.c_str()); }

 public:
  std::string name_;
};

TEST(Pread64TestNoTempFile, BadFileDescriptor) {
  char buf[1024];
  EXPECT_THAT(pread64(-1, buf, 1024, 0), SyscallFailsWithErrno(EBADF));
}

TEST_F(Pread64Test, ZeroBuffer) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_RDWR));

  char msg[] = "hello world";
  EXPECT_THAT(pwrite64(fd.get(), msg, strlen(msg), 0),
              SyscallSucceedsWithValue(strlen(msg)));

  char buf[10];
  EXPECT_THAT(pread64(fd.get(), buf, 0, 0), SyscallSucceedsWithValue(0));
}

TEST_F(Pread64Test, BadBuffer) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_RDWR));

  char msg[] = "hello world";
  EXPECT_THAT(pwrite64(fd.get(), msg, strlen(msg), 0),
              SyscallSucceedsWithValue(strlen(msg)));

  char* bad_buffer = nullptr;
  EXPECT_THAT(pread64(fd.get(), bad_buffer, 1024, 0),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(Pread64Test, WriteOnlyNotReadable) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_WRONLY));

  char buf[1024];
  EXPECT_THAT(pread64(fd.get(), buf, 1024, 0), SyscallFailsWithErrno(EBADF));
}

TEST_F(Pread64Test, DirNotReadable) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), O_RDONLY));

  char buf[1024];
  EXPECT_THAT(pread64(fd.get(), buf, 1024, 0), SyscallFailsWithErrno(EISDIR));
}

TEST_F(Pread64Test, BadOffset) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_RDONLY));

  char buf[1024];
  EXPECT_THAT(pread64(fd.get(), buf, 1024, -1), SyscallFailsWithErrno(EINVAL));
}

TEST_F(Pread64Test, OffsetNotIncremented) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_RDWR));

  char msg[] = "hello world";
  EXPECT_THAT(write(fd.get(), msg, strlen(msg)),
              SyscallSucceedsWithValue(strlen(msg)));
  int offset;
  EXPECT_THAT(offset = lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());

  char buf1[1024];
  EXPECT_THAT(pread64(fd.get(), buf1, 1024, 0),
              SyscallSucceedsWithValue(strlen(msg)));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(offset));

  char buf2[1024];
  EXPECT_THAT(pread64(fd.get(), buf2, 1024, 3),
              SyscallSucceedsWithValue(strlen(msg) - 3));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(offset));
}

TEST_F(Pread64Test, EndOfFile) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name_, O_RDONLY));

  char buf[1024];
  EXPECT_THAT(pread64(fd.get(), buf, 1024, 0), SyscallSucceedsWithValue(0));
}

TEST(Pread64TestNoTempFile, CantReadSocketPair_NoRandomSave) {
  int sock_fds[2];
  EXPECT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds), SyscallSucceeds());

  char buf[1024];
  EXPECT_THAT(pread64(sock_fds[0], buf, 1024, 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(pread64(sock_fds[1], buf, 1024, 0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(sock_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(sock_fds[1]), SyscallSucceeds());
}

TEST(Pread64TestNoTempFile, CantReadPipe) {
  char buf[1024];

  int pipe_fds[2];
  EXPECT_THAT(pipe(pipe_fds), SyscallSucceeds());

  EXPECT_THAT(pread64(pipe_fds[0], buf, 1024, 0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
