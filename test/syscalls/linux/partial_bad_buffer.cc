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
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Gt;

namespace gvisor {
namespace testing {

namespace {

constexpr char kMessage[] = "hello world";

// PartialBadBufferTest checks the result of various IO syscalls when passed a
// buffer that does not have the space specified in the syscall (most of it is
// PROT_NONE). Linux is annoyingly inconsistent among different syscalls, so we
// test all of them.
class PartialBadBufferTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create and open a directory for getdents cases.
    directory_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(
        directory_fd_ = open(directory_.path().c_str(), O_RDONLY | O_DIRECTORY),
        SyscallSucceeds());

    // Create and open a normal file, placing it in the directory
    // so the getdents cases have some dirents.
    name_ = JoinPath(directory_.path(), "a");
    ASSERT_THAT(fd_ = open(name_.c_str(), O_RDWR | O_CREAT, 0644),
                SyscallSucceeds());

    // Write some initial data.
    size_t size = sizeof(kMessage) - 1;
    EXPECT_THAT(WriteFd(fd_, &kMessage, size), SyscallSucceedsWithValue(size));

    ASSERT_THAT(lseek(fd_, 0, SEEK_SET), SyscallSucceeds());

    addr_ = mmap(0, 2 * kPageSize, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(addr_, MAP_FAILED);
    char* buf = reinterpret_cast<char*>(addr_);

    // Guard page for our read to run into.
    ASSERT_THAT(mprotect(reinterpret_cast<void*>(buf + kPageSize), kPageSize,
                         PROT_NONE),
                SyscallSucceeds());

    // Leave only one free byte in the buffer.
    bad_buffer_ = buf + kPageSize - 1;
  }

  void TearDown() override {
    EXPECT_THAT(munmap(addr_, 2 * kPageSize), SyscallSucceeds()) << addr_;
    EXPECT_THAT(close(fd_), SyscallSucceeds());
    EXPECT_THAT(unlink(name_.c_str()), SyscallSucceeds());
    EXPECT_THAT(close(directory_fd_), SyscallSucceeds());
  }

  // Return buffer with n bytes of free space.
  // N.B. this is the same buffer used to back bad_buffer_.
  char* FreeBytes(size_t n) {
    TEST_CHECK(n <= static_cast<size_t>(4096));
    return reinterpret_cast<char*>(addr_) + kPageSize - n;
  }

  std::string name_;
  int fd_;
  TempPath directory_;
  int directory_fd_;
  void* addr_;
  char* bad_buffer_;
};

// We do both "big" and "small" tests to try to hit the "zero copy" and
// non-"zero copy" paths, which have different code paths for handling faults.

TEST_F(PartialBadBufferTest, ReadBig) {
  EXPECT_THAT(RetryEINTR(read)(fd_, bad_buffer_, kPageSize),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadSmall) {
  EXPECT_THAT(RetryEINTR(read)(fd_, bad_buffer_, 10),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadBig) {
  EXPECT_THAT(RetryEINTR(pread)(fd_, bad_buffer_, kPageSize, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadSmall) {
  EXPECT_THAT(RetryEINTR(pread)(fd_, bad_buffer_, 10, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadvBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(readv)(fd_, &vec, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadvSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(readv)(fd_, &vec, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadvBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(preadv)(fd_, &vec, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadvSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(preadv)(fd_, &vec, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, WriteBig) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(RetryEINTR(write)(fd_, bad_buffer_, kPageSize),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, WriteSmall) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(RetryEINTR(write)(fd_, bad_buffer_, 10),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, PwriteBig) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(RetryEINTR(pwrite)(fd_, bad_buffer_, kPageSize, 0),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, PwriteSmall) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(RetryEINTR(pwrite)(fd_, bad_buffer_, 10, 0),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, WritevBig) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(writev)(fd_, &vec, 1), SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, WritevSmall) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(writev)(fd_, &vec, 1), SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, PwritevBig) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(pwritev)(fd_, &vec, 1, 0),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(PartialBadBufferTest, PwritevSmall) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(pwritev)(fd_, &vec, 1, 0),
              SyscallFailsWithErrno(EFAULT));
}

// getdents returns EFAULT when the you claim the buffer is large enough, but
// it actually isn't.
TEST_F(PartialBadBufferTest, GetdentsBig) {
  EXPECT_THAT(RetryEINTR(syscall)(SYS_getdents64, directory_fd_, bad_buffer_,
                                  kPageSize),
              SyscallFailsWithErrno(EFAULT));
}

// getdents returns EINVAL when the you claim the buffer is too small.
TEST_F(PartialBadBufferTest, GetdentsSmall) {
  EXPECT_THAT(
      RetryEINTR(syscall)(SYS_getdents64, directory_fd_, bad_buffer_, 10),
      SyscallFailsWithErrno(EINVAL));
}

// getdents will write entries into a buffer if there is space before it faults.
TEST_F(PartialBadBufferTest, GetdentsOneEntry) {
  // 30 bytes is enough for one (small) entry.
  char* buf = FreeBytes(30);

  EXPECT_THAT(
      RetryEINTR(syscall)(SYS_getdents64, directory_fd_, buf, kPageSize),
      SyscallSucceedsWithValue(Gt(0)));
}

// Verify that when write returns EFAULT the kernel hasn't silently written
// the initial valid bytes.
TEST_F(PartialBadBufferTest, WriteEfaultIsntPartial) {
  // FIXME(b/24788078): The sentry write syscalls will return immediately
  // if Access returns an error, but Access may not return an error
  // and the sentry will instead perform a partial write.
  SKIP_IF(IsRunningOnGvisor());

  bad_buffer_[0] = 'A';
  EXPECT_THAT(RetryEINTR(write)(fd_, bad_buffer_, 10),
              SyscallFailsWithErrno(EFAULT));

  size_t size = 255;
  char buf[255];
  memset(buf, 0, size);

  EXPECT_THAT(RetryEINTR(pread)(fd_, buf, size, 0),
              SyscallSucceedsWithValue(sizeof(kMessage) - 1));

  // 'A' has not been written.
  EXPECT_STREQ(buf, kMessage);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
