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
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/syscalls/linux/readv_common.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

class ReadvTest : public FileTest {
  void SetUp() override {
    FileTest::SetUp();

    ASSERT_THAT(write(test_file_fd_.get(), kReadvTestData, kReadvTestDataSize),
                SyscallSucceedsWithValue(kReadvTestDataSize));
    ASSERT_THAT(lseek(test_file_fd_.get(), 0, SEEK_SET),
                SyscallSucceedsWithValue(0));
    ASSERT_THAT(write(test_pipe_[1], kReadvTestData, kReadvTestDataSize),
                SyscallSucceedsWithValue(kReadvTestDataSize));
  }
};

TEST_F(ReadvTest, ReadOneBufferPerByte_File) {
  ReadOneBufferPerByte(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadOneBufferPerByte_Pipe) {
  ReadOneBufferPerByte(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadOneHalfAtATime_File) {
  ReadOneHalfAtATime(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadOneHalfAtATime_Pipe) {
  ReadOneHalfAtATime(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadAllOneBuffer_File) {
  ReadAllOneBuffer(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadAllOneBuffer_Pipe) { ReadAllOneBuffer(test_pipe_[0]); }

TEST_F(ReadvTest, ReadAllOneLargeBuffer_File) {
  ReadAllOneLargeBuffer(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadAllOneLargeBuffer_Pipe) {
  ReadAllOneLargeBuffer(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadBuffersOverlapping_File) {
  ReadBuffersOverlapping(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadBuffersOverlapping_Pipe) {
  ReadBuffersOverlapping(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadBuffersDiscontinuous_File) {
  ReadBuffersDiscontinuous(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadBuffersDiscontinuous_Pipe) {
  ReadBuffersDiscontinuous(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadIovecsCompletelyFilled_File) {
  ReadIovecsCompletelyFilled(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadIovecsCompletelyFilled_Pipe) {
  ReadIovecsCompletelyFilled(test_pipe_[0]);
}

TEST_F(ReadvTest, BadFileDescriptor) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  ASSERT_THAT(readv(-1, iov, 1024), SyscallFailsWithErrno(EBADF));
}

TEST_F(ReadvTest, BadIovecsPointer_File) {
  ASSERT_THAT(readv(test_file_fd_.get(), nullptr, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, BadIovecsPointer_Pipe) {
  ASSERT_THAT(readv(test_pipe_[0], nullptr, 1), SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, BadIovecBase_File) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, BadIovecBase_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, ZeroIovecs_File) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1), SyscallSucceeds());
}

TEST_F(ReadvTest, ZeroIovecs_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallSucceeds());
}

TEST_F(ReadvTest, NotReadable_File) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  std::string wronly_file = NewTempAbsPath();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(wronly_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR));
  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EBADF));
  fd.reset();  // Close before unlinking.
  ASSERT_THAT(unlink(wronly_file.c_str()), SyscallSucceeds());
}

TEST_F(ReadvTest, NotReadable_Pipe) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_pipe_[1], iov, 1), SyscallFailsWithErrno(EBADF));
}

TEST_F(ReadvTest, DirNotReadable) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), O_RDONLY));
  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EISDIR));
}

TEST_F(ReadvTest, OffsetIncremented) {
  char* buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;

  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  ASSERT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kReadvTestDataSize));

  free(buffer);
}

TEST_F(ReadvTest, EndOfFile) {
  char* buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(buffer);

  buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1), SyscallSucceedsWithValue(0));
  free(buffer);
}

TEST_F(ReadvTest, WouldBlock_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(iov[0].iov_base);

  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallFailsWithErrno(EAGAIN));
  free(iov[0].iov_base);
}

TEST_F(ReadvTest, ZeroBuffer) {
  char buf[10];
  struct iovec iov[1];
  iov[0].iov_base = buf;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallSucceedsWithValue(0));
}

TEST_F(ReadvTest, NullIovecInNonemptyArray) {
  std::vector<char> buf(kReadvTestDataSize);
  struct iovec iov[2];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 0;
  iov[1].iov_base = buf.data();
  iov[1].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 2),
              SyscallSucceedsWithValue(kReadvTestDataSize));
}

TEST_F(ReadvTest, IovecOutsideTaskAddressRangeInNonemptyArray) {
  std::vector<char> buf(kReadvTestDataSize);
  struct iovec iov[2];
  iov[0].iov_base = reinterpret_cast<void*>(~static_cast<uintptr_t>(0));
  iov[0].iov_len = 0;
  iov[1].iov_base = buf.data();
  iov[1].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 2),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, ReadvBadOpenOpathFlag) {
  SKIP_IF(IsRunningWithVFS1());
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EBADF));
}

// This test depends on the maximum extent of a single readv() syscall, so
// we can't tolerate interruption from saving.
TEST(ReadvTestNoFixture, TruncatedAtMax_NoRandomSave) {
  // Ensure that we won't be interrupted by ITIMER_PROF. This is particularly
  // important in environments where automated profiling tools may start
  // ITIMER_PROF automatically.
  struct itimerval itv = {};
  auto const cleanup_itimer =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_PROF, itv));

  // From Linux's include/linux/fs.h.
  size_t const MAX_RW_COUNT = INT_MAX & ~(kPageSize - 1);

  // Create an iovec array with 3 segments pointing to consecutive parts of a
  // buffer. The first covers all but the last three pages, and should be
  // written to in its entirety. The second covers the last page before
  // MAX_RW_COUNT and the first page after; only the first page should be
  // written to. The third covers the last page of the buffer, and should be
  // skipped entirely.
  size_t const kBufferSize = MAX_RW_COUNT + 2 * kPageSize;
  size_t const kFirstOffset = MAX_RW_COUNT - kPageSize;
  size_t const kSecondOffset = MAX_RW_COUNT + kPageSize;
  // The buffer is too big to fit on the stack.
  std::vector<char> buf(kBufferSize);
  struct iovec iov[3];
  iov[0].iov_base = buf.data();
  iov[0].iov_len = kFirstOffset;
  iov[1].iov_base = buf.data() + kFirstOffset;
  iov[1].iov_len = kSecondOffset - kFirstOffset;
  iov[2].iov_base = buf.data() + kSecondOffset;
  iov[2].iov_len = kBufferSize - kSecondOffset;

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));
  EXPECT_THAT(readv(fd.get(), iov, 3), SyscallSucceedsWithValue(MAX_RW_COUNT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
