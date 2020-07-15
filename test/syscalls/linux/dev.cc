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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(DevTest, LseekDevUrandom) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/urandom", O_RDONLY));
  EXPECT_THAT(lseek(fd.get(), -10, SEEK_CUR), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), -10, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
}

TEST(DevTest, LseekDevNull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  EXPECT_THAT(lseek(fd.get(), -10, SEEK_CUR), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), -10, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(DevTest, LseekDevZero) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(DevTest, LseekDevFull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/full", O_RDONLY));
  EXPECT_THAT(lseek(fd.get(), 123, SEEK_SET), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd.get(), 123, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd.get(), 123, SEEK_END), SyscallSucceedsWithValue(0));
}

TEST(DevTest, LseekDevKmsg) {
  SKIP_IF(IsRunningWithVFS1());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDONLY));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(lseek(fd.get(), 1, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_DATA), SyscallSucceedsWithValue(0));
}

TEST(DevTest, LseekDevNullFreshFile) {
  // Seeks to /dev/null always return 0.
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));

  EXPECT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd1.get(), 1000, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const FileDescriptor fd3 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  EXPECT_THAT(lseek(fd3.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

TEST(DevTest, OpenTruncate) {
  // Truncation is ignored on linux and gvisor for device files.
  ASSERT_NO_ERRNO_AND_VALUE(
      Open("/dev/null", O_CREAT | O_TRUNC | O_WRONLY, 0644));
  ASSERT_NO_ERRNO_AND_VALUE(
      Open("/dev/zero", O_CREAT | O_TRUNC | O_WRONLY, 0644));
  ASSERT_NO_ERRNO_AND_VALUE(
      Open("/dev/full", O_CREAT | O_TRUNC | O_WRONLY, 0644));
  SKIP_IF(IsRunningWithVFS1());
  ASSERT_NO_ERRNO_AND_VALUE(
      Open("/dev/kmsg", O_CREAT | O_TRUNC | O_WRONLY, 0644));
}

TEST(DevTest, Pread64DevNull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  char buf[1];
  EXPECT_THAT(pread64(fd.get(), buf, 1, 0), SyscallSucceedsWithValue(0));
}

TEST(DevTest, Pread64DevZero) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));
  char buf[1];
  EXPECT_THAT(pread64(fd.get(), buf, 1, 0), SyscallSucceedsWithValue(1));
}

TEST(DevTest, Pread64DevFull) {
  // /dev/full behaves like /dev/zero with respect to reads.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/full", O_RDONLY));
  char buf[1];
  EXPECT_THAT(pread64(fd.get(), buf, 1, 0), SyscallSucceedsWithValue(1));
}

TEST(DevTest, ReadDevNull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  std::vector<char> buf(1);
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), 1), SyscallSucceeds());
}

// Do not allow random save as it could lead to partial reads.
TEST(DevTest, ReadDevZero_NoRandomSave) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));

  constexpr int kReadSize = 128 * 1024;
  std::vector<char> buf(kReadSize, 1);
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), kReadSize),
              SyscallSucceedsWithValue(kReadSize));
  EXPECT_EQ(std::vector<char>(kReadSize, 0), buf);
}

TEST(DevTest, WriteDevNull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_WRONLY));
  EXPECT_THAT(WriteFd(fd.get(), "a", 1), SyscallSucceedsWithValue(1));
}

TEST(DevTest, WriteDevZero) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_WRONLY));
  EXPECT_THAT(WriteFd(fd.get(), "a", 1), SyscallSucceedsWithValue(1));
}

TEST(DevTest, WriteDevFull) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/full", O_WRONLY));
  EXPECT_THAT(WriteFd(fd.get(), "a", 1), SyscallFailsWithErrno(ENOSPC));
}

TEST(DevTest, ReadWriteDevKmsg) {
  SKIP_IF(IsRunningWithVFS1());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDWR));

  constexpr int bufferSize = 1024;
  std::vector<char> oversizeBuffer(bufferSize * 2);
  EXPECT_THAT(WriteFd(fd.get(), oversizeBuffer.data(), bufferSize * 2),
              SyscallFailsWithErrno(EINVAL));
  std::vector<char> writeBuffer(bufferSize);
  RandomizeBuffer(writeBuffer.data(), writeBuffer.size());
  EXPECT_THAT(WriteFd(fd.get(), writeBuffer.data(), bufferSize),
              SyscallSucceedsWithValue(bufferSize));

  std::vector<char> readBuffer(bufferSize);
  EXPECT_THAT(ReadFd(fd.get(), readBuffer.data(), bufferSize / 2),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(ReadFd(fd.get(), readBuffer.data(), bufferSize),
              SyscallSucceedsWithValue(bufferSize));
  EXPECT_EQ(writeBuffer, readBuffer);
  EXPECT_THAT(ReadFd(fd.get(), readBuffer.data(), bufferSize),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(DevTest, OverwriteDevKmsgBuffer) {
  SKIP_IF(IsRunningWithVFS1());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDWR));

  constexpr int overwriteAmount = 10;
  constexpr int bufferEntryMax = 512;
  for (int i = 0; i < bufferEntryMax + overwriteAmount; i++) {
    EXPECT_THAT(WriteFd(fd.get(), &i, 1), SyscallSucceedsWithValue(1));
  }
  std::vector<int> buf(1);
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), 1), SyscallFailsWithErrno(EPIPE));
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(overwriteAmount, buf.front());
}

TEST(DevTest, MultipleOpenAccessKmsg) {
  SKIP_IF(IsRunningWithVFS1());
  FileDescriptor writeFd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDWR));
  constexpr int bufferSize = 1024;
  std::vector<char> writeBuffer(bufferSize);
  RandomizeBuffer(writeBuffer.data(), writeBuffer.size());
  EXPECT_THAT(WriteFd(writeFd.get(), writeBuffer.data(), bufferSize),
              SyscallSucceedsWithValue(bufferSize));
  EXPECT_THAT(close(writeFd.release()), SyscallSucceeds());

  FileDescriptor readFd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDWR));
  std::vector<char> readBuffer(bufferSize);
  EXPECT_THAT(ReadFd(readFd.get(), readBuffer.data(), bufferSize),
              SyscallSucceedsWithValue(bufferSize));
  EXPECT_EQ(writeBuffer, readBuffer);
}

TEST(DevTest, NonblockReadDevKmsg) {
  SKIP_IF(IsRunningWithVFS1());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/kmsg", O_RDWR & O_NONBLOCK));
  std::vector<char> buf(1);
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), 1), SyscallFailsWithErrno(EAGAIN));
}

TEST(DevTest, TTYExists) {
  struct stat statbuf = {};
  ASSERT_THAT(stat("/dev/tty", &statbuf), SyscallSucceeds());
  // Check that it's a character device with rw-rw-rw- permissions.
  EXPECT_EQ(statbuf.st_mode, S_IFCHR | 0666);
}

TEST(DevTest, OpenDevFuse) {
  // Note(gvisor.dev/issue/3076) This won't work in the sentry until the new
  // device registration is complete.
  SKIP_IF(IsRunningWithVFS1() || IsRunningOnGvisor() || !IsFUSEEnabled());

  ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDONLY));
}

}  // namespace
}  // namespace testing

}  // namespace gvisor
