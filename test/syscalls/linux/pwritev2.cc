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
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef SYS_pwritev2
#if defined(__x86_64__)
#define SYS_pwritev2 328
#else
#error "Unknown architecture"
#endif
#endif  // SYS_pwrite2

#ifndef RWF_HIPRI
#define RWF_HIPRI 0x1
#endif  // RWF_HIPRI

#ifndef RWF_DSYNC
#define RWF_DSYNC 0x2
#endif  // RWF_DSYNC

#ifndef RWF_SYNC
#define RWF_SYNC 0x4
#endif  // RWF_SYNC

constexpr int kBufSize = 1024;

void SetContent(std::vector<char>& content) {
  for (uint i = 0; i < content.size(); i++) {
    content[i] = static_cast<char>((i % 10) + '0');
  }
}

ssize_t pwritev2(unsigned long fd, const struct iovec* iov,
                 unsigned long iovcnt, off_t offset, unsigned long flags) {
  // syscall on pwritev2 does some weird things (see man syscall and search
  // pwritev2), so we insert a 0 to word align the flags argument on native.
  return syscall(SYS_pwritev2, fd, iov, iovcnt, offset, 0, flags);
}

// This test is the base case where we call pwritev (no offset, no flags).
TEST(Writev2Test, TestBaseCall) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  std::vector<char> content(kBufSize);
  SetContent(content);
  struct iovec iov[2];
  iov[0].iov_base = content.data();
  iov[0].iov_len = content.size() / 2;
  iov[1].iov_base = static_cast<char*>(iov[0].iov_base) + (content.size() / 2);
  iov[1].iov_len = content.size() / 2;

  ASSERT_THAT(pwritev2(fd.get(), iov, /*iovcnt=*/2,
                       /*offset=*/0, /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  std::vector<char> buf(kBufSize);
  EXPECT_THAT(read(fd.get(), buf.data(), kBufSize),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_EQ(content, buf);
}

// This test is where we call pwritev2 with a positive offset and no flags.
TEST(Pwritev2Test, TestValidPositiveOffset) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  std::string prefix(kBufSize, '0');

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), prefix, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  std::vector<char> content(kBufSize);
  SetContent(content);
  struct iovec iov;
  iov.iov_base = content.data();
  iov.iov_len = content.size();

  ASSERT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/prefix.size(), /*flags=*/0),
              SyscallSucceedsWithValue(content.size()));

  std::vector<char> buf(prefix.size() + content.size());
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  std::vector<char> want(prefix.begin(), prefix.end());
  want.insert(want.end(), content.begin(), content.end());
  EXPECT_EQ(want, buf);
}

// This test is the base case where we call writev by using -1 as the offset.
// The write should use the file offset, so the test increments the file offset
// prior to call pwritev2.
TEST(Pwritev2Test, TestNegativeOneOffset) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const std::string prefix = "00";
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), prefix.data(), TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  ASSERT_THAT(lseek(fd.get(), prefix.size(), SEEK_SET),
              SyscallSucceedsWithValue(prefix.size()));

  std::vector<char> content(kBufSize);
  SetContent(content);
  struct iovec iov;
  iov.iov_base = content.data();
  iov.iov_len = content.size();

  ASSERT_THAT(pwritev2(fd.get(), &iov, /*iovcnt*/ 1,
                       /*offset=*/static_cast<off_t>(-1), /*flags=*/0),
              SyscallSucceedsWithValue(content.size()));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(prefix.size() + content.size()));

  std::vector<char> buf(prefix.size() + content.size());
  EXPECT_THAT(pread(fd.get(), buf.data(), buf.size(), /*offset=*/0),
              SyscallSucceedsWithValue(buf.size()));

  std::vector<char> want(prefix.begin(), prefix.end());
  want.insert(want.end(), content.begin(), content.end());
  EXPECT_EQ(want, buf);
}

// pwritev2 requires if the RWF_HIPRI flag is passed, the fd must be opened with
// O_DIRECT. This test implements a correct call with the RWF_HIPRI flag.
TEST(Pwritev2Test, TestCallWithRWF_HIPRI) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  std::vector<char> content(kBufSize);
  SetContent(content);
  struct iovec iov;
  iov.iov_base = content.data();
  iov.iov_len = content.size();

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/0, /*flags=*/RWF_HIPRI),
              SyscallSucceedsWithValue(kBufSize));

  std::vector<char> buf(content.size());
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_EQ(buf, content);
}

// This test checks that pwritev2 can be called with valid flags
TEST(Pwritev2Test, TestCallWithValidFlags) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  std::vector<char> content(kBufSize, '0');
  struct iovec iov;
  iov.iov_base = content.data();
  iov.iov_len = content.size();

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/0, /*flags=*/RWF_DSYNC),
              SyscallSucceedsWithValue(kBufSize));

  std::vector<char> buf(content.size());
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_EQ(buf, content);

  SetContent(content);

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/0, /*flags=*/0x4),
              SyscallSucceedsWithValue(kBufSize));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(content.size()));

  EXPECT_THAT(pread(fd.get(), buf.data(), buf.size(), /*offset=*/0),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_EQ(buf, content);
}

// This test calls pwritev2 with a bad file descriptor.
TEST(Writev2Test, TestBadFile) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);
  ASSERT_THAT(pwritev2(/*fd=*/-1, /*iov=*/nullptr, /*iovcnt=*/0,
                       /*offset=*/0, /*flags=*/0),
              SyscallFailsWithErrno(EBADF));
}

// This test calls pwrite2 with an invalid offset.
TEST(Pwritev2Test, TestInvalidOffset) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  char buf[16];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/static_cast<off_t>(-8), /*flags=*/0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(Pwritev2Test, TestUnseekableFileValid) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  int pipe_fds[2];

  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  std::vector<char> content(32, '0');
  SetContent(content);
  struct iovec iov;
  iov.iov_base = content.data();
  iov.iov_len = content.size();

  EXPECT_THAT(pwritev2(pipe_fds[1], &iov, /*iovcnt=*/1,
                       /*offset=*/static_cast<off_t>(-1), /*flags=*/0),
              SyscallSucceedsWithValue(content.size()));

  std::vector<char> buf(content.size());
  EXPECT_THAT(read(pipe_fds[0], buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_EQ(content, buf);

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

// Calling pwritev2 with a non-negative offset calls pwritev.  Calling pwritev
// with an unseekable file is not allowed. A pipe is used for an unseekable
// file.
TEST(Pwritev2Test, TestUnseekableFileInValid) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  int pipe_fds[2];
  char buf[16];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  EXPECT_THAT(pwritev2(pipe_fds[1], &iov, /*iovcnt=*/1,
                       /*offset=*/2, /*flags=*/0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

TEST(Pwritev2Test, TestReadOnlyFile) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  char buf[16];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/0, /*flags=*/0),
              SyscallFailsWithErrno(EBADF));
}

// This test calls pwritev2 with an invalid flag.
TEST(Pwritev2Test, TestInvalidFlag) {
  SKIP_IF(pwritev2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR | O_DIRECT));

  char buf[16];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  EXPECT_THAT(pwritev2(fd.get(), &iov, /*iovcnt=*/1,
                       /*offset=*/0, /*flags=*/0xF0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
