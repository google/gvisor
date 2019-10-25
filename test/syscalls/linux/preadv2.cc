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
#include "absl/memory/memory.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef SYS_preadv2
#if defined(__x86_64__)
#define SYS_preadv2 327
#else
#error "Unknown architecture"
#endif
#endif  // SYS_preadv2

#ifndef RWF_HIPRI
#define RWF_HIPRI 0x1
#endif  // RWF_HIPRI

constexpr int kBufSize = 1024;

std::string SetContent() {
  std::string content;
  for (int i = 0; i < kBufSize; i++) {
    content += static_cast<char>((i % 10) + '0');
  }
  return content;
}

ssize_t preadv2(unsigned long fd, const struct iovec* iov, unsigned long iovcnt,
                off_t offset, unsigned long flags) {
  // syscall on preadv2 does some weird things (see man syscall and search
  // preadv2), so we insert a 0 to word align the flags argument on native.
  return syscall(SYS_preadv2, fd, iov, iovcnt, offset, 0, flags);
}

// This test is the base case where we call preadv (no offset, no flags).
TEST(Preadv2Test, TestBaseCall) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  std::string content = SetContent();

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), content, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  std::vector<char> buf(kBufSize);
  struct iovec iov[2];
  iov[0].iov_base = buf.data();
  iov[0].iov_len = buf.size() / 2;
  iov[1].iov_base = static_cast<char*>(iov[0].iov_base) + (content.size() / 2);
  iov[1].iov_len = content.size() / 2;

  EXPECT_THAT(preadv2(fd.get(), iov, /*iovcnt*/ 2, /*offset=*/0, /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// This test is where we call preadv with an offset and no flags.
TEST(Preadv2Test, TestValidPositiveOffset) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  std::string content = SetContent();
  const std::string prefix = "0";

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), prefix + content, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  std::vector<char> buf(kBufSize, '0');
  struct iovec iov;
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  EXPECT_THAT(preadv2(fd.get(), &iov, /*iovcnt=*/1, /*offset=*/prefix.size(),
                      /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// This test is the base case where we call readv by using -1 as the offset. The
// read should use the file offset, so the test increments it by one prior to
// calling preadv2.
TEST(Preadv2Test, TestNegativeOneOffset) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  std::string content = SetContent();
  const std::string prefix = "231";

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), prefix + content, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  ASSERT_THAT(lseek(fd.get(), prefix.size(), SEEK_SET),
              SyscallSucceedsWithValue(prefix.size()));

  std::vector<char> buf(kBufSize, '0');
  struct iovec iov;
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  EXPECT_THAT(preadv2(fd.get(), &iov, /*iovcnt=*/1, /*offset=*/-1, /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(prefix.size() + buf.size()));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// preadv2 requires if the RWF_HIPRI flag is passed, the fd must be opened with
// O_DIRECT. This test implements a correct call with the RWF_HIPRI flag.
TEST(Preadv2Test, TestCallWithRWF_HIPRI) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  std::string content = SetContent();

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), content, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  EXPECT_THAT(fsync(fd.get()), SyscallSucceeds());

  std::vector<char> buf(kBufSize, '0');
  struct iovec iov;
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  EXPECT_THAT(
      preadv2(fd.get(), &iov, /*iovcnt=*/1, /*offset=*/0, /*flags=*/RWF_HIPRI),
      SyscallSucceedsWithValue(kBufSize));

  EXPECT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}
// This test calls preadv2 with an invalid flag.
TEST(Preadv2Test, TestInvalidFlag) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY | O_DIRECT));

  std::vector<char> buf(kBufSize, '0');
  struct iovec iov;
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  EXPECT_THAT(preadv2(fd.get(), &iov, /*iovcnt=*/1,
                      /*offset=*/0, /*flags=*/0xF0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

// This test calls preadv2 with an invalid offset.
TEST(Preadv2Test, TestInvalidOffset) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY | O_DIRECT));

  auto iov = absl::make_unique<struct iovec[]>(1);
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 0;

  EXPECT_THAT(preadv2(fd.get(), iov.get(), /*iovcnt=*/1, /*offset=*/-8,
                      /*flags=*/RWF_HIPRI),
              SyscallFailsWithErrno(EINVAL));
}

// This test calls preadv with a file set O_WRONLY.
TEST(Preadv2Test, TestUnreadableFile) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));

  auto iov = absl::make_unique<struct iovec[]>(1);
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 0;

  EXPECT_THAT(preadv2(fd.get(), iov.get(), /*iovcnt=*/1,
                      /*offset=*/0, /*flags=*/0),
              SyscallFailsWithErrno(EBADF));
}

// Calling preadv2 with a non-negative offset calls preadv.  Calling preadv with
// an unseekable file is not allowed. A pipe is used for an unseekable file.
TEST(Preadv2Test, TestUnseekableFileInvalid) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  int pipe_fds[2];

  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  auto iov = absl::make_unique<struct iovec[]>(1);
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 0;

  EXPECT_THAT(preadv2(pipe_fds[0], iov.get(), /*iovcnt=*/1,
                      /*offset=*/2, /*flags=*/0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

TEST(Preadv2Test, TestUnseekableFileValid) {
  SKIP_IF(preadv2(-1, nullptr, 0, 0, 0) < 0 && errno == ENOSYS);

  int pipe_fds[2];

  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  std::vector<char> content(32, 'X');

  EXPECT_THAT(write(pipe_fds[1], content.data(), content.size()),
              SyscallSucceedsWithValue(content.size()));

  std::vector<char> buf(content.size());
  auto iov = absl::make_unique<struct iovec[]>(1);
  iov[0].iov_base = buf.data();
  iov[0].iov_len = buf.size();

  EXPECT_THAT(preadv2(pipe_fds[0], iov.get(), /*iovcnt=*/1,
                      /*offset=*/static_cast<off_t>(-1), /*flags=*/0),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_EQ(content, buf);

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
