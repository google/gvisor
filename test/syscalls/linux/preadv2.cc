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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/syscalls/linux/readv_common.h"
#include "test/util/file_descriptor.h"
#include "test/util/memory_util.h"
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

// This test is the base case where we call preadv (no offset, no flags).
TEST(Preadv2Test, TestBaseCall) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }
  std::string content = SetContent();

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), content, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  std::vector<char> buf(kBufSize);
  struct iovec iov;
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt*/ 1,
                      /*offset=*/0, /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// This test is where we call preadv with an offset and no flags.
TEST(Preadv2Test, TestValidPositiveOffset) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }
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

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt=*/1,
                      /*offset=*/prefix.size(), /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// This test is the base case where we call readv by using -1 as the offset. The
// read should use the file offset, so the test increments it by one prior to
// calling preadv2.
TEST(Preadv2Test, TestNegativeOneOffset) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }
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

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt=*/1,
                      /*offset=*/static_cast<off_t>(-1), /*flags=*/0),
              SyscallSucceedsWithValue(kBufSize));

  EXPECT_EQ(content, std::string(buf.data(), buf.size()));
}

// This test calls preadv2 with an invalid flag.
TEST(Preadv2Test, TestInvalidFlag) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY | O_DIRECT));

  struct iovec iov;

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt=*/1,
                      /*offset=*/0, /*flags=*/RWF_HIPRI << 1),
              SyscallFailsWithErrno(EINVAL));
}

// This test calls preadv2 with an invalid offset.
TEST(Preadv2Test, TestInvalidOffset) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY | O_DIRECT));
  struct iovec iov;

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt=*/1,
                      /*offset=*/static_cast<off_t>(-8), /*flags=*/RWF_HIPRI),
              SyscallFailsWithErrno(EINVAL));
}

// This test calls preadv with a file set O_WRONLY.
TEST(Preadv2Test, TestUnreadableFile) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));
  struct iovec iov;

  EXPECT_THAT(syscall(SYS_preadv2, fd.get(), &iov, /*iov_cnt=*/1,
                      /*offset=*/0, /*flags=*/0),
              SyscallFailsWithErrno(EBADF));
}

// Calling preadv2 with a non-negative offset calls preadv.  Calling preadv with
// an unseekable file is not allowed. A pipe is used for an unseekable file.
TEST(Preadv2Test, TestUnseekableFile) {
  if (!IsRunningOnGvisor()) {
    SKIP_BEFORE_KERNEL(/*major_version=*/4, /*minor_version=*/6);
  }

  int pipe_fds[2];

  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());

  struct iovec iov;

  EXPECT_THAT(syscall(SYS_preadv2, pipe_fds[0], &iov, /*iov_cnt=*/1,
                      /*offset=*/2, /*flags=*/0),
              SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(pipe_fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipe_fds[1]), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
