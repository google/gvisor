// Copyright 2021 The gVisor Authors.
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
#include <time.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

constexpr mode_t mode = 1;

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<FileDescriptor> createdDeleted() {
  auto path = NewTempAbsPath();
  PosixErrorOr<FileDescriptor> fd = Open(path, O_RDWR | O_CREAT, mode);
  if (!fd.ok()) {
    return fd.error();
  }

  auto err = Unlink(path);
  if (!err.ok()) {
    return err;
  }
  return fd;
}

TEST(DeletedTest, Utime) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(createdDeleted());

  const struct timespec times[2] = {{10, 0}, {20, 0}};
  EXPECT_THAT(futimens(fd.get(), times), SyscallSucceeds());

  struct stat stat;
  ASSERT_THAT(fstat(fd.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(10, stat.st_atime);
  EXPECT_EQ(20, stat.st_mtime);
}

TEST(DeletedTest, Chmod) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(createdDeleted());

  ASSERT_THAT(fchmod(fd.get(), mode + 1), SyscallSucceeds());

  struct stat stat;
  ASSERT_THAT(fstat(fd.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(mode + 1, stat.st_mode & ~S_IFMT);
}

TEST(DeletedTest, Truncate) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(createdDeleted());
  const std::string data = "foobar";
  ASSERT_THAT(write(fd.get(), data.c_str(), data.size()), SyscallSucceeds());

  ASSERT_THAT(ftruncate(fd.get(), 0), SyscallSucceeds());

  struct stat stat;
  ASSERT_THAT(fstat(fd.get(), &stat), SyscallSucceeds());
  ASSERT_EQ(stat.st_size, 0);
}

TEST(DeletedTest, Fallocate) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(createdDeleted());

  ASSERT_THAT(fallocate(fd.get(), 0, 0, 123), SyscallSucceeds());

  struct stat stat;
  ASSERT_THAT(fstat(fd.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(123, stat.st_size);
}

// Tests that a file can be created with the same path as a deleted file that
// still have an open FD to it.
TEST(DeletedTest, Replace) {
  auto path = NewTempAbsPath();
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_CREAT, mode));
  ASSERT_NO_ERRNO(Unlink(path));

  auto other =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_CREAT | O_EXCL, mode));

  auto stat = ASSERT_NO_ERRNO_AND_VALUE(Fstat(fd.get()));
  auto stat_other = ASSERT_NO_ERRNO_AND_VALUE(Fstat(other.get()));
  ASSERT_NE(stat.st_ino, stat_other.st_ino);

  // Check that the path points to the new file.
  stat = ASSERT_NO_ERRNO_AND_VALUE(Stat(path));
  ASSERT_EQ(stat.st_ino, stat_other.st_ino);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
