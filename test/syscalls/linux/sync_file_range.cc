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
#include <stdio.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SyncFileRangeTest, TempFileSucceeds) {
  auto tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path(), O_RDWR));
  constexpr char data[] = "some data to sync";
  int fd = f.get();

  EXPECT_THAT(write(fd, data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));
  EXPECT_THAT(sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE),
              SyscallSucceeds());
  EXPECT_THAT(sync_file_range(fd, 0, 0, 0), SyscallSucceeds());
  EXPECT_THAT(
      sync_file_range(fd, 0, 0,
                      SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER |
                          SYNC_FILE_RANGE_WAIT_BEFORE),
      SyscallSucceeds());
  EXPECT_THAT(sync_file_range(
                  fd, 0, 1, SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER),
              SyscallSucceeds());
  EXPECT_THAT(sync_file_range(
                  fd, 1, 0, SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER),
              SyscallSucceeds());
}

TEST(SyncFileRangeTest, CannotSyncFileRangeOnUnopenedFd) {
  auto tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path(), O_RDWR));
  constexpr char data[] = "some data to sync";
  int fd = f.get();

  EXPECT_THAT(write(fd, data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));

  pid_t pid = fork();
  if (pid == 0) {
    f.reset();

    // fd is now invalid.
    TEST_CHECK(sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE) == -1);
    TEST_PCHECK(errno == EBADF);
    _exit(0);
  }

  int status = 0;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(SyncFileRangeTest, BadArgs) {
  auto tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path(), O_RDWR));
  int fd = f.get();

  EXPECT_THAT(sync_file_range(fd, -1, 0, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(sync_file_range(fd, 0, -1, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(sync_file_range(fd, 8912, INT64_MAX - 4096, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SyncFileRangeTest, CannotSyncFileRangeWithWaitBefore) {
  auto tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path(), O_RDWR));
  constexpr char data[] = "some data to sync";
  int fd = f.get();

  EXPECT_THAT(write(fd, data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));
  if (IsRunningOnGvisor()) {
    EXPECT_THAT(sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WAIT_BEFORE),
                SyscallFailsWithErrno(ENOSYS));
    EXPECT_THAT(
        sync_file_range(fd, 0, 0,
                        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE),
        SyscallFailsWithErrno(ENOSYS));
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
