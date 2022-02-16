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
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SyncTest, SyncEverything) {
  ASSERT_THAT(syscall(SYS_sync), SyscallSucceeds());
}

TEST(SyncTest, SyncFileSytem) {
  int fd;
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(fd = open(f.path().c_str(), O_RDONLY), SyscallSucceeds());
  EXPECT_THAT(syncfs(fd), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(SyncTest, SyncFromPipe) {
  int pipes[2];
  EXPECT_THAT(pipe(pipes), SyscallSucceeds());
  EXPECT_THAT(syncfs(pipes[0]), SyscallSucceeds());
  EXPECT_THAT(syncfs(pipes[1]), SyscallSucceeds());
  EXPECT_THAT(close(pipes[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipes[1]), SyscallSucceeds());
}

TEST(SyncTest, CannotSyncFileSystemAtBadFd) {
  EXPECT_THAT(syncfs(-1), SyscallFailsWithErrno(EBADF));
}

TEST(SyncTest, CannotSyncFileSystemAtOpathFD) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  EXPECT_THAT(syncfs(fd.get()), SyscallFailsWithErrno(EBADF));
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
