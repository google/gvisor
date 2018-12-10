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
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FsyncTest, TempFileSucceeds) {
  std::string path = NewTempAbsPath();
  int fd;
  EXPECT_THAT(fd = open(path.c_str(), O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());
  const std::string data = "some data to sync";
  EXPECT_THAT(write(fd, data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_THAT(fsync(fd), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
  ASSERT_THAT(unlink(path.c_str()), SyscallSucceeds());
}

TEST(FsyncTest, CannotFsyncOnUnopenedFd) {
  int fd;
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(fd = open(f.path().c_str(), O_RDONLY), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());

  // fd is now invalid.
  EXPECT_THAT(fsync(fd), SyscallFailsWithErrno(EBADF));
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
