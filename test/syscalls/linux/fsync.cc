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

TEST(FsyncTest, TempFileSucceeds) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));
  const std::string data = "some data to sync";
  EXPECT_THAT(write(fd.get(), data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_THAT(fsync(fd.get()), SyscallSucceeds());
}

TEST(FsyncTest, TempDirSucceeds) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY));
  EXPECT_THAT(fsync(fd.get()), SyscallSucceeds());
}

TEST(FsyncTest, CannotFsyncOnUnopenedFd) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int fd;
  ASSERT_THAT(fd = open(file.path().c_str(), O_RDONLY), SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());

  // fd is now invalid.
  EXPECT_THAT(fsync(fd), SyscallFailsWithErrno(EBADF));
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
