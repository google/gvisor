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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FchdirTest, Success) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int fd;
  ASSERT_THAT(fd = open(temp_dir.path().c_str(), O_DIRECTORY | O_RDONLY),
              SyscallSucceeds());

  EXPECT_THAT(fchdir(fd), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  // Change CWD to a permanent location as temp dirs will be cleaned up.
  EXPECT_THAT(chdir("/"), SyscallSucceeds());
}

TEST(FchdirTest, InvalidFD) {
  EXPECT_THAT(fchdir(-1), SyscallFailsWithErrno(EBADF));
}

TEST(FchdirTest, PermissionDenied) {
  // Drop capabilities that allow us to override directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0666 /* mode */));

  int fd;
  ASSERT_THAT(fd = open(temp_dir.path().c_str(), O_DIRECTORY | O_RDONLY),
              SyscallSucceeds());

  EXPECT_THAT(fchdir(fd), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(FchdirTest, NotDir) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  int fd;
  ASSERT_THAT(fd = open(temp_file.path().c_str(), O_CREAT | O_RDONLY, 0777),
              SyscallSucceeds());

  EXPECT_THAT(fchdir(fd), SyscallFailsWithErrno(ENOTDIR));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
