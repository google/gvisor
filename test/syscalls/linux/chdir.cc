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
#include <linux/limits.h>
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

TEST(ChdirTest, Success) {
  auto old_dir = GetAbsoluteTestTmpdir();
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chdir(temp_dir.path().c_str()), SyscallSucceeds());
  // Temp path destructor deletes the newly created tmp dir and Sentry rejects
  // saving when its current dir is still pointing to the path. Switch to a
  // permanent path here.
  EXPECT_THAT(chdir(old_dir.c_str()), SyscallSucceeds());
}

TEST(ChdirTest, PermissionDenied) {
  // Drop capabilities that allow us to override directory permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0666 /* mode */));
  EXPECT_THAT(chdir(temp_dir.path().c_str()), SyscallFailsWithErrno(EACCES));
}

TEST(ChdirTest, NotDir) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(chdir(temp_file.path().c_str()), SyscallFailsWithErrno(ENOTDIR));
}

TEST(ChdirTest, NotExist) {
  EXPECT_THAT(chdir("/foo/bar"), SyscallFailsWithErrno(ENOENT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
