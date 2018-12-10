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
#include <sys/statfs.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(StatfsTest, CannotStatBadPath) {
  auto temp_file = NewTempAbsPathInDir("/tmp");

  struct statfs st;
  EXPECT_THAT(statfs(temp_file.c_str(), &st), SyscallFailsWithErrno(ENOENT));
}

TEST(StatfsTest, InternalTmpfs) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  struct statfs st;
  EXPECT_THAT(statfs(temp_file.path().c_str(), &st), SyscallSucceeds());
}

TEST(StatfsTest, InternalDevShm) {
  struct statfs st;
  EXPECT_THAT(statfs("/dev/shm", &st), SyscallSucceeds());
}

TEST(StatfsTest, NameLen) {
  struct statfs st;
  EXPECT_THAT(statfs("/dev/shm", &st), SyscallSucceeds());

  EXPECT_EQ(st.f_namelen, NAME_MAX);
}

TEST(FstatfsTest, CannotStatBadFd) {
  struct statfs st;
  EXPECT_THAT(fstatfs(-1, &st), SyscallFailsWithErrno(EBADF));
}

TEST(FstatfsTest, InternalTmpfs) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_RDONLY));

  struct statfs st;
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
}

TEST(FstatfsTest, InternalDevShm) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/shm", O_RDONLY));

  struct statfs st;
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
