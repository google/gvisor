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
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int kMode = 0666;

TEST(CreatTest, CreatCreatesNewFile) {
  std::string const path = NewTempAbsPath();
  struct stat buf;
  int fd;
  ASSERT_THAT(stat(path.c_str(), &buf), SyscallFailsWithErrno(ENOENT));
  ASSERT_THAT(fd = creat(path.c_str(), kMode), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  EXPECT_THAT(stat(path.c_str(), &buf), SyscallSucceeds());
}

TEST(CreatTest, CreatTruncatesExistingFile) {
  auto temp_path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int fd;
  ASSERT_NO_ERRNO(SetContents(temp_path.path(), "non-empty"));
  ASSERT_THAT(fd = creat(temp_path.path().c_str(), kMode), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  std::string new_contents;
  ASSERT_NO_ERRNO(GetContents(temp_path.path(), &new_contents));
  EXPECT_EQ("", new_contents);
}

TEST(CreatTest, CreatWithNameTooLong) {
  // Start with a unique name, and pad it to NAME_MAX + 1;
  std::string name = NewTempRelPath();
  int padding = (NAME_MAX + 1) - name.size();
  name.append(padding, 'x');
  const std::string& path = JoinPath(GetAbsoluteTestTmpdir(), name);

  // Creation should return ENAMETOOLONG.
  ASSERT_THAT(creat(path.c_str(), kMode), SyscallFailsWithErrno(ENAMETOOLONG));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
