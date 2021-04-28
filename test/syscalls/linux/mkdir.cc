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
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class MkdirTest : public ::testing::Test {
 protected:
  // SetUp creates various configurations of files.
  void SetUp() override { dirname_ = NewTempAbsPath(); }

  // TearDown unlinks created files.
  void TearDown() override {
    EXPECT_THAT(rmdir(dirname_.c_str()), SyscallSucceeds());
  }

  std::string dirname_;
};

TEST_F(MkdirTest, CanCreateWritableDir) {
  ASSERT_THAT(mkdir(dirname_.c_str(), 0777), SyscallSucceeds());
  std::string filename = JoinPath(dirname_, "anything");
  int fd;
  ASSERT_THAT(fd = open(filename.c_str(), O_RDWR | O_CREAT, 0666),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  ASSERT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

TEST_F(MkdirTest, HonorsUmask) {
  constexpr mode_t kMask = 0111;
  TempUmask mask(kMask);
  ASSERT_THAT(mkdir(dirname_.c_str(), 0777), SyscallSucceeds());
  struct stat statbuf;
  ASSERT_THAT(stat(dirname_.c_str(), &statbuf), SyscallSucceeds());
  EXPECT_EQ(0777 & ~kMask, statbuf.st_mode & 0777);
}

TEST_F(MkdirTest, HonorsUmask2) {
  constexpr mode_t kMask = 0142;
  TempUmask mask(kMask);
  ASSERT_THAT(mkdir(dirname_.c_str(), 0777), SyscallSucceeds());
  struct stat statbuf;
  ASSERT_THAT(stat(dirname_.c_str(), &statbuf), SyscallSucceeds());
  EXPECT_EQ(0777 & ~kMask, statbuf.st_mode & 0777);
}

TEST_F(MkdirTest, FailsOnDirWithoutWritePerms) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  ASSERT_THAT(mkdir(dirname_.c_str(), 0555), SyscallSucceeds());
  auto dir = JoinPath(dirname_.c_str(), "foo");
  EXPECT_THAT(mkdir(dir.c_str(), 0777), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(open(JoinPath(dirname_, "file").c_str(), O_RDWR | O_CREAT, 0666),
              SyscallFailsWithErrno(EACCES));
}

TEST_F(MkdirTest, DirAlreadyExists) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  ASSERT_THAT(mkdir(dirname_.c_str(), 0777), SyscallSucceeds());
  auto dir = JoinPath(dirname_.c_str(), "foo");
  EXPECT_THAT(mkdir(dir.c_str(), 0777), SyscallSucceeds());

  struct {
    int mode;
    int err;
  } tests[] = {
      {.mode = 0000, .err = EACCES},  // No perm
      {.mode = 0100, .err = EEXIST},  // Exec only
      {.mode = 0200, .err = EACCES},  // Write only
      {.mode = 0300, .err = EEXIST},  // Write+exec
      {.mode = 0400, .err = EACCES},  // Read only
      {.mode = 0500, .err = EEXIST},  // Read+exec
      {.mode = 0600, .err = EACCES},  // Read+write
      {.mode = 0700, .err = EEXIST},  // All
  };
  for (const auto& t : tests) {
    printf("mode: 0%o\n", t.mode);
    EXPECT_THAT(chmod(dirname_.c_str(), t.mode), SyscallSucceeds());
    EXPECT_THAT(mkdir(dir.c_str(), 0777), SyscallFailsWithErrno(t.err));
  }

  // Clean up.
  EXPECT_THAT(chmod(dirname_.c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(rmdir(dir.c_str()), SyscallSucceeds());
}

TEST_F(MkdirTest, MkdirAtEmptyPath) {
  ASSERT_THAT(mkdir(dirname_.c_str(), 0777), SyscallSucceeds());
  auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dirname_, O_RDONLY | O_DIRECTORY, 0666));
  EXPECT_THAT(mkdirat(fd.get(), "", 0777), SyscallFailsWithErrno(ENOENT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
