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

#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// TODO(gvisor.dev/issue/2370): This test is currently very rudimentary.
class Pwrite64 : public ::testing::Test {
  void SetUp() override {
    name_ = NewTempAbsPath();
    int fd;
    ASSERT_THAT(fd = open(name_.c_str(), O_CREAT, 0644), SyscallSucceeds());
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  void TearDown() override { unlink(name_.c_str()); }

 public:
  std::string name_;
};

TEST_F(Pwrite64, AppendOnly) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), 0),
              SyscallSucceedsWithValue(buf.size()));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, InvalidArgs) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), -1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, Overflow) {
  int fd;
  ASSERT_THAT(fd = open(name_.c_str(), O_APPEND | O_RDWR), SyscallSucceeds());
  constexpr int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(PwriteFd(fd, buf.data(), buf.size(), 0x7fffffffffffffffull),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Pwrite64, WriteWithOpath) {
  SKIP_IF(IsRunningWithVFS1());

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), "", TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  std::vector<char> buf(1);
  EXPECT_THAT(PwriteFd(fd.get(), buf.data(), 1, 0),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(close(fd.get()), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
