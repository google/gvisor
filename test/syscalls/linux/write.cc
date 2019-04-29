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
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {
// This test is currently very rudimentary.
//
// TODO(edahlgren):
// * bad buffer states (EFAULT).
// * bad fds (wrong permission, wrong type of file, EBADF).
// * check offset is incremented.
// * check for EOF.
// * writing to pipes, symlinks, special files.
class WriteTest : public ::testing::Test {
 public:
  ssize_t WriteBytes(int fd, int bytes) {
    std::vector<char> buf(bytes);
    std::fill(buf.begin(), buf.end(), 'a');
    return WriteFd(fd, buf.data(), buf.size());
  }
};

TEST_F(WriteTest, WriteNoExceedsRLimit) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  int fd;
  struct rlimit setlim;
  const int target_lim = 1024;
  setlim.rlim_cur = target_lim;
  setlim.rlim_max = RLIM_INFINITY;
  const std::string pathname = NewTempAbsPath();
  ASSERT_THAT(fd = open(pathname.c_str(), O_WRONLY | O_CREAT, S_IRWXU),
              SyscallSucceeds());
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());

  EXPECT_THAT(WriteBytes(fd, target_lim), SyscallSucceedsWithValue(target_lim));

  std::vector<char> buf(target_lim + 1);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(pwrite(fd, buf.data(), target_lim, 1), SyscallSucceeds());
  EXPECT_THAT(pwrite64(fd, buf.data(), target_lim, 1), SyscallSucceeds());

  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(WriteTest, WriteExceedsRLimit) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  int fd;
  sigset_t filesize_mask;
  sigemptyset(&filesize_mask);
  sigaddset(&filesize_mask, SIGXFSZ);

  struct rlimit setlim;
  const int target_lim = 1024;
  setlim.rlim_cur = target_lim;
  setlim.rlim_max = RLIM_INFINITY;

  const std::string pathname = NewTempAbsPath();
  ASSERT_THAT(fd = open(pathname.c_str(), O_WRONLY | O_CREAT, S_IRWXU),
              SyscallSucceeds());
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());
  ASSERT_THAT(sigprocmask(SIG_BLOCK, &filesize_mask, nullptr),
              SyscallSucceeds());
  std::vector<char> buf(target_lim + 2);
  std::fill(buf.begin(), buf.end(), 'a');

  EXPECT_THAT(write(fd, buf.data(), target_lim + 1),
              SyscallSucceedsWithValue(target_lim));
  EXPECT_THAT(write(fd, buf.data(), 1), SyscallFailsWithErrno(EFBIG));
  siginfo_t info;
  struct timespec timelimit = {0, 0};
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  EXPECT_THAT(pwrite(fd, buf.data(), target_lim + 1, 1),
              SyscallSucceedsWithValue(target_lim - 1));
  EXPECT_THAT(pwrite(fd, buf.data(), 1, target_lim),
              SyscallFailsWithErrno(EFBIG));
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  EXPECT_THAT(pwrite64(fd, buf.data(), target_lim + 1, 1),
              SyscallSucceedsWithValue(target_lim - 1));
  EXPECT_THAT(pwrite64(fd, buf.data(), 1, target_lim),
              SyscallFailsWithErrno(EFBIG));
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &filesize_mask, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
