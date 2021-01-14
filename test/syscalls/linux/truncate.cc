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
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class FixtureTruncateTest : public FileTest {
  void SetUp() override { FileTest::SetUp(); }
};

TEST_F(FixtureTruncateTest, Truncate) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Stay at size zero.
  EXPECT_THAT(truncate(test_file_name_.c_str(), 0), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to ten bytes.
  EXPECT_THAT(truncate(test_file_name_.c_str(), 10), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 10);

  // Can't be truncated to a negative number.
  EXPECT_THAT(truncate(test_file_name_.c_str(), -1),
              SyscallFailsWithErrno(EINVAL));

  // Try growing past the file size limit.
  sigset_t new_mask;
  sigemptyset(&new_mask);
  sigaddset(&new_mask, SIGXFSZ);
  sigprocmask(SIG_BLOCK, &new_mask, nullptr);
  struct timespec timelimit;
  timelimit.tv_sec = 10;
  timelimit.tv_nsec = 0;

  struct rlimit setlim;
  setlim.rlim_cur = 1024;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());
  EXPECT_THAT(truncate(test_file_name_.c_str(), 1025),
              SyscallFailsWithErrno(EFBIG));
  EXPECT_EQ(sigtimedwait(&new_mask, nullptr, &timelimit), SIGXFSZ);
  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &new_mask, nullptr), SyscallSucceeds());

  // Shrink back down to zero.
  EXPECT_THAT(truncate(test_file_name_.c_str(), 0), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);
}

TEST_F(FixtureTruncateTest, Ftruncate) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Stay at size zero.
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 0), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to ten bytes.
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 10), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 10);

  // Can't be truncated to a negative number.
  EXPECT_THAT(ftruncate(test_file_fd_.get(), -1),
              SyscallFailsWithErrno(EINVAL));

  // Try growing past the file size limit.
  sigset_t new_mask;
  sigemptyset(&new_mask);
  sigaddset(&new_mask, SIGXFSZ);
  sigprocmask(SIG_BLOCK, &new_mask, nullptr);
  struct timespec timelimit;
  timelimit.tv_sec = 10;
  timelimit.tv_nsec = 0;

  struct rlimit setlim;
  setlim.rlim_cur = 1024;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 1025),
              SyscallFailsWithErrno(EFBIG));
  EXPECT_EQ(sigtimedwait(&new_mask, nullptr, &timelimit), SIGXFSZ);
  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &new_mask, nullptr), SyscallSucceeds());

  // Shrink back down to zero.
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 0), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);
}

// Truncating a file down clears that portion of the file.
TEST_F(FixtureTruncateTest, FtruncateShrinkGrow) {
  std::vector<char> buf(10, 'a');
  EXPECT_THAT(WriteFd(test_file_fd_.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Shrink then regrow the file. This should clear the second half of the file.
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 5), SyscallSucceeds());
  EXPECT_THAT(ftruncate(test_file_fd_.get(), 10), SyscallSucceeds());

  EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_SET), SyscallSucceeds());

  std::vector<char> buf2(10);
  EXPECT_THAT(ReadFd(test_file_fd_.get(), buf2.data(), buf2.size()),
              SyscallSucceedsWithValue(buf2.size()));

  std::vector<char> expect = {'a',  'a',  'a',  'a',  'a',
                              '\0', '\0', '\0', '\0', '\0'};
  EXPECT_EQ(expect, buf2);
}

TEST(TruncateTest, TruncateDir) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(truncate(temp_dir.path().c_str(), 0),
              SyscallFailsWithErrno(EISDIR));
}

TEST(TruncateTest, FtruncateDir) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_dir.path(), O_DIRECTORY | O_RDONLY));
  EXPECT_THAT(ftruncate(fd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(TruncateTest, TruncateNonWriteable) {
  // Make sure we don't have CAP_DAC_OVERRIDE, since that allows the user to
  // always override write permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(), 0555 /* mode */));
  EXPECT_THAT(truncate(temp_file.path().c_str(), 0),
              SyscallFailsWithErrno(EACCES));
}

TEST(TruncateTest, FtruncateNonWriteable) {
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(), 0555 /* mode */));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_RDONLY));
  EXPECT_THAT(ftruncate(fd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(TruncateTest, FtruncateOpathFile) {
  SKIP_IF(IsRunningWithVFS1());
  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(), 0555 /* mode */));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_PATH));
  EXPECT_THAT(ftruncate(fd.get(), 0), SyscallFailsWithErrno(EBADF));
}

// ftruncate(2) should succeed as long as the file descriptor is writeable,
// regardless of whether the file permissions allow writing.
TEST(TruncateTest, FtruncateWithoutWritePermission_NoRandomSave) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  // The only time we can open a file with flags forbidden by its permissions
  // is when we are creating the file. We cannot re-open with the same flags,
  // so we cannot restore an fd obtained from such an operation.
  const DisableSave ds;
  auto path = NewTempAbsPath();
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_CREAT, 0444));

  // In goferfs, ftruncate may be converted to a remote truncate operation that
  // unavoidably requires write permission.
  SKIP_IF(IsRunningOnGvisor() && !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(path)));
  ASSERT_THAT(ftruncate(fd.get(), 100), SyscallSucceeds());
}

TEST(TruncateTest, TruncateNonExist) {
  EXPECT_THAT(truncate("/foo/bar", 0), SyscallFailsWithErrno(ENOENT));
}

TEST(TruncateTest, FtruncateVirtualTmp_NoRandomSave) {
  auto temp_file = NewTempAbsPathInDir("/dev/shm");
  const DisableSave ds;  // Incompatible permissions.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file, O_RDWR | O_CREAT | O_EXCL, 0));
  EXPECT_THAT(ftruncate(fd.get(), 100), SyscallSucceeds());
}

// NOTE: There are additional truncate(2)/ftruncate(2) tests in mknod.cc
// which are there to avoid running the tests on a number of different
// filesystems which may not support mknod.

}  // namespace

}  // namespace testing
}  // namespace gvisor
