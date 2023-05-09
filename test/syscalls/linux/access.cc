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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Ge;

namespace gvisor {
namespace testing {

namespace {

class AccessTest : public ::testing::Test {
 public:
  std::string CreateTempFile(int perm) {
    const std::string path = NewTempAbsPath();
    const int fd = open(path.c_str(), O_CREAT | O_RDONLY, perm);
    TEST_PCHECK(fd > 0);
    TEST_PCHECK(close(fd) == 0);
    return path;
  }

 protected:
  // SetUp creates various configurations of files.
  void SetUp() override {
    // Move to the temporary directory. This allows us to reason more easily
    // about absolute and relative paths.
    ASSERT_THAT(chdir(GetAbsoluteTestTmpdir().c_str()), SyscallSucceeds());

    // Create an empty file, standard permissions.
    relfile_ = NewTempRelPath();
    int fd;
    ASSERT_THAT(fd = open(relfile_.c_str(), O_CREAT | O_TRUNC, 0644),
                SyscallSucceedsWithValue(Ge(0)));
    ASSERT_THAT(close(fd), SyscallSucceeds());
    absfile_ = GetAbsoluteTestTmpdir() + "/" + relfile_;

    // Create an empty directory, no writable permissions.
    absdir_ = NewTempAbsPath();
    reldir_ = JoinPath(Basename(absdir_), "");
    ASSERT_THAT(mkdir(reldir_.c_str(), 0555), SyscallSucceeds());

    // This file doesn't exist.
    relnone_ = NewTempRelPath();
    absnone_ = GetAbsoluteTestTmpdir() + "/" + relnone_;
  }

  // TearDown unlinks created files.
  void TearDown() override {
    ASSERT_THAT(unlink(absfile_.c_str()), SyscallSucceeds());
    ASSERT_THAT(rmdir(absdir_.c_str()), SyscallSucceeds());
  }

  std::string relfile_;
  std::string reldir_;

  std::string absfile_;
  std::string absdir_;

  std::string relnone_;
  std::string absnone_;
};

TEST_F(AccessTest, RelativeFile) {
  EXPECT_THAT(access(relfile_.c_str(), R_OK), SyscallSucceeds());
}

TEST_F(AccessTest, RelativeDir) {
  EXPECT_THAT(access(reldir_.c_str(), R_OK | X_OK), SyscallSucceeds());
}

TEST_F(AccessTest, AbsFile) {
  EXPECT_THAT(access(absfile_.c_str(), R_OK), SyscallSucceeds());
}

TEST_F(AccessTest, AbsDir) {
  EXPECT_THAT(access(absdir_.c_str(), R_OK | X_OK), SyscallSucceeds());
}

TEST_F(AccessTest, RelDoesNotExist) {
  EXPECT_THAT(access(relnone_.c_str(), R_OK), SyscallFailsWithErrno(ENOENT));
}

TEST_F(AccessTest, AbsDoesNotExist) {
  EXPECT_THAT(access(absnone_.c_str(), R_OK), SyscallFailsWithErrno(ENOENT));
}

TEST_F(AccessTest, InvalidMode) {
  EXPECT_THAT(access(relfile_.c_str(), 0xffffffff),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(AccessTest, NoPerms) {
  // Drop capabilities that allow us to override permissions. We must drop
  // PERMITTED because access() checks those instead of EFFECTIVE.
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_OVERRIDE));
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_READ_SEARCH));

  EXPECT_THAT(access(absdir_.c_str(), W_OK), SyscallFailsWithErrno(EACCES));
}

TEST_F(AccessTest, InvalidName) {
  EXPECT_THAT(access(reinterpret_cast<char*>(0x1234), W_OK),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(AccessTest, UsrReadOnly) {
  // Drop capabilities that allow us to override permissions. We must drop
  // PERMITTED because access() checks those instead of EFFECTIVE.
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_OVERRIDE));
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_READ_SEARCH));

  const std::string filename = CreateTempFile(0400);
  EXPECT_THAT(access(filename.c_str(), R_OK), SyscallSucceeds());
  EXPECT_THAT(access(filename.c_str(), W_OK), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(access(filename.c_str(), X_OK), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

TEST_F(AccessTest, UsrReadExec) {
  // Drop capabilities that allow us to override permissions. We must drop
  // PERMITTED because access() checks those instead of EFFECTIVE.
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_OVERRIDE));
  ASSERT_NO_ERRNO(DropPermittedCapability(CAP_DAC_READ_SEARCH));

  const std::string filename = CreateTempFile(0500);
  EXPECT_THAT(access(filename.c_str(), R_OK | X_OK), SyscallSucceeds());
  EXPECT_THAT(access(filename.c_str(), W_OK), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

TEST_F(AccessTest, UsrReadWrite) {
  const std::string filename = CreateTempFile(0600);
  EXPECT_THAT(access(filename.c_str(), R_OK | W_OK), SyscallSucceeds());
  EXPECT_THAT(access(filename.c_str(), X_OK), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

TEST_F(AccessTest, UsrReadWriteExec) {
  const std::string filename = CreateTempFile(0700);
  EXPECT_THAT(access(filename.c_str(), R_OK | W_OK | X_OK), SyscallSucceeds());
  EXPECT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

// glibc faccessat() is a wrapper around either the faccessat syscall that tries
// to implement flags in userspace, or the faccessat2 syscall. We want to test
// syscalls specifically, so use syscall(2) directly.
int sys_faccessat(int dirfd, const char* pathname, int mode) {
  return syscall(SYS_faccessat, dirfd, pathname, mode);
}

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif  // SYS_faccessat2

int sys_faccessat2(int dirfd, const char* pathname, int mode, int flags) {
  return syscall(SYS_faccessat2, dirfd, pathname, mode, flags);
}

TEST(FaccessatTest, SymlinkFollowed) {
  const std::string target_path = NewTempAbsPath();
  const std::string symlink_path = NewTempAbsPath();
  ASSERT_THAT(symlink(target_path.c_str(), symlink_path.c_str()),
              SyscallSucceeds());

  // faccessat() should initially fail with ENOENT since it follows the symlink
  // to a file that doesn't exist.
  EXPECT_THAT(sys_faccessat(-1, symlink_path.c_str(), F_OK),
              SyscallFailsWithErrno(ENOENT));

  // After creating the symlink target, faccessat() should succeed.
  int fd;
  ASSERT_THAT(fd = open(target_path.c_str(), O_CREAT | O_EXCL, 0644),
              SyscallSucceeds());
  close(fd);
  EXPECT_THAT(sys_faccessat(-1, symlink_path.c_str(), F_OK), SyscallSucceeds());
}

PosixErrorOr<bool> Faccessat2Supported() {
  if (IsRunningOnGvisor()) {
    return true;
  }
  int ret = sys_faccessat2(-1, "/", F_OK, 0);
  if (ret == 0) {
    return true;
  }
  if (errno == ENOSYS) {
    return false;
  }
  return PosixError(errno, "unexpected errno from faccessat2(/)");
}

TEST(Faccessat2Test, SymlinkFollowedByDefault) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(Faccessat2Supported()));

  const std::string target_path = NewTempAbsPath();
  const std::string symlink_path = NewTempAbsPath();
  ASSERT_THAT(symlink(target_path.c_str(), symlink_path.c_str()),
              SyscallSucceeds());

  // faccessat2() should initially fail with ENOENT since, by default, it
  // follows the symlink to a file that doesn't exist.
  EXPECT_THAT(sys_faccessat2(-1, symlink_path.c_str(), F_OK, 0 /* flags */),
              SyscallFailsWithErrno(ENOENT));

  // After creating the symlink target, faccessat2() should succeed.
  int fd;
  ASSERT_THAT(fd = open(target_path.c_str(), O_CREAT | O_EXCL, 0644),
              SyscallSucceeds());
  close(fd);
  EXPECT_THAT(sys_faccessat2(-1, symlink_path.c_str(), F_OK, 0 /* flags */),
              SyscallSucceeds());
}

TEST(Faccessat2Test, SymlinkNofollow) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(Faccessat2Supported()));

  const std::string target_path = NewTempAbsPath();
  const std::string symlink_path = NewTempAbsPath();
  ASSERT_THAT(symlink(target_path.c_str(), symlink_path.c_str()),
              SyscallSucceeds());

  EXPECT_THAT(
      sys_faccessat2(-1, symlink_path.c_str(), F_OK, AT_SYMLINK_NOFOLLOW),
      SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
