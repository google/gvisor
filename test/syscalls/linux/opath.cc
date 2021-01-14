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

#include <string>

#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(ChmodTest, FchmodFileWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  ASSERT_THAT(fchmod(fd.get(), 0444), SyscallFailsWithErrno(EBADF));
}

TEST(ChmodTest, FchmodDirWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));

  ASSERT_THAT(fchmod(fd.get(), 0444), SyscallFailsWithErrno(EBADF));
}

// TEST(ChmodTest, FchmodatWithOpath) {
//   SKIP_IF(IsRunningWithVFS1());
//   // Drop capabilities that allow us to override file permissions.
//   ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

//   const auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
//   const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
//   const auto fd =
//       ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));

//   ASSERT_THAT(fchmodat(
//       fd.get(), std::string(Basename(temp_file.path())).c_str(), 0444, 0),
//               SyscallSucceeds());
//   EXPECT_THAT(close(fd.get()), SyscallSucceeds());

//   EXPECT_THAT(open(temp_file.path().c_str(), O_RDWR),
//               SyscallFailsWithErrno(EACCES));
// }

// TEST(ChmodTest, FchmodatEmptyPathWithOpath) {
//   SKIP_IF(IsRunningWithVFS1());
//   const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
//   const auto fd =
//       ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));

//   ASSERT_THAT(fchmodat(fd.get(), "", 0444, AT_EMPTY_PATH),
//               SyscallFailsWithErrno(EBADF));
// }

TEST(ChownTest, FchownFileWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  ASSERT_THAT(fchown(fd.get(), 0, 0), SyscallFailsWithErrno(EBADF));
}

TEST(ChownTest, FchownDirWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));

  ASSERT_THAT(fchown(fd.get(), 0, 0), SyscallFailsWithErrno(EBADF));
}

// TEST(ChownTest, FchownatWithOpath) {
//   SKIP_IF(IsRunningWithVFS1());
//   const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
//   auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
//   const auto dirfd =
//       ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));
//   ASSERT_THAT(fchownat(dirfd.get(), file.path().c_str(), 0, 0, 0),
//               SyscallSucceeds());
// }

// TEST(ChownTest, FchownatEmptyPathWithOpath) {
//   SKIP_IF(IsRunningWithVFS1());
//   const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
//   const auto dirfd =
//       ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));
//   ASSERT_THAT(fchownat(dirfd.get(), "", 0, 0, AT_EMPTY_PATH),
//               SyscallFailsWithErrno(EBADF));
// }

PosixErrorOr<FileDescriptor> Dup2(const FileDescriptor& fd, int target_fd) {
  int new_fd = dup2(fd.get(), target_fd);
  if (new_fd < 0) {
    return PosixError(errno, "Dup2");
  }
  return FileDescriptor(new_fd);
}

PosixErrorOr<FileDescriptor> Dup3(const FileDescriptor& fd, int target_fd,
                                  int flags) {
  int new_fd = dup3(fd.get(), target_fd, flags);
  if (new_fd < 0) {
    return PosixError(errno, "Dup2");
  }
  return FileDescriptor(new_fd);
}

void CheckSameFile(const FileDescriptor& fd1, const FileDescriptor& fd2) {
  struct stat stat_result1, stat_result2;
  ASSERT_THAT(fstat(fd1.get(), &stat_result1), SyscallSucceeds());
  ASSERT_THAT(fstat(fd2.get(), &stat_result2), SyscallSucceeds());
  EXPECT_EQ(stat_result1.st_dev, stat_result2.st_dev);
  EXPECT_EQ(stat_result1.st_ino, stat_result2.st_ino);
}

TEST(DupTest, DupWithOpath) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));

  // Dup the descriptor and make sure it's the same file.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  CheckSameFile(fd, nfd);
}

TEST(DupTest, Dup2WithOpath) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());

  ASSERT_NE(fd.get(), nfd.get());
  CheckSameFile(fd, nfd);

  // Dup over the file above.
  int target_fd = nfd.release();
  FileDescriptor nfd2 = ASSERT_NO_ERRNO_AND_VALUE(Dup2(fd, target_fd));
  EXPECT_EQ(target_fd, nfd2.get());
  CheckSameFile(fd, nfd2);
}

TEST(DupTest, Dup3WithOpath) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  CheckSameFile(fd, nfd);

  // Dup over the file above, check that it has no CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), 0));
  CheckSameFile(fd, nfd);
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Dup over the file again, check that it does not CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), O_CLOEXEC));
  CheckSameFile(fd, nfd);
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

int fallocate(int fd, int mode, off_t offset, off_t len) {
  return RetryEINTR(syscall)(__NR_fallocate, fd, mode, offset, len);
}

class AllocateTest : public FileTest {
  void SetUp() override { FileTest::SetUp(); }
};

TEST_F(AllocateTest, FallocateWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));
  EXPECT_THAT(fallocate(fd.get(), 0, 0, 10), SyscallFailsWithErrno(EBADF));
}

TEST(FchdirTest, SuccessWithOpath) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int fd;
  ASSERT_THAT(fd = open(temp_dir.path().c_str(), O_DIRECTORY | O_PATH),
              SyscallSucceeds());

  EXPECT_THAT(fchdir(fd), SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  // Change CWD to a permanent location as temp dirs will be cleaned up.
  EXPECT_THAT(chdir("/"), SyscallSucceeds());
}

TEST(FcntlTest, FcntlDupWithOpath) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));

  int nfd;
  // Dup the descriptor and make sure it's the same file.
  EXPECT_THAT(nfd = fcntl(fd.get(), F_DUPFD, 0), SyscallSucceeds());
  ASSERT_NE(fd.get(), nfd);
  CheckSameFile(fd.get(), nfd);
}

TEST(FcntlTest, SetFileStatusFlagWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_PATH));

  EXPECT_THAT(fcntl(fd.get(), F_SETFL, 0), SyscallFailsWithErrno(EBADF));
}

TEST(FcntlTest, SetOwnWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_PATH));

  EXPECT_THAT(fcntl(fd.get(), F_SETOWN, 0), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(fcntl(fd.get(), F_GETOWN, 0), SyscallFailsWithErrno(EBADF));

  EXPECT_THAT(fcntl(fd.get(), F_SETOWN_EX, 0), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(fcntl(fd.get(), F_GETOWN_EX, 0), SyscallFailsWithErrno(EBADF));
}

TEST(FcntlTest, SetCloExecWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  // Open a file descriptor with FD_CLOEXEC descriptor flag not set.
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_PATH));
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Set the FD_CLOEXEC flag.
  ASSERT_THAT(fcntl(fd.get(), F_SETFD, FD_CLOEXEC), SyscallSucceeds());
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

// Only select flags passed to open appear in F_GETFL when opened with O_PATH.
TEST(FcntlTest, GetOpathFlag) {
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int flags = O_RDWR | O_DIRECT | O_SYNC | O_NONBLOCK | O_APPEND | O_PATH |
              O_NOFOLLOW | O_DIRECTORY;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), flags));

  int expected = O_PATH | O_NOFOLLOW | O_DIRECTORY;

  int rflags;
  EXPECT_THAT(rflags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(rflags, expected);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
