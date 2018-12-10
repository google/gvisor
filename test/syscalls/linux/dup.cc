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
#include <sys/eventfd.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

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

TEST(DupTest, Dup) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Dup the descriptor and make sure it's the same file.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  CheckSameFile(fd, nfd);
}

TEST(DupTest, DupClearsCloExec) {
  FileDescriptor nfd;

  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag set.
  int event_fd = 0;
  ASSERT_THAT(event_fd = eventfd(0, EFD_CLOEXEC), SyscallSucceeds());
  FileDescriptor event_fd_closer(event_fd);

  EXPECT_THAT(fcntl(event_fd_closer.get(), F_GETFD),
              SyscallSucceedsWithValue(FD_CLOEXEC));

  // Duplicate the descriptor. Ensure that it doesn't have FD_CLOEXEC set.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(event_fd_closer.Dup());
  ASSERT_NE(event_fd_closer.get(), nfd.get());
  CheckSameFile(event_fd_closer, nfd);
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(0));
}

TEST(DupTest, Dup2) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

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

TEST(DupTest, Dup2SameFD) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Should succeed.
  ASSERT_THAT(dup2(fd.get(), fd.get()), SyscallSucceedsWithValue(fd.get()));
}

TEST(DupTest, Dup3) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

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

TEST(DupTest, Dup3FailsSameFD) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Only dup3 fails if the new and old fd are the same.
  ASSERT_THAT(dup3(fd.get(), fd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
