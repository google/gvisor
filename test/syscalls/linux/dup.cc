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
#include <sys/resource.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
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

TEST(DupTest, Dup) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Dup the descriptor and make sure it's the same file.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
}

TEST(DupTest, DupClearsCloExec) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag set.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_CLOEXEC));
  EXPECT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));

  // Duplicate the descriptor. Ensure that it doesn't have FD_CLOEXEC set.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(0));
}

TEST(DupTest, DupWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));
  int flags;
  ASSERT_THAT(flags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());

  // Dup the descriptor and make sure it's the same file.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFL), SyscallSucceedsWithValue(flags));
}

TEST(DupTest, Dup2) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());

  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));

  // Dup over the file above.
  int target_fd = nfd.release();
  FileDescriptor nfd2 = ASSERT_NO_ERRNO_AND_VALUE(Dup2(fd, target_fd));
  EXPECT_EQ(target_fd, nfd2.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd2));
}

TEST(DupTest, Rlimit) {
  constexpr int kFDLimit = 101;
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  struct rlimit rl = {};
  EXPECT_THAT(getrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  // Lower the rlimit first, as it may be equal to /proc/sys/fs/nr_open, in
  // which case even users with CAP_SYS_RESOURCE can't raise it.
  rl.rlim_cur = kFDLimit * 2;
  ASSERT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  FileDescriptor aboveLimitFD =
      ASSERT_NO_ERRNO_AND_VALUE(Dup2(fd, kFDLimit * 2 - 1));

  rl.rlim_cur = kFDLimit;
  ASSERT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());
  ASSERT_THAT(dup3(fd.get(), kFDLimit, 0), SyscallFails());

  std::vector<std::unique_ptr<FileDescriptor>> fds;
  int prev = fd.get();
  for (int i = 0; i < kFDLimit; i++) {
    int d = dup(fd.get());
    if (d == -1) {
      break;
    }
    std::unique_ptr<FileDescriptor> f = absl::make_unique<FileDescriptor>(d);
    EXPECT_LT(d, kFDLimit);
    EXPECT_GT(d, prev);
    prev = d;
    fds.push_back(std::move(f));
  }
  EXPECT_EQ(fds.size(), kFDLimit - fd.get() - 1);
}

TEST(DupTest, Dup2SameFD) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Should succeed.
  ASSERT_THAT(dup2(fd.get(), fd.get()), SyscallSucceedsWithValue(fd.get()));
}

TEST(DupTest, Dup2WithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));
  int flags;
  ASSERT_THAT(flags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());

  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFL), SyscallSucceedsWithValue(flags));

  // Dup over the file above.
  int target_fd = nfd.release();
  FileDescriptor nfd2 = ASSERT_NO_ERRNO_AND_VALUE(Dup2(fd, target_fd));
  EXPECT_EQ(target_fd, nfd2.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd2));
  EXPECT_THAT(fcntl(nfd2.get(), F_GETFL), SyscallSucceedsWithValue(flags));
}

TEST(DupTest, Dup3) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));

  // Dup over the file above, check that it has no CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), 0));
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Dup over the file again, check that it does not CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), O_CLOEXEC));
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

TEST(DupTest, Dup3FailsSameFD) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Only dup3 fails if the new and old fd are the same.
  ASSERT_THAT(dup3(fd.get(), fd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(DupTest, Dup3WithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_PATH));
  EXPECT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));
  int flags;
  ASSERT_THAT(flags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());

  // Regular dup once.
  FileDescriptor nfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_NE(fd.get(), nfd.get());
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));

  // Dup over the file above, check that it has no CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), 0));
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(0));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFL), SyscallSucceedsWithValue(flags));

  // Dup over the file again, check that it does not CLOEXEC.
  nfd = ASSERT_NO_ERRNO_AND_VALUE(Dup3(fd, nfd.release(), O_CLOEXEC));
  ASSERT_NO_ERRNO(CheckSameFile(fd, nfd));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  EXPECT_THAT(fcntl(nfd.get(), F_GETFL), SyscallSucceedsWithValue(flags));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
