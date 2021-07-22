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
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <ctime>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

int fallocate(int fd, int mode, off_t offset, off_t len) {
  return RetryEINTR(syscall)(__NR_fallocate, fd, mode, offset, len);
}

class AllocateTest : public FileTest {
  void SetUp() override { FileTest::SetUp(); }
};

TEST_F(AllocateTest, Fallocate) {
  // Check that it starts at size zero.
  struct stat buf;
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 0);

  // Grow to ten bytes.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 0, 10), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 10);

  // Allocate to a smaller size should be noop.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 0, 5), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 10);

  // Grow again.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 0, 20), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 20);

  // Grow with offset.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 10, 20), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 30);

  // Grow with offset beyond EOF.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 39, 1), SyscallSucceeds());
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 40);

  // Given length 0 should fail with EINVAL.
  ASSERT_THAT(fallocate(test_file_fd_.get(), 0, 50, 0),
              SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(fstat(test_file_fd_.get(), &buf), SyscallSucceeds());
  EXPECT_EQ(buf.st_size, 40);
}

TEST_F(AllocateTest, FallocateInvalid) {
  // Invalid FD
  EXPECT_THAT(fallocate(-1, 0, 0, 10), SyscallFailsWithErrno(EBADF));

  // Negative offset and size.
  EXPECT_THAT(fallocate(test_file_fd_.get(), 0, -1, 10),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fallocate(test_file_fd_.get(), 0, 0, -1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fallocate(test_file_fd_.get(), 0, -1, -1),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(AllocateTest, FallocateReadonly) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));
  EXPECT_THAT(fallocate(fd.get(), 0, 0, 10), SyscallFailsWithErrno(EBADF));
}

TEST_F(AllocateTest, FallocateWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));
  EXPECT_THAT(fallocate(fd.get(), 0, 0, 10), SyscallFailsWithErrno(EBADF));
}

TEST_F(AllocateTest, FallocatePipe) {
  int pipes[2];
  EXPECT_THAT(pipe(pipes), SyscallSucceeds());
  auto cleanup = Cleanup([&pipes] {
    EXPECT_THAT(close(pipes[0]), SyscallSucceeds());
    EXPECT_THAT(close(pipes[1]), SyscallSucceeds());
  });

  EXPECT_THAT(fallocate(pipes[1], 0, 0, 10), SyscallFailsWithErrno(ESPIPE));
}

TEST_F(AllocateTest, FallocateChar) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDWR));
  EXPECT_THAT(fallocate(fd.get(), 0, 0, 10), SyscallFailsWithErrno(ENODEV));
}

TEST_F(AllocateTest, FallocateRlimit) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  // Try growing past the file size limit.
  sigset_t new_mask;
  sigemptyset(&new_mask);
  sigaddset(&new_mask, SIGXFSZ);
  sigprocmask(SIG_BLOCK, &new_mask, nullptr);

  struct rlimit setlim = {};
  setlim.rlim_cur = 1024;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());

  EXPECT_THAT(fallocate(test_file_fd_.get(), 0, 0, 1025),
              SyscallFailsWithErrno(EFBIG));

  struct timespec timelimit = {};
  timelimit.tv_sec = 10;
  EXPECT_EQ(sigtimedwait(&new_mask, nullptr, &timelimit), SIGXFSZ);
  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &new_mask, nullptr), SyscallSucceeds());
}

TEST_F(AllocateTest, FallocateOtherFDs) {
  int fd;
  ASSERT_THAT(fd = timerfd_create(CLOCK_MONOTONIC, 0), SyscallSucceeds());
  auto timer_fd = FileDescriptor(fd);
  EXPECT_THAT(fallocate(timer_fd.get(), 0, 0, 10),
              SyscallFailsWithErrno(ENODEV));

  sigset_t mask;
  sigemptyset(&mask);
  ASSERT_THAT(fd = signalfd(-1, &mask, 0), SyscallSucceeds());
  auto sfd = FileDescriptor(fd);
  EXPECT_THAT(fallocate(sfd.get(), 0, 0, 10), SyscallFailsWithErrno(ENODEV));

  auto efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));
  EXPECT_THAT(fallocate(efd.get(), 0, 0, 10), SyscallFailsWithErrno(ENODEV));

  auto sockfd = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  EXPECT_THAT(fallocate(sockfd.get(), 0, 0, 10), SyscallFailsWithErrno(ENODEV));

  int socks[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, PF_UNIX, socks),
              SyscallSucceeds());
  auto sock0 = FileDescriptor(socks[0]);
  auto sock1 = FileDescriptor(socks[1]);
  EXPECT_THAT(fallocate(sock0.get(), 0, 0, 10), SyscallFailsWithErrno(ENODEV));

  int pipefds[2];
  ASSERT_THAT(pipe(pipefds), SyscallSucceeds());
  EXPECT_THAT(fallocate(pipefds[1], 0, 0, 10), SyscallFailsWithErrno(ESPIPE));
  close(pipefds[0]);
  close(pipefds[1]);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
