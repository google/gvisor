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
#include <signal.h>
#include <syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/base/port.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/timer_util.h"

DEFINE_string(child_setlock_on, "",
              "Contains the path to try to set a file lock on.");
DEFINE_bool(child_setlock_write, false,
            "Whether to set a writable lock (otherwise readable)");
DEFINE_bool(blocking, false,
            "Whether to set a blocking lock (otherwise non-blocking).");
DEFINE_bool(retry_eintr, false, "Whether to retry in the subprocess on EINTR.");
DEFINE_uint64(child_setlock_start, 0, "The value of struct flock start");
DEFINE_uint64(child_setlock_len, 0, "The value of struct flock len");
DEFINE_int32(socket_fd, -1,
             "A socket to use for communicating more state back "
             "to the parent.");

namespace gvisor {
namespace testing {

// O_LARGEFILE as defined by Linux. glibc tries to be clever by setting it to 0
// because "it isn't needed", even though Linux can return it via F_GETFL.
constexpr int kOLargeFile = 00100000;

class FcntlLockTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Let's make a socket pair.
    ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_), SyscallSucceeds());
  }

  void TearDown() override {
    EXPECT_THAT(close(fds_[0]), SyscallSucceeds());
    EXPECT_THAT(close(fds_[1]), SyscallSucceeds());
  }

  int64_t GetSubprocessFcntlTimeInUsec() {
    int64_t ret = 0;
    EXPECT_THAT(ReadFd(fds_[0], reinterpret_cast<void*>(&ret), sizeof(ret)),
                SyscallSucceedsWithValue(sizeof(ret)));
    return ret;
  }

  // The first fd will remain with the process creating the subprocess
  // and the second will go to the subprocess.
  int fds_[2] = {};
};

namespace {

PosixErrorOr<Cleanup> SubprocessLock(std::string const& path, bool for_write,
                                     bool blocking, bool retry_eintr, int fd,
                                     off_t start, off_t length, pid_t* child) {
  std::vector<std::string> args = {
      "/proc/self/exe",        "--child_setlock_on", path,
      "--child_setlock_start", absl::StrCat(start),  "--child_setlock_len",
      absl::StrCat(length),    "--socket_fd",        absl::StrCat(fd)};

  if (for_write) {
    args.push_back("--child_setlock_write");
  }

  if (blocking) {
    args.push_back("--blocking");
  }

  if (retry_eintr) {
    args.push_back("--retry_eintr");
  }

  int execve_errno = 0;
  ASSIGN_OR_RETURN_ERRNO(
      auto cleanup,
      ForkAndExec("/proc/self/exe", ExecveArray(args.begin(), args.end()), {},
                  nullptr, child, &execve_errno));

  if (execve_errno != 0) {
    return PosixError(execve_errno, "execve");
  }

  return std::move(cleanup);
}

TEST(FcntlTest, SetCloExec) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag not set.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, 0));
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Set the FD_CLOEXEC flag.
  ASSERT_THAT(fcntl(fd.get(), F_SETFD, FD_CLOEXEC), SyscallSucceeds());
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

TEST(FcntlTest, ClearCloExec) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag set.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_CLOEXEC));
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));

  // Clear the FD_CLOEXEC flag.
  ASSERT_THAT(fcntl(fd.get(), F_SETFD, 0), SyscallSucceeds());
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, IndependentDescriptorFlags) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag not set.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, 0));
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Duplicate the descriptor. Ensure that it also doesn't have FD_CLOEXEC.
  FileDescriptor newfd = ASSERT_NO_ERRNO_AND_VALUE(fd.Dup());
  ASSERT_THAT(fcntl(newfd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Set FD_CLOEXEC on the first FD.
  ASSERT_THAT(fcntl(fd.get(), F_SETFD, FD_CLOEXEC), SyscallSucceeds());
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));

  // Ensure that the second FD is unaffected by the change on the first.
  ASSERT_THAT(fcntl(newfd.get(), F_GETFD), SyscallSucceedsWithValue(0));
}

// All file description flags passed to open appear in F_GETFL.
TEST(FcntlTest, GetAllFlags) {
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int flags = O_RDWR | O_DIRECT | O_SYNC | O_NONBLOCK | O_APPEND;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), flags));

  // Linux forces O_LARGEFILE on all 64-bit kernels and gVisor's is 64-bit.
  int expected = flags | kOLargeFile;

  int rflags;
  EXPECT_THAT(rflags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(rflags, expected);
}

TEST(FcntlTest, SetFlags) {
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), 0));

  int const flags = O_RDWR | O_DIRECT | O_SYNC | O_NONBLOCK | O_APPEND;
  EXPECT_THAT(fcntl(fd.get(), F_SETFL, flags), SyscallSucceeds());

  // Can't set O_RDWR or O_SYNC.
  // Linux forces O_LARGEFILE on all 64-bit kernels and gVisor's is 64-bit.
  int expected = O_DIRECT | O_NONBLOCK | O_APPEND | kOLargeFile;

  int rflags;
  EXPECT_THAT(rflags = fcntl(fd.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(rflags, expected);
}

TEST_F(FcntlLockTest, SetLockBadFd) {
  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // len 0 has a special meaning: lock all bytes despite how
  // large the file grows.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(-1, F_SETLK, &fl), SyscallFailsWithErrno(EBADF));
}

TEST_F(FcntlLockTest, SetLockPipe) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd, but doesn't matter, we expect this to fail.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(fds[0], F_SETLK, &fl), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(close(fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetLockDir) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetLockBadOpenFlagsWrite) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY, 0666));

  struct flock fl0;
  fl0.l_type = F_WRLCK;
  fl0.l_whence = SEEK_SET;
  fl0.l_start = 0;
  // Same as SetLockBadFd.
  fl0.l_len = 0;

  // Expect that setting a write lock using a read only file descriptor
  // won't work.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl0), SyscallFailsWithErrno(EBADF));
}

TEST_F(FcntlLockTest, SetLockBadOpenFlagsRead) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY, 0666));

  struct flock fl1;
  fl1.l_type = F_RDLCK;
  fl1.l_whence = SEEK_SET;
  fl1.l_start = 0;
  // Same as SetLockBadFd.
  fl1.l_len = 0;

  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl1), SyscallFailsWithErrno(EBADF));
}

TEST_F(FcntlLockTest, SetLockUnlockOnNothing) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetWriteLockSingleProc) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd0 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  EXPECT_THAT(fcntl(fd0.get(), F_SETLK, &fl), SyscallSucceeds());
  // Expect to be able to take the same lock on the same fd no problem.
  EXPECT_THAT(fcntl(fd0.get(), F_SETLK, &fl), SyscallSucceeds());

  FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  // Expect to be able to take the same lock from a different fd but for
  // the same process.
  EXPECT_THAT(fcntl(fd1.get(), F_SETLK, &fl), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetReadLockMultiProc) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // spawn a child process to take a read lock on the same file.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), false /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetReadThenWriteLockMultiProc) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Assert that another process trying to lock on the same file will fail
  // with EAGAIN.  It's important that we keep the fd above open so that
  // that the other process will contend with the lock.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;

  // Close the fd: we want to test that another process can acquire the
  // lock after this point.
  fd.reset();
  // Assert that another process can now acquire the lock.

  child_pid = 0;
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetWriteThenReadLockMultiProc) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));
  // Same as SetReadThenWriteLockMultiProc.

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  // Same as SetReadThenWriteLockMultiProc.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Same as SetReadThenWriteLockMultiProc.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), false /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;

  // Same as SetReadThenWriteLockMultiProc.
  fd.reset();  // Close the fd.

  // Same as SetReadThenWriteLockMultiProc.
  child_pid = 0;
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), false /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetWriteLockMultiProc) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));
  // Same as SetReadThenWriteLockMultiProc.

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  // Same as SetReadWriteLockMultiProc.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Same as SetReadWriteLockMultiProc.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;

  fd.reset();  // Close the FD.
  // Same as SetReadWriteLockMultiProc.
  child_pid = 0;
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetLockIsRegional) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 4096;

  // Same as SetReadWriteLockMultiProc.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Same as SetReadWriteLockMultiProc.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_len, 0, &child_pid));
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetLockUpgradeDowngrade) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  // Same as SetReadWriteLockMultiProc.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Upgrade to a write lock.  This will prevent anyone else from taking
  // the lock.
  fl.l_type = F_WRLCK;
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Same as SetReadWriteLockMultiProc.,
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), false /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;

  // Downgrade back to a read lock.
  fl.l_type = F_RDLCK;
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Do the same stint as before, but this time it should succeed.
  child_pid = 0;
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), false /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetLockDroppedOnClose) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  // While somewhat surprising, obtaining another fd to the same file and
  // then closing it in this process drops *all* locks.
  FileDescriptor other_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));
  // Same as SetReadThenWriteLockMultiProc.

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  // Same as SetReadWriteLockMultiProc.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  other_fd.reset();  // Close.

  // Expect to be able to get the lock, given that the close above dropped it.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(file.path(), true /* write lock */,
                     false /* nonblocking */, false /* no eintr retry */,
                     -1 /* no socket fd */, fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetLockUnlock) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  // Setup two regional locks with different permissions.
  struct flock fl0;
  fl0.l_type = F_WRLCK;
  fl0.l_whence = SEEK_SET;
  fl0.l_start = 0;
  fl0.l_len = 4096;

  struct flock fl1;
  fl1.l_type = F_RDLCK;
  fl1.l_whence = SEEK_SET;
  fl1.l_start = 4096;
  // Same as SetLockBadFd.
  fl1.l_len = 0;

  // Set both region locks.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl0), SyscallSucceeds());
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl1), SyscallSucceeds());

  // Another process should fail to take a read lock on the entire file
  // due to the regional write lock.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), false /* write lock */, false /* nonblocking */,
      false /* no eintr retry */, -1 /* no socket fd */, 0, 0, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;

  // Then only unlock the writable one.  This should ensure that other
  // processes can take any read lock that it wants.
  fl0.l_type = F_UNLCK;
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl0), SyscallSucceeds());

  // Another process should now succeed to get a read lock on the entire file.
  child_pid = 0;
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), false /* write lock */, false /* nonblocking */,
      false /* no eintr retry */, -1 /* no socket fd */, 0, 0, &child_pid));
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST_F(FcntlLockTest, SetLockAcrossRename) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  // Setup two regional locks with different permissions.
  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // Same as SetLockBadFd.
  fl.l_len = 0;

  // Set the region lock.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl), SyscallSucceeds());

  // Rename the file to someplace nearby.
  std::string const newpath = NewTempAbsPath();
  EXPECT_THAT(rename(file.path().c_str(), newpath.c_str()), SyscallSucceeds());

  // Another process should fail to take a read lock on the renamed file
  // since we still have an open handle to the inode.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      SubprocessLock(newpath, false /* write lock */, false /* nonblocking */,
                     false /* no eintr retry */, -1 /* no socket fd */,
                     fl.l_start, fl.l_len, &child_pid));

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == EAGAIN)
      << "Exited with code: " << status;
}

// NOTE: The blocking tests below aren't perfect. It's hard to assert exactly
// what the kernel did while handling a syscall. These tests are timing based
// because there really isn't any other reasonable way to assert that correct
// blocking behavior happened.

// This test will verify that blocking works as expected when another process
// holds a write lock when obtaining a write lock. This test will hold the lock
// for some amount of time and then wait for the second process to send over the
// socket_fd the amount of time it was blocked for before the lock succeeded.
TEST_F(FcntlLockTest, SetWriteLockThenBlockingWriteLock) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // Take the write lock.
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Attempt to take the read lock in a sub process. This will immediately block
  // so we will release our lock after some amount of time and then assert the
  // amount of time the other process was blocked for.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), true /* write lock */, true /* Blocking Lock */,
      true /* Retry on EINTR */, fds_[1] /* Socket fd for timing information */,
      fl.l_start, fl.l_len, &child_pid));

  // We will wait kHoldLockForSec before we release our lock allowing the
  // subprocess to obtain it.
  constexpr absl::Duration kHoldLockFor = absl::Seconds(5);
  const int64_t kMinBlockTimeUsec = absl::ToInt64Microseconds(absl::Seconds(1));

  absl::SleepFor(kHoldLockFor);

  // Unlock our write lock.
  fl.l_type = F_UNLCK;
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Read the blocked time from the subprocess socket.
  int64_t subprocess_blocked_time_usec = GetSubprocessFcntlTimeInUsec();

  // We must have been waiting at least kMinBlockTime.
  EXPECT_GT(subprocess_blocked_time_usec, kMinBlockTimeUsec);

  // The FCNTL write lock must always succeed as it will simply block until it
  // can obtain the lock.
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

// This test will veirfy that blocking works as expected when another process
// holds a read lock when obtaining a write lock. This test will hold the lock
// for some amount of time and then wait for the second process to send over the
// socket_fd the amount of time it was blocked for before the lock succeeded.
TEST_F(FcntlLockTest, SetReadLockThenBlockingWriteLock) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // Take the write lock.
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Attempt to take the read lock in a sub process. This will immediately block
  // so we will release our lock after some amount of time and then assert the
  // amount of time the other process was blocked for.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), true /* write lock */, true /* Blocking Lock */,
      true /* Retry on EINTR */, fds_[1] /* Socket fd for timing information */,
      fl.l_start, fl.l_len, &child_pid));

  // We will wait kHoldLockForSec before we release our lock allowing the
  // subprocess to obtain it.
  constexpr absl::Duration kHoldLockFor = absl::Seconds(5);

  const int64_t kMinBlockTimeUsec = absl::ToInt64Microseconds(absl::Seconds(1));

  absl::SleepFor(kHoldLockFor);

  // Unlock our READ lock.
  fl.l_type = F_UNLCK;
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Read the blocked time from the subprocess socket.
  int64_t subprocess_blocked_time_usec = GetSubprocessFcntlTimeInUsec();

  // We must have been waiting at least kMinBlockTime.
  EXPECT_GT(subprocess_blocked_time_usec, kMinBlockTimeUsec);

  // The FCNTL write lock must always succeed as it will simply block until it
  // can obtain the lock.
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

// This test will veirfy that blocking works as expected when another process
// holds a write lock when obtaining a read lock. This test will hold the lock
// for some amount of time and then wait for the second process to send over the
// socket_fd the amount of time it was blocked for before the lock succeeded.
TEST_F(FcntlLockTest, SetWriteLockThenBlockingReadLock) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // Take the write lock.
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Attempt to take the read lock in a sub process. This will immediately block
  // so we will release our lock after some amount of time and then assert the
  // amount of time the other process was blocked for.
  pid_t child_pid = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), false /* read lock */, true /* Blocking Lock */,
      true /* Retry on EINTR */, fds_[1] /* Socket fd for timing information */,
      fl.l_start, fl.l_len, &child_pid));

  // We will wait kHoldLockForSec before we release our lock allowing the
  // subprocess to obtain it.
  constexpr absl::Duration kHoldLockFor = absl::Seconds(5);

  const int64_t kMinBlockTimeUsec = absl::ToInt64Microseconds(absl::Seconds(1));

  absl::SleepFor(kHoldLockFor);

  // Unlock our write lock.
  fl.l_type = F_UNLCK;
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Read the blocked time from the subprocess socket.
  int64_t subprocess_blocked_time_usec = GetSubprocessFcntlTimeInUsec();

  // We must have been waiting at least kMinBlockTime.
  EXPECT_GT(subprocess_blocked_time_usec, kMinBlockTimeUsec);

  // The FCNTL read lock must always succeed as it will simply block until it
  // can obtain the lock.
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

// This test will verify that when one process only holds a read lock that
// another will not block while obtaining a read lock when F_SETLKW is used.
TEST_F(FcntlLockTest, SetReadLockThenBlockingReadLock) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0666));

  struct flock fl;
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // Take the READ lock.
  ASSERT_THAT(fcntl(fd.get(), F_SETLKW, &fl), SyscallSucceeds());

  // Attempt to take the read lock in a sub process. Since multiple processes
  // can hold a read lock this should immediately return without blocking
  // even though we used F_SETLKW in the subprocess.
  pid_t child_pid = 0;
  auto sp = ASSERT_NO_ERRNO_AND_VALUE(SubprocessLock(
      file.path(), false /* read lock */, true /* Blocking Lock */,
      true /* Retry on EINTR */, -1 /* No fd, should not block */, fl.l_start,
      fl.l_len, &child_pid));

  // We never release the lock and the subprocess should still obtain it without
  // blocking for any period of time.
  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "Exited with code: " << status;
}

TEST(FcntlTest, GetO_ASYNC) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int flag_fl = -1;
  ASSERT_THAT(flag_fl = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(flag_fl & O_ASYNC, 0);

  int flag_fd = -1;
  ASSERT_THAT(flag_fd = fcntl(s.get(), F_GETFD), SyscallSucceeds());
  EXPECT_EQ(flag_fd & O_ASYNC, 0);
}

TEST(FcntlTest, SetFlO_ASYNC) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int before_fl = -1;
  ASSERT_THAT(before_fl = fcntl(s.get(), F_GETFL), SyscallSucceeds());

  int before_fd = -1;
  ASSERT_THAT(before_fd = fcntl(s.get(), F_GETFD), SyscallSucceeds());

  ASSERT_THAT(fcntl(s.get(), F_SETFL, before_fl | O_ASYNC), SyscallSucceeds());

  int after_fl = -1;
  ASSERT_THAT(after_fl = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(after_fl, before_fl | O_ASYNC);

  int after_fd = -1;
  ASSERT_THAT(after_fd = fcntl(s.get(), F_GETFD), SyscallSucceeds());
  EXPECT_EQ(after_fd, before_fd);
}

TEST(FcntlTest, SetFdO_ASYNC) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int before_fl = -1;
  ASSERT_THAT(before_fl = fcntl(s.get(), F_GETFL), SyscallSucceeds());

  int before_fd = -1;
  ASSERT_THAT(before_fd = fcntl(s.get(), F_GETFD), SyscallSucceeds());

  ASSERT_THAT(fcntl(s.get(), F_SETFD, before_fd | O_ASYNC), SyscallSucceeds());

  int after_fl = -1;
  ASSERT_THAT(after_fl = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(after_fl, before_fl);

  int after_fd = -1;
  ASSERT_THAT(after_fd = fcntl(s.get(), F_GETFD), SyscallSucceeds());
  EXPECT_EQ(after_fd, before_fd);
}

TEST(FcntlTest, DupAfterO_ASYNC) {
  FileDescriptor s1 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int before = -1;
  ASSERT_THAT(before = fcntl(s1.get(), F_GETFL), SyscallSucceeds());

  ASSERT_THAT(fcntl(s1.get(), F_SETFL, before | O_ASYNC), SyscallSucceeds());

  FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(s1.Dup());

  int after = -1;
  ASSERT_THAT(after = fcntl(fd2.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(after & O_ASYNC, O_ASYNC);
}

TEST(FcntlTest, GetOwn) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (!FLAGS_child_setlock_on.empty()) {
    int socket_fd = FLAGS_socket_fd;
    int fd = open(FLAGS_child_setlock_on.c_str(), O_RDWR, 0666);
    if (fd == -1 && errno != 0) {
      int err = errno;
      std::cerr << "CHILD open " << FLAGS_child_setlock_on << " failed " << err
                << std::endl;
      exit(err);
    }

    struct flock fl;
    if (FLAGS_child_setlock_write) {
      fl.l_type = F_WRLCK;
    } else {
      fl.l_type = F_RDLCK;
    }
    fl.l_whence = SEEK_SET;
    fl.l_start = FLAGS_child_setlock_start;
    fl.l_len = FLAGS_child_setlock_len;

    // Test the fcntl, no need to log, the error is unambiguously
    // from fcntl at this point.
    int err = 0;
    int ret = 0;

    gvisor::testing::MonotonicTimer timer;
    timer.Start();
    do {
      ret = fcntl(fd, FLAGS_blocking ? F_SETLKW : F_SETLK, &fl);
    } while (FLAGS_retry_eintr && ret == -1 && errno == EINTR);
    auto usec = absl::ToInt64Microseconds(timer.Duration());

    if (ret == -1 && errno != 0) {
      err = errno;
    }

    // If there is a socket fd let's send back the time in microseconds it took
    // to execute this syscall.
    if (socket_fd != -1) {
      gvisor::testing::WriteFd(socket_fd, reinterpret_cast<void*>(&usec),
                                     sizeof(usec));
      close(socket_fd);
    }

    close(fd);
    exit(err);
  }

  return RUN_ALL_TESTS();
}
