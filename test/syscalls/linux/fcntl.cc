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
#include <signal.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include <atomic>
#include <deque>
#include <iostream>
#include <list>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/base/port.h"
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

ABSL_FLAG(std::string, child_set_lock_on, "",
          "Contains the path to try to set a file lock on.");
ABSL_FLAG(bool, child_set_lock_write, false,
          "Whether to set a writable lock (otherwise readable)");
ABSL_FLAG(bool, blocking, false,
          "Whether to set a blocking lock (otherwise non-blocking).");
ABSL_FLAG(bool, retry_eintr, false,
          "Whether to retry in the subprocess on EINTR.");
ABSL_FLAG(uint64_t, child_set_lock_start, 0, "The value of struct flock start");
ABSL_FLAG(uint64_t, child_set_lock_len, 0, "The value of struct flock len");
ABSL_FLAG(int32_t, socket_fd, -1,
          "A socket to use for communicating more state back "
          "to the parent.");

namespace gvisor {
namespace testing {

std::function<void(int, siginfo_t*, void*)> setsig_signal_handle;
void setsig_signal_handler(int signum, siginfo_t* siginfo, void* ucontext) {
  setsig_signal_handle(signum, siginfo, ucontext);
}

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

struct SignalDelivery {
  int num;
  siginfo_t info;
};

class FcntlSignalTest : public ::testing::Test {
 public:
  void SetUp() override {
    int pipe_fds[2];
    ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), SyscallSucceeds());
    pipe_read_fd_ = pipe_fds[0];
    pipe_write_fd_ = pipe_fds[1];
  }

  PosixErrorOr<Cleanup> RegisterSignalHandler(int signum) {
    struct sigaction handler;
    handler.sa_sigaction = setsig_signal_handler;
    setsig_signal_handle = [&](int signum, siginfo_t* siginfo,
                               void* unused_ucontext) {
      SignalDelivery sig;
      sig.num = signum;
      sig.info = *siginfo;
      signals_received_.push_back(sig);
      num_signals_received_++;
    };
    sigemptyset(&handler.sa_mask);
    handler.sa_flags = SA_SIGINFO;
    return ScopedSigaction(signum, handler);
  }

  void FlushAndCloseFD(int fd) {
    char buf;
    int read_bytes;
    do {
      read_bytes = read(fd, &buf, 1);
    } while (read_bytes > 0);
    // read() can also fail with EWOULDBLOCK since the pipe is open in
    // non-blocking mode. This is not an error.
    EXPECT_TRUE(read_bytes == 0 || (read_bytes == -1 && errno == EWOULDBLOCK));
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }

  void DupReadFD() {
    ASSERT_THAT(pipe_read_fd_dup_ = dup(pipe_read_fd_), SyscallSucceeds());
    max_expected_signals++;
  }

  void RegisterFD(int fd, int signum) {
    ASSERT_THAT(fcntl(fd, F_SETOWN, getpid()), SyscallSucceeds());
    ASSERT_THAT(fcntl(fd, F_SETSIG, signum), SyscallSucceeds());
    int old_flags;
    ASSERT_THAT(old_flags = fcntl(fd, F_GETFL), SyscallSucceeds());
    ASSERT_THAT(fcntl(fd, F_SETFL, old_flags | O_ASYNC), SyscallSucceeds());
  }

  void GenerateIOEvent() {
    ASSERT_THAT(write(pipe_write_fd_, "test", 4), SyscallSucceedsWithValue(4));
  }

  void WaitForSignalDelivery(absl::Duration timeout) {
    absl::Time wait_start = absl::Now();
    while (num_signals_received_ < max_expected_signals &&
           absl::Now() - wait_start < timeout) {
      absl::SleepFor(absl::Milliseconds(10));
    }
  }

  int pipe_read_fd_ = -1;
  int pipe_read_fd_dup_ = -1;
  int pipe_write_fd_ = -1;
  int max_expected_signals = 1;
  std::deque<SignalDelivery> signals_received_;
  std::atomic<int> num_signals_received_ = 0;
};

namespace {

PosixErrorOr<Cleanup> SubprocessLock(std::string const& path, bool for_write,
                                     bool blocking, bool retry_eintr, int fd,
                                     off_t start, off_t length, pid_t* child) {
  std::vector<std::string> args = {
      "/proc/self/exe",         "--child_set_lock_on", path,
      "--child_set_lock_start", absl::StrCat(start),   "--child_set_lock_len",
      absl::StrCat(length),     "--socket_fd",         absl::StrCat(fd)};

  if (for_write) {
    args.push_back("--child_set_lock_write");
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

void CheckSameFile(int fd1, int fd2) {
  struct stat stat_result1, stat_result2;
  ASSERT_THAT(fstat(fd1, &stat_result1), SyscallSucceeds());
  ASSERT_THAT(fstat(fd2, &stat_result2), SyscallSucceeds());
  EXPECT_EQ(stat_result1.st_dev, stat_result2.st_dev);
  EXPECT_EQ(stat_result1.st_ino, stat_result2.st_ino);
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

TEST(FcntlTest, SetCloExecBadFD) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag not set.
  FileDescriptor f = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, 0));
  auto fd = f.get();
  f.reset();
  ASSERT_THAT(fcntl(fd, F_GETFD), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(fcntl(fd, F_SETFD, FD_CLOEXEC), SyscallFailsWithErrno(EBADF));
}

TEST(FcntlTest, SetCloExec) {
  // Open an eventfd file descriptor with FD_CLOEXEC descriptor flag not set.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, 0));
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(0));

  // Set the FD_CLOEXEC flag.
  ASSERT_THAT(fcntl(fd.get(), F_SETFD, FD_CLOEXEC), SyscallSucceeds());
  ASSERT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
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

void TestLock(int fd, short lock_type = F_RDLCK) {  // NOLINT, type in flock
  struct flock fl;
  fl.l_type = lock_type;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // len 0 locks all bytes despite how large the file grows.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(fd, F_SETLK, &fl), SyscallSucceeds());
}

void TestLockBadFD(int fd,
                   short lock_type = F_RDLCK) {  // NOLINT, type in flock
  struct flock fl;
  fl.l_type = lock_type;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  // len 0 locks all bytes despite how large the file grows.
  fl.l_len = 0;
  EXPECT_THAT(fcntl(fd, F_SETLK, &fl), SyscallFailsWithErrno(EBADF));
}

TEST_F(FcntlLockTest, SetLockBadFd) { TestLockBadFD(-1); }

TEST_F(FcntlLockTest, SetLockDir) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY, 0000));
  TestLock(fd.get());
}

TEST_F(FcntlLockTest, SetLockSymlink) {
  // TODO(gvisor.dev/issue/2782): Replace with IsRunningWithVFS1() when O_PATH
  // is supported.
  SKIP_IF(IsRunningOnGvisor());

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto symlink = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), file.path()));

  auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(symlink.path(), O_RDONLY | O_PATH, 0000));
  TestLockBadFD(fd.get());
}

TEST_F(FcntlLockTest, SetLockProc) {
  auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/status", O_RDONLY, 0000));
  TestLock(fd.get());
}

TEST_F(FcntlLockTest, SetLockPipe) {
  SKIP_IF(IsRunningWithVFS1());

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  TestLock(fds[0]);
  TestLockBadFD(fds[0], F_WRLCK);

  TestLock(fds[1], F_WRLCK);
  TestLockBadFD(fds[1]);

  EXPECT_THAT(close(fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetLockSocket) {
  SKIP_IF(IsRunningWithVFS1());

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(sock, SyscallSucceeds());

  struct sockaddr_un addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true /* abstract */, AF_UNIX));
  ASSERT_THAT(
      bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());

  TestLock(sock);
  EXPECT_THAT(close(sock), SyscallSucceeds());
}

TEST_F(FcntlLockTest, SetLockBadOpenFlagsWrite) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY, 0666));

  struct flock fl0;
  fl0.l_type = F_WRLCK;
  fl0.l_whence = SEEK_SET;
  fl0.l_start = 0;
  fl0.l_len = 0;  // Lock all file

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

TEST_F(FcntlLockTest, SetLockWithOpath) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  struct flock fl0;
  fl0.l_type = F_WRLCK;
  fl0.l_whence = SEEK_SET;
  fl0.l_start = 0;
  fl0.l_len = 0;  // Lock all file

  // Expect that setting a write lock using a Opath file descriptor
  // won't work.
  EXPECT_THAT(fcntl(fd.get(), F_SETLK, &fl0), SyscallFailsWithErrno(EBADF));
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

// This test will verify that blocking works as expected when another process
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

TEST(FcntlTest, GetOwnNone) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  // Use the raw syscall because the glibc wrapper may convert F_{GET,SET}OWN
  // into F_{GET,SET}OWN_EX.
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, GetOwnExNone) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, SetOwnInvalidPid) {
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, 12345678),
              SyscallFailsWithErrno(ESRCH));
}

TEST(FcntlTest, SetOwnInvalidPgrp) {
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, -12345678),
              SyscallFailsWithErrno(ESRCH));
}

TEST(FcntlTest, SetOwnPid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  pid_t pid;
  EXPECT_THAT(pid = getpid(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, pid),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(pid));
}

TEST(FcntlTest, SetOwnPgrp) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  pid_t pgid;
  EXPECT_THAT(pgid = getpgrp(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, -pgid),
              SyscallSucceedsWithValue(0));

  // Verify with F_GETOWN_EX; using F_GETOWN on Linux may incorrectly treat the
  // negative return value as an error, converting the return value to -1 and
  // setting errno accordingly.
  f_owner_ex got_owner = {};
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &got_owner),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(got_owner.type, F_OWNER_PGRP);
  EXPECT_EQ(got_owner.pid, pgid);
}

TEST(FcntlTest, SetOwnUnset) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  // Set and unset pid.
  pid_t pid;
  EXPECT_THAT(pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, pid),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, 0),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));

  // Set and unset pgid.
  pid_t pgid;
  EXPECT_THAT(pgid = getpgrp(), SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, -pgid),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, 0),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));
}

// F_SETOWN flips the sign of negative values, an operation that is guarded
// against overflow.
TEST(FcntlTest, SetOwnOverflow) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, INT_MIN),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FcntlTest, SetOwnExInvalidType) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = __pid_type(-1);
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FcntlTest, SetOwnExInvalidTid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = F_OWNER_TID;
  owner.pid = -1;

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallFailsWithErrno(ESRCH));
}

TEST(FcntlTest, SetOwnExInvalidPid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = F_OWNER_PID;
  owner.pid = -1;

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallFailsWithErrno(ESRCH));
}

TEST(FcntlTest, SetOwnExInvalidPgrp) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = F_OWNER_PGRP;
  owner.pid = -1;

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallFailsWithErrno(ESRCH));
}

TEST(FcntlTest, SetOwnExTid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = F_OWNER_TID;
  EXPECT_THAT(owner.pid = syscall(__NR_gettid), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(owner.pid));
}

TEST(FcntlTest, SetOwnExPid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex owner = {};
  owner.type = F_OWNER_PID;
  EXPECT_THAT(owner.pid = getpid(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(owner.pid));
}

TEST(FcntlTest, SetOwnExPgrp) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex set_owner = {};
  set_owner.type = F_OWNER_PGRP;
  EXPECT_THAT(set_owner.pid = getpgrp(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &set_owner),
              SyscallSucceedsWithValue(0));

  // Verify with F_GETOWN_EX; using F_GETOWN on Linux may incorrectly treat the
  // negative return value as an error, converting the return value to -1 and
  // setting errno accordingly.
  f_owner_ex got_owner = {};
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &got_owner),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(got_owner.type, set_owner.type);
  EXPECT_EQ(got_owner.pid, set_owner.pid);
}

TEST(FcntlTest, SetOwnExUnset) {
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  // Set and unset pid.
  f_owner_ex owner = {};
  owner.type = F_OWNER_PID;
  EXPECT_THAT(owner.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));
  owner.pid = 0;
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));

  // Set and unset pgid.
  owner.type = F_OWNER_PGRP;
  EXPECT_THAT(owner.pid = getpgrp(), SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));
  owner.pid = 0;
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &owner),
              SyscallSucceedsWithValue(0));

  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, GetOwnExTid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex set_owner = {};
  set_owner.type = F_OWNER_TID;
  EXPECT_THAT(set_owner.pid = syscall(__NR_gettid), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &set_owner),
              SyscallSucceedsWithValue(0));

  f_owner_ex got_owner = {};
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &got_owner),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(got_owner.type, set_owner.type);
  EXPECT_EQ(got_owner.pid, set_owner.pid);
}

TEST(FcntlTest, GetOwnExPid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex set_owner = {};
  set_owner.type = F_OWNER_PID;
  EXPECT_THAT(set_owner.pid = getpid(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &set_owner),
              SyscallSucceedsWithValue(0));

  f_owner_ex got_owner = {};
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &got_owner),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(got_owner.type, set_owner.type);
  EXPECT_EQ(got_owner.pid, set_owner.pid);
}

TEST(FcntlTest, GetOwnExPgrp) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  f_owner_ex set_owner = {};
  set_owner.type = F_OWNER_PGRP;
  EXPECT_THAT(set_owner.pid = getpgrp(), SyscallSucceeds());

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN_EX, &set_owner),
              SyscallSucceedsWithValue(0));

  f_owner_ex got_owner = {};
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETOWN_EX, &got_owner),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(got_owner.type, set_owner.type);
  EXPECT_EQ(got_owner.pid, set_owner.pid);
}

TEST(FcntlTest, SetSig) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGUSR1),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(SIGUSR1));
}

TEST(FcntlTest, SetSigDefaultsToZero) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  // Defaults to returning the zero value, indicating default behavior (SIGIO).
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, SetSigToDefault) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGIO),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(SIGIO));

  // Can be reset to the default behavior.
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, SetSigInvalid) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGRTMAX + 1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(0));
}

TEST(FcntlTest, SetSigInvalidDoesNotResetPreviousChoice) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGUSR1),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGRTMAX + 1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(syscall(__NR_fcntl, s.get(), F_GETSIG),
              SyscallSucceedsWithValue(SIGUSR1));
}

TEST_F(FcntlSignalTest, SetSigDefault) {
  const auto signal_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGIO));
  RegisterFD(pipe_read_fd_, 0);  // Zero = default behavior
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  signals_received_.pop_front();
  EXPECT_EQ(sig.num, SIGIO);
  EXPECT_EQ(sig.info.si_signo, SIGIO);
  // siginfo contents is undefined in this case.
}

TEST_F(FcntlSignalTest, SetSigCustom) {
  const auto signal_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  signals_received_.pop_front();
  EXPECT_EQ(sig.num, SIGUSR1);
  EXPECT_EQ(sig.info.si_signo, SIGUSR1);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigUnregisterStillGetsSigio) {
  const auto sigio_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGIO));
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  RegisterFD(pipe_read_fd_, 0);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  signals_received_.pop_front();
  EXPECT_EQ(sig.num, SIGIO);
  // siginfo contents is undefined in this case.
}

TEST_F(FcntlSignalTest, SetSigWithSigioStillGetsSiginfo) {
  const auto signal_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGIO));
  RegisterFD(pipe_read_fd_, SIGIO);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  EXPECT_EQ(sig.num, SIGIO);
  EXPECT_EQ(sig.info.si_signo, SIGIO);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupThenCloseOld) {
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  FlushAndCloseFD(pipe_read_fd_);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the **old** FD (even though it is closed).
  EXPECT_EQ(sig.num, SIGUSR1);
  EXPECT_EQ(sig.info.si_signo, SIGUSR1);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupThenCloseNew) {
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  FlushAndCloseFD(pipe_read_fd_dup_);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the old FD.
  EXPECT_EQ(sig.num, SIGUSR1);
  EXPECT_EQ(sig.info.si_signo, SIGUSR1);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupOldRegistered) {
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the old FD.
  EXPECT_EQ(sig.num, SIGUSR1);
  EXPECT_EQ(sig.info.si_signo, SIGUSR1);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupNewRegistered) {
  const auto sigusr2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR2));
  DupReadFD();
  RegisterFD(pipe_read_fd_dup_, SIGUSR2);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the new FD.
  EXPECT_EQ(sig.num, SIGUSR2);
  EXPECT_EQ(sig.info.si_signo, SIGUSR2);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_dup_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupBothRegistered) {
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  const auto sigusr2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR2));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  RegisterFD(pipe_read_fd_dup_, SIGUSR2);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the **new** signal number, but the **old** FD.
  EXPECT_EQ(sig.num, SIGUSR2);
  EXPECT_EQ(sig.info.si_signo, SIGUSR2);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupBothRegisteredAfterDup) {
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  const auto sigusr2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR2));
  DupReadFD();
  RegisterFD(pipe_read_fd_, SIGUSR1);
  RegisterFD(pipe_read_fd_dup_, SIGUSR2);
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with the **new** signal number, but the **old** FD.
  EXPECT_EQ(sig.num, SIGUSR2);
  EXPECT_EQ(sig.info.si_signo, SIGUSR2);
  EXPECT_EQ(sig.info.si_fd, pipe_read_fd_);
  EXPECT_EQ(sig.info.si_band, EPOLLIN | EPOLLRDNORM);
}

TEST_F(FcntlSignalTest, SetSigDupUnregisterOld) {
  const auto sigio_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGIO));
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  const auto sigusr2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR2));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  RegisterFD(pipe_read_fd_dup_, SIGUSR2);
  RegisterFD(pipe_read_fd_, 0);  // Should go back to SIGIO behavior.
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with SIGIO.
  EXPECT_EQ(sig.num, SIGIO);
  // siginfo is undefined in this case.
}

TEST_F(FcntlSignalTest, SetSigDupUnregisterNew) {
  const auto sigio_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGIO));
  const auto sigusr1_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR1));
  const auto sigusr2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(RegisterSignalHandler(SIGUSR2));
  RegisterFD(pipe_read_fd_, SIGUSR1);
  DupReadFD();
  RegisterFD(pipe_read_fd_dup_, SIGUSR2);
  RegisterFD(pipe_read_fd_dup_, 0);  // Should go back to SIGIO behavior.
  GenerateIOEvent();
  WaitForSignalDelivery(absl::Seconds(1));
  ASSERT_EQ(num_signals_received_, 1);
  SignalDelivery sig = signals_received_.front();
  // We get a signal with SIGIO.
  EXPECT_EQ(sig.num, SIGIO);
  // siginfo is undefined in this case.
}

// Make sure that making multiple concurrent changes to async signal generation
// does not cause any race issues.
TEST(FcntlTest, SetFlSetOwnSetSigDoNotRace) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  pid_t pid;
  EXPECT_THAT(pid = getpid(), SyscallSucceeds());

  constexpr absl::Duration runtime = absl::Milliseconds(300);
  auto set_async = [&s, &runtime] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETFL, O_ASYNC),
                  SyscallSucceeds());
      sched_yield();
    }
  };
  auto reset_async = [&s, &runtime] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETFL, 0), SyscallSucceeds());
      sched_yield();
    }
  };
  auto set_own = [&s, &pid, &runtime] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETOWN, pid),
                  SyscallSucceeds());
      sched_yield();
    }
  };
  auto set_sig = [&s, &runtime] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      ASSERT_THAT(syscall(__NR_fcntl, s.get(), F_SETSIG, SIGUSR1),
                  SyscallSucceeds());
      sched_yield();
    }
  };

  std::list<ScopedThread> threads;
  for (int i = 0; i < 10; i++) {
    threads.emplace_back(set_async);
    threads.emplace_back(reset_async);
    threads.emplace_back(set_own);
    threads.emplace_back(set_sig);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int set_lock() {
  const std::string set_lock_on = absl::GetFlag(FLAGS_child_set_lock_on);
  int socket_fd = absl::GetFlag(FLAGS_socket_fd);
  int fd = open(set_lock_on.c_str(), O_RDWR, 0666);
  if (fd == -1 && errno != 0) {
    int err = errno;
    std::cerr << "CHILD open " << set_lock_on << " failed: " << err
              << std::endl;
    return err;
  }

  struct flock fl;
  if (absl::GetFlag(FLAGS_child_set_lock_write)) {
    fl.l_type = F_WRLCK;
  } else {
    fl.l_type = F_RDLCK;
  }
  fl.l_whence = SEEK_SET;
  fl.l_start = absl::GetFlag(FLAGS_child_set_lock_start);
  fl.l_len = absl::GetFlag(FLAGS_child_set_lock_len);

  // Test the fcntl.
  int err = 0;
  int ret = 0;

  gvisor::testing::MonotonicTimer timer;
  timer.Start();
  do {
    ret = fcntl(fd, absl::GetFlag(FLAGS_blocking) ? F_SETLKW : F_SETLK, &fl);
  } while (absl::GetFlag(FLAGS_retry_eintr) && ret == -1 && errno == EINTR);
  auto usec = absl::ToInt64Microseconds(timer.Duration());

  if (ret == -1 && errno != 0) {
    err = errno;
    std::cerr << "CHILD lock " << set_lock_on << " failed " << err << std::endl;
  }

  // If there is a socket fd let's send back the time in microseconds it took
  // to execute this syscall.
  if (socket_fd != -1) {
    gvisor::testing::WriteFd(socket_fd, reinterpret_cast<void*>(&usec),
                                   sizeof(usec));
    close(socket_fd);
  }

  close(fd);
  return err;
}

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);

  if (!absl::GetFlag(FLAGS_child_set_lock_on).empty()) {
    exit(set_lock());
  }

  return gvisor::testing::RunAllTests();
}
