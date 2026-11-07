// Copyright 2021 The gVisor Authors.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<FileDescriptor> OpenRetryEINTR(std::string const& path, int flags,
                                            mode_t mode = 0) {
  while (true) {
    auto maybe_fd = Open(path, flags, mode);
    if (maybe_fd.ok() || maybe_fd.error().errno_value() != EINTR) {
      return maybe_fd;
    }
  }
}

TEST(FifoTest, MknodAtFIFO) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string fifo_relpath = NewTempRelPath();
  const std::string fifo = JoinPath(dir.path(), fifo_relpath);

  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path().c_str(), O_RDONLY));
  ASSERT_THAT(mknodat(dirfd.get(), fifo_relpath.c_str(), S_IFIFO | S_IRUSR, 0),
              SyscallSucceeds());

  struct stat st;
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));
}

TEST(FifoTest, Fifo) {
  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  struct stat st;
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some std::string";
  std::vector<char> buf(512);

  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(OpenRetryEINTR(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  // Write-end of the pipe.
  FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenRetryEINTR(fifo.c_str(), O_WRONLY));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
}

TEST(FifoTest, FifoOtrunc) {
  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  struct stat st = {};
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some std::string";
  std::vector<char> buf(512);
  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(OpenRetryEINTR(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  // Write-end of the pipe.
  FileDescriptor wfd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenRetryEINTR(fifo.c_str(), O_WRONLY | O_TRUNC));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
}

TEST(FifoTest, FifoTruncNoOp) {
  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  EXPECT_THAT(truncate(fifo.c_str(), 0), SyscallFailsWithErrno(EINVAL));

  struct stat st = {};
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some std::string";
  std::vector<char> buf(512);
  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(OpenRetryEINTR(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  FileDescriptor wfd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenRetryEINTR(fifo.c_str(), O_WRONLY | O_TRUNC));
  EXPECT_THAT(ftruncate(wfd.get(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(ftruncate(wfd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

void TestSigHandler(int sig, siginfo_t* info, void* ucontext) {}

TEST(FifoTest, OpenBlockedAndInterrupted) {
  constexpr int kSigno = SIGUSR1;
  constexpr int kSigvalue = 42;

  // Install our signal handler.
  struct sigaction sa = {};
  sa.sa_sigaction = TestSigHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));

  // Ensure that kSigno is unblocked on at least one thread.
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, kSigno));

  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD;
  sev.sigev_signo = kSigno;
  sev.sigev_value.sival_int = kSigvalue;
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));

  constexpr absl::Duration kPeriod = absl::Seconds(1);
  struct itimerspec its = {};
  its.it_value = its.it_interval = absl::ToTimespec(kPeriod);
  ASSERT_NO_ERRNO(timer.Set(0, its));

  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  EXPECT_THAT(open(fifo.c_str(), O_WRONLY), SyscallFailsWithErrno(EINTR));
  EXPECT_THAT(open(fifo.c_str(), O_RDONLY), SyscallFailsWithErrno(EINTR));
}

void CheckRestartedOpen(int flags) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY));
  ASSERT_THAT(mkfifoat(dirfd.get(), "fifo", 0600), SyscallSucceeds());

  struct sigaction sa = {};
  sa.sa_sigaction = [](int, siginfo_t* info, void*) {
    // Only make a peer available once the signal has interrupted openat.
    // The child keeps this peer open until the first openat returns.
    if (openat(info->si_value.sival_int, "fifo", O_RDWR) < 0) {
      _exit(255);
    }
  };
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);

  pid_t child = fork();
  if (child == 0) {
    if (sigaction(SIGUSR1, &sa, nullptr) < 0 ||
        sigprocmask(SIG_UNBLOCK, &mask, nullptr) < 0) {
      _exit(255);
    }
    _exit(openat(dirfd.get(), "fifo", flags) < 0 ? errno : 0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  Cleanup reap([child] {
    kill(child, SIGKILL);
    RetryEINTR(waitpid)(child, nullptr, 0);
  });

  const std::string status_path = "/proc/" + std::to_string(child) + "/status";
  auto wait_for_state = [&](char state) {
    const std::string field = std::string("\nState:\t") + state;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    do {
      auto status = GetContents(status_path);
      if (!status.ok()) {
        ADD_FAILURE() << status.error();
        return false;
      }
      if (status.ValueOrDie().find(field) != std::string::npos) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
  };
  // The child runs no other blocking syscall before opening the FIFO.
  ASSERT_TRUE(wait_for_state('S')) << "child did not block in openat";
  union sigval value = {};
  value.sival_int = dirfd.get();
  ASSERT_THAT(sigqueue(child, SIGUSR1, value), SyscallSucceeds());
  ASSERT_TRUE(wait_for_state('Z')) << "openat did not return after SIGUSR1";
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  reap.Release();
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0) << "openat returned errno "
                                    << WEXITSTATUS(status);
}

TEST(FifoTest, RestartBlockedReadOpen) { CheckRestartedOpen(O_RDONLY); }

TEST(FifoTest, RestartBlockedWriteOpen) { CheckRestartedOpen(O_WRONLY); }

TEST(FifoTest, FifoOpenRDWR) {
  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  struct stat st;
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some std::string";
  std::vector<char> buf(msg.length() + 1);

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenRetryEINTR(fifo.c_str(), O_RDWR));
  EXPECT_THAT(WriteFd(fd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(ReadFd(fd.get(), buf.data(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_EQ(msg, std::string(buf.data()));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
