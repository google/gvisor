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
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

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

std::atomic<int> signals_delivered;

void CountingSigHandler(int sig, siginfo_t* info, void* ucontext) {
  signals_delivered.fetch_add(1, std::memory_order_relaxed);
}

// Interrupts a blocking FIFO open with a handled signal and checks that the
// open is restarted (SA_RESTART) or fails with EINTR (no SA_RESTART).
//
// The interrupting signals come from a second thread rather than a timer, so
// nothing here depends on wall-clock timing. Without SA_RESTART the peer end is
// never opened, so the open can only return by being interrupted. With
// SA_RESTART the peer end is not opened until the handler has run twice during
// a single open(2), which an open that fails with EINTR cannot reach.
void FifoOpenInterrupted(int open_flags, bool restart) {
  constexpr int kSigno = SIGUSR1;
  const int peer_flags = open_flags == O_RDONLY ? O_WRONLY : O_RDONLY;

  struct sigaction sa = {};
  sa.sa_sigaction = CountingSigHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | (restart ? SA_RESTART : 0);
  const auto scoped_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kSigno, sa));
  const auto scoped_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, kSigno));

  const std::string fifo = NewTempAbsPath();
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  signals_delivered.store(0, std::memory_order_relaxed);
  std::atomic<bool> returned(false);
  const pid_t opener = gettid();
  int peer = -1;

  ScopedThread signaller([&] {
    // Interrupt the open. With SA_RESTART, stop once the handler has run twice
    // during a single open(2); without it, the first delivery ends the open.
    while (!returned.load(std::memory_order_acquire) &&
           (!restart ||
            signals_delivered.load(std::memory_order_relaxed) < 2)) {
      TEST_PCHECK(tgkill(getpid(), opener, kSigno) == 0);
      sched_yield();
    }
    if (!restart) {
      return;
    }
    // Signalling has stopped, so the opener restarts a last time and blocks.
    // Give it a peer so that the open can complete. Retry, because an
    // interrupted open drops its reader or writer reference before restarting
    // and a peer opened in that window fails with ENXIO, and keep the peer open
    // until the opener returns, because a restart re-samples the pipe's open
    // counters. O_NONBLOCK so that this cannot block if the opener gave up.
    while (!returned.load(std::memory_order_acquire) &&
           (peer = open(fifo.c_str(), peer_flags | O_NONBLOCK)) < 0) {
      sched_yield();
    }
  });

  const int fd = open(fifo.c_str(), open_flags);
  const int open_errno = errno;
  returned.store(true, std::memory_order_release);
  signaller.Join();

  if (fd >= 0) {
    EXPECT_THAT(close(fd), SyscallSucceeds());
  }
  if (peer >= 0) {
    EXPECT_THAT(close(peer), SyscallSucceeds());
  }
  errno = open_errno;
  if (restart) {
    EXPECT_THAT(fd, SyscallSucceeds());
    // Proves the open was interrupted and resumed, not left to complete.
    EXPECT_GE(signals_delivered.load(std::memory_order_relaxed), 2);
  } else {
    EXPECT_THAT(fd, SyscallFailsWithErrno(EINTR));
  }
}

TEST(FifoTest, OpenBlockedAndInterrupted) {
  FifoOpenInterrupted(O_RDONLY, /*restart=*/false);
  FifoOpenInterrupted(O_WRONLY, /*restart=*/false);
}

TEST(FifoTest, OpenBlockedAndRestarted) {
  FifoOpenInterrupted(O_RDONLY, /*restart=*/true);
  FifoOpenInterrupted(O_WRONLY, /*restart=*/true);
}

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
