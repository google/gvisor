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

#include <fcntl.h> /* Obtain O_* constant definitions */
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/uio.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Used as a non-zero sentinel value, below.
constexpr int kTestValue = 0x12345678;

// Used for synchronization in race tests.
const absl::Duration syncDelay = absl::Seconds(2);

struct PipeCreator {
  std::string name_;

  // void (fds, is_blocking, is_namedpipe).
  std::function<void(int[2], bool*, bool*)> create_;
};

class PipeTest : public ::testing::TestWithParam<PipeCreator> {
 public:
  static void SetUpTestSuite() {
    // Tests intentionally generate SIGPIPE.
    TEST_PCHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  }

  // Initializes rfd_ and wfd_ as a blocking pipe.
  //
  // The return value indicates success: the test should be skipped otherwise.
  bool CreateBlocking() { return create(true); }

  // Initializes rfd_ and wfd_ as a non-blocking pipe.
  //
  // The return value is per CreateBlocking.
  bool CreateNonBlocking() { return create(false); }

  // Returns true iff the pipe represents a named pipe.
  bool IsNamedPipe() const { return named_pipe_; }

  size_t Size() const {
    int s1 = fcntl(rfd_.get(), F_GETPIPE_SZ);
    int s2 = fcntl(wfd_.get(), F_GETPIPE_SZ);
    EXPECT_GT(s1, 0);
    EXPECT_GT(s2, 0);
    EXPECT_EQ(s1, s2);
    return static_cast<size_t>(s1);
  }

  static void TearDownTestSuite() {
    TEST_PCHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
  }

 private:
  bool create(bool wants_blocking) {
    // Generate the pipe.
    int fds[2] = {-1, -1};
    bool is_blocking = false;
    GetParam().create_(fds, &is_blocking, &named_pipe_);
    if (fds[0] < 0 || fds[1] < 0) {
      return false;
    }

    // Save descriptors.
    rfd_.reset(fds[0]);
    wfd_.reset(fds[1]);

    // Adjust blocking, if needed.
    if (!is_blocking && wants_blocking) {
      // Clear the blocking flag.
      EXPECT_THAT(fcntl(fds[0], F_SETFL, 0), SyscallSucceeds());
      EXPECT_THAT(fcntl(fds[1], F_SETFL, 0), SyscallSucceeds());
    } else if (is_blocking && !wants_blocking) {
      // Set the descriptors to blocking.
      EXPECT_THAT(fcntl(fds[0], F_SETFL, O_NONBLOCK), SyscallSucceeds());
      EXPECT_THAT(fcntl(fds[1], F_SETFL, O_NONBLOCK), SyscallSucceeds());
    }

    return true;
  }

 protected:
  FileDescriptor rfd_;
  FileDescriptor wfd_;

 private:
  bool named_pipe_ = false;
};

TEST_P(PipeTest, Inode) {
  SKIP_IF(!CreateBlocking());

  // Ensure that the inode number is the same for each end.
  struct stat rst;
  ASSERT_THAT(fstat(rfd_.get(), &rst), SyscallSucceeds());
  struct stat wst;
  ASSERT_THAT(fstat(wfd_.get(), &wst), SyscallSucceeds());
  EXPECT_EQ(rst.st_ino, wst.st_ino);
}

TEST_P(PipeTest, Permissions) {
  SKIP_IF(!CreateBlocking());

  // Attempt bad operations.
  int buf = kTestValue;
  ASSERT_THAT(write(rfd_.get(), &buf, sizeof(buf)),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(read(wfd_.get(), &buf, sizeof(buf)),
              SyscallFailsWithErrno(EBADF));
}

TEST_P(PipeTest, Flags) {
  SKIP_IF(!CreateBlocking());

  if (IsNamedPipe()) {
    // May be stubbed to zero; define locally.
    EXPECT_THAT(fcntl(rfd_.get(), F_GETFL),
                SyscallSucceedsWithValue(kOLargeFile | O_RDONLY));
    EXPECT_THAT(fcntl(wfd_.get(), F_GETFL),
                SyscallSucceedsWithValue(kOLargeFile | O_WRONLY));
  } else {
    EXPECT_THAT(fcntl(rfd_.get(), F_GETFL), SyscallSucceedsWithValue(O_RDONLY));
    EXPECT_THAT(fcntl(wfd_.get(), F_GETFL), SyscallSucceedsWithValue(O_WRONLY));
  }
}

TEST_P(PipeTest, Write) {
  SKIP_IF(!CreateBlocking());

  int wbuf = kTestValue;
  int rbuf = ~kTestValue;
  ASSERT_THAT(write(wfd_.get(), &wbuf, sizeof(wbuf)),
              SyscallSucceedsWithValue(sizeof(wbuf)));
  ASSERT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(wbuf, rbuf);
}

TEST_P(PipeTest, WritePage) {
  SKIP_IF(!CreateBlocking());

  std::vector<char> wbuf(kPageSize);
  RandomizeBuffer(wbuf.data(), wbuf.size());
  std::vector<char> rbuf(wbuf.size());

  ASSERT_THAT(write(wfd_.get(), wbuf.data(), wbuf.size()),
              SyscallSucceedsWithValue(wbuf.size()));
  ASSERT_THAT(read(rfd_.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(rbuf.size()));
  EXPECT_EQ(memcmp(rbuf.data(), wbuf.data(), wbuf.size()), 0);
}

TEST_P(PipeTest, NonBlocking) {
  SKIP_IF(!CreateNonBlocking());

  int wbuf = kTestValue;
  int rbuf = ~kTestValue;
  EXPECT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallFailsWithErrno(EWOULDBLOCK));
  ASSERT_THAT(write(wfd_.get(), &wbuf, sizeof(wbuf)),
              SyscallSucceedsWithValue(sizeof(wbuf)));

  ASSERT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(wbuf, rbuf);
  EXPECT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST(PipeTest, StatFS) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  struct statfs st;
  EXPECT_THAT(fstatfs(fds[0], &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, PIPEFS_MAGIC);
  EXPECT_EQ(st.f_bsize, getpagesize());
  EXPECT_EQ(st.f_namelen, NAME_MAX);
}

TEST(Pipe2Test, CloExec) {
  int fds[2];
  ASSERT_THAT(pipe2(fds, O_CLOEXEC), SyscallSucceeds());
  EXPECT_THAT(fcntl(fds[0], F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  EXPECT_THAT(fcntl(fds[1], F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  EXPECT_THAT(close(fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST(Pipe2Test, BadOptions) {
  int fds[2];
  EXPECT_THAT(pipe2(fds, 0xDEAD), SyscallFailsWithErrno(EINVAL));
}

// Tests that opening named pipes with O_TRUNC shouldn't cause an error, but
// calls to (f)truncate should.
TEST(NamedPipeTest, Truncate) {
  const std::string tmp_path = NewTempAbsPath();
  SKIP_IF(mkfifo(tmp_path.c_str(), 0644) != 0);

  ASSERT_THAT(open(tmp_path.c_str(), O_NONBLOCK | O_RDONLY), SyscallSucceeds());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(tmp_path.c_str(), O_RDWR | O_NONBLOCK | O_TRUNC));

  ASSERT_THAT(truncate(tmp_path.c_str(), 0), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(ftruncate(fd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST_P(PipeTest, Seek) {
  SKIP_IF(!CreateBlocking());

  for (int i = 0; i < 4; i++) {
    // Attempt absolute seeks.
    EXPECT_THAT(lseek(rfd_.get(), 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(rfd_.get(), 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));

    // Attempt relative seeks.
    EXPECT_THAT(lseek(rfd_.get(), 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(rfd_.get(), 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));

    // Attempt end-of-file seeks.
    EXPECT_THAT(lseek(rfd_.get(), 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(rfd_.get(), -4, SEEK_END), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
    EXPECT_THAT(lseek(wfd_.get(), -4, SEEK_END), SyscallFailsWithErrno(ESPIPE));

    // Add some more data to the pipe.
    int buf = kTestValue;
    ASSERT_THAT(write(wfd_.get(), &buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
  }
}

TEST_P(PipeTest, OffsetCalls) {
  SKIP_IF(!CreateBlocking());

  int buf;
  EXPECT_THAT(pread(wfd_.get(), &buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(pwrite(rfd_.get(), &buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ESPIPE));

  struct iovec iov;
  iov.iov_base = &buf;
  iov.iov_len = sizeof(buf);
  EXPECT_THAT(preadv(wfd_.get(), &iov, 1, 0), SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(pwritev(rfd_.get(), &iov, 1, 0), SyscallFailsWithErrno(ESPIPE));
}

TEST_P(PipeTest, WriterSideCloses) {
  SKIP_IF(!CreateBlocking());

  ScopedThread t([this]() {
    int buf = ~kTestValue;
    ASSERT_THAT(read(rfd_.get(), &buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    EXPECT_EQ(buf, kTestValue);
    // This will return when the close() completes.
    ASSERT_THAT(read(rfd_.get(), &buf, sizeof(buf)), SyscallSucceeds());
    // This will return straight away.
    ASSERT_THAT(read(rfd_.get(), &buf, sizeof(buf)),
                SyscallSucceedsWithValue(0));
  });

  // Sleep a bit so the thread can block.
  absl::SleepFor(syncDelay);

  // Write to unblock.
  int buf = kTestValue;
  ASSERT_THAT(write(wfd_.get(), &buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Sleep a bit so the thread can block again.
  absl::SleepFor(syncDelay);

  // Allow the thread to complete.
  ASSERT_THAT(close(wfd_.release()), SyscallSucceeds());
  t.Join();
}

TEST_P(PipeTest, WriterSideClosesReadDataFirst) {
  SKIP_IF(!CreateBlocking());

  int wbuf = kTestValue;
  ASSERT_THAT(write(wfd_.get(), &wbuf, sizeof(wbuf)),
              SyscallSucceedsWithValue(sizeof(wbuf)));
  ASSERT_THAT(close(wfd_.release()), SyscallSucceeds());

  int rbuf;
  ASSERT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(wbuf, rbuf);
  EXPECT_THAT(read(rfd_.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(0));
}

TEST_P(PipeTest, ReaderSideCloses) {
  SKIP_IF(!CreateBlocking());

  ASSERT_THAT(close(rfd_.release()), SyscallSucceeds());
  int buf = kTestValue;
  EXPECT_THAT(write(wfd_.get(), &buf, sizeof(buf)),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(PipeTest, CloseTwice) {
  SKIP_IF(!CreateBlocking());

  int reader = rfd_.release();
  int writer = wfd_.release();
  ASSERT_THAT(close(reader), SyscallSucceeds());
  ASSERT_THAT(close(writer), SyscallSucceeds());
  EXPECT_THAT(close(reader), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(close(writer), SyscallFailsWithErrno(EBADF));
}

// Blocking write returns EPIPE when read end is closed if nothing has been
// written.
TEST_P(PipeTest, BlockWriteClosed) {
  SKIP_IF(!CreateBlocking());

  absl::Notification notify;
  ScopedThread t([this, &notify]() {
    std::vector<char> buf(Size());
    // Exactly fill the pipe buffer.
    ASSERT_THAT(WriteFd(wfd_.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(buf.size()));

    notify.Notify();

    // Attempt to write one more byte. Blocks.
    // N.B. Don't use WriteFd, we don't want a retry.
    EXPECT_THAT(write(wfd_.get(), buf.data(), 1), SyscallFailsWithErrno(EPIPE));
  });

  notify.WaitForNotification();
  ASSERT_THAT(close(rfd_.release()), SyscallSucceeds());
  t.Join();
}

// Blocking write returns EPIPE when read end is closed even if something has
// been written.
TEST_P(PipeTest, BlockPartialWriteClosed) {
  SKIP_IF(!CreateBlocking());

  ScopedThread t([this]() {
    const int pipe_size = Size();
    std::vector<char> buf(2 * pipe_size);

    // Write more than fits in the buffer. Blocks then returns partial write
    // when the other end is closed. The next call returns EPIPE.
    ASSERT_THAT(write(wfd_.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(pipe_size));
    EXPECT_THAT(write(wfd_.get(), buf.data(), buf.size()),
                SyscallFailsWithErrno(EPIPE));
  });

  // Leave time for write to become blocked.
  absl::SleepFor(syncDelay);

  // Unblock the above.
  ASSERT_THAT(close(rfd_.release()), SyscallSucceeds());
  t.Join();
}

TEST_P(PipeTest, ReadFromClosedFd_NoRandomSave) {
  SKIP_IF(!CreateBlocking());

  absl::Notification notify;
  ScopedThread t([this, &notify]() {
    notify.Notify();
    int buf;
    ASSERT_THAT(read(rfd_.get(), &buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    ASSERT_EQ(kTestValue, buf);
  });
  notify.WaitForNotification();

  // Make sure that the thread gets to read().
  absl::SleepFor(syncDelay);

  {
    // We cannot save/restore here as the read end of pipe is closed but there
    // is ongoing read() above. We will not be able to restart the read()
    // successfully in restore run since the read fd is closed.
    const DisableSave ds;
    ASSERT_THAT(close(rfd_.release()), SyscallSucceeds());
    int buf = kTestValue;
    ASSERT_THAT(write(wfd_.get(), &buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    t.Join();
  }
}

TEST_P(PipeTest, FionRead) {
  SKIP_IF(!CreateBlocking());

  int n;
  ASSERT_THAT(ioctl(rfd_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
  ASSERT_THAT(ioctl(wfd_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  std::vector<char> buf(Size());
  ASSERT_THAT(write(wfd_.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  EXPECT_THAT(ioctl(rfd_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, buf.size());
  EXPECT_THAT(ioctl(wfd_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, buf.size());
}

// Test that opening an empty anonymous pipe RDONLY via /proc/self/fd/N does not
// block waiting for a writer.
TEST_P(PipeTest, OpenViaProcSelfFD) {
  SKIP_IF(!CreateBlocking());
  SKIP_IF(IsNamedPipe());

  // Close the write end of the pipe.
  ASSERT_THAT(close(wfd_.release()), SyscallSucceeds());

  // Open other side via /proc/self/fd.  It should not block.
  FileDescriptor proc_self_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrCat("/proc/self/fd/", rfd_.get()), O_RDONLY));
}

// Test that opening and reading from an anonymous pipe (with existing writes)
// RDONLY via /proc/self/fd/N returns the existing data.
TEST_P(PipeTest, OpenViaProcSelfFDWithWrites) {
  SKIP_IF(!CreateBlocking());
  SKIP_IF(IsNamedPipe());

  // Write to the pipe and then close the write fd.
  int wbuf = kTestValue;
  ASSERT_THAT(write(wfd_.get(), &wbuf, sizeof(wbuf)),
              SyscallSucceedsWithValue(sizeof(wbuf)));
  ASSERT_THAT(close(wfd_.release()), SyscallSucceeds());

  // Open read side via /proc/self/fd, and read from it.
  FileDescriptor proc_self_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrCat("/proc/self/fd/", rfd_.get()), O_RDONLY));
  int rbuf;
  ASSERT_THAT(read(proc_self_fd.get(), &rbuf, sizeof(rbuf)),
              SyscallSucceedsWithValue(sizeof(rbuf)));
  EXPECT_EQ(wbuf, rbuf);
}

// Test that accesses of /proc/<PID>/fd correctly decrement the refcount.
TEST_P(PipeTest, ProcFDReleasesFile) {
  SKIP_IF(!CreateBlocking());

  // Stat the pipe FD, which shouldn't alter the refcount.
  struct stat wst;
  ASSERT_THAT(lstat(absl::StrCat("/proc/self/fd/", wfd_.get()).c_str(), &wst),
              SyscallSucceeds());

  // Close the write end and ensure that read indicates EOF.
  wfd_.reset();
  char buf;
  ASSERT_THAT(read(rfd_.get(), &buf, 1), SyscallSucceedsWithValue(0));
}

// Same for /proc/<PID>/fdinfo.
TEST_P(PipeTest, ProcFDInfoReleasesFile) {
  SKIP_IF(!CreateBlocking());

  // Stat the pipe FD, which shouldn't alter the refcount.
  struct stat wst;
  ASSERT_THAT(
      lstat(absl::StrCat("/proc/self/fdinfo/", wfd_.get()).c_str(), &wst),
      SyscallSucceeds());

  // Close the write end and ensure that read indicates EOF.
  wfd_.reset();
  char buf;
  ASSERT_THAT(read(rfd_.get(), &buf, 1), SyscallSucceedsWithValue(0));
}

TEST_P(PipeTest, SizeChange) {
  SKIP_IF(!CreateBlocking());

  // Set the minimum possible size.
  ASSERT_THAT(fcntl(rfd_.get(), F_SETPIPE_SZ, 0), SyscallSucceeds());
  int min = Size();
  EXPECT_GT(min, 0);  // Should be rounded up.

  // Set from the read end.
  ASSERT_THAT(fcntl(rfd_.get(), F_SETPIPE_SZ, min + 1), SyscallSucceeds());
  int med = Size();
  EXPECT_GT(med, min);  // Should have grown, may be rounded.

  // Set from the write end.
  ASSERT_THAT(fcntl(wfd_.get(), F_SETPIPE_SZ, med + 1), SyscallSucceeds());
  int max = Size();
  EXPECT_GT(max, med);  // Ditto.
}

TEST_P(PipeTest, SizeChangeMax) {
  SKIP_IF(!CreateBlocking());

  // Assert there's some maximum.
  EXPECT_THAT(fcntl(rfd_.get(), F_SETPIPE_SZ, 0x7fffffffffffffff),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fcntl(wfd_.get(), F_SETPIPE_SZ, 0x7fffffffffffffff),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PipeTest, SizeChangeFull) {
  SKIP_IF(!CreateBlocking());

  // Ensure that we adjust to a large enough size to avoid rounding when we
  // perform the size decrease. If rounding occurs, we may not actually
  // adjust the size and the call below will return success. It was found via
  // experimentation that this granularity avoids the rounding for Linux.
  constexpr int kDelta = 64 * 1024;
  ASSERT_THAT(fcntl(wfd_.get(), F_SETPIPE_SZ, Size() + kDelta),
              SyscallSucceeds());

  // Fill the buffer and try to change down.
  std::vector<char> buf(Size());
  ASSERT_THAT(write(wfd_.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  EXPECT_THAT(fcntl(wfd_.get(), F_SETPIPE_SZ, Size() - kDelta),
              SyscallFailsWithErrno(EBUSY));
}

TEST_P(PipeTest, Streaming) {
  SKIP_IF(!CreateBlocking());

  // We make too many calls to go through full save cycles.
  DisableSave ds;

  // Size() requires 2 syscalls, call it once and remember the value.
  const size_t pipe_size = Size();
  const size_t streamed_bytes = 4 * pipe_size;

  absl::Notification notify;
  ScopedThread t([&, this]() {
    std::vector<char> buf(1024);
    // Don't start until it's full.
    notify.WaitForNotification();
    size_t total = 0;
    while (total < streamed_bytes) {
      ASSERT_THAT(read(rfd_.get(), buf.data(), buf.size()),
                  SyscallSucceedsWithValue(buf.size()));
      total += buf.size();
    }
  });

  // Write 4 bytes * pipe_size. It will fill up the pipe once, notify the reader
  // to start. Then we write pipe size worth 3 more times to ensure the reader
  // can follow along.
  //
  // The size of each write (which is determined by buf.size()) must be smaller
  // than the size of the pipe (which, in the "smallbuffer" configuration, is 1
  // page) for the check for notify.Notify() below to be correct.
  std::vector<char> buf(1024);
  RandomizeBuffer(buf.data(), buf.size());
  size_t total = 0;
  while (total < streamed_bytes) {
    ASSERT_THAT(write(wfd_.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(buf.size()));
    total += buf.size();

    // Is the next write about to fill up the buffer? Wake up the reader once.
    if (total < pipe_size && (total + buf.size()) >= pipe_size) {
      notify.Notify();
    }
  }
}

std::string PipeCreatorName(::testing::TestParamInfo<PipeCreator> info) {
  return info.param.name_;  // Use the name specified.
}

INSTANTIATE_TEST_SUITE_P(
    Pipes, PipeTest,
    ::testing::Values(
        PipeCreator{
            "pipe",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              ASSERT_THAT(pipe(fds), SyscallSucceeds());
              *is_blocking = true;
              *is_namedpipe = false;
            },
        },
        PipeCreator{
            "pipe2blocking",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              ASSERT_THAT(pipe2(fds, 0), SyscallSucceeds());
              *is_blocking = true;
              *is_namedpipe = false;
            },
        },
        PipeCreator{
            "pipe2nonblocking",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              ASSERT_THAT(pipe2(fds, O_NONBLOCK), SyscallSucceeds());
              *is_blocking = false;
              *is_namedpipe = false;
            },
        },
        PipeCreator{
            "smallbuffer",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              // Set to the minimum available size (will round up).
              ASSERT_THAT(pipe(fds), SyscallSucceeds());
              ASSERT_THAT(fcntl(fds[0], F_SETPIPE_SZ, 0), SyscallSucceeds());
              *is_blocking = true;
              *is_namedpipe = false;
            },
        },
        PipeCreator{
            "namednonblocking",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              // Create a new file-based pipe (non-blocking).
              std::string path;
              {
                auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
                path = file.path();
              }
              SKIP_IF(mkfifo(path.c_str(), 0644) != 0);
              fds[0] = open(path.c_str(), O_NONBLOCK | O_RDONLY);
              fds[1] = open(path.c_str(), O_NONBLOCK | O_WRONLY);
              MaybeSave();
              *is_blocking = false;
              *is_namedpipe = true;
            },
        },
        PipeCreator{
            "namedblocking",
            [](int fds[2], bool* is_blocking, bool* is_namedpipe) {
              // Create a new file-based pipe (blocking).
              std::string path;
              {
                auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
                path = file.path();
              }
              SKIP_IF(mkfifo(path.c_str(), 0644) != 0);
              ScopedThread t(
                  [&path, &fds]() { fds[1] = open(path.c_str(), O_WRONLY); });
              fds[0] = open(path.c_str(), O_RDONLY);
              t.Join();
              MaybeSave();
              *is_blocking = true;
              *is_namedpipe = true;
            },
        }),
    PipeCreatorName);

}  // namespace
}  // namespace testing
}  // namespace gvisor
