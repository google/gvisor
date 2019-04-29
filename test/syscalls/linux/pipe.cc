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

#include <fcntl.h> /* Obtain O_* constant definitions */
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Buffer size of a pipe.
//
// TODO(b/35762278): Get this from F_GETPIPE_SZ.
constexpr int kPipeSize = 65536;

class PipeTest : public ::testing::Test {
 public:
  static void SetUpTestCase() {
    // Tests intentionally generate SIGPIPE.
    TEST_PCHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  }

  static void TearDownTestCase() {
    TEST_PCHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
  }
};

TEST_F(PipeTest, Basic) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int i = 0x12345678;
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  // Ensure that the inode number is the same for each end.
  struct stat rst;
  ASSERT_THAT(fstat(fds[0], &rst), SyscallSucceeds());
  struct stat wst;
  ASSERT_THAT(fstat(fds[1], &wst), SyscallSucceeds());
  EXPECT_EQ(rst.st_ino, wst.st_ino);

  ASSERT_THAT(write(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(read(fds[1], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));

  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  int j;
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  EXPECT_EQ(i, j);

  ASSERT_THAT(fcntl(fds[0], F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(fds[1], F_GETFL), SyscallSucceedsWithValue(O_WRONLY));

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, BasicCloExec) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int i = 0x12345678;
  ASSERT_THAT(pipe2(fds, O_CLOEXEC), SyscallSucceeds());

  ASSERT_THAT(write(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(read(fds[1], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));

  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  int j;
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  EXPECT_EQ(i, j);

  ASSERT_THAT(fcntl(fds[0], F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(fds[1], F_GETFL), SyscallSucceeds());

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, BasicNoBlock) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int i = 0x12345678;
  ASSERT_THAT(pipe2(fds, O_NONBLOCK), SyscallSucceeds());

  ASSERT_THAT(write(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(read(fds[1], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));

  ASSERT_THAT(read(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EWOULDBLOCK));
  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  int j;
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  EXPECT_EQ(i, j);
  ASSERT_THAT(read(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EWOULDBLOCK));

  ASSERT_THAT(fcntl(fds[0], F_GETFL), SyscallSucceedsWithValue(O_NONBLOCK));
  ASSERT_THAT(fcntl(fds[1], F_GETFL),
              SyscallSucceedsWithValue(O_NONBLOCK | O_WRONLY));

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, BasicBothOptions) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int i = 0x12345678;
  ASSERT_THAT(pipe2(fds, O_NONBLOCK | O_CLOEXEC), SyscallSucceeds());

  ASSERT_THAT(write(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(read(fds[1], &i, sizeof(i)), SyscallFailsWithErrno(EBADF));

  ASSERT_THAT(read(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EWOULDBLOCK));
  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  int j;
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  EXPECT_EQ(i, j);
  ASSERT_THAT(read(fds[0], &i, sizeof(i)), SyscallFailsWithErrno(EWOULDBLOCK));

  ASSERT_THAT(fcntl(fds[0], F_GETFL), SyscallSucceedsWithValue(O_NONBLOCK));
  ASSERT_THAT(fcntl(fds[1], F_GETFL),
              SyscallSucceedsWithValue(O_NONBLOCK | O_WRONLY));

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, BasicBadOptions) {
  int fds[2];
  ASSERT_THAT(pipe2(fds, 0xDEAD), SyscallFailsWithErrno(EINVAL));
}

TEST_F(PipeTest, Seek) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int i = 0x12345678;
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  ASSERT_THAT(lseek(fds[0], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[0], 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[0], 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));

  ASSERT_THAT(lseek(fds[0], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[0], 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));

  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  int j;

  ASSERT_THAT(lseek(fds[0], 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[0], 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 4, SEEK_SET), SyscallFailsWithErrno(ESPIPE));

  ASSERT_THAT(lseek(fds[0], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[0], 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 0, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));
  ASSERT_THAT(lseek(fds[1], 4, SEEK_CUR), SyscallFailsWithErrno(ESPIPE));

  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  EXPECT_EQ(i, j);

  ASSERT_THAT(fcntl(fds[0], F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(fds[1], F_GETFL), SyscallSucceedsWithValue(O_WRONLY));

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, AbsoluteOffsetSyscallsFail) {
  // Syscalls for IO at absolute offsets fail because pipes are not seekable.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  std::vector<char> buf(4096);
  struct iovec iov;

  EXPECT_THAT(pread(fds[1], buf.data(), buf.size(), 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(pwrite(fds[0], buf.data(), buf.size(), 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(preadv(fds[1], &iov, 1, 0), SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(pwritev(fds[0], &iov, 1, 0), SyscallFailsWithErrno(ESPIPE));

  EXPECT_THAT(close(fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, WriterSideCloses) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  int rfd = fds[0];
  int i = 123;
  ScopedThread t([rfd]() {
    int j;
    ASSERT_THAT(read(rfd, &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
    // This will return when the close() completes.
    ASSERT_THAT(read(rfd, &j, sizeof(j)), SyscallSucceeds());
    // This will return straight away.
    ASSERT_THAT(read(rfd, &j, sizeof(j)), SyscallSucceeds());
  });
  // Sleep a bit so the thread can block.
  absl::SleepFor(absl::Seconds(1.0));
  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  // Sleep a bit so the thread can block again.
  absl::SleepFor(absl::Seconds(3.0));
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
  t.Join();

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
}

TEST_F(PipeTest, WriterSideClosesReadDataFirst) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  int i = 123;
  ASSERT_THAT(write(fds[1], &i, sizeof(i)),
              SyscallSucceedsWithValue(sizeof(i)));
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
  int j;
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceedsWithValue(sizeof(j)));
  ASSERT_EQ(j, i);
  ASSERT_THAT(read(fds[0], &j, sizeof(j)), SyscallSucceeds());

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
}

TEST_F(PipeTest, ReaderSideCloses) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  int i = 123;
  ASSERT_THAT(write(fds[1], &i, sizeof(i)), SyscallFailsWithErrno(EPIPE));

  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, CloseTwice) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
  ASSERT_THAT(close(fds[0]), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(close(fds[1]), SyscallFailsWithErrno(EBADF));

  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[0]), SyscallFailsWithErrno(EBADF));
  ASSERT_THAT(close(fds[1]), SyscallFailsWithErrno(EBADF));
}

// Blocking write returns EPIPE when read end is closed if nothing has been
// written.
TEST_F(PipeTest, BlockWriteClosed) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  int wfd = fds[1];

  absl::Notification notify;
  ScopedThread t([wfd, &notify]() {
    std::vector<char> buf(kPipeSize);
    // Exactly fill the pipe buffer.
    ASSERT_THAT(WriteFd(wfd, buf.data(), buf.size()),
                SyscallSucceedsWithValue(buf.size()));

    notify.Notify();

    // Attempt to write one more byte. Blocks.
    // N.B. Don't use WriteFd, we don't want a retry.
    ASSERT_THAT(write(wfd, buf.data(), 1), SyscallFailsWithErrno(EPIPE));
  });

  notify.WaitForNotification();
  absl::SleepFor(absl::Seconds(1.0));
  ASSERT_THAT(close(fds[0]), SyscallSucceeds());

  t.Join();

  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

// Blocking write returns EPIPE when read end is closed even if something has
// been written.
//
// FIXME(b/35924046): Pipe writes blocking early allows S/R to interrupt the
// write(2) call before the buffer is full. Then the next call will will return
// non-zero instead of EPIPE.
TEST_F(PipeTest, BlockPartialWriteClosed_NoRandomSave) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  int wfd = fds[1];

  ScopedThread t([wfd]() {
    std::vector<char> buf(2 * kPipeSize);
    // Write more than fits in the buffer. Blocks then returns partial write
    // when the other end is closed. The next call returns EPIPE.
    if (IsRunningOnGvisor()) {
      // FIXME(b/35924046): Pipe writes block early on gVisor, resulting in a
      // shorter than expected partial write.
      ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                  SyscallSucceedsWithValue(::testing::Gt(0)));
    } else {
      ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                  SyscallSucceedsWithValue(kPipeSize));
    }
    ASSERT_THAT(write(wfd, buf.data(), buf.size()),
                SyscallFailsWithErrno(EPIPE));
  });

  // Leave time for write to become blocked.
  absl::SleepFor(absl::Seconds(1.0));

  ASSERT_THAT(close(fds[0]), SyscallSucceeds());

  t.Join();

  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, ReadFromClosedFd_NoRandomSave) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  int rfd = fds[0];
  absl::Notification notify;
  ScopedThread t([rfd, &notify]() {
    int f;
    notify.Notify();
    ASSERT_THAT(read(rfd, &f, sizeof(f)), SyscallSucceedsWithValue(sizeof(f)));
    ASSERT_EQ(123, f);
  });
  notify.WaitForNotification();
  // Make sure that the thread gets to read().
  absl::SleepFor(absl::Seconds(5.0));
  {
    // We cannot save/restore here as the read end of pipe is closed but there
    // is ongoing read() above. We will not be able to restart the read()
    // successfully in restore run since the read fd is closed.
    const DisableSave ds;
    ASSERT_THAT(close(fds[0]), SyscallSucceeds());
    int i = 123;
    ASSERT_THAT(write(fds[1], &i, sizeof(i)),
                SyscallSucceedsWithValue(sizeof(i)));
    t.Join();
  }
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(PipeTest, FionRead) {
  // fds[0] is read end, fds[1] is write end.
  int fds[2];
  int data[2] = {0x12345678, 0x9101112};
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  int n = -1;
  EXPECT_THAT(ioctl(fds[0], FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
  n = -1;
  EXPECT_THAT(ioctl(fds[1], FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  EXPECT_THAT(write(fds[1], data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));

  n = -1;
  EXPECT_THAT(ioctl(fds[0], FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(data));
  n = -1;
  EXPECT_THAT(ioctl(fds[1], FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(data));
}

// Test that opening an empty anonymous pipe RDONLY via /proc/self/fd/N does not
// block waiting for a writer.
TEST_F(PipeTest, OpenViaProcSelfFD) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Close the write end of the pipe.
  wfd.release();

  // Open other side via /proc/self/fd.  It should not block.
  FileDescriptor proc_self_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrCat("/proc/self/fd/", fds[0]), O_RDONLY));
}

// Test that opening and reading from an anonymous pipe (with existing writes)
// RDONLY via /proc/self/fd/N returns the existing data.
TEST_F(PipeTest, OpenViaProcSelfFDWithWrites) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Write to the pipe and then close the write fd.
  char data = 'x';
  ASSERT_THAT(write(fds[1], &data, 1), SyscallSucceedsWithValue(1));
  wfd.release();

  // Open read side via /proc/self/fd, and read from it.
  FileDescriptor proc_self_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(absl::StrCat("/proc/self/fd/", fds[0]), O_RDONLY));
  char got;
  ASSERT_THAT(read(proc_self_fd.get(), &got, 1), SyscallSucceedsWithValue(1));

  // We should get what we sent.
  EXPECT_EQ(got, data);
}

TEST_F(PipeTest, LargeFile) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  int rflags;
  EXPECT_THAT(rflags = fcntl(rfd.get(), F_GETFL), SyscallSucceeds());

  // The kernel did *not* set O_LARGEFILE.
  EXPECT_EQ(rflags, 0);
}

// Test that accesses of /proc/<PID>/fd/<FD> and /proc/<PID>/fdinfo/<FD>
// correctly decrement the refcount of that file descriptor.
TEST_F(PipeTest, ProcFDReleasesFile) {
  std::vector<std::string> paths = {"/proc/self/fd/", "/proc/self/fdinfo/"};
  for (const std::string& path : paths) {
    int fds[2];
    ASSERT_THAT(pipe(fds), SyscallSucceeds());
    FileDescriptor rfd(fds[0]);
    FileDescriptor wfd(fds[1]);

    // Stat the pipe FD, which shouldn't alter the refcount of the write end of
    // the pipe.
    struct stat wst;
    ASSERT_THAT(lstat(absl::StrCat(path.c_str(), wfd.get()).c_str(), &wst),
                SyscallSucceeds());
    // Close the write end of the pipe and ensure that read indicates EOF.
    wfd.reset();
    char buf;
    ASSERT_THAT(read(rfd.get(), &buf, 1), SyscallSucceedsWithValue(0));
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
