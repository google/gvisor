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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "test/util/cleanup.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class WriteTest : public ::testing::Test {
 public:
  ssize_t WriteBytes(int fd, int bytes) {
    std::vector<char> buf(bytes);
    std::fill(buf.begin(), buf.end(), 'a');
    return WriteFd(fd, buf.data(), buf.size());
  }
};

TEST_F(WriteTest, WriteNoExceedsRLimit) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  int fd;
  struct rlimit setlim;
  const int target_lim = 1024;
  setlim.rlim_cur = target_lim;
  setlim.rlim_max = RLIM_INFINITY;
  const std::string pathname = NewTempAbsPath();
  ASSERT_THAT(fd = open(pathname.c_str(), O_WRONLY | O_CREAT, S_IRWXU),
              SyscallSucceeds());
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());

  EXPECT_THAT(WriteBytes(fd, target_lim), SyscallSucceedsWithValue(target_lim));

  std::vector<char> buf(target_lim + 1);
  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(pwrite(fd, buf.data(), target_lim, 1), SyscallSucceeds());
  EXPECT_THAT(pwrite64(fd, buf.data(), target_lim, 1), SyscallSucceeds());

  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(WriteTest, WriteExceedsRLimit) {
  // Get the current rlimit and restore after test run.
  struct rlimit initial_lim;
  ASSERT_THAT(getrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  auto cleanup = Cleanup([&initial_lim] {
    EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &initial_lim), SyscallSucceeds());
  });

  int fd;
  sigset_t filesize_mask;
  sigemptyset(&filesize_mask);
  sigaddset(&filesize_mask, SIGXFSZ);

  struct rlimit setlim;
  const int target_lim = 1024;
  setlim.rlim_cur = target_lim;
  setlim.rlim_max = RLIM_INFINITY;

  const std::string pathname = NewTempAbsPath();
  ASSERT_THAT(fd = open(pathname.c_str(), O_WRONLY | O_CREAT, S_IRWXU),
              SyscallSucceeds());
  ASSERT_THAT(setrlimit(RLIMIT_FSIZE, &setlim), SyscallSucceeds());
  ASSERT_THAT(sigprocmask(SIG_BLOCK, &filesize_mask, nullptr),
              SyscallSucceeds());
  std::vector<char> buf(target_lim + 2);
  std::fill(buf.begin(), buf.end(), 'a');

  EXPECT_THAT(write(fd, buf.data(), target_lim + 1),
              SyscallSucceedsWithValue(target_lim));
  EXPECT_THAT(write(fd, buf.data(), 1), SyscallFailsWithErrno(EFBIG));
  siginfo_t info;
  struct timespec timelimit = {0, 0};
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  EXPECT_THAT(pwrite(fd, buf.data(), target_lim + 1, 1),
              SyscallSucceedsWithValue(target_lim - 1));
  EXPECT_THAT(pwrite(fd, buf.data(), 1, target_lim),
              SyscallFailsWithErrno(EFBIG));
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  EXPECT_THAT(pwrite64(fd, buf.data(), target_lim + 1, 1),
              SyscallSucceedsWithValue(target_lim - 1));
  EXPECT_THAT(pwrite64(fd, buf.data(), 1, target_lim),
              SyscallFailsWithErrno(EFBIG));
  ASSERT_THAT(RetryEINTR(sigtimedwait)(&filesize_mask, &info, &timelimit),
              SyscallSucceedsWithValue(SIGXFSZ));
  EXPECT_EQ(info.si_code, SI_USER);
  EXPECT_EQ(info.si_pid, getpid());
  EXPECT_EQ(info.si_uid, getuid());

  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &filesize_mask, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(WriteTest, WriteIncrementOffset) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int fd = f.get();

  EXPECT_THAT(WriteBytes(fd, 0), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const int bytes_first = 1024;
  EXPECT_THAT(WriteBytes(fd, bytes_first),
              SyscallSucceedsWithValue(bytes_first));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(bytes_first));

  const int bytes_second = 512;
  EXPECT_THAT(WriteBytes(fd, bytes_second),
              SyscallSucceedsWithValue(bytes_second));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR),
              SyscallSucceedsWithValue(bytes_first + bytes_second));
}

TEST_F(WriteTest, WriteIncrementOffsetSeek) {
  const std::string data = "hello world\n";
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), data, TempPath::kDefaultFileMode));
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int fd = f.get();

  const int seek_offset = data.size() / 2;
  ASSERT_THAT(lseek(fd, seek_offset, SEEK_SET),
              SyscallSucceedsWithValue(seek_offset));

  const int write_bytes = 512;
  EXPECT_THAT(WriteBytes(fd, write_bytes),
              SyscallSucceedsWithValue(write_bytes));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR),
              SyscallSucceedsWithValue(seek_offset + write_bytes));
}

TEST_F(WriteTest, WriteIncrementOffsetAppend) {
  const std::string data = "hello world\n";
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), data, TempPath::kDefaultFileMode));
  FileDescriptor f = ASSERT_NO_ERRNO_AND_VALUE(
      Open(tmpfile.path().c_str(), O_WRONLY | O_APPEND));
  int fd = f.get();

  EXPECT_THAT(WriteBytes(fd, 1024), SyscallSucceedsWithValue(1024));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR),
              SyscallSucceedsWithValue(data.size() + 1024));
}

TEST_F(WriteTest, WriteIncrementOffsetEOF) {
  const std::string data = "hello world\n";
  const TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), data, TempPath::kDefaultFileMode));
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int fd = f.get();

  EXPECT_THAT(lseek(fd, 0, SEEK_END), SyscallSucceedsWithValue(data.size()));

  EXPECT_THAT(WriteBytes(fd, 1024), SyscallSucceedsWithValue(1024));
  EXPECT_THAT(lseek(fd, 0, SEEK_END),
              SyscallSucceedsWithValue(data.size() + 1024));
}

TEST_F(WriteTest, PwriteNoChangeOffset) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int fd = f.get();

  const std::string data = "hello world\n";

  EXPECT_THAT(pwrite(fd, data.data(), data.size(), 0),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const int bytes_total = 1024;
  ASSERT_THAT(WriteBytes(fd, bytes_total),
              SyscallSucceedsWithValue(bytes_total));
  ASSERT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(bytes_total));

  EXPECT_THAT(pwrite(fd, data.data(), data.size(), bytes_total),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(bytes_total));
}

TEST_F(WriteTest, WriteWithOpath) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_PATH));
  int fd = f.get();

  EXPECT_THAT(WriteBytes(fd, 1024), SyscallFailsWithErrno(EBADF));
}

TEST_F(WriteTest, WritevWithOpath) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_PATH));
  int fd = f.get();

  char buf[16];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  EXPECT_THAT(writev(fd, &iov, /*__count=*/1), SyscallFailsWithErrno(EBADF));
}

TEST_F(WriteTest, PwriteWithOpath) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor f =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_PATH));
  int fd = f.get();

  const std::string data = "hello world\n";

  EXPECT_THAT(pwrite(fd, data.data(), data.size(), 0),
              SyscallFailsWithErrno(EBADF));
}

// Test that partial writes that hit SIGSEGV are correctly handled and return
// partial write.
TEST_F(WriteTest, PartialWriteSIGSEGV) {
  // Allocate 2 pages and remove permission from the second.
  const size_t size = 2 * kPageSize;
  void* addr = mmap(0, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  ASSERT_NE(addr, MAP_FAILED);
  auto cleanup = Cleanup(
      [addr, size] { EXPECT_THAT(munmap(addr, size), SyscallSucceeds()); });

  void* badAddr = reinterpret_cast<char*>(addr) + kPageSize;
  ASSERT_THAT(mprotect(badAddr, kPageSize, PROT_NONE), SyscallSucceeds());

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_WRONLY));

  // Attempt to write both pages to the file. Create a non-contiguous iovec pair
  // to ensure operation is done in 2 steps.
  struct iovec iov[] = {
      {
          .iov_base = addr,
          .iov_len = kPageSize,
      },
      {
          .iov_base = addr,
          .iov_len = size,
      },
  };
  // Write should succeed for the first iovec and half of the second (=2 pages).
  EXPECT_THAT(pwritev(fd.get(), iov, ABSL_ARRAYSIZE(iov), 0),
              SyscallSucceedsWithValue(2 * kPageSize));
}

// Test that partial writes that hit SIGBUS are correctly handled and return
// partial write.
TEST_F(WriteTest, PartialWriteSIGBUS) {
  SKIP_IF(getenv("GVISOR_GOFER_UNCACHED"));  // Can't mmap from uncached files.
  // TODO(b/264306751): Remove once FUSE implements mmap.
  SKIP_IF(getenv("GVISOR_FUSE_TEST"));

  TempPath mapfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd_map =
      ASSERT_NO_ERRNO_AND_VALUE(Open(mapfile.path().c_str(), O_RDWR));

  // Let the first page be read to force a partial write.
  ASSERT_THAT(ftruncate(fd_map.get(), kPageSize), SyscallSucceeds());

  // Map 2 pages, one of which is not allocated in the backing file. Reading
  // from it will trigger a SIGBUS.
  const size_t size = 2 * kPageSize;
  void* addr =
      mmap(NULL, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd_map.get(), 0);
  ASSERT_NE(addr, MAP_FAILED);
  auto cleanup = Cleanup(
      [addr, size] { EXPECT_THAT(munmap(addr, size), SyscallSucceeds()); });

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_WRONLY));

  // Attempt to write both pages to the file. Create a non-contiguous iovec pair
  // to ensure operation is done in 2 steps.
  struct iovec iov[] = {
      {
          .iov_base = addr,
          .iov_len = kPageSize,
      },
      {
          .iov_base = addr,
          .iov_len = size,
      },
  };
  // Write should succeed for the first iovec and half of the second (=2 pages).
  ASSERT_THAT(pwritev(fd.get(), iov, ABSL_ARRAYSIZE(iov), 0),
              SyscallSucceedsWithValue(2 * kPageSize));
}

// Test that write with a nullptr buffer fails with EFAULT.
TEST_F(WriteTest, WriteNullBuffer) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  // Use raw syscall to bypass libc's nonnull annotation.
  EXPECT_THAT(syscall(SYS_write, fd.get(), nullptr, 1),
              SyscallFailsWithErrno(EFAULT));
}

// Test that pwrite with a nullptr buffer fails with EFAULT.
TEST_F(WriteTest, PwriteNullBuffer) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  // Use raw syscall to bypass libc's nonnull annotation and check kernel
  // EFAULT.
  EXPECT_THAT(syscall(SYS_pwrite64, fd.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EFAULT));
}

// Test that writev with a bad iov_base buffer fails with EFAULT.
TEST_F(WriteTest, WritevBadBuffer) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  struct iovec iov;
  iov.iov_base = reinterpret_cast<void*>(0x1);  // Bad address
  iov.iov_len = 1;

  EXPECT_THAT(writev(fd.get(), &iov, 1), SyscallFailsWithErrno(EFAULT));
}

// Test that write with zero length and nullptr buffer succeeds.
TEST_F(WriteTest, WriteZeroLengthNullBuffer) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  EXPECT_THAT(write(fd.get(), nullptr, 0), SyscallSucceedsWithValue(0));
}

// Test that write to a closed fd fails with EBADF.
TEST_F(WriteTest, WriteClosedFd) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int raw_fd = fd.get();
  fd.reset();

  char buf[16] = {};
  EXPECT_THAT(write(raw_fd, buf, sizeof(buf)), SyscallFailsWithErrno(EBADF));
}

// Test that pwrite to a closed fd fails with EBADF.
TEST_F(WriteTest, PwriteClosedFd) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));
  int raw_fd = fd.get();
  fd.reset();

  char buf[16] = {};
  EXPECT_THAT(pwrite(raw_fd, buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EBADF));
}

// Test that write to a negative fd fails with EBADF.
TEST_F(WriteTest, WriteNegativeFd) {
  char buf[16] = {};
  EXPECT_THAT(write(-1, buf, sizeof(buf)), SyscallFailsWithErrno(EBADF));
}

// Test that pwrite to a negative fd fails with EBADF.
TEST_F(WriteTest, PwriteNegativeFd) {
  char buf[16] = {};
  EXPECT_THAT(pwrite(-1, buf, sizeof(buf), 0), SyscallFailsWithErrno(EBADF));
}

// Test that write to a read-only fd fails with EBADF.
TEST_F(WriteTest, WriteReadOnlyFd) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_RDONLY));

  char buf[16] = {};
  EXPECT_THAT(write(fd.get(), buf, sizeof(buf)), SyscallFailsWithErrno(EBADF));
}

// Test that pwrite to a read-only fd fails with EBADF.
TEST_F(WriteTest, PwriteReadOnlyFd) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_RDONLY));

  char buf[16] = {};
  EXPECT_THAT(pwrite(fd.get(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EBADF));
}

// Test that pwrite with a negative offset fails with EINVAL.
TEST_F(WriteTest, PwriteNegativeOffset) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  char buf[16] = {};
  EXPECT_THAT(pwrite(fd.get(), buf, sizeof(buf), -1),
              SyscallFailsWithErrno(EINVAL));
}

// Test writing to a pipe.
TEST_F(WriteTest, WriteToPipe) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  auto cleanup = Cleanup([&pipe_fds] {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
  });

  const std::string data = "hello pipe";
  EXPECT_THAT(write(pipe_fds[1], data.data(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  char buf[32];
  EXPECT_THAT(read(pipe_fds[0], buf, sizeof(buf)),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(std::string(buf, data.size()), data);
}

// Test that pwrite to a pipe fails with ESPIPE.
TEST_F(WriteTest, PwriteToPipe) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  auto cleanup = Cleanup([&pipe_fds] {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
  });

  const std::string data = "hello pipe";
  EXPECT_THAT(pwrite(pipe_fds[1], data.data(), data.size(), 0),
              SyscallFailsWithErrno(ESPIPE));
}

// Test that write to the read end of a pipe fails with EBADF.
TEST_F(WriteTest, WriteToReadEndOfPipe) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  auto cleanup = Cleanup([&pipe_fds] {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
  });

  char buf[16] = {};
  EXPECT_THAT(write(pipe_fds[0], buf, sizeof(buf)),
              SyscallFailsWithErrno(EBADF));
}

// Test writing through a symlink.
TEST_F(WriteTest, WriteToSymlink) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string link_path = NewTempAbsPath();
  ASSERT_THAT(symlink(tmpfile.path().c_str(), link_path.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&link_path] { unlink(link_path.c_str()); });

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(link_path.c_str(), O_WRONLY));

  const std::string data = "hello symlink";
  EXPECT_THAT(write(fd.get(), data.data(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  // Verify data was written to the actual file.
  FileDescriptor read_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_RDONLY));
  char buf[32];
  EXPECT_THAT(read(read_fd.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(std::string(buf, data.size()), data);
}

// Test that opening a symlink with O_NOFOLLOW for writing fails.
TEST_F(WriteTest, WriteToSymlinkNoFollow) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string link_path = NewTempAbsPath();
  ASSERT_THAT(symlink(tmpfile.path().c_str(), link_path.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([&link_path] { unlink(link_path.c_str()); });

  EXPECT_THAT(open(link_path.c_str(), O_WRONLY | O_NOFOLLOW),
              SyscallFailsWithErrno(ELOOP));
}

// Test writing to /dev/null succeeds and discards data.
TEST_F(WriteTest, WriteToDevNull) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_WRONLY));

  const std::string data = "this will be discarded";
  EXPECT_THAT(write(fd.get(), data.data(), data.size()),
              SyscallSucceedsWithValue(data.size()));
}

// Test writing to /dev/null with large buffer.
TEST_F(WriteTest, WriteLargeToDevNull) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_WRONLY));

  std::vector<char> large_buf(1024 * 1024, 'x');  // 1MB
  EXPECT_THAT(write(fd.get(), large_buf.data(), large_buf.size()),
              SyscallSucceedsWithValue(large_buf.size()));
}

// Test pwrite to /dev/null.
TEST_F(WriteTest, PwriteToDevNull) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_WRONLY));

  const std::string data = "pwrite to null";
  EXPECT_THAT(pwrite(fd.get(), data.data(), data.size(), 100),
              SyscallSucceedsWithValue(data.size()));
}

// Test writing to /dev/zero succeeds.
TEST_F(WriteTest, WriteToDevZero) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_WRONLY));

  const std::string data = "writing to zero";
  EXPECT_THAT(write(fd.get(), data.data(), data.size()),
              SyscallSucceedsWithValue(data.size()));
}

// Test that writev with zero-length iovec array returns 0.
TEST_F(WriteTest, WritevEmptyIovec) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  EXPECT_THAT(writev(fd.get(), nullptr, 0), SyscallSucceedsWithValue(0));
}

// Test that writev with iov_len=0 entries succeeds.
TEST_F(WriteTest, WritevZeroLengthEntries) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_WRONLY));

  char buf1[] = "hello";
  char buf2[] = "world";
  struct iovec iov[] = {
      {.iov_base = nullptr, .iov_len = 0},  // Zero-length entry
      {.iov_base = buf1, .iov_len = 5},
      {.iov_base = nullptr, .iov_len = 0},  // Another zero-length entry
      {.iov_base = buf2, .iov_len = 5},
  };

  EXPECT_THAT(writev(fd.get(), iov, ABSL_ARRAYSIZE(iov)),
              SyscallSucceedsWithValue(10));
}

// Test write extends file past EOF.
TEST_F(WriteTest, WriteExtendsPastEOF) {
  const std::string initial_data = "initial";
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), initial_data, TempPath::kDefaultFileMode));
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_RDWR));

  // Seek to end.
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END),
              SyscallSucceedsWithValue(initial_data.size()));

  // Write extends past EOF.
  const std::string additional = " plus more";
  EXPECT_THAT(write(fd.get(), additional.data(), additional.size()),
              SyscallSucceedsWithValue(additional.size()));

  // Verify the file size increased.
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size,
            static_cast<off_t>(initial_data.size() + additional.size()));
}

// Test pwrite at offset beyond EOF creates a hole.
TEST_F(WriteTest, PwriteBeyondEOFCreatesHole) {
  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_RDWR));

  const std::string data = "at offset 100";
  const off_t write_offset = 100;

  EXPECT_THAT(pwrite(fd.get(), data.data(), data.size(), write_offset),
              SyscallSucceedsWithValue(data.size()));

  // Verify file size.
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, static_cast<off_t>(write_offset + data.size()));

  // Read back and verify hole contains zeros.
  std::vector<char> buf(write_offset);
  EXPECT_THAT(pread(fd.get(), buf.data(), buf.size(), 0),
              SyscallSucceedsWithValue(buf.size()));
  EXPECT_EQ(buf, std::vector<char>(write_offset, '\0'));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
