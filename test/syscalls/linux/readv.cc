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
#include <limits.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/syscalls/linux/readv_common.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

class ReadvTest : public FileTest {
  void SetUp() override {
    FileTest::SetUp();

    ASSERT_THAT(write(test_file_fd_.get(), kReadvTestData, kReadvTestDataSize),
                SyscallSucceedsWithValue(kReadvTestDataSize));
    ASSERT_THAT(lseek(test_file_fd_.get(), 0, SEEK_SET),
                SyscallSucceedsWithValue(0));
    ASSERT_THAT(write(test_pipe_[1], kReadvTestData, kReadvTestDataSize),
                SyscallSucceedsWithValue(kReadvTestDataSize));
  }
};

TEST_F(ReadvTest, ReadOneBufferPerByte_File) {
  ReadOneBufferPerByte(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadOneBufferPerByte_Pipe) {
  ReadOneBufferPerByte(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadOneHalfAtATime_File) {
  ReadOneHalfAtATime(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadOneHalfAtATime_Pipe) {
  ReadOneHalfAtATime(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadAllOneBuffer_File) {
  ReadAllOneBuffer(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadAllOneBuffer_Pipe) { ReadAllOneBuffer(test_pipe_[0]); }

TEST_F(ReadvTest, ReadAllOneLargeBuffer_File) {
  ReadAllOneLargeBuffer(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadAllOneLargeBuffer_Pipe) {
  ReadAllOneLargeBuffer(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadBuffersOverlapping_File) {
  ReadBuffersOverlapping(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadBuffersOverlapping_Pipe) {
  ReadBuffersOverlapping(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadBuffersDiscontinuous_File) {
  ReadBuffersDiscontinuous(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadBuffersDiscontinuous_Pipe) {
  ReadBuffersDiscontinuous(test_pipe_[0]);
}

TEST_F(ReadvTest, ReadIovecsCompletelyFilled_File) {
  ReadIovecsCompletelyFilled(test_file_fd_.get());
}

TEST_F(ReadvTest, ReadIovecsCompletelyFilled_Pipe) {
  ReadIovecsCompletelyFilled(test_pipe_[0]);
}

TEST_F(ReadvTest, BadFileDescriptor) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  ASSERT_THAT(readv(-1, iov, 1), SyscallFailsWithErrno(EBADF));
}
TEST_F(ReadvTest, BadIovecsPointer_File) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
  ASSERT_THAT(readv(test_file_fd_.get(), nullptr, 1),
              SyscallFailsWithErrno(EFAULT));
#pragma GCC diagnostic pop
}

TEST_F(ReadvTest, BadIovecsPointer_Pipe) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
  ASSERT_THAT(readv(test_pipe_[0], nullptr, 1), SyscallFailsWithErrno(EFAULT));
#pragma GCC diagnostic pop
}

TEST_F(ReadvTest, BadIovecBase_File) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, BadIovecBase_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, IovecImportRejectsInvalidLengthBeforeLaterMetadataFault) {
  constexpr int kCount = 1024;
  const size_t invalid_length = std::numeric_limits<size_t>::max();
  const struct {
    const char* name;
    size_t first_length;
    bool protect_metadata;
    int error;
  } cases[] = {
      {"readable-invalid-length", invalid_length, false, EINVAL},
      {"metadata-fault", 1, true, EFAULT},
      {"invalid-length-and-metadata-fault", invalid_length, true, EINVAL},
  };
  for (const auto& tc : cases) {
    SCOPED_TRACE(tc.name);
    // The second placement puts the next entry across the page boundary.
    for (size_t gap : {sizeof(iovec), sizeof(iovec) + sizeof(uint64_t)}) {
      SCOPED_TRACE(gap);
      std::vector<char> dst(32, '#');
      const auto before = dst;
      const Mapping metadata = ASSERT_NO_ERRNO_AND_VALUE(
          MmapAnon(kPageSize + kCount * sizeof(iovec), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE));
      auto* next_page = static_cast<char*>(metadata.ptr()) + kPageSize;
      auto* iov = reinterpret_cast<iovec*>(next_page - gap);
      std::fill_n(iov, kCount, iovec{});
      iov[0] = {dst.data(), tc.first_length};
      if (tc.protect_metadata) {
        ASSERT_THAT(mprotect(next_page, kPageSize, PROT_NONE),
                    SyscallSucceeds());
      }
      ASSERT_THAT(lseek(test_file_fd_.get(), 1, SEEK_SET),
                  SyscallSucceedsWithValue(1));
      EXPECT_THAT(syscall(SYS_readv, test_file_fd_.get(), iov, kCount),
                  SyscallFailsWithErrno(tc.error));
      EXPECT_EQ(dst, before);
      EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
                  SyscallSucceedsWithValue(1));
    }
  }
}

TEST_F(ReadvTest, IovecImportAcrossUnalignedMetadataPages) {
  constexpr int kCount = 1024;
  for (bool protect_metadata : {false, true}) {
    SCOPED_TRACE(protect_metadata);
    std::vector<char> dst(32, '#');
    const auto before = dst;
    const Mapping metadata = ASSERT_NO_ERRNO_AND_VALUE(
        MmapAnon(kPageSize + kCount * sizeof(iovec), PROT_READ | PROT_WRITE,
                 MAP_PRIVATE));
    auto* next_page = static_cast<char*>(metadata.ptr()) + kPageSize;
    auto* iov = next_page - 7;
    std::vector<iovec> entries(kCount);
    entries.front() = {dst.data(), 1};
    entries.back() = {dst.data() + 1, 1};
    std::memcpy(iov, entries.data(), entries.size() * sizeof(iovec));
    if (protect_metadata) {
      ASSERT_THAT(mprotect(next_page, kPageSize, PROT_NONE), SyscallSucceeds());
    }
    ASSERT_THAT(lseek(test_file_fd_.get(), 0, SEEK_SET),
                SyscallSucceedsWithValue(0));
    if (protect_metadata) {
      EXPECT_THAT(syscall(SYS_readv, test_file_fd_.get(), iov, kCount),
                  SyscallFailsWithErrno(EFAULT));
      EXPECT_EQ(dst, before);
      EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
                  SyscallSucceedsWithValue(0));
    } else {
      EXPECT_THAT(syscall(SYS_readv, test_file_fd_.get(), iov, kCount),
                  SyscallSucceedsWithValue(2));
      auto expected = before;
      expected[0] = kReadvTestData[0];
      expected[1] = kReadvTestData[1];
      EXPECT_EQ(dst, expected);
      EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
                  SyscallSucceedsWithValue(2));
    }
  }
}

TEST_F(ReadvTest, IovecImportValidatesLengthBeyondMaxReadCount) {
  std::vector<char> dst(kReadvTestDataSize, '#');
  const auto before = dst;
  iovec entries[] = {
      {dst.data(), static_cast<size_t>(INT_MAX & ~(kPageSize - 1))},
      {dst.data(), std::numeric_limits<size_t>::max()},
  };
  EXPECT_THAT(syscall(SYS_readv, test_file_fd_.get(), entries, 2),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_EQ(dst, before);
  EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(0));
}

TEST_F(ReadvTest, IovecImportRejectsInvalidLengthWithoutTouchingLaterMetadata) {
  const int raw_uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (raw_uffd < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
    GTEST_SKIP() << "userfaultfd kernel-fault handling unavailable: "
                 << std::strerror(errno);
  }
  ASSERT_THAT(raw_uffd, SyscallSucceeds());
  const FileDescriptor uffd(raw_uffd);
  uffdio_api api = {};
  api.api = UFFD_API;
  ASSERT_THAT(ioctl(uffd.get(), UFFDIO_API, &api), SyscallSucceeds());
  constexpr int kCount = 1024;
  for (bool invalid_length : {false, true}) {
    SCOPED_TRACE(invalid_length ? "invalid-first" : "valid-first");
    std::vector<char> dst(32, '#');
    const auto before = dst;
    const Mapping metadata = ASSERT_NO_ERRNO_AND_VALUE(
        MmapAnon(kPageSize + kCount * sizeof(iovec), PROT_READ | PROT_WRITE,
                 MAP_PRIVATE));
    auto* next_page = static_cast<char*>(metadata.ptr()) + kPageSize;
    auto* iov = reinterpret_cast<iovec*>(next_page - sizeof(iovec));
    std::fill_n(iov, kCount, iovec{});
    iov[0] = {dst.data(),
              invalid_length ? std::numeric_limits<size_t>::max() : 1};
    uffdio_register registration = {};
    registration.range.start = reinterpret_cast<uintptr_t>(next_page);
    registration.range.len = kPageSize;
    registration.mode = UFFDIO_REGISTER_MODE_MISSING;
    ASSERT_THAT(ioctl(uffd.get(), UFFDIO_REGISTER, &registration),
                SyscallSucceeds());
    ASSERT_THAT(madvise(next_page, kPageSize, MADV_DONTNEED),
                SyscallSucceeds());
    ASSERT_THAT(lseek(test_file_fd_.get(), 1, SEEK_SET),
                SyscallSucceedsWithValue(1));
    const FileDescriptor completion(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(completion.get(), 0);
    long result = 0;
    int read_errno = 0;
    ScopedThread reader([&] {
      result = syscall(SYS_readv, test_file_fd_.get(), iov, kCount);
      read_errno = errno;
      const uint64_t done = 1;
      EXPECT_THAT(write(completion.get(), &done, sizeof(done)),
                  SyscallSucceedsWithValue(sizeof(done)));
    });
    // Unregister before joining on assertion failure to release a faulting
    // reader.
    Cleanup unregister([&] {
      EXPECT_THAT(ioctl(uffd.get(), UFFDIO_UNREGISTER, &registration.range),
                  SyscallSucceeds());
    });
    pollfd events[] = {{uffd.get(), POLLIN, 0}, {completion.get(), POLLIN, 0}};
    ASSERT_THAT(RetryEINTR(poll)(events, 2, 10000),
                SyscallSucceedsWithValue(1));
    if (invalid_length) {
      EXPECT_EQ(events[0].revents, 0);
      ASSERT_EQ(events[1].revents, POLLIN);
    } else {
      ASSERT_EQ(events[0].revents, POLLIN);
      EXPECT_EQ(events[1].revents, 0);
      uffd_msg message = {};
      ASSERT_THAT(read(uffd.get(), &message, sizeof(message)),
                  SyscallSucceedsWithValue(sizeof(message)));
      EXPECT_EQ(message.event, UFFD_EVENT_PAGEFAULT);
      EXPECT_EQ(message.arg.pagefault.address & ~(kPageSize - 1),
                reinterpret_cast<uintptr_t>(next_page));
      uffdio_zeropage zero = {};
      zero.range = registration.range;
      ASSERT_THAT(ioctl(uffd.get(), UFFDIO_ZEROPAGE, &zero), SyscallSucceeds());
    }
    reader.Join();
    if (invalid_length) {
      EXPECT_EQ(result, -1);
      EXPECT_EQ(read_errno, EINVAL);
      EXPECT_EQ(dst, before);
      EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
                  SyscallSucceedsWithValue(1));
    } else {
      EXPECT_EQ(result, 1);
      auto expected = before;
      expected[0] = kReadvTestData[1];
      EXPECT_EQ(dst, expected);
      EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
                  SyscallSucceedsWithValue(2));
    }
  }
}

TEST_F(ReadvTest, ZeroIovecs_File) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1), SyscallSucceeds());
}

TEST_F(ReadvTest, ZeroIovecs_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallSucceeds());
}

TEST_F(ReadvTest, NotReadable_File) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  std::string wronly_file = NewTempAbsPath();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(wronly_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR));
  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EBADF));
  fd.reset();  // Close before unlinking.
  ASSERT_THAT(unlink(wronly_file.c_str()), SyscallSucceeds());
}

TEST_F(ReadvTest, NotReadable_Pipe) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_pipe_[1], iov, 1), SyscallFailsWithErrno(EBADF));
}

TEST_F(ReadvTest, DirNotReadable) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), O_RDONLY));
  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EISDIR));
}

TEST_F(ReadvTest, OffsetIncremented) {
  char* buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;

  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  ASSERT_THAT(lseek(test_file_fd_.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kReadvTestDataSize));

  free(buffer);
}

TEST_F(ReadvTest, EndOfFile) {
  char* buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(buffer);

  buffer = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_base = buffer;
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 1), SyscallSucceedsWithValue(0));
  free(buffer);
}

TEST_F(ReadvTest, WouldBlock_Pipe) {
  struct iovec iov[1];
  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(iov[0].iov_base);

  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallFailsWithErrno(EAGAIN));
  free(iov[0].iov_base);
}

TEST_F(ReadvTest, ZeroBuffer) {
  char buf[10];
  struct iovec iov[1];
  iov[0].iov_base = buf;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_pipe_[0], iov, 1), SyscallSucceedsWithValue(0));
}

TEST_F(ReadvTest, NullIovecInNonemptyArray) {
  std::vector<char> buf(kReadvTestDataSize);
  struct iovec iov[2];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 0;
  iov[1].iov_base = buf.data();
  iov[1].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 2),
              SyscallSucceedsWithValue(kReadvTestDataSize));
}

TEST_F(ReadvTest, IovecOutsideTaskAddressRangeInNonemptyArray) {
  std::vector<char> buf(kReadvTestDataSize);
  struct iovec iov[2];
  iov[0].iov_base = reinterpret_cast<void*>(~static_cast<uintptr_t>(0));
  iov[0].iov_len = 0;
  iov[1].iov_base = buf.data();
  iov[1].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_file_fd_.get(), iov, 2),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvTest, ReadvWithOpath) {
  char buffer[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = 1024;

  TempPath tmpfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tmpfile.path().c_str(), O_PATH));

  ASSERT_THAT(readv(fd.get(), iov, 1), SyscallFailsWithErrno(EBADF));
}

// This test depends on the maximum extent of a single readv() syscall, so
// we can't tolerate interruption from saving.
TEST(ReadvTestNoFixture, TruncatedAtMax) {
  // Ensure that we won't be interrupted by ITIMER_PROF. This is particularly
  // important in environments where automated profiling tools may start
  // ITIMER_PROF automatically.
  struct itimerval itv = {};
  auto const cleanup_itimer =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedItimer(ITIMER_PROF, itv));

  // From Linux's include/linux/fs.h.
  size_t const MAX_RW_COUNT = INT_MAX & ~(kPageSize - 1);

  // Create an iovec array with 3 segments pointing to consecutive parts of a
  // buffer. The first covers all but the last three pages, and should be
  // written to in its entirety. The second covers the last page before
  // MAX_RW_COUNT and the first page after; only the first page should be
  // written to. The third covers the last page of the buffer, and should be
  // skipped entirely.
  size_t const kBufferSize = MAX_RW_COUNT + 2 * kPageSize;
  size_t const kFirstOffset = MAX_RW_COUNT - kPageSize;
  size_t const kSecondOffset = MAX_RW_COUNT + kPageSize;
  // The buffer is too big to fit on the stack.
  std::vector<char> buf(kBufferSize);
  struct iovec iov[3];
  iov[0].iov_base = buf.data();
  iov[0].iov_len = kFirstOffset;
  iov[1].iov_base = buf.data() + kFirstOffset;
  iov[1].iov_len = kSecondOffset - kFirstOffset;
  iov[2].iov_base = buf.data() + kSecondOffset;
  iov[2].iov_len = kBufferSize - kSecondOffset;

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));
  EXPECT_THAT(readv(fd.get(), iov, 3), SyscallSucceedsWithValue(MAX_RW_COUNT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
