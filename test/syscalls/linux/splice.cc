// Copyright 2019 The gVisor Authors.
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
#include <linux/unistd.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SpliceTest, TwoRegularFiles) {
  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor out_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Verify that it is rejected as expected; regardless of offsets.
  loff_t in_offset = 0;
  loff_t out_offset = 0;
  EXPECT_THAT(splice(in_fd.get(), &in_offset, out_fd.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(in_fd.get(), nullptr, out_fd.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(in_fd.get(), &in_offset, out_fd.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(in_fd.get(), nullptr, out_fd.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
}

int memfd_create(const std::string& name, unsigned int flags) {
  return syscall(__NR_memfd_create, name.c_str(), flags);
}

TEST(SpliceTest, NegativeOffset) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill the pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Open the output file as write only.
  int fd;
  EXPECT_THAT(fd = memfd_create("negative", 0), SyscallSucceeds());
  const FileDescriptor out_fd(fd);

  loff_t out_offset = 0xffffffffffffffffull;
  constexpr int kSize = 2;
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), &out_offset, kSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Write offset + size overflows int64.
//
// This is a regression test for b/148041624.
TEST(SpliceTest, WriteOverflow) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill the pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Open the output file.
  int fd;
  EXPECT_THAT(fd = memfd_create("overflow", 0), SyscallSucceeds());
  const FileDescriptor out_fd(fd);

  // out_offset + kSize overflows INT64_MAX.
  loff_t out_offset = 0x7ffffffffffffffeull;
  constexpr int kSize = 3;
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), &out_offset, kSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SpliceTest, SamePipe) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill the pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Attempt to splice to itself.
  EXPECT_THAT(splice(rfd.get(), nullptr, wfd.get(), nullptr, kPageSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(TeeTest, SamePipe) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill the pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Attempt to tee to itself.
  EXPECT_THAT(tee(rfd.get(), wfd.get(), kPageSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(TeeTest, RegularFile) {
  // Open some file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Attempt to tee from the file.
  EXPECT_THAT(tee(in_fd.get(), wfd.get(), kPageSize, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(tee(rfd.get(), in_fd.get(), kPageSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SpliceTest, PipeOffsets) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // All pipe offsets should be rejected.
  loff_t in_offset = 0;
  loff_t out_offset = 0;
  EXPECT_THAT(splice(rfd1.get(), &in_offset, wfd2.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(splice(rfd1.get(), nullptr, wfd2.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(ESPIPE));
  EXPECT_THAT(splice(rfd1.get(), &in_offset, wfd2.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(ESPIPE));
}

// Event FDs may be used with splice without an offset.
TEST(SpliceTest, FromEventFD) {
  // Open the input eventfd with an initial value so that it is readable.
  constexpr uint64_t kEventFDValue = 1;
  int efd;
  ASSERT_THAT(efd = eventfd(kEventFDValue, 0), SyscallSucceeds());
  const FileDescriptor in_fd(efd);

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice 8-byte eventfd value to pipe.
  constexpr int kEventFDSize = 8;
  EXPECT_THAT(splice(in_fd.get(), nullptr, wfd.get(), nullptr, kEventFDSize, 0),
              SyscallSucceedsWithValue(kEventFDSize));

  // Contents should be equal.
  std::vector<char> rbuf(kEventFDSize);
  ASSERT_THAT(read(rfd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kEventFDSize));
  EXPECT_EQ(memcmp(rbuf.data(), &kEventFDValue, rbuf.size()), 0);
}

// Event FDs may not be used with splice with an offset.
TEST(SpliceTest, FromEventFDOffset) {
  int efd;
  ASSERT_THAT(efd = eventfd(0, 0), SyscallSucceeds());
  const FileDescriptor in_fd(efd);

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Attempt to splice 8-byte eventfd value to pipe with offset.
  //
  // This is not allowed because eventfd doesn't support pread.
  constexpr int kEventFDSize = 8;
  loff_t in_off = 0;
  EXPECT_THAT(splice(in_fd.get(), &in_off, wfd.get(), nullptr, kEventFDSize, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Event FDs may not be used with splice with an offset.
TEST(SpliceTest, ToEventFDOffset) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill with a value.
  constexpr int kEventFDSize = 8;
  std::vector<char> buf(kEventFDSize);
  buf[0] = 1;
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kEventFDSize));

  int efd;
  ASSERT_THAT(efd = eventfd(0, 0), SyscallSucceeds());
  const FileDescriptor out_fd(efd);

  // Attempt to splice 8-byte eventfd value to pipe with offset.
  //
  // This is not allowed because eventfd doesn't support pwrite.
  loff_t out_off = 0;
  EXPECT_THAT(
      splice(rfd.get(), nullptr, out_fd.get(), &out_off, kEventFDSize, 0),
      SyscallFailsWithErrno(EINVAL));
}

TEST(SpliceTest, ToPipe) {
  // Open the input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(in_fd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(lseek(in_fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice to the pipe.
  EXPECT_THAT(splice(in_fd.get(), nullptr, wfd.get(), nullptr, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Contents should be equal.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), buf.size()), 0);
}

TEST(SpliceTest, ToPipeEOF) {
  // Create and open an empty input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice from the empty file to the pipe.
  EXPECT_THAT(splice(in_fd.get(), nullptr, wfd.get(), nullptr, 123, 0),
              SyscallSucceedsWithValue(0));
}

TEST(SpliceTest, ToPipeOffset) {
  // Open the input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(in_fd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice to the pipe.
  loff_t in_offset = kPageSize / 2;
  EXPECT_THAT(
      splice(in_fd.get(), &in_offset, wfd.get(), nullptr, kPageSize / 2, 0),
      SyscallSucceedsWithValue(kPageSize / 2));

  // Contents should be equal to only the second part.
  std::vector<char> rbuf(kPageSize / 2);
  ASSERT_THAT(read(rfd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize / 2));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data() + (kPageSize / 2), rbuf.size()), 0);
}

TEST(SpliceTest, FromPipe) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Open the output file.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor out_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Splice to the output file.
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), nullptr, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // The offset of the output should be equal to kPageSize. We assert that and
  // reset to zero so that we can read the contents and ensure they match.
  EXPECT_THAT(lseek(out_fd.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(lseek(out_fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Contents should be equal.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(out_fd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), buf.size()), 0);
}

TEST(SpliceTest, FromPipeMultiple) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  std::string buf = "abcABC123";
  ASSERT_THAT(write(wfd.get(), buf.c_str(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Open the output file.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor out_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Splice from the pipe to the output file over several calls.
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), nullptr, 3, 0),
              SyscallSucceedsWithValue(3));
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), nullptr, 3, 0),
              SyscallSucceedsWithValue(3));
  EXPECT_THAT(splice(rfd.get(), nullptr, out_fd.get(), nullptr, 3, 0),
              SyscallSucceedsWithValue(3));

  // Reset cursor to zero so that we can check the contents.
  ASSERT_THAT(lseek(out_fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Contents should be equal.
  std::vector<char> rbuf(buf.size());
  ASSERT_THAT(read(out_fd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(rbuf.size()));
  EXPECT_EQ(memcmp(rbuf.data(), buf.c_str(), buf.size()), 0);
}

TEST(SpliceTest, FromPipeOffset) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Open the input file.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor out_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Splice to the output file.
  loff_t out_offset = kPageSize / 2;
  EXPECT_THAT(
      splice(rfd.get(), nullptr, out_fd.get(), &out_offset, kPageSize, 0),
      SyscallSucceedsWithValue(kPageSize));

  // Content should reflect the splice. We write to a specific offset in the
  // file, so the internals should now be allocated sparsely.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(out_fd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  std::vector<char> zbuf(kPageSize / 2);
  memset(zbuf.data(), 0, zbuf.size());
  EXPECT_EQ(memcmp(rbuf.data(), zbuf.data(), zbuf.size()), 0);
  EXPECT_EQ(memcmp(rbuf.data() + kPageSize / 2, buf.data(), kPageSize / 2), 0);
}

TEST(SpliceTest, TwoPipes) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd1.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Splice to the second pipe, using two operations.
  EXPECT_THAT(
      splice(rfd1.get(), nullptr, wfd2.get(), nullptr, kPageSize / 2, 0),
      SyscallSucceedsWithValue(kPageSize / 2));
  EXPECT_THAT(
      splice(rfd1.get(), nullptr, wfd2.get(), nullptr, kPageSize / 2, 0),
      SyscallSucceedsWithValue(kPageSize / 2));

  // Content should reflect the splice.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd2.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), kPageSize), 0);
}

TEST(SpliceTest, TwoPipesPartialRead) {
  // Create two pipes.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor first_rfd(fds[0]);
  const FileDescriptor first_wfd(fds[1]);
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor second_rfd(fds[0]);
  const FileDescriptor second_wfd(fds[1]);

  // Write half a page of data to the first pipe.
  std::vector<char> buf(kPageSize / 2);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(first_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize / 2));

  // Attempt to splice one page from the first pipe to the second; it should
  // immediately return after splicing the half-page previously written to the
  // first pipe.
  EXPECT_THAT(
      splice(first_rfd.get(), nullptr, second_wfd.get(), nullptr, kPageSize, 0),
      SyscallSucceedsWithValue(kPageSize / 2));
}

TEST(SpliceTest, TwoPipesPartialWrite) {
  // Create two pipes.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor first_rfd(fds[0]);
  const FileDescriptor first_wfd(fds[1]);
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor second_rfd(fds[0]);
  const FileDescriptor second_wfd(fds[1]);

  // Write two pages of data to the first pipe.
  std::vector<char> buf(2 * kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(first_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(2 * kPageSize));

  // Limit the second pipe to two pages, then write one page of data to it.
  ASSERT_THAT(fcntl(second_wfd.get(), F_SETPIPE_SZ, 2 * kPageSize),
              SyscallSucceeds());
  ASSERT_THAT(write(second_wfd.get(), buf.data(), buf.size() / 2),
              SyscallSucceedsWithValue(kPageSize));

  // Attempt to splice two pages from the first pipe to the second; it should
  // immediately return after splicing the first page previously written to the
  // first pipe.
  EXPECT_THAT(splice(first_rfd.get(), nullptr, second_wfd.get(), nullptr,
                     2 * kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));
}

TEST(TeeTest, TwoPipesPartialRead) {
  // Create two pipes.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor first_rfd(fds[0]);
  const FileDescriptor first_wfd(fds[1]);
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor second_rfd(fds[0]);
  const FileDescriptor second_wfd(fds[1]);

  // Write half a page of data to the first pipe.
  std::vector<char> buf(kPageSize / 2);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(first_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize / 2));

  // Attempt to tee one page from the first pipe to the second; it should
  // immediately return after copying the half-page previously written to the
  // first pipe.
  EXPECT_THAT(tee(first_rfd.get(), second_wfd.get(), kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize / 2));
}

TEST(TeeTest, TwoPipesPartialWrite) {
  // Create two pipes.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor first_rfd(fds[0]);
  const FileDescriptor first_wfd(fds[1]);
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor second_rfd(fds[0]);
  const FileDescriptor second_wfd(fds[1]);

  // Write two pages of data to the first pipe.
  std::vector<char> buf(2 * kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(first_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(2 * kPageSize));

  // Limit the second pipe to two pages, then write one page of data to it.
  ASSERT_THAT(fcntl(second_wfd.get(), F_SETPIPE_SZ, 2 * kPageSize),
              SyscallSucceeds());
  ASSERT_THAT(write(second_wfd.get(), buf.data(), buf.size() / 2),
              SyscallSucceedsWithValue(kPageSize));

  // Attempt to tee two pages from the first pipe to the second; it should
  // immediately return after copying the first page previously written to the
  // first pipe.
  EXPECT_THAT(tee(first_rfd.get(), second_wfd.get(), 2 * kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));
}

TEST(SpliceTest, TwoPipesCircular) {
  // This test deadlocks the sentry on VFS1 because VFS1 splice ordering is
  // based on fs.File.UniqueID, which does not prevent circular ordering between
  // e.g. inode-level locks taken by fs.FileOperations.
  SKIP_IF(IsRunningWithVFS1());

  // Create two pipes.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor first_rfd(fds[0]);
  const FileDescriptor first_wfd(fds[1]);
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor second_rfd(fds[0]);
  const FileDescriptor second_wfd(fds[1]);

  // On Linux, each pipe is normally limited to
  // include/linux/pipe_fs_i.h:PIPE_DEF_BUFFERS buffers worth of data.
  constexpr size_t PIPE_DEF_BUFFERS = 16;

  // Write some data to each pipe. Below we splice 1 byte at a time between
  // pipes, which very quickly causes each byte to be stored in a separate
  // buffer, so we must ensure that the total amount of data in the system is <=
  // PIPE_DEF_BUFFERS bytes.
  std::vector<char> buf(PIPE_DEF_BUFFERS / 2);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(first_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  ASSERT_THAT(write(second_wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Have another thread splice from the second pipe to the first, while we
  // splice from the first to the second. The test passes if this does not
  // deadlock.
  const int kIterations = 1000;
  DisableSave ds;
  ScopedThread t([&]() {
    for (int i = 0; i < kIterations; i++) {
      ASSERT_THAT(
          splice(second_rfd.get(), nullptr, first_wfd.get(), nullptr, 1, 0),
          SyscallSucceedsWithValue(1));
    }
  });
  for (int i = 0; i < kIterations; i++) {
    ASSERT_THAT(
        splice(first_rfd.get(), nullptr, second_wfd.get(), nullptr, 1, 0),
        SyscallSucceedsWithValue(1));
  }
}

TEST(SpliceTest, Blocking) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // This thread writes to the main pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ScopedThread t([&]() {
    ASSERT_THAT(write(wfd1.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(kPageSize));
  });

  // Attempt a splice immediately; it should block.
  EXPECT_THAT(splice(rfd1.get(), nullptr, wfd2.get(), nullptr, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Thread should be joinable.
  t.Join();

  // Content should reflect the splice.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd2.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), kPageSize), 0);
}

TEST(TeeTest, Blocking) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // This thread writes to the main pipe.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ScopedThread t([&]() {
    ASSERT_THAT(write(wfd1.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(kPageSize));
  });

  // Attempt a tee immediately; it should block.
  EXPECT_THAT(tee(rfd1.get(), wfd2.get(), kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Thread should be joinable.
  t.Join();

  // Content should reflect the splice, in both pipes.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd2.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), kPageSize), 0);
  ASSERT_THAT(read(rfd1.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), kPageSize), 0);
}

TEST(TeeTest, BlockingWrite) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // Make some data available to be read.
  std::vector<char> buf1(kPageSize);
  RandomizeBuffer(buf1.data(), buf1.size());
  ASSERT_THAT(write(wfd1.get(), buf1.data(), buf1.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Fill up the write pipe's buffer.
  int pipe_size = -1;
  ASSERT_THAT(pipe_size = fcntl(wfd2.get(), F_GETPIPE_SZ), SyscallSucceeds());
  std::vector<char> buf2(pipe_size);
  ASSERT_THAT(write(wfd2.get(), buf2.data(), buf2.size()),
              SyscallSucceedsWithValue(pipe_size));

  ScopedThread t([&]() {
    absl::SleepFor(absl::Milliseconds(100));
    ASSERT_THAT(read(rfd2.get(), buf2.data(), buf2.size()),
                SyscallSucceedsWithValue(pipe_size));
  });

  // Attempt a tee immediately; it should block.
  EXPECT_THAT(tee(rfd1.get(), wfd2.get(), kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Thread should be joinable.
  t.Join();

  // Content should reflect the tee.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd2.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf1.data(), kPageSize), 0);
}

TEST(SpliceTest, NonBlocking) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // Splice with no data to back it.
  EXPECT_THAT(splice(rfd1.get(), nullptr, wfd2.get(), nullptr, kPageSize,
                     SPLICE_F_NONBLOCK),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(TeeTest, NonBlocking) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // Splice with no data to back it.
  EXPECT_THAT(tee(rfd1.get(), wfd2.get(), kPageSize, SPLICE_F_NONBLOCK),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(TeeTest, MultiPage) {
  // Create two new pipes.
  int first[2], second[2];
  ASSERT_THAT(pipe(first), SyscallSucceeds());
  const FileDescriptor rfd1(first[0]);
  const FileDescriptor wfd1(first[1]);
  ASSERT_THAT(pipe(second), SyscallSucceeds());
  const FileDescriptor rfd2(second[0]);
  const FileDescriptor wfd2(second[1]);

  // Make some data available to be read.
  std::vector<char> wbuf(8 * kPageSize);
  RandomizeBuffer(wbuf.data(), wbuf.size());
  ASSERT_THAT(write(wfd1.get(), wbuf.data(), wbuf.size()),
              SyscallSucceedsWithValue(wbuf.size()));

  // Attempt a tee immediately; it should complete.
  EXPECT_THAT(tee(rfd1.get(), wfd2.get(), wbuf.size(), 0),
              SyscallSucceedsWithValue(wbuf.size()));

  // Content should reflect the tee.
  std::vector<char> rbuf(wbuf.size());
  ASSERT_THAT(read(rfd2.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(rbuf.size()));
  EXPECT_EQ(memcmp(rbuf.data(), wbuf.data(), rbuf.size()), 0);
  ASSERT_THAT(read(rfd1.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(rbuf.size()));
  EXPECT_EQ(memcmp(rbuf.data(), wbuf.data(), rbuf.size()), 0);
}

TEST(SpliceTest, FromPipeMaxFileSize) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Open the input file.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor out_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  EXPECT_THAT(ftruncate(out_fd.get(), 13 << 20), SyscallSucceeds());
  EXPECT_THAT(lseek(out_fd.get(), 0, SEEK_END),
              SyscallSucceedsWithValue(13 << 20));

  // Set our file size limit.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGXFSZ);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);
  rlimit rlim = {};
  rlim.rlim_cur = rlim.rlim_max = (13 << 20);
  EXPECT_THAT(setrlimit(RLIMIT_FSIZE, &rlim), SyscallSucceeds());

  // Splice to the output file.
  EXPECT_THAT(
      splice(rfd.get(), nullptr, out_fd.get(), nullptr, 3 * kPageSize, 0),
      SyscallFailsWithErrno(EFBIG));

  // Contents should be equal.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), buf.size()), 0);
}

TEST(SpliceTest, FromPipeToDevZero) {
  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  const FileDescriptor zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_WRONLY));

  // Close the write end to prevent blocking below.
  wfd.reset();

  // Splice to /dev/zero. The first call should empty the pipe, and the return
  // value should not exceed the number of bytes available for reading.
  EXPECT_THAT(
      splice(rfd.get(), nullptr, zero.get(), nullptr, kPageSize + 123, 0),
      SyscallSucceedsWithValue(kPageSize));
  EXPECT_THAT(splice(rfd.get(), nullptr, zero.get(), nullptr, 1, 0),
              SyscallSucceedsWithValue(0));
}

static volatile int signaled = 0;
void SigUsr1Handler(int sig, siginfo_t* info, void* context) { signaled = 1; }

TEST(SpliceTest, ToPipeWithSmallCapacityDoesNotSpin_NoRandomSave) {
  // Writes to a pipe that are less than PIPE_BUF must be atomic. This test
  // creates a pipe with only 128 bytes of capacity (< PIPE_BUF) and checks that
  // splicing to the pipe does not spin. See b/170743336.

  // Create a file with one page of data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(buf.data(), buf.size()),
      TempPath::kDefaultFileMode));
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  // Create a pipe with size 4096, and fill all but 128 bytes of it.
  int p[2];
  ASSERT_THAT(pipe(p), SyscallSucceeds());
  ASSERT_THAT(fcntl(p[1], F_SETPIPE_SZ, kPageSize), SyscallSucceeds());
  const int kWriteSize = kPageSize - 128;
  std::vector<char> writeBuf(kWriteSize);
  RandomizeBuffer(writeBuf.data(), writeBuf.size());
  ASSERT_THAT(write(p[1], writeBuf.data(), writeBuf.size()),
              SyscallSucceedsWithValue(kWriteSize));

  // Set up signal handler.
  struct sigaction sa = {};
  sa.sa_sigaction = SigUsr1Handler;
  sa.sa_flags = SA_SIGINFO;
  const auto cleanup_sigact =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  // Send SIGUSR1 to this thread in 1 second.
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = SIGUSR1;
  sev.sigev_notify_thread_id = gettid();
  auto timer = ASSERT_NO_ERRNO_AND_VALUE(TimerCreate(CLOCK_MONOTONIC, sev));
  struct itimerspec its = {};
  its.it_value = absl::ToTimespec(absl::Seconds(1));
  DisableSave ds;  // Asserting an EINTR.
  ASSERT_NO_ERRNO(timer.Set(0, its));

  // Now splice the file to the pipe. This should block, but not spin, and
  // should return EINTR because it is interrupted by the signal.
  EXPECT_THAT(splice(fd.get(), nullptr, p[1], nullptr, kPageSize, 0),
              SyscallFailsWithErrno(EINTR));

  // Alarm should have been handled.
  EXPECT_EQ(signaled, 1);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
