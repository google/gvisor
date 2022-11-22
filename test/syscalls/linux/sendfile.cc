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
#include <linux/unistd.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SendFileTest, SendZeroBytes) {
  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct value.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, 0),
              SyscallSucceedsWithValue(0));
}

TEST(SendFileTest, InvalidOffset) {
  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct value.
  off_t offset = -1;
  EXPECT_THAT(sendfile(outf.get(), inf.get(), &offset, 0),
              SyscallFailsWithErrno(EINVAL));
}

int memfd_create(const std::string& name, unsigned int flags) {
  return syscall(__NR_memfd_create, name.c_str(), flags);
}

TEST(SendFileTest, Overflow) {
  // Create input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file.
  int fd;
  EXPECT_THAT(fd = memfd_create("overflow", 0), SyscallSucceeds());
  const FileDescriptor outf(fd);

  // out_offset + kSize overflows INT64_MAX.
  loff_t out_offset = 0x7ffffffffffffffeull;
  constexpr int kSize = 3;
  EXPECT_THAT(sendfile(outf.get(), inf.get(), &out_offset, kSize),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SendFileTest, SendTrivially) {
  // Create temp files.
  constexpr char kData[] = "To be, or not to be, that is the question:";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(bytes_sent = sendfile(outf.get(), inf.get(), nullptr, kDataSize),
              SyscallSucceedsWithValue(kDataSize));

  // Close outf to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kDataSize));
  EXPECT_EQ(kData, absl::string_view(actual, bytes_sent));
}

TEST(SendFileTest, SendTriviallyWithBothFilesReadWrite) {
  // Create temp files.
  constexpr char kData[] = "Whether 'tis nobler in the mind to suffer";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as readwrite.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Open the output file as readwrite.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(bytes_sent = sendfile(outf.get(), inf.get(), nullptr, kDataSize),
              SyscallSucceedsWithValue(kDataSize));

  // Close outf to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kDataSize));
  EXPECT_EQ(kData, absl::string_view(actual, bytes_sent));
}

TEST(SendFileTest, SendAndUpdateFileOffset) {
  // Create temp files.
  // Test input string length must be > 2 AND even.
  constexpr char kData[] = "The slings and arrows of outrageous fortune,";
  constexpr int kDataSize = sizeof(kData) - 1;
  constexpr int kHalfDataSize = kDataSize / 2;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(
      bytes_sent = sendfile(outf.get(), inf.get(), nullptr, kHalfDataSize),
      SyscallSucceedsWithValue(kHalfDataSize));

  // Close outf to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kHalfDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(absl::string_view(kData, kHalfDataSize),
            absl::string_view(actual, bytes_sent));

  // Verify that the input file offset has been updated.
  ASSERT_THAT(read(inf.get(), &actual, kDataSize - bytes_sent),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(
      absl::string_view(kData + kDataSize - bytes_sent, kDataSize - bytes_sent),
      absl::string_view(actual, kHalfDataSize));
}

TEST(SendFileTest, SendAndUpdateFileOffsetFromNonzeroStartingPoint) {
  // Create temp files.
  // Test input string length must be > 2 AND divisible by 4.
  constexpr char kData[] = "The slings and arrows of outrageous fortune,";
  constexpr int kDataSize = sizeof(kData) - 1;
  constexpr int kHalfDataSize = kDataSize / 2;
  constexpr int kQuarterDataSize = kHalfDataSize / 2;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Read a quarter of the data from the infile which should update the file
  // offset, we don't actually care about the data so it goes into the garbage.
  char garbage[kQuarterDataSize];
  ASSERT_THAT(read(inf.get(), &garbage, kQuarterDataSize),
              SyscallSucceedsWithValue(kQuarterDataSize));

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(
      bytes_sent = sendfile(outf.get(), inf.get(), nullptr, kHalfDataSize),
      SyscallSucceedsWithValue(kHalfDataSize));

  // Close out_fd to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kHalfDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(absl::string_view(kData + kQuarterDataSize, kHalfDataSize),
            absl::string_view(actual, bytes_sent));

  // Verify that the input file offset has been updated.
  ASSERT_THAT(read(inf.get(), &actual, kQuarterDataSize),
              SyscallSucceedsWithValue(kQuarterDataSize));

  EXPECT_EQ(
      absl::string_view(kData + kDataSize - kQuarterDataSize, kQuarterDataSize),
      absl::string_view(actual, kQuarterDataSize));
}

TEST(SendFileTest, SendAndUpdateGivenOffset) {
  // Create temp files.
  // Test input string length must be >= 4 AND divisible by 4.
  constexpr char kData[] = "Or to take Arms against a Sea of troubles,";
  constexpr int kDataSize = sizeof(kData) + 1;
  constexpr int kHalfDataSize = kDataSize / 2;
  constexpr int kQuarterDataSize = kHalfDataSize / 2;
  constexpr int kThreeFourthsDataSize = 3 * kDataSize / 4;

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Create offset for sending.
  off_t offset = kQuarterDataSize;

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(
      bytes_sent = sendfile(outf.get(), inf.get(), &offset, kHalfDataSize),
      SyscallSucceedsWithValue(kHalfDataSize));

  // Close out_fd to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kHalfDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(absl::string_view(kData + kQuarterDataSize, kHalfDataSize),
            absl::string_view(actual, bytes_sent));

  // Verify that the input file offset has NOT been updated.
  ASSERT_THAT(read(inf.get(), &actual, kHalfDataSize),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(absl::string_view(kData, kHalfDataSize),
            absl::string_view(actual, kHalfDataSize));

  // Verify that the offset pointer has been updated.
  EXPECT_EQ(offset, kThreeFourthsDataSize);
}

TEST(SendFileTest, DoNotSendfileIfOutfileIsAppendOnly) {
  // Create temp files.
  constexpr char kData[] = "And by opposing end them: to die, to sleep";
  constexpr int kDataSize = sizeof(kData) - 1;

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as append only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY | O_APPEND));

  // Send data and verify that sendfile returns the correct errno.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SendFileTest, AppendCheckOrdering) {
  constexpr char kData[] = "And by opposing end them: to die, to sleep";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));

  const FileDescriptor read =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));
  const FileDescriptor write =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));
  const FileDescriptor append =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_APPEND));

  // Check that read/write file mode is verified before append.
  EXPECT_THAT(sendfile(append.get(), read.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(sendfile(write.get(), write.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EBADF));
}

TEST(SendFileTest, DoNotSendfileIfOutfileIsNotWritable) {
  // Create temp files.
  constexpr char kData[] = "No more; and by a sleep, to say we end";
  constexpr int kDataSize = sizeof(kData) - 1;

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as read only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Send data and verify that sendfile returns the correct errno.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EBADF));
}

TEST(SendFileTest, DoNotSendfileIfInfileIsNotReadable) {
  // Create temp files.
  constexpr char kData[] = "the heart-ache, and the thousand natural shocks";
  constexpr int kDataSize = sizeof(kData) - 1;

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as write only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_WRONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct errno.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EBADF));
}

TEST(SendFileTest, DoNotSendANegativeNumberOfBytes) {
  // Create temp files.
  constexpr char kData[] = "that Flesh is heir to? 'Tis a consummation";

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct errno.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, -1),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SendFileTest, SendTheCorrectNumberOfBytesEvenIfWeTryToSendTooManyBytes) {
  // Create temp files.
  constexpr char kData[] = "devoutly to be wished. To die, to sleep,";
  constexpr int kDataSize = sizeof(kData) - 1;

  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  FileDescriptor outf;
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Send data and verify that sendfile returns the correct value.
  int bytes_sent;
  EXPECT_THAT(
      bytes_sent = sendfile(outf.get(), inf.get(), nullptr, kDataSize + 100),
      SyscallSucceedsWithValue(kDataSize));

  // Close outf to avoid leak.
  outf.reset();

  // Open the output file as read only.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));

  // Verify that the output file has the correct data.
  char actual[kDataSize];
  ASSERT_THAT(read(outf.get(), &actual, bytes_sent),
              SyscallSucceedsWithValue(kDataSize));
  EXPECT_EQ(kData, absl::string_view(actual, bytes_sent));
}

TEST(SendFileTest, SendToNotARegularFile) {
  // Make temp input directory and open as read only.
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY));

  // Make temp output file and open as write only.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Receive an error since a directory is not a regular file.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, 1),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SendFileTest, SendPipeWouldBlock) {
  // This test fails on Linux, likely due to a Linux bug.
  SKIP_IF(!IsRunningOnGvisor());
  // Create temp file.
  constexpr char kData[] =
      "The fool doth think he is wise, but the wise man knows himself to be a "
      "fool.";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Setup the output named pipe.
  int fds[2];
  ASSERT_THAT(pipe2(fds, O_NONBLOCK), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill up the pipe's buffer.
  int pipe_size = -1;
  ASSERT_THAT(pipe_size = fcntl(wfd.get(), F_GETPIPE_SZ), SyscallSucceeds());
  std::vector<char> buf(2 * pipe_size);
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(pipe_size));

  EXPECT_THAT(sendfile(wfd.get(), inf.get(), nullptr, kDataSize),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST(SendFileTest, SendPipeEOF) {
  // Create and open an empty input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Setup the output named pipe.
  int fds[2];
  ASSERT_THAT(pipe2(fds, O_NONBLOCK), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  EXPECT_THAT(sendfile(wfd.get(), inf.get(), nullptr, 123),
              SyscallSucceedsWithValue(0));
}

TEST(SendFileTest, SendToFullPipeReturnsEAGAIN) {
  // This test fails on Linux, likely due to a Linux bug.
  SKIP_IF(!IsRunningOnGvisor());
  // Create and open an empty input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Set up the output pipe.
  int fds[2];
  ASSERT_THAT(pipe2(fds, O_NONBLOCK), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  int pipe_size = -1;
  ASSERT_THAT(pipe_size = fcntl(wfd.get(), F_GETPIPE_SZ), SyscallSucceeds());
  int data_size = pipe_size * 8;
  ASSERT_THAT(ftruncate(in_fd.get(), data_size), SyscallSucceeds());

  ASSERT_THAT(sendfile(wfd.get(), in_fd.get(), 0, data_size),
              SyscallSucceeds());
  EXPECT_THAT(sendfile(wfd.get(), in_fd.get(), 0, data_size),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(SendFileTest, SendPipeBlocks) {
  // Create temp file.
  constexpr char kData[] =
      "The fault, dear Brutus, is not in our stars, but in ourselves.";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Setup the output named pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Fill up the pipe's buffer.
  int pipe_size = -1;
  ASSERT_THAT(pipe_size = fcntl(wfd.get(), F_GETPIPE_SZ), SyscallSucceeds());
  std::vector<char> buf(pipe_size);
  ASSERT_THAT(write(wfd.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(pipe_size));

  ScopedThread t([&]() {
    absl::SleepFor(absl::Milliseconds(100));
    ASSERT_THAT(read(rfd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(pipe_size));
  });

  EXPECT_THAT(sendfile(wfd.get(), inf.get(), nullptr, kDataSize),
              SyscallSucceedsWithValue(kDataSize));
}

TEST(SendFileTest, SendFileToPipe) {
  // Create temp file.
  constexpr char kData[] = "<insert-quote-here>";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Create a pipe for sending to a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Expect to read up to the given size.
  std::vector<char> buf(kDataSize);
  ScopedThread t([&]() {
    absl::SleepFor(absl::Milliseconds(100));
    ASSERT_THAT(read(rfd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(kDataSize));
  });

  // Send with twice the size of the file, which should hit EOF.
  EXPECT_THAT(sendfile(wfd.get(), inf.get(), nullptr, kDataSize * 2),
              SyscallSucceedsWithValue(kDataSize));
}

TEST(SendFileTest, SendFileToSelf) {
  int rawfd;
  ASSERT_THAT(rawfd = memfd_create("memfd", 0), SyscallSucceeds());
  const FileDescriptor fd(rawfd);

  char c = 0x01;
  ASSERT_THAT(WriteFd(fd.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Arbitrarily chosen to make sendfile() take long enough that the sentry
  // watchdog usually fires unless it's reset by sendfile() between iterations
  // of the buffered copy. See b/172076632.
  constexpr size_t kSendfileSize = 0xa00000;

  off_t offset = 0;
  ASSERT_THAT(sendfile(fd.get(), fd.get(), &offset, kSendfileSize),
              SyscallSucceedsWithValue(kSendfileSize));
}

// NOTE(b/237442794): Regression test. Make sure sendfile works with a count
// larger than input file size.
TEST(SendFileTest, LargeCount) {
  // Create input file with some wisdom. It is imperative to use a
  // Shakespearean quote, consistent with the rest of this file.
  constexpr std::string_view kData =
      "We know what we are, but know not what we may be.";
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));

  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Set a count larger than kDataSize.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, 2 * kData.size()),
              SyscallSucceedsWithValue(kData.size()));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
