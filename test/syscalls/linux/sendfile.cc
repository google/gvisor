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
#include <sys/sendfile.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

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
  // Test input std::string length must be > 2 AND even.
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

  // Verify that the input file offset has been updated
  ASSERT_THAT(read(inf.get(), &actual, kDataSize - bytes_sent),
              SyscallSucceedsWithValue(kHalfDataSize));
  EXPECT_EQ(
      absl::string_view(kData + kDataSize - bytes_sent, kDataSize - bytes_sent),
      absl::string_view(actual, kHalfDataSize));
}

TEST(SendFileTest, SendAndUpdateFileOffsetFromNonzeroStartingPoint) {
  // Create temp files.
  // Test input std::string length must be > 2 AND divisible by 4.
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

  // Verify that the input file offset has been updated
  ASSERT_THAT(read(inf.get(), &actual, kQuarterDataSize),
              SyscallSucceedsWithValue(kQuarterDataSize));

  EXPECT_EQ(
      absl::string_view(kData + kDataSize - kQuarterDataSize, kQuarterDataSize),
      absl::string_view(actual, kQuarterDataSize));
}

TEST(SendFileTest, SendAndUpdateGivenOffset) {
  // Create temp files.
  // Test input std::string length must be >= 4 AND divisible by 4.
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
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_APPEND));

  // Send data and verify that sendfile returns the correct errno.
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, kDataSize),
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
  EXPECT_THAT(sendfile(outf.get(), inf.get(), nullptr, 0),
              SyscallFailsWithErrno(EINVAL));
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
