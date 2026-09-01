// Copyright 2026 The gVisor Authors.
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
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef SYS_copy_file_range
#if defined(__x86_64__)
#define SYS_copy_file_range 326
#elif defined(__aarch64__)
#define SYS_copy_file_range 285
#else
#error "Unknown architecture"
#endif
#endif  // SYS_copy_file_range

// Direct syscall invocation to bypass any glibc emulation.
ssize_t CopyFileRange(int fd_in, off_t* off_in, int fd_out, off_t* off_out,
                      size_t len, unsigned int flags) {
  return syscall(SYS_copy_file_range, fd_in, off_in, fd_out, off_out, len,
                 flags);
}

// Returns the full contents of the file at `path`.
PosixErrorOr<std::string> ReadWholeFile(absl::string_view path) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, Open(std::string(path), O_RDONLY));
  std::string contents;
  char buf[1024];
  ssize_t n;
  while ((n = read(fd.get(), buf, sizeof(buf))) > 0) {
    contents.append(buf, n);
  }
  if (n < 0) {
    return PosixError(errno, "read");
  }
  return contents;
}

constexpr absl::string_view kData = "0123456789abcdefghijklmnopqrstuvwxyz";

class CopyFileRangeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    in_file_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
        GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
    out_file_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  }

  PosixErrorOr<FileDescriptor> In(int flags = O_RDONLY) {
    return Open(in_file_.path(), flags);
  }
  PosixErrorOr<FileDescriptor> Out(int flags = O_WRONLY) {
    return Open(out_file_.path(), flags);
  }

  TempPath in_file_;
  TempPath out_file_;
};

// Implicit offsets advance file positions on both descriptors.
TEST_F(CopyFileRangeTest, BasicNullOffsets) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(
      CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, kData.size(), 0),
      SyscallSucceedsWithValue(kData.size()));

  EXPECT_THAT(lseek(inf.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kData.size()));
  EXPECT_THAT(lseek(outf.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kData.size()));

  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())), kData);
}

// Explicit offsets do not move file positions.
TEST_F(CopyFileRangeTest, ExplicitOffsetsDoNotMoveFilePositions) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t in_off = 10;
  off_t out_off = 0;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, outf.get(), &out_off, 5, 0),
              SyscallSucceedsWithValue(5));

  EXPECT_EQ(in_off, 15);
  EXPECT_EQ(out_off, 5);
  EXPECT_THAT(lseek(inf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(outf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())),
            kData.substr(10, 5));
}

// Mixing an explicit input offset with an implicit output offset is allowed.
TEST_F(CopyFileRangeTest, MixedOffsetsImplicitOutput) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t in_off = 4;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, outf.get(), nullptr, 6, 0),
              SyscallSucceedsWithValue(6));

  EXPECT_EQ(in_off, 10);
  EXPECT_THAT(lseek(inf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(outf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(6));
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())),
            kData.substr(4, 6));
}

// Mixing an implicit input offset with an explicit output offset is allowed.
TEST_F(CopyFileRangeTest, MixedOffsetsImplicitInput) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  ASSERT_THAT(lseek(inf.get(), 4, SEEK_SET), SyscallSucceedsWithValue(4));

  off_t out_off = 0;
  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), &out_off, 6, 0),
              SyscallSucceedsWithValue(6));

  EXPECT_EQ(out_off, 6);
  EXPECT_THAT(lseek(inf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(10));
  EXPECT_THAT(lseek(outf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())),
            kData.substr(4, 6));
}

// Count larger than input length is clamped to EOF.
TEST_F(CopyFileRangeTest, ShortenedToEOF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(
      CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 1 << 20, 0),
      SyscallSucceedsWithValue(kData.size()));
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())), kData);
}

// Starting at or past EOF copies nothing.
TEST_F(CopyFileRangeTest, StartAtEOF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t in_off = kData.size();
  off_t out_off = 0;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, outf.get(), &out_off, 100, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(in_off, static_cast<off_t>(kData.size()));
  EXPECT_EQ(out_off, 0);
}

TEST_F(CopyFileRangeTest, ZeroCount) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 0, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(inf.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

// Output offset beyond EOF extends the file.
TEST_F(CopyFileRangeTest, OutputOffsetBeyondEOFExtendsFile) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t in_off = 0;
  off_t out_off = 8;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, outf.get(), &out_off, 4, 0),
              SyscallSucceedsWithValue(4));

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path()));
  ASSERT_EQ(got.size(), 12);
  EXPECT_EQ(got.substr(0, 8), std::string(8, '\0'));
  EXPECT_EQ(got.substr(8), kData.substr(0, 4));
}

// Copies issued in multiple calls resume correctly.
TEST_F(CopyFileRangeTest, Resumable) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  size_t total = 0;
  while (total < kData.size()) {
    const ssize_t n = CopyFileRange(inf.get(), nullptr, outf.get(), nullptr,
                                    kData.size() - total, 0);
    ASSERT_THAT(n, SyscallSucceeds());
    if (n == 0) break;
    total += n;
  }
  EXPECT_EQ(total, kData.size());
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())), kData);
}

TEST_F(CopyFileRangeTest, NonZeroFlagsIsEINVAL) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 1, 1),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(CopyFileRangeTest, BadFDIsEBADF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(-1, nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, -1, nullptr, 1, 0),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(CopyFileRangeTest, UnreadableInputIsEBADF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In(O_WRONLY));
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(CopyFileRangeTest, UnwritableOutputIsEBADF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out(O_RDONLY));

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EBADF));
}

// Unlike sendfile(2), copy_file_range(2) rejects append-only output with EBADF.
TEST_F(CopyFileRangeTest, AppendOnlyOutputIsEBADF) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Out(O_WRONLY | O_APPEND));

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(CopyFileRangeTest, DirectoryInputIsEISDIR) {
  const FileDescriptor dirf = ASSERT_NO_ERRNO_AND_VALUE(
      Open(GetAbsoluteTestTmpdir(), O_RDONLY | O_DIRECTORY));
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(dirf.get(), nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EISDIR));
}

TEST_F(CopyFileRangeTest, PipeIsEINVAL) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(rfd.get(), nullptr, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, wfd.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Negative offset with non-zero count returns EOVERFLOW.
TEST_F(CopyFileRangeTest, NegativeOffsetIsEOVERFLOW) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t bad = -1;
  off_t good = 0;
  EXPECT_THAT(CopyFileRange(inf.get(), &bad, outf.get(), &good, 1, 0),
              SyscallFailsWithErrno(EOVERFLOW));
  EXPECT_THAT(CopyFileRange(inf.get(), &good, outf.get(), &bad, 1, 0),
              SyscallFailsWithErrno(EOVERFLOW));
}

// Negative offset with zero count returns EINVAL.
TEST_F(CopyFileRangeTest, NegativeOffsetZeroCountIsEINVAL) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t bad = -1;
  off_t good = 0;
  EXPECT_THAT(CopyFileRange(inf.get(), &bad, outf.get(), &good, 0, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Overlapping ranges within the same file return EINVAL.
TEST_F(CopyFileRangeTest, SameFileOverlapIsEINVAL) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In(O_RDWR));

  off_t in_off = 0;
  off_t out_off = 4;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, inf.get(), &out_off, 10, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Non-overlapping ranges within the same file succeed.
TEST_F(CopyFileRangeTest, SameFileNoOverlapSucceeds) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In(O_RDWR));

  off_t in_off = 0;
  off_t out_off = 20;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, inf.get(), &out_off, 10, 0),
              SyscallSucceedsWithValue(10));

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(in_file_.path()));
  EXPECT_EQ(got.substr(20, 10), kData.substr(0, 10));
}

// Overlapping ranges across different FDs for the same file return EINVAL.
TEST_F(CopyFileRangeTest, SameFileTwoFDsOverlapIsEINVAL) {
  const FileDescriptor a = ASSERT_NO_ERRNO_AND_VALUE(In(O_RDWR));
  const FileDescriptor b = ASSERT_NO_ERRNO_AND_VALUE(In(O_RDWR));

  off_t in_off = 0;
  off_t out_off = 1;
  EXPECT_THAT(CopyFileRange(a.get(), &in_off, b.get(), &out_off, 10, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Count is clamped to input size rather than rejected.
TEST_F(CopyFileRangeTest, HugeCountIsShortenedNotRejected) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr,
                            static_cast<size_t>(1) << 62, 0),
              SyscallSucceedsWithValue(kData.size()));
}

// Offset + count overflow returns EOVERFLOW.
TEST_F(CopyFileRangeTest, OverflowingRangeIsEOVERFLOW) {
  const FileDescriptor inf = ASSERT_NO_ERRNO_AND_VALUE(In());
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  off_t in_off = 0;
  off_t out_off = 1;
  EXPECT_THAT(CopyFileRange(inf.get(), &in_off, outf.get(), &out_off,
                            static_cast<size_t>(-1), 0),
              SyscallFailsWithErrno(EOVERFLOW));
}

// An empty input file copies nothing.
TEST_F(CopyFileRangeTest, EmptyInput) {
  const TempPath empty = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(empty.path(), O_RDONLY));
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  EXPECT_THAT(CopyFileRange(inf.get(), nullptr, outf.get(), nullptr, 100, 0),
              SyscallSucceedsWithValue(0));
}

// Large copies exceeding internal buffer size succeed.
TEST_F(CopyFileRangeTest, LargeCopy) {
  constexpr size_t kSize = 4 << 20;  // 4MiB, well past the internal buffer.
  std::string big(kSize, '\0');
  for (size_t i = 0; i < kSize; ++i) {
    big[i] = static_cast<char>(i % 251);
  }
  const TempPath src = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), big, TempPath::kDefaultFileMode));

  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(src.path(), O_RDONLY));
  const FileDescriptor outf = ASSERT_NO_ERRNO_AND_VALUE(Out());

  size_t total = 0;
  while (total < kSize) {
    const ssize_t n = CopyFileRange(inf.get(), nullptr, outf.get(), nullptr,
                                    kSize - total, 0);
    ASSERT_THAT(n, SyscallSucceeds());
    if (n == 0) break;
    total += n;
  }
  EXPECT_EQ(total, kSize);
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadWholeFile(out_file_.path())), big);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
