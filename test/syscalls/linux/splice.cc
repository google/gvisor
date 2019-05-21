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
#include <sys/sendfile.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SpliceTest, TwoRegularFiles) {
  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Open the output file as write only.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Verify that it is rejected as expected; regardless of offsets.
  loff_t in_offset = 0;
  loff_t out_offset = 0;
  EXPECT_THAT(splice(inf.get(), &in_offset, outf.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(inf.get(), nullptr, outf.get(), &out_offset, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(inf.get(), &in_offset, outf.get(), nullptr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(splice(inf.get(), nullptr, outf.get(), nullptr, 1, 0),
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
  SKIP_IF(IsRunningOnGvisor());

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
  SKIP_IF(IsRunningOnGvisor());

  // Open some file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Attempt to tee from the file.
  EXPECT_THAT(tee(inf.get(), wfd.get(), kPageSize, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(tee(rfd.get(), inf.get(), kPageSize, 0),
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

TEST(SpliceTest, ToPipe) {
  // Open the input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(inf.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(lseek(inf.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice to the pipe.
  EXPECT_THAT(splice(inf.get(), nullptr, wfd.get(), nullptr, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Contents should be equal.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(rfd.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), buf.size()), 0);
}

TEST(SpliceTest, ToPipeOffset) {
  // Open the input file.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));

  // Fill with some random data.
  std::vector<char> buf(kPageSize);
  RandomizeBuffer(buf.data(), buf.size());
  ASSERT_THAT(write(inf.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(kPageSize));

  // Create a new pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor rfd(fds[0]);
  const FileDescriptor wfd(fds[1]);

  // Splice to the pipe.
  loff_t in_offset = kPageSize / 2;
  EXPECT_THAT(
      splice(inf.get(), &in_offset, wfd.get(), nullptr, kPageSize / 2, 0),
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

  // Open the input file.
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Splice to the output file.
  EXPECT_THAT(splice(rfd.get(), nullptr, outf.get(), nullptr, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // The offset of the output should be equal to kPageSize. We assert that and
  // reset to zero so that we can read the contents and ensure they match.
  EXPECT_THAT(lseek(outf.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(lseek(outf.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Contents should be equal.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(outf.get(), rbuf.data(), rbuf.size()),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(memcmp(rbuf.data(), buf.data(), buf.size()), 0);
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
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDWR));

  // Splice to the output file.
  loff_t out_offset = kPageSize / 2;
  EXPECT_THAT(splice(rfd.get(), nullptr, outf.get(), &out_offset, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Content should reflect the splice. We write to a specific offset in the
  // file, so the internals should now be allocated sparsely.
  std::vector<char> rbuf(kPageSize);
  ASSERT_THAT(read(outf.get(), rbuf.data(), rbuf.size()),
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
  SKIP_IF(IsRunningOnGvisor());

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
  SKIP_IF(IsRunningOnGvisor());

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

}  // namespace

}  // namespace testing
}  // namespace gvisor
