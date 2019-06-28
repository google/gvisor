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
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(MknodTest, RegularFile) {
  const std::string node0 = NewTempAbsPath();
  EXPECT_THAT(mknod(node0.c_str(), S_IFREG, 0), SyscallSucceeds());

  const std::string node1 = NewTempAbsPath();
  EXPECT_THAT(mknod(node1.c_str(), 0, 0), SyscallSucceeds());
}

TEST(MknodTest, MknodAtRegularFile) {
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

TEST(MknodTest, MknodOnExistingPathFails) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const TempPath slink = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), file.path()));

  EXPECT_THAT(mknod(file.path().c_str(), S_IFREG, 0),
              SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(file.path().c_str(), S_IFIFO, 0),
              SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(slink.path().c_str(), S_IFREG, 0),
              SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(slink.path().c_str(), S_IFIFO, 0),
              SyscallFailsWithErrno(EEXIST));
}

TEST(MknodTest, UnimplementedTypesReturnError) {
  const std::string path = NewTempAbsPath();

  if (IsRunningOnGvisor()) {
    ASSERT_THAT(mknod(path.c_str(), S_IFSOCK, 0),
                SyscallFailsWithErrno(EOPNOTSUPP));
  }
  // These will fail on linux as well since we don't have CAP_MKNOD.
  ASSERT_THAT(mknod(path.c_str(), S_IFCHR, 0), SyscallFailsWithErrno(EPERM));
  ASSERT_THAT(mknod(path.c_str(), S_IFBLK, 0), SyscallFailsWithErrno(EPERM));
}

TEST(MknodTest, Fifo) {
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
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  // Write-end of the pipe.
  FileDescriptor wfd = ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_WRONLY));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
}

TEST(MknodTest, FifoOtrunc) {
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
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  // Write-end of the pipe.
  FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_WRONLY | O_TRUNC));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
}

TEST(MknodTest, FifoTruncNoOp) {
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
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_RDONLY));
    EXPECT_THAT(ReadFd(fd.get(), buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
  });

  FileDescriptor wfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(fifo.c_str(), O_WRONLY | O_TRUNC));
  EXPECT_THAT(ftruncate(wfd.get(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(WriteFd(wfd.get(), msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(ftruncate(wfd.get(), 0), SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
