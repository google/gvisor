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
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(MknodTest, RegularFile) {
  std::string const node0 = NewTempAbsPathInDir("/tmp");
  std::string const node1 = NewTempAbsPathInDir("/tmp");
  ASSERT_THAT(mknod(node0.c_str(), S_IFREG, 0), SyscallSucceeds());
  ASSERT_THAT(mknod(node1.c_str(), 0, 0), SyscallSucceeds());
}

TEST(MknodTest, MknodAtRegularFile) {
  std::string const fifo_relpath = NewTempRelPath();
  std::string const fifo = JoinPath("/tmp", fifo_relpath);
  int dirfd;
  ASSERT_THAT(dirfd = open("/tmp", O_RDONLY), SyscallSucceeds());
  ASSERT_THAT(mknodat(dirfd, fifo_relpath.c_str(), S_IFIFO | S_IRUSR, 0),
              SyscallSucceeds());
  EXPECT_THAT(close(dirfd), SyscallSucceeds());

  struct stat st;
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));
}

TEST(MknodTest, MknodOnExistingPathFails) {
  std::string const file = NewTempAbsPathInDir("/tmp");
  std::string const slink = NewTempAbsPathInDir("/tmp");
  int fd;
  ASSERT_THAT(fd = open(file.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
  ASSERT_THAT(symlink(file.c_str(), slink.c_str()), SyscallSucceeds());

  EXPECT_THAT(mknod(file.c_str(), S_IFREG, 0), SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(file.c_str(), S_IFIFO, 0), SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(slink.c_str(), S_IFREG, 0), SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(mknod(slink.c_str(), S_IFIFO, 0), SyscallFailsWithErrno(EEXIST));
}

TEST(MknodTest, UnimplementedTypesReturnError) {
  if (IsRunningOnGvisor()) {
    ASSERT_THAT(mknod("/tmp/a_socket", S_IFSOCK, 0),
                SyscallFailsWithErrno(EOPNOTSUPP));
  }
  // These will fail on linux as well since we don't have CAP_MKNOD.
  ASSERT_THAT(mknod("/tmp/a_chardev", S_IFCHR, 0),
              SyscallFailsWithErrno(EPERM));
  ASSERT_THAT(mknod("/tmp/a_blkdev", S_IFBLK, 0), SyscallFailsWithErrno(EPERM));
}

TEST(MknodTest, Fifo) {
  std::string const fifo = NewTempAbsPathInDir("/tmp");
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  struct stat st;
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some string";
  std::vector<char> buf(512);

  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    int fd;
    ASSERT_THAT(fd = open(fifo.c_str(), O_RDONLY), SyscallSucceeds());
    EXPECT_THAT(read(fd, buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
    EXPECT_THAT(close(fd), SyscallSucceeds());
  });

  // Write-end of the pipe.
  int wfd;
  ASSERT_THAT(wfd = open(fifo.c_str(), O_WRONLY), SyscallSucceeds());
  EXPECT_THAT(write(wfd, msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(close(wfd), SyscallSucceeds());
}

TEST(MknodTest, FifoOtrunc) {
  std::string const fifo = NewTempAbsPathInDir("/tmp");
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  struct stat st = {};
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some string";
  std::vector<char> buf(512);
  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    int fd;
    ASSERT_THAT(fd = open(fifo.c_str(), O_RDONLY), SyscallSucceeds());
    EXPECT_THAT(read(fd, buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
    EXPECT_THAT(close(fd), SyscallSucceeds());
  });

  int wfd;
  ASSERT_THAT(wfd = open(fifo.c_str(), O_TRUNC | O_WRONLY), SyscallSucceeds());
  EXPECT_THAT(write(wfd, msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(close(wfd), SyscallSucceeds());
}

TEST(MknodTest, FifoTruncNoOp) {
  std::string const fifo = NewTempAbsPathInDir("/tmp");
  ASSERT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  EXPECT_THAT(truncate(fifo.c_str(), 0), SyscallFailsWithErrno(EINVAL));

  struct stat st = {};
  ASSERT_THAT(stat(fifo.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  std::string msg = "some string";
  std::vector<char> buf(512);
  // Read-end of the pipe.
  ScopedThread t([&fifo, &buf, &msg]() {
    int rfd = 0;
    ASSERT_THAT(rfd = open(fifo.c_str(), O_RDONLY), SyscallSucceeds());
    EXPECT_THAT(ReadFd(rfd, buf.data(), buf.size()),
                SyscallSucceedsWithValue(msg.length()));
    EXPECT_EQ(msg, std::string(buf.data()));
    EXPECT_THAT(close(rfd), SyscallSucceeds());
  });

  int wfd = 0;
  ASSERT_THAT(wfd = open(fifo.c_str(), O_TRUNC | O_WRONLY), SyscallSucceeds());
  EXPECT_THAT(ftruncate(wfd, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(WriteFd(wfd, msg.c_str(), msg.length()),
              SyscallSucceedsWithValue(msg.length()));
  EXPECT_THAT(ftruncate(wfd, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(close(wfd), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
