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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

TEST(MknodTest, RegularFilePermissions) {
  const std::string node = NewTempAbsPath();
  mode_t newUmask = 0077;
  umask(newUmask);

  // Attempt to open file with mode 0777. Not specifying file type should create
  // a regualar file.
  mode_t perms = S_IRWXU | S_IRWXG | S_IRWXO;
  EXPECT_THAT(mknod(node.c_str(), perms, 0), SyscallSucceeds());

  // In the absence of a default ACL, the permissions of the created node are
  // (mode & ~umask).  -- mknod(2)
  mode_t wantPerms = perms & ~newUmask;
  struct stat st;
  ASSERT_THAT(stat(node.c_str(), &st), SyscallSucceeds());
  ASSERT_EQ(st.st_mode & 0777, wantPerms);

  // "Zero file type is equivalent to type S_IFREG." - mknod(2)
  ASSERT_EQ(st.st_mode & S_IFMT, S_IFREG);
}

TEST(MknodTest, MknodAtFIFO) {
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

TEST(MknodTest, Socket) {
  ASSERT_THAT(chdir(GetAbsoluteTestTmpdir().c_str()), SyscallSucceeds());

  auto filename = NewTempRelPath();

  ASSERT_THAT(mknod(filename.c_str(), S_IFSOCK | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());

  int sk;
  ASSERT_THAT(sk = socket(AF_UNIX, SOCK_SEQPACKET, 0), SyscallSucceeds());
  FileDescriptor fd(sk);

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  absl::SNPrintF(addr.sun_path, sizeof(addr.sun_path), "%s", filename.c_str());
  ASSERT_THAT(connect(sk, (struct sockaddr *)&addr, sizeof(addr)),
              SyscallFailsWithErrno(ECONNREFUSED));
  ASSERT_THAT(unlink(filename.c_str()), SyscallSucceeds());
}

TEST(MknodTest, MknodAtEmptyPath) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY, 0666));
  EXPECT_THAT(mknodat(fd.get(), "", S_IFREG | 0777, 0),
              SyscallFailsWithErrno(ENOENT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
