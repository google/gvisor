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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_umask.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// From linux/magic.h, but we can't depend on linux headers here.
#define SOCKFS_MAGIC 0x534F434B

TEST(SocketTest, UnixSocketPairProtocol) {
  int socks[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, PF_UNIX, socks),
              SyscallSucceeds());
  close(socks[0]);
  close(socks[1]);
}

TEST(SocketTest, ProtocolUnix) {
  struct {
    int domain, type, protocol;
  } tests[] = {
      {AF_UNIX, SOCK_STREAM, PF_UNIX},
      {AF_UNIX, SOCK_SEQPACKET, PF_UNIX},
      {AF_UNIX, SOCK_DGRAM, PF_UNIX},
  };
  for (long unsigned int i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    ASSERT_NO_ERRNO_AND_VALUE(
        Socket(tests[i].domain, tests[i].type, tests[i].protocol));
  }
}

TEST(SocketTest, ProtocolInet) {
  struct {
    int domain, type, protocol;
  } tests[] = {
      {AF_INET, SOCK_DGRAM, IPPROTO_UDP},
      {AF_INET, SOCK_STREAM, IPPROTO_TCP},
  };
  for (long unsigned int i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    ASSERT_NO_ERRNO_AND_VALUE(
        Socket(tests[i].domain, tests[i].type, tests[i].protocol));
  }
}

TEST(SocketTest, UnixSocketStat) {
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  // The permissions of the file created with bind(2) should be defined by the
  // permissions of the bound socket and the umask.
  mode_t sock_perm = 0765, mask = 0123;
  ASSERT_THAT(fchmod(bound.get(), sock_perm), SyscallSucceeds());
  TempUmask m(mask);

  struct sockaddr_un addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(/*abstract=*/false, AF_UNIX));
  ASSERT_THAT(bind(bound.get(), reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());

  struct stat statbuf = {};
  ASSERT_THAT(stat(addr.sun_path, &statbuf), SyscallSucceeds());

  // Mode should be S_IFSOCK.
  EXPECT_EQ(statbuf.st_mode, S_IFSOCK | (sock_perm & ~mask));

  // Timestamps should be equal and non-zero.
  // TODO(b/158882152): Sockets currently don't implement timestamps.
  if (!IsRunningOnGvisor()) {
    EXPECT_NE(statbuf.st_atime, 0);
    EXPECT_EQ(statbuf.st_atime, statbuf.st_mtime);
    EXPECT_EQ(statbuf.st_atime, statbuf.st_ctime);
  }
}

TEST(SocketTest, UnixSocketStatFS) {
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  struct statfs st;
  EXPECT_THAT(fstatfs(bound.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, SOCKFS_MAGIC);
  EXPECT_EQ(st.f_bsize, getpagesize());
  EXPECT_EQ(st.f_namelen, NAME_MAX);
}

using SocketOpenTest = ::testing::TestWithParam<int>;

// UDS cannot be opened.
TEST_P(SocketOpenTest, Unix) {
  // FIXME(b/142001530): Open incorrectly succeeds on gVisor.
  SKIP_IF(IsRunningWithVFS1());

  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  struct sockaddr_un addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(/*abstract=*/false, AF_UNIX));

  ASSERT_THAT(bind(bound.get(), reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());

  EXPECT_THAT(open(addr.sun_path, GetParam()), SyscallFailsWithErrno(ENXIO));
}

INSTANTIATE_TEST_SUITE_P(OpenModes, SocketOpenTest,
                         ::testing::Values(O_RDONLY, O_RDWR));

}  // namespace testing
}  // namespace gvisor
