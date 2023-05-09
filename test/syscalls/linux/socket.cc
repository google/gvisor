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
#include <sys/wait.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
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
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
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
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    ASSERT_NO_ERRNO_AND_VALUE(
        Socket(tests[i].domain, tests[i].type, tests[i].protocol));
  }
}

TEST(SocketTest, UnixSocketStat) {
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
  EXPECT_NE(statbuf.st_atime, 0);
  EXPECT_EQ(statbuf.st_atime, statbuf.st_mtime);
  EXPECT_EQ(statbuf.st_atime, statbuf.st_ctime);
}

TEST(SocketTest, UnixSocketStatFS) {
  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  struct statfs st;
  EXPECT_THAT(fstatfs(bound.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, SOCKFS_MAGIC);
  EXPECT_EQ(st.f_bsize, getpagesize());
  EXPECT_EQ(st.f_namelen, NAME_MAX);
}

TEST(SocketTest, UnixSCMRightsOnlyPassedOnce) {
  const DisableSave ds;

  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());
  // Send more than what will fit inside the send/receive buffers, so that it is
  // split into multiple messages.
  constexpr int kBufSize = 0x100000;
  // Heap allocation is async-signal-unsafe and thus cannot occur between fork()
  // and execve().
  std::vector<char> buf(kBufSize);

  pid_t pid = fork();
  if (pid == 0) {
    TEST_PCHECK(close(sockets[0]) == 0);

    // Construct a message with some control message.
    struct msghdr msg = {};
    char control[CMSG_SPACE(sizeof(int))] = {};
    struct iovec iov = {};
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    ((int*)CMSG_DATA(cmsg))[0] = sockets[1];

    iov.iov_base = buf.data();
    iov.iov_len = kBufSize;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    int n = sendmsg(sockets[1], &msg, 0);
    TEST_PCHECK(n == kBufSize);
    TEST_PCHECK(shutdown(sockets[1], SHUT_RDWR) == 0);
    TEST_PCHECK(close(sockets[1]) == 0);
    _exit(0);
  }

  close(sockets[1]);

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int))] = {};
  struct iovec iov = {};
  msg.msg_control = &control;
  msg.msg_controllen = sizeof(control);

  iov.iov_base = buf.data();
  iov.iov_len = kBufSize;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // The control message should only be present in the first message received.
  int n;
  ASSERT_THAT(n = recvmsg(sockets[0], &msg, 0), SyscallSucceeds());
  ASSERT_GT(n, 0);
  ASSERT_EQ(msg.msg_controllen, CMSG_SPACE(sizeof(int)));

  while (n > 0) {
    ASSERT_THAT(n = recvmsg(sockets[0], &msg, 0), SyscallSucceeds());
    ASSERT_EQ(msg.msg_controllen, 0);
  }

  close(sockets[0]);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST(SocketTest, Permission) {
  FileDescriptor socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_DGRAM, 0));

  auto stat = ASSERT_NO_ERRNO_AND_VALUE(Fstat(socket.get()));
  EXPECT_EQ(0777, stat.st_mode & ~S_IFMT);
}

using SocketOpenTest = ::testing::TestWithParam<int>;

// UDS cannot be opened.
TEST_P(SocketOpenTest, Unix) {
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
