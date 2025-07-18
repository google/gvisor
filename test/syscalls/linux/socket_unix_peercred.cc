// Copyright 2024 The gVisor Authors.
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

#include "test/syscalls/linux/socket_unix_peercred.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void AssertCredSetTo(struct ucred peerCreds, pid_t pid, uid_t uid, gid_t gid) {
  ASSERT_EQ(peerCreds.pid, pid);
  ASSERT_EQ(peerCreds.uid, uid);
  ASSERT_EQ(peerCreds.gid, gid);
}

void TestCredSetTo(struct ucred peerCreds, pid_t pid, uid_t uid, gid_t gid) {
  TEST_PCHECK_MSG(peerCreds.pid == pid, "peer pid does not match expected pid");
  TEST_PCHECK_MSG(peerCreds.uid == uid, "peer uid does not match expected uid");
  TEST_PCHECK_MSG(peerCreds.gid == gid, "peer gid does not match expected gid");
}

TEST_P(UnixSocketPairPeerCredTest, GetPeerCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct ucred cred;
  socklen_t len = sizeof(cred);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_PEERCRED, &cred, &len),
      SyscallSucceeds());

  AssertCredSetTo(cred, getpid(), getuid(), getgid());
}

TEST_P(UnixSocketPairPeerCredTest, PeerCredBeforeListen) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }

  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  // Before listen, the peer credentials should not be set.
  struct ucred peerCreds;
  socklen_t peerCredsLen = sizeof(peerCreds);
  ASSERT_THAT(getsockopt(server_socket.get(), SOL_SOCKET, SO_PEERCRED,
                         &peerCreds, &peerCredsLen),
              SyscallSucceeds());
  AssertCredSetTo(peerCreds, 0, -1, -1);
}

TEST_P(UnixSocketPairPeerCredTest, PeerCredAfterListen) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));

  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());
  // After listen, the peer credentials should be set to process credentials.
  struct ucred peerCreds;
  socklen_t peerCredsLen = sizeof(peerCreds);
  ASSERT_THAT(getsockopt(server_socket.get(), SOL_SOCKET, SO_PEERCRED,
                         &peerCreds, &peerCredsLen),
              SyscallSucceeds());
  AssertCredSetTo(peerCreds, getpid(), getuid(), getgid());
}

TEST_P(UnixSocketPairPeerCredTest, BeforeConnect) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  const auto client = [&] {
    auto client_socket = Socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_PCHECK_MSG(client_socket.ok(), "client socket failed");

    // Before connect, the peer credentials should not be set.
    struct ucred peerCreds;
    socklen_t peerCredsLen = sizeof(peerCreds);
    ASSERT_THAT(getsockopt(client_socket.ValueOrDie().get(), SOL_SOCKET,
                           SO_PEERCRED, &peerCreds, &peerCredsLen),
                SyscallSucceeds());
    TestCredSetTo(peerCreds, 0, -1, -1);
  };
  EXPECT_THAT(InForkedProcess(client), IsPosixErrorOkAndHolds(0));
}

TEST_P(UnixSocketPairPeerCredTest, AfterConnectClientPeerCred) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  pid_t server_pid = getpid();
  gid_t server_gid = getgid();
  uid_t server_uid = getuid();
  const auto client = [&] {
    auto client_socket = Socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_PCHECK_MSG(client_socket.ok(), "client socket failed");
    TEST_PCHECK_MSG(connect(client_socket.ValueOrDie().get(), AsSockAddr(&addr),
                            sizeof(addr)) == 0,
                    "connect failed");
    struct ucred clientPeerCred;
    socklen_t len = sizeof(clientPeerCred);
    // After connect, the peer credentials should be set to the server's
    // credentials.
    TEST_PCHECK_MSG(getsockopt(client_socket.ValueOrDie().get(), SOL_SOCKET,
                               SO_PEERCRED, &clientPeerCred, &len) == 0,
                    "client getsockopt failed");
    TestCredSetTo(clientPeerCred, server_pid, server_uid, server_gid);
  };
  EXPECT_THAT(InForkedProcess(client), IsPosixErrorOkAndHolds(0));
}

TEST_P(UnixSocketPairPeerCredTest, AfterConnectServerPeerCred) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  const auto client = [&] {
    auto client_socket = Socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_PCHECK_MSG(client_socket.ok(), "client socket failed");
    TEST_PCHECK_MSG(connect(client_socket.ValueOrDie().get(), AsSockAddr(&addr),
                            sizeof(addr)) == 0,
                    "connect failed");
  };
  pid_t pid = fork();
  if (pid == 0) {
    client();
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  // Wait for the client to exit.
  int status;
  ASSERT_GE(waitpid(pid, &status, 0), 0);
  auto accepted_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(server_socket.get(), nullptr, nullptr));

  struct ucred serverPeerCred;
  socklen_t len = sizeof(serverPeerCred);
  ASSERT_THAT(getsockopt(accepted_socket.get(), SOL_SOCKET, SO_PEERCRED,
                         &serverPeerCred, &len),
              SyscallSucceeds());
  // After connection is established, the peer credentials should be set to the
  // client's credentials.
  AssertCredSetTo(serverPeerCred, pid, getuid(), getgid());
  struct ucred serverSocPeerCred;
  ASSERT_THAT(getsockopt(server_socket.get(), SOL_SOCKET, SO_PEERCRED,
                         &serverSocPeerCred, &len),
              SyscallSucceeds());
  // The listening socket's credentials should remain its own.
  AssertCredSetTo(serverSocPeerCred, getpid(), getuid(), getgid());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
