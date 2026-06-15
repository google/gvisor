// Copyright 2025 The gVisor Authors.
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

#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
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

TEST_P(UnixSocketPeerCredTest, GetPeerCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct ucred cred;
  socklen_t len = sizeof(cred);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_PEERCRED, &cred, &len),
      SyscallSucceeds());

  AssertCredSetTo(cred, getpid(), getuid(), getgid());
}

TEST_P(UnixSocketPeerCredTest, PeerCredBeforeListen) {
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

TEST_P(UnixSocketPeerCredTest, PeerCredAfterListen) {
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

TEST_P(UnixSocketPeerCredTest, AfterConnectClientPeerCred) {
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

TEST_P(UnixSocketPeerCredTest, AfterConnectServerPeerCred) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  // Create a pipe.
  int pipe_fd[2];
  ASSERT_THAT(pipe(pipe_fd), SyscallSucceeds());
  // Create a server socket.
  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  const auto client = [&] {
    TEST_PCHECK_MSG(close(pipe_fd[1]) == 0, "close failed");
    auto client_socket = Socket(AF_UNIX, SOCK_STREAM, 0);
    auto client_soc = client_socket.ValueOrDie().get();
    TEST_PCHECK_MSG(client_socket.ok(), "client socket failed");
    TEST_PCHECK_MSG(connect(client_soc, AsSockAddr(&addr), sizeof(addr)) == 0,
                    "connect failed");
    // Wait for the server to close the connection.
    char ok = 0;
    TEST_PCHECK_MSG(read(pipe_fd[0], &ok, sizeof(ok)) == sizeof(ok),
                    "read failed");
    TEST_PCHECK_MSG(close(pipe_fd[0]) == 0, "closing pipe failed");
    TEST_PCHECK_MSG(close(client_soc) == 0, "closing client socket failed");
  };
  pid_t pid = fork();
  if (pid == 0) {
    client();
    _exit(0);
  }
  MaybeSave();
  ASSERT_GT(pid, 0);
  ASSERT_THAT(close(pipe_fd[0]), SyscallSucceeds());

  char ok = 1;
  ASSERT_THAT(write(pipe_fd[1], &ok, sizeof(ok)),
              SyscallSucceedsWithValue(sizeof(ok)));
  ASSERT_THAT(close(pipe_fd[1]), SyscallSucceeds());
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
  // Wait for the client to exit.
  int status;
  ASSERT_GE(waitpid(pid, &status, 0), 0);
}

// SO_PEERCRED must keep reporting the PID captured at connection time even
// after the peer has exited and been reaped.
TEST_P(UnixSocketPeerCredTest, PeerCredSurvivesPeerExit) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  // Pipe used to tell the client when to exit (after we have accepted).
  int pipe_fd[2];
  ASSERT_THAT(pipe(pipe_fd), SyscallSucceeds());

  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  const auto client = [&] {
    TEST_PCHECK_MSG(close(pipe_fd[1]) == 0, "close failed");
    auto client_socket = Socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_PCHECK_MSG(client_socket.ok(), "client socket failed");
    auto client_soc = client_socket.ValueOrDie().get();
    TEST_PCHECK_MSG(connect(client_soc, AsSockAddr(&addr), sizeof(addr)) == 0,
                    "connect failed");
    // Wait for the parent to accept and signal us before exiting.
    char ok = 0;
    TEST_PCHECK_MSG(read(pipe_fd[0], &ok, sizeof(ok)) == sizeof(ok),
                    "read failed");
  };
  pid_t pid = fork();
  if (pid == 0) {
    client();
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  ASSERT_THAT(close(pipe_fd[0]), SyscallSucceeds());

  // Accept the connection while the client is still alive.
  auto accepted_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(server_socket.get(), nullptr, nullptr));

  // Tell the client to exit and reap it, so the connecting task is fully gone
  // before we read its credentials.
  char ok = 1;
  ASSERT_THAT(write(pipe_fd[1], &ok, sizeof(ok)),
              SyscallSucceedsWithValue(sizeof(ok)));
  ASSERT_THAT(close(pipe_fd[1]), SyscallSucceeds());
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "child exited abnormally: status=" << status;

  // The peer is dead and reaped, but SO_PEERCRED must still report its original
  // PID rather than 0.
  struct ucred serverPeerCred;
  socklen_t len = sizeof(serverPeerCred);
  ASSERT_THAT(getsockopt(accepted_socket.get(), SOL_SOCKET, SO_PEERCRED,
                         &serverPeerCred, &len),
              SyscallSucceeds());
  AssertCredSetTo(serverPeerCred, pid, getuid(), getgid());
}

// Arguments passed to peerCredNSConnectChild, which runs in a separate (cloned)
// process in its own PID namespace.
struct PeerCredNSChildArgs {
  struct sockaddr_un addr;
  // pipe_w is written with the child's PID as seen in its own (new) PID
  // namespace, signalling the parent that the connection is established.
  int pipe_w;
};

// peerCredNSConnectChild is the entry point of a process cloned into a new PID
// namespace (so getpid() returns 1). It connects to addr, reports its
// in-namespace PID, then blocks until the parent closes the connection.
int peerCredNSConnectChild(void* arg) {
  auto* a = static_cast<PeerCredNSChildArgs*>(arg);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  TEST_PCHECK_MSG(s >= 0, "child socket failed");
  TEST_PCHECK_MSG(connect(s, AsSockAddr(&a->addr), sizeof(a->addr)) == 0,
                  "child connect failed");
  pid_t in_ns_pid = getpid();  // 1 in the new PID namespace.
  TEST_PCHECK_MSG(
      write(a->pipe_w, &in_ns_pid, sizeof(in_ns_pid)) == sizeof(in_ns_pid),
      "child write failed");
  // Stay alive until the parent has read our credentials and closes the
  // accepted socket, which we observe as EOF.
  char c;
  while (read(s, &c, sizeof(c)) > 0) {
  }
  _exit(0);
}

// SO_PEERCRED must report the peer's PID translated into the reader's PID
// namespace. The peer connects from a child PID namespace, so the reader in the
// ancestor (root) namespace must see the peer's root-namespace PID, not its
// in-namespace PID (which is 1).
TEST_P(UnixSocketPeerCredTest, PeerCredAcrossPIDNamespace) {
  if (GetParam().type != SOCK_STREAM) {
    GTEST_SKIP() << "Test requires SOCK_STREAM";
  }
  // Creating a PID namespace requires CAP_SYS_ADMIN.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(true, AF_UNIX));
  auto server_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(bind(server_socket.get(), AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(server_socket.get(), 5), SyscallSucceeds());

  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  PeerCredNSChildArgs args = {
      .addr = addr,
      .pipe_w = sync_pipe[1],
  };

  // Clone a child into a new PID namespace.
  constexpr int kStackSize = 4096;
  Mapping stack = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0));
  pid_t child_pid = clone(peerCredNSConnectChild,
                          reinterpret_cast<char*>(stack.ptr()) + stack.len(),
                          CLONE_NEWPID | SIGCHLD, &args);
  ASSERT_THAT(child_pid, SyscallSucceeds());
  ASSERT_THAT(close(sync_pipe[1]), SyscallSucceeds());

  // Read the child's in-namespace PID, confirming it is PID 1 of a new
  // namespace (and that the connection is established).
  pid_t child_in_ns_pid = 0;
  ASSERT_THAT(read(sync_pipe[0], &child_in_ns_pid, sizeof(child_in_ns_pid)),
              SyscallSucceedsWithValue(sizeof(child_in_ns_pid)));
  EXPECT_EQ(child_in_ns_pid, 1);

  {
    auto accepted_socket = ASSERT_NO_ERRNO_AND_VALUE(
        Accept(server_socket.get(), nullptr, nullptr));
    struct ucred peerCreds;
    socklen_t len = sizeof(peerCreds);
    ASSERT_THAT(getsockopt(accepted_socket.get(), SOL_SOCKET, SO_PEERCRED,
                           &peerCreds, &len),
                SyscallSucceeds());
    // The PID must be the peer's PID in *our* namespace.
    EXPECT_EQ(peerCreds.pid, child_pid);
    EXPECT_EQ(peerCreds.uid, getuid());
    EXPECT_EQ(peerCreds.gid, getgid());
    // accepted_socket closes here, releasing the child from its blocking read.
  }

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "child exited abnormally: status=" << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
