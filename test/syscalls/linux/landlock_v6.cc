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

// Landlock syscall tests (ABI v6).

#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV6Test, SignalScopeBlocksSignalToOutsideProcess) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  struct sigaction old = {};
  ASSERT_THAT(sigaction(SIGUSR1, &sa, &old), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_SIGNAL);
    EnforceOrDie(fd);
    _exit(ClassifyScope(kill(getppid(), SIGUSR1)));
  }));
  EXPECT_THAT(sigaction(SIGUSR1, &old, nullptr), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV6Test, SignalScopeAllowsSignalWithinDomain) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_SIGNAL);
    EnforceOrDie(fd);
    pid_t pid = fork();
    if (pid == 0) {
      pause();
      _exit(0);
    }
    int rc = kill(pid, SIGKILL);
    int st;
    waitpid(pid, &st, 0);
    _exit(ClassifyScope(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV6Test, AbstractUnixScopeBlocksConnectToOutsideSocket) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  const std::string name = "landlock_test_" + std::to_string(getpid());
  struct sockaddr_un addr;
  socklen_t addrlen = AbstractAddr(name, &addr);

  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_THAT(listener, SyscallSucceeds());
  ASSERT_THAT(
      bind(listener, reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());
  ASSERT_THAT(listen(listener, 1), SyscallSucceeds());

  static std::string child_name;
  child_name = name;
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
    EnforceOrDie(fd);
    struct sockaddr_un a;
    socklen_t alen = AbstractAddr(child_name, &a);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    int rc = connect(s, reinterpret_cast<struct sockaddr*>(&a), alen);
    close(s);
    _exit(ClassifyScope(rc));
  }));
  close(listener);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV6Test, AbstractUnixScopeAllowsPathnameSocket) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string sock_path = JoinPath(dir.path(), "sock");
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  ASSERT_LT(sock_path.size(), sizeof(addr.sun_path));
  memcpy(addr.sun_path, sock_path.data(), sock_path.size());

  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_THAT(listener, SyscallSucceeds());
  ASSERT_THAT(
      bind(listener, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(listener, 1), SyscallSucceeds());

  static std::string child_path;
  child_path = sock_path;
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
    EnforceOrDie(fd);
    struct sockaddr_un a = {};
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, child_path.data(), child_path.size());
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    int rc = connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof(a));
    close(s);
    _exit(ClassifyScope(rc));
  }));
  close(listener);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
