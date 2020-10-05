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

#include <sys/ioctl.h>
#include <termios.h>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/pty_util.h"

namespace gvisor {
namespace testing {

namespace {

// StealTTY tests whether privileged processes can steal controlling terminals.
// If the stealing process has CAP_SYS_ADMIN in the root user namespace, the
// test ensures that stealing works. If it has non-root CAP_SYS_ADMIN, it
// ensures stealing fails.
TEST(JobControlRootTest, StealTTY) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  bool true_root = true;
  if (!IsRunningOnGvisor()) {
    // If running in Linux, we may only have CAP_SYS_ADMIN in a non-root user
    // namespace (i.e. we are not truly root). We use init_module as a proxy for
    // whether we are true root, as it returns EPERM immediately.
    ASSERT_THAT(syscall(SYS_init_module, nullptr, 0, nullptr), SyscallFails());
    true_root = errno != EPERM;

    // Make this a session leader, which also drops the controlling terminal.
    // In the gVisor test environment, this test will be run as the session
    // leader already (as the sentry init process).
    ASSERT_THAT(setsid(), SyscallSucceeds());
  }

  FileDescriptor master =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master));

  // Make replica the controlling terminal.
  ASSERT_THAT(ioctl(replica.get(), TIOCSCTTY, 0), SyscallSucceeds());

  // Fork, join a new session, and try to steal the parent's controlling
  // terminal, which should succeed when we have CAP_SYS_ADMIN and pass an arg
  // of 1.
  pid_t child = fork();
  if (!child) {
    ASSERT_THAT(setsid(), SyscallSucceeds());
    // We shouldn't be able to steal the terminal with the wrong arg value.
    TEST_PCHECK(ioctl(replica.get(), TIOCSCTTY, 0));
    // We should be able to steal it if we are true root.
    TEST_PCHECK(true_root == !ioctl(replica.get(), TIOCSCTTY, 1));
    _exit(0);
  }

  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_EQ(wstatus, 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
