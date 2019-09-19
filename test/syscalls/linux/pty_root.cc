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

// These tests should be run as root.
namespace {

TEST(JobControlRootTest, StealTTY) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Make this a session leader, which also drops the controlling terminal.
  // In the gVisor test environment, this test will be run as the session
  // leader already (as the sentry init process).
  if (!IsRunningOnGvisor()) {
    ASSERT_THAT(setsid(), SyscallSucceeds());
  }

  FileDescriptor master =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
  FileDescriptor slave = ASSERT_NO_ERRNO_AND_VALUE(OpenSlave(master));

  // Make slave the controlling terminal.
  ASSERT_THAT(ioctl(slave.get(), TIOCSCTTY, 0), SyscallSucceeds());

  // Fork, join a new session, and try to steal the parent's controlling
  // terminal, which should succeed when we have CAP_SYS_ADMIN and pass an arg
  // of 1.
  pid_t child = fork();
  if (!child) {
    ASSERT_THAT(setsid(), SyscallSucceeds());
    // We shouldn't be able to steal the terminal with the wrong arg value.
    TEST_PCHECK(ioctl(slave.get(), TIOCSCTTY, 0));
    // We should be able to steal it here.
    TEST_PCHECK(!ioctl(slave.get(), TIOCSCTTY, 1));
    _exit(0);
  }

  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_EQ(wstatus, 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
