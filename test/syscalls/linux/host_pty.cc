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

#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "absl/strings/numbers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/pty_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(HostPtyTest, Termios2) {
  // We expect a host PTY FD to be passed.
  char* fd_str = getenv("TEST_HOST_PTY_FD");
  ASSERT_NE(fd_str, nullptr) << "TEST_HOST_PTY_FD environment variable not set";
  int fd;
  ASSERT_TRUE(absl::SimpleAtoi(fd_str, &fd)) << "Invalid TEST_HOST_PTY_FD: " << fd_str;

  struct termios t;
  ASSERT_THAT(ioctl(fd, TCGETS, &t), SyscallSucceeds());

  struct kernel_termios2 t2 = {};
  ASSERT_THAT(ioctl(fd, TCGETS2, &t2), SyscallSucceeds());

  EXPECT_EQ(t.c_iflag, t2.c_iflag);
  EXPECT_EQ(t.c_oflag, t2.c_oflag);
  EXPECT_EQ(t.c_cflag, t2.c_cflag);
  EXPECT_EQ(t.c_lflag, t2.c_lflag);
  for (int i = 0; i < NCCS && i < KERNEL_NCCS; ++i) {
    EXPECT_EQ(t.c_cc[i], t2.c_cc[i]);
  }

  // Test TCSETS2.
  auto original_lflag = t2.c_lflag;
  t2.c_lflag ^= ECHO;
  ASSERT_THAT(ioctl(fd, TCSETS2, &t2), SyscallSucceeds());

  struct kernel_termios2 t3 = {};
  ASSERT_THAT(ioctl(fd, TCGETS2, &t3), SyscallSucceeds());
  EXPECT_EQ(t2.c_lflag, t3.c_lflag);

  // Restore original flags.
  t2.c_lflag = original_lflag;
  ASSERT_THAT(ioctl(fd, TCSETS2, &t2), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
