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

#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <ctime>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "test/util/logging.h"
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
  ASSERT_TRUE(absl::SimpleAtoi(fd_str, &fd))
      << "Invalid TEST_HOST_PTY_FD: " << fd_str;

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

TEST(HostPtyTest, SigwinchOnWindowSizeChange) {
  char* fd_str = getenv("TEST_HOST_PTY_FD");
  ASSERT_NE(fd_str, nullptr) << "TEST_HOST_PTY_FD environment variable not set";
  int fd;
  ASSERT_TRUE(absl::SimpleAtoi(fd_str, &fd))
      << "Invalid TEST_HOST_PTY_FD: " << fd_str;

  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  pid_t child = fork();
  if (child == 0) {
    close(sync_pipe[0]);

    // Create new session and set the imported TTY as controlling terminal.
    TEST_PCHECK(setsid() >= 0);
    // Try TIOCSCTTY with steal=0, if it fails, try with steal=1. This is
    // necessary because the host TTY might already be the controlling
    // terminal of a process on the host.
    if (ioctl(fd, TIOCSCTTY, 0) < 0) {
      TEST_PCHECK(ioctl(fd, TIOCSCTTY, 1) >= 0);
    }

    // Block SIGWINCH.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGWINCH);
    sigset_t old_set;
    TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, &old_set) == 0);

    // Notify parent we are ready.
    char c = 'r';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Wait for SIGWINCH.
    struct timespec timeout = {};
    timeout.tv_sec = 10;
    int sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(1);  // Failed to receive SIGWINCH.
    }

    // Notify parent we got it.
    c = '1';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Now wait for another SIGWINCH.
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(2);  // Failed to receive second SIGWINCH.
    }

    // Notify parent we got it.
    c = '2';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Now expect NO SIGWINCH if we set the same size.
    timeout.tv_sec = 2;
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig == SIGWINCH) {
      _exit(3);  // Unexpected SIGWINCH.
    }

    // Notify parent.
    c = '3';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Test TIOCSWINSZ from replica (self-signaling).
    struct winsize ws = {};
    TEST_PCHECK(ioctl(fd, TIOCGWINSZ, &ws) == 0);
    ws.ws_row++;
    ws.ws_col++;
    TEST_PCHECK(ioctl(fd, TIOCSWINSZ, &ws) == 0);
    timeout.tv_sec = 10;
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(4);  // Failed to receive SIGWINCH after replica TIOCSWINSZ.
    }

    // Notify parent.
    c = '4';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    close(sync_pipe[1]);
    _exit(42);  // Success.
  }
  ASSERT_GT(child, 0);
  close(sync_pipe[1]);

  // Wait for child to be ready.
  char c;
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'r');

  // Get current size.
  struct winsize ws = {};
  ASSERT_THAT(ioctl(fd, TIOCGWINSZ, &ws), SyscallSucceeds());

  // 1. Change size.
  ws.ws_row++;
  ws.ws_col++;
  ASSERT_THAT(ioctl(fd, TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '1');

  // 2. Change size again.
  ws.ws_row++;
  ws.ws_col++;
  ASSERT_THAT(ioctl(fd, TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '2');

  // 3. Set same size.
  ASSERT_THAT(ioctl(fd, TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '3');

  // Wait for child to perform self-signaling test.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '4');

  close(sync_pipe[0]);

  // Wait for child.
  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(wstatus));
  EXPECT_EQ(WEXITSTATUS(wstatus), 42);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
