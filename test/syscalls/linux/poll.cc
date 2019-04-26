// Copyright 2018 Google LLC
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

#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <iostream>

#include "gtest/gtest.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/base_poll_test.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

class PollTest : public BasePollTest {
 protected:
  void SetUp() override { BasePollTest::SetUp(); }
  void TearDown() override { BasePollTest::TearDown(); }
};

TEST_F(PollTest, InvalidFds) {
  // fds is invalid because it's null, but we tell ppoll the length is non-zero.
  EXPECT_THAT(poll(nullptr, 1, 1), SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(poll(nullptr, -1, 1), SyscallFailsWithErrno(EINVAL));
}

TEST_F(PollTest, NullFds) {
  EXPECT_THAT(poll(nullptr, 0, 10), SyscallSucceeds());
}

TEST_F(PollTest, ZeroTimeout) {
  EXPECT_THAT(poll(nullptr, 0, 0), SyscallSucceeds());
}

// If random S/R interrupts the poll, SIGALRM may be delivered before poll
// restarts, causing the poll to hang forever.
TEST_F(PollTest, NegativeTimeout_NoRandomSave) {
  // Negative timeout mean wait forever so set a timer.
  SetTimer(absl::Milliseconds(100));
  EXPECT_THAT(poll(nullptr, 0, -1), SyscallFailsWithErrno(EINTR));
  EXPECT_TRUE(TimerFired());
}

TEST_F(PollTest, NonBlockingEventPOLLIN) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Write some data to the pipe.
  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(fd1.get(), s, strlen(s) + 1), SyscallSucceeds());

  // Poll on the reader fd with POLLIN event.
  struct pollfd poll_fd = {fd0.get(), POLLIN, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 0), SyscallSucceedsWithValue(1));

  // Should trigger POLLIN event.
  EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
}

TEST_F(PollTest, BlockingEventPOLLIN) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Start a blocking poll on the read fd.
  absl::Notification notify;
  ScopedThread t([&fd0, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {fd0.get(), POLLIN, 0};
    EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, -1), SyscallSucceedsWithValue(1));

    // Should trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
  });

  notify.WaitForNotification();
  absl::SleepFor(absl::Seconds(1.0));

  // Write some data to the pipe.
  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(fd1.get(), s, strlen(s) + 1), SyscallSucceeds());
}

TEST_F(PollTest, NonBlockingEventPOLLHUP) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Close the writer fd.
  fd1.reset();

  // Poll on the reader fd with POLLIN event.
  struct pollfd poll_fd = {fd0.get(), POLLIN, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 0), SyscallSucceedsWithValue(1));

  // Should trigger POLLHUP event.
  EXPECT_EQ(poll_fd.revents & POLLHUP, POLLHUP);

  // Should not trigger POLLIN event.
  EXPECT_EQ(poll_fd.revents & POLLIN, 0);
}

TEST_F(PollTest, BlockingEventPOLLHUP) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Start a blocking poll on the read fd.
  absl::Notification notify;
  ScopedThread t([&fd0, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {fd0.get(), POLLIN, 0};
    EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, -1), SyscallSucceedsWithValue(1));

    // Should trigger POLLHUP event.
    EXPECT_EQ(poll_fd.revents & POLLHUP, POLLHUP);

    // Should not trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, 0);
  });

  notify.WaitForNotification();
  absl::SleepFor(absl::Seconds(1.0));

  // Write some data and close the writer fd.
  fd1.reset();
}

TEST_F(PollTest, NonBlockingEventPOLLERR) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Close the reader fd.
  fd0.reset();

  // Poll on the writer fd with POLLOUT event.
  struct pollfd poll_fd = {fd1.get(), POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 0), SyscallSucceedsWithValue(1));

  // Should trigger POLLERR event.
  EXPECT_EQ(poll_fd.revents & POLLERR, POLLERR);

  // Should also trigger POLLOUT event.
  EXPECT_EQ(poll_fd.revents & POLLOUT, POLLOUT);
}

// This test will validate that if an FD is already ready on some event, whether
// it's POLLIN or POLLOUT it will not immediately return unless that's actually
// what the caller was interested in.
TEST_F(PollTest, ImmediatelyReturnOnlyOnPollEvents) {
  // Create a pipe.
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Wait for read related event on the write side of the pipe, since a write
  // is possible on fds[1] it would mean that POLLOUT would return immediately.
  // We should make sure that we're not woken up with that state that we didn't
  // specificially request.
  constexpr int kTimeoutMs = 100;
  struct pollfd poll_fd = {fd1.get(), POLLIN | POLLPRI | POLLRDHUP, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, kTimeoutMs),
              SyscallSucceedsWithValue(0));  // We should timeout.
  EXPECT_EQ(poll_fd.revents, 0);  // Nothing should be in returned events.

  // Now let's poll on POLLOUT and we should get back 1 fd as being ready and
  // it should contain POLLOUT in the revents.
  poll_fd.events = POLLOUT;
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, kTimeoutMs),
              SyscallSucceedsWithValue(1));  // 1 fd should have an event.
  EXPECT_EQ(poll_fd.revents, POLLOUT);       // POLLOUT should be in revents.
}

// This test validates that poll(2) while data is available immediately returns.
TEST_F(PollTest, PollLevelTriggered) {
  int fds[2] = {};
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, /*protocol=*/0, fds),
              SyscallSucceeds());

  FileDescriptor fd0(fds[0]);
  FileDescriptor fd1(fds[1]);

  // Write two bytes to the socket.
  const char* kBuf = "aa";
  ASSERT_THAT(RetryEINTR(send)(fd0.get(), kBuf, /*len=*/2, /*flags=*/0),
              SyscallSucceedsWithValue(2));  // 2 bytes should be written.

  // Poll(2) should immediately return as there is data available to read.
  constexpr int kInfiniteTimeout = -1;
  struct pollfd poll_fd = {fd1.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, /*nfds=*/1, kInfiniteTimeout),
              SyscallSucceedsWithValue(1));  // 1 fd should be ready to read.
  EXPECT_NE(poll_fd.revents & POLLIN, 0);

  // Read a single byte.
  char read_byte = 0;
  ASSERT_THAT(RetryEINTR(recv)(fd1.get(), &read_byte, /*len=*/1, /*flags=*/0),
              SyscallSucceedsWithValue(1));  // 1 byte should be read.
  ASSERT_EQ(read_byte, 'a');  // We should have read a single 'a'.

  // Create a separate pollfd for our second poll.
  struct pollfd poll_fd_after = {fd1.get(), POLLIN, 0};

  // Poll(2) should again immediately return since we only read one byte.
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd_after, /*nfds=*/1, kInfiniteTimeout),
              SyscallSucceedsWithValue(1));  // 1 fd should be ready to read.
  EXPECT_NE(poll_fd_after.revents & POLLIN, 0);
}

TEST_F(PollTest, Nfds) {
  // Stash value of RLIMIT_NOFILES.
  struct rlimit rlim;
  TEST_PCHECK(getrlimit(RLIMIT_NOFILE, &rlim) == 0);

  // gVisor caps the number of FDs that epoll can use beyond RLIMIT_NOFILE.
  constexpr rlim_t gVisorMax = 1048576;
  if (rlim.rlim_cur > gVisorMax) {
    rlim.rlim_cur = gVisorMax;
    TEST_PCHECK(setrlimit(RLIMIT_NOFILE, &rlim) == 0);
  }

  rlim_t max_fds = rlim.rlim_cur;
  std::cout << "Using limit: " << max_fds;

  // Create an eventfd. Since its value is initially zero, it is writable.
  FileDescriptor efd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());

  // Create the biggest possible pollfd array such that each element is valid.
  // Each entry in the 'fds' array refers to the eventfd and polls for
  // "writable" events (events=POLLOUT). This essentially guarantees that the
  // poll() is a no-op and allows negative testing of the 'nfds' parameter.
  std::vector<struct pollfd> fds(max_fds, {.fd = efd.get(), .events = POLLOUT});

  // Verify that 'nfds' up to RLIMIT_NOFILE are allowed.
  EXPECT_THAT(RetryEINTR(poll)(fds.data(), 1, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(RetryEINTR(poll)(fds.data(), max_fds / 2, 1),
              SyscallSucceedsWithValue(max_fds / 2));
  EXPECT_THAT(RetryEINTR(poll)(fds.data(), max_fds, 1),
              SyscallSucceedsWithValue(max_fds));

  // If 'nfds' exceeds RLIMIT_NOFILE then it must fail with EINVAL.
  EXPECT_THAT(poll(fds.data(), max_fds + 1, 1), SyscallFailsWithErrno(EINVAL));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
