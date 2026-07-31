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

#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cerrno>
#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of unbound dgram unix sockets.
using UnboundDgramUnixSocketPairTest = SocketPairTest;

TEST_P(UnboundDgramUnixSocketPairTest, BindConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, SelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->first_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, DoubleConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, GetRemoteAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addressLength = sockets->first_addr_size();
  struct sockaddr_storage address = {};
  ASSERT_THAT(getpeername(sockets->second_fd(), (struct sockaddr*)(&address),
                          &addressLength),
              SyscallSucceeds());
  EXPECT_EQ(
      0, memcmp(&address, sockets->first_addr(), sockets->first_addr_size()));
}

TEST_P(UnboundDgramUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(sendto(sockets->second_fd(), sent_data, sizeof(sent_data), 0,
                     sockets->first_addr(), sockets->first_addr_size()),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data)];
  ASSERT_THAT(ReadFd(sockets->first_fd(), received_data, sizeof(received_data)),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));
}

TEST_P(UnboundDgramUnixSocketPairTest, ZeroWriteAllowed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  char sent_data[3];
  // Send a zero length packet.
  ASSERT_THAT(write(sockets->second_fd(), sent_data, 0),
              SyscallSucceedsWithValue(0));
  // Receive the packet.
  char received_data[sizeof(sent_data)];
  ASSERT_THAT(read(sockets->first_fd(), received_data, sizeof(received_data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(UnboundDgramUnixSocketPairTest, Listen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(listen(sockets->first_fd(), 0), SyscallFailsWithErrno(ENOTSUP));
}

TEST_P(UnboundDgramUnixSocketPairTest, Accept) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(ENOTSUP));
}

TEST_P(UnboundDgramUnixSocketPairTest, SendtoWithoutConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char data = 'a';
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->second_fd(), &data, sizeof(data), 0,
                         sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceedsWithValue(sizeof(data)));
}

TEST_P(UnboundDgramUnixSocketPairTest, SendtoWithoutConnectPassCreds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  SetSoPassCred(sockets->first_fd());
  char data = 'a';
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->second_fd(), &data, sizeof(data), 0,
                         sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceedsWithValue(sizeof(data)));
  ucred creds;
  creds.pid = -1;
  char buf[sizeof(data) + 1];
  ASSERT_NO_FATAL_FAILURE(
      RecvCreds(sockets->first_fd(), &creds, buf, sizeof(buf), sizeof(data)));
  EXPECT_EQ(0, memcmp(&data, buf, sizeof(data)));
  EXPECT_THAT(getpid(), SyscallSucceedsWithValue(creds.pid));
}

// A bound datagram socket may have multiple senders. One sender shutting
// down its write side must not affect the shared receive queue: messages
// sent before the shutdown remain readable, other senders can still send,
// and a drained queue reports EAGAIN, not EOF.
TEST_P(UnboundDgramUnixSocketPairTest,
       WriteShutdownOfOneSenderDoesNotCloseQueue) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  auto second_sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // sockets->first_fd() is the receiver; both senders connect to it.
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(second_sender->first_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // The first sender sends a message and shuts down its write side: its own
  // sends must start failing.
  char first_data[3] = {'a', 'b', 'c'};
  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), first_data, sizeof(first_data), 0),
      SyscallSucceedsWithValue(sizeof(first_data)));
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_WR), SyscallSucceeds());
  EXPECT_THAT(RetryEINTR(send)(sockets->second_fd(), first_data,
                               sizeof(first_data), MSG_NOSIGNAL),
              SyscallFailsWithErrno(EPIPE));

  // The second sender is unaffected by the first sender's shutdown.
  char second_data[3] = {'x', 'y', 'z'};
  ASSERT_THAT(RetryEINTR(send)(second_sender->first_fd(), second_data,
                               sizeof(second_data), 0),
              SyscallSucceedsWithValue(sizeof(second_data)));

  // The receiver sees both messages, and then an empty queue (EAGAIN), not
  // EOF.
  char received_data[3] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                               sizeof(received_data), MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(first_data)));
  EXPECT_EQ(memcmp(first_data, received_data, sizeof(first_data)), 0);
  ASSERT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                               sizeof(received_data), MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(second_data)));
  EXPECT_EQ(memcmp(second_data, received_data, sizeof(second_data)), 0);
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                               sizeof(received_data), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// After a connected datagram socket shuts down both directions, poll on it
// reports POLLHUP. Linux sets EPOLLHUP when sk_shutdown == SHUTDOWN_MASK,
// EPOLLRDHUP|EPOLLIN for the read shutdown, and EPOLLOUT since buffer space
// is available (see unix_dgram_poll()). The bound peer it was connected to
// observes nothing.
TEST_P(UnboundDgramUnixSocketPairTest, PollAfterFullShutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RDWR), SyscallSucceeds());

  struct pollfd poll_fd = {sockets->second_fd(), POLLIN | POLLOUT | POLLRDHUP,
                           0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(poll_fd.revents, POLLIN | POLLOUT | POLLRDHUP | POLLHUP);

  // The bound peer is unaffected: nothing to report.
  struct pollfd peer_poll_fd = {sockets->first_fd(), POLLIN | POLLRDHUP, 0};
  EXPECT_THAT(RetryEINTR(poll)(&peer_poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(0));
}

// A blocked poller interested only in hangup events (events=0; POLLHUP is
// unmaskable) on a connected datagram sender must be woken by the sender's
// own concurrent full shutdown: unix_shutdown() wakes all waiters via
// sk_state_change(), and the poller re-evaluates to POLLHUP.
TEST_P(UnboundDgramUnixSocketPairTest, ShutdownWakesHangupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  const int fd = sockets->second_fd();
  struct pollfd pfd = {fd, 0, 0};
  int ret = 0;
  ScopedThread t([&] { ret = RetryEINTR(poll)(&pfd, 1, 3000); });
  // Give the poller time to block; if the shutdown still wins the race, the
  // test degrades to checking poll's entry-time readiness, which is
  // separately covered by PollAfterFullShutdown.
  absl::SleepFor(absl::Milliseconds(300));
  ASSERT_THAT(shutdown(fd, SHUT_RDWR), SyscallSucceeds());
  t.Join();

  EXPECT_EQ(ret, 1);
  EXPECT_EQ(pfd.revents, POLLHUP);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnboundDgramUnixSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(FilesystemUnboundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
