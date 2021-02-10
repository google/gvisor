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
#include <sys/un.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of connected stream unix sockets.
using StreamUnixSocketPairTest = SocketPairTest;

TEST_P(StreamUnixSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  char data[10] = {};
  ASSERT_THAT(read(sockets->second_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, RecvmsgOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set timeout so that it will not wait for ever.
  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv,
                         sizeof(tv)),
              SyscallSucceeds());

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  char received_data[10] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(recvmsg(sockets->second_fd(), &msg, MSG_WAITALL),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosedWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

TEST_P(StreamUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  constexpr char kStr[] = "abc";
  ASSERT_THAT(sendto(sockets->second_fd(), kStr, 3, 0, (struct sockaddr*)&addr,
                     sizeof(addr)),
              SyscallFailsWithErrno(EISCONN));
}

TEST_P(StreamUnixSocketPairTest, SetAndGetSocketLinger) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct linger sl = {1, 5};
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)),
      SyscallSucceedsWithValue(0));

  struct linger got_linger = {};
  socklen_t length = sizeof(sl);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_LINGER,
                         &got_linger, &length),
              SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got_linger));
  EXPECT_EQ(0, memcmp(&got_linger, &sl, length));
}

TEST_P(StreamUnixSocketPairTest, GetSocketAcceptConn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
      SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

TEST_P(StreamUnixSocketPairTest, SetSocketSendBuf) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  auto s = sockets->first_fd();
  int max = 0;
  int min = 0;
  {
    // Discover maxmimum buffer size by setting to a really large value.
    constexpr int kRcvBufSz = INT_MAX;
    ASSERT_THAT(
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by setting it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(
      setsockopt(s, SOL_SOCKET, SO_SNDBUF, &quarter_sz, sizeof(quarter_sz)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  // Linux doubles the value set by SO_SNDBUF/SO_SNDBUF.
  quarter_sz *= 2;
  ASSERT_EQ(quarter_sz, val);
}

TEST_P(StreamUnixSocketPairTest, IncreasedSocketSendBufUnblocksWrites) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int sock = sockets->first_fd();
  int buf_size = 0;
  socklen_t buf_size_len = sizeof(buf_size);
  ASSERT_THAT(getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, &buf_size_len),
              SyscallSucceeds());
  int opts;
  ASSERT_THAT(opts = fcntl(sock, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(sock, F_SETFL, opts), SyscallSucceeds());

  std::vector<char> buf(buf_size / 4);
  // Write till the socket buffer is full.
  while (RetryEINTR(send)(sock, buf.data(), buf.size(), 0) != -1) {
    // Sleep to give linux a chance to move data from the send buffer to the
    // receive buffer.
    absl::SleepFor(absl::Milliseconds(10));  // 10ms.
  }
  // The last error should have been EWOULDBLOCK.
  ASSERT_EQ(errno, EWOULDBLOCK);

  // Now increase the socket send buffer.
  buf_size = buf_size * 2;
  ASSERT_THAT(
      setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)),
      SyscallSucceeds());

  // The send should succeed again.
  ASSERT_THAT(RetryEINTR(send)(sock, buf.data(), buf.size(), 0),
              SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, StreamUnixSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(UnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(FilesystemBoundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractBoundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK}))))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
