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

#include <fcntl.h>
#ifdef __linux__
#include <linux/filter.h>
#endif  // __linux__
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <limits>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<sockaddr_storage> InetLoopbackAddr(int family) {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  addr.ss_family = family;
  switch (family) {
    case AF_INET:
      reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr.s_addr =
          htonl(INADDR_LOOPBACK);
      break;
    case AF_INET6:
      reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr =
          in6addr_loopback;
      break;
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
  return addr;
}

static void FillSocketBuffers(int sender, int receiver) {
  // Set the FD to O_NONBLOCK.
  int opts;
  int orig_opts;
  ASSERT_THAT(opts = fcntl(sender, F_GETFL), SyscallSucceeds());
  orig_opts = opts;
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(sender, F_SETFL, opts), SyscallSucceeds());

  // Set TCP_NODELAY, which will cause linux to fill the receive buffer from the
  // send buffer as quickly as possibly. This way we can fill up both buffers
  // faster.
  constexpr int tcp_nodelay_flag = 1;
  ASSERT_THAT(setsockopt(sender, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_flag,
                         sizeof(tcp_nodelay_flag)),
              SyscallSucceeds());

  // Set a 256KB send/receive buffer.
  int buf_sz = 1 << 18;
  EXPECT_THAT(
      setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz)),
      SyscallSucceedsWithValue(0));
  EXPECT_THAT(
      setsockopt(sender, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz)),
      SyscallSucceedsWithValue(0));

  // Create a large buffer that will be used for sending.
  std::vector<char> buf(1 << 16);

  // Write until we receive an error.
  while (RetryEINTR(send)(sender, buf.data(), buf.size(), 0) != -1) {
    // Sleep to give linux a chance to move data from the send buffer to the
    // receive buffer.
    usleep(10000);  // 10ms.
  }
  // The last error should have been EWOULDBLOCK.
  ASSERT_EQ(errno, EWOULDBLOCK);

  // Restore the fcntl opts
  ASSERT_THAT(fcntl(sender, F_SETFL, orig_opts), SyscallSucceeds());
}

// Fixture for tests parameterized by the address family to use (AF_INET and
// AF_INET6) when creating sockets.
class TcpSocketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates three sockets that will be used by test cases -- a listener, one
  // that connects, and the accepted one.
  void SetUp() override;

  // Closes the sockets created by SetUp().
  void TearDown() override;

  // Listening socket.
  int listener_ = -1;

  // Socket connected via connect().
  int first_fd = -1;

  // Socket connected via accept().
  int second_fd = -1;

  // Initial size of the send buffer.
  int sendbuf_size_ = -1;
};

void TcpSocketTest::SetUp() {
  ASSERT_THAT(listener_ = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());

  ASSERT_THAT(first_fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listener_, AsSockAddr(&addr), addrlen), SyscallSucceeds());

  ASSERT_THAT(listen(listener_, SOMAXCONN), SyscallSucceeds());

  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listener_, AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(first_fd, AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  // Get the initial send buffer size.
  socklen_t optlen = sizeof(sendbuf_size_);
  ASSERT_THAT(
      getsockopt(first_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf_size_, &optlen),
      SyscallSucceeds());

  // Accept the connection.
  ASSERT_THAT(second_fd = RetryEINTR(accept)(listener_, nullptr, nullptr),
              SyscallSucceeds());
}

void TcpSocketTest::TearDown() {
  EXPECT_THAT(close(listener_), SyscallSucceeds());
  if (first_fd >= 0) {
    EXPECT_THAT(close(first_fd), SyscallSucceeds());
  }
  if (second_fd >= 0) {
    EXPECT_THAT(close(second_fd), SyscallSucceeds());
  }
}

TEST_P(TcpSocketTest, ConnectOnEstablishedConnection) {
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  ASSERT_THAT(connect(first_fd, reinterpret_cast<const struct sockaddr*>(&addr),
                      addrlen),
              SyscallFailsWithErrno(EISCONN));
  ASSERT_THAT(connect(second_fd,
                      reinterpret_cast<const struct sockaddr*>(&addr), addrlen),
              SyscallFailsWithErrno(EISCONN));
}

TEST_P(TcpSocketTest, ShutdownWriteInTimeWait) {
  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallSucceeds());
  EXPECT_THAT(shutdown(first_fd, SHUT_RDWR), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));  // Wait to enter TIME_WAIT.
  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(TcpSocketTest, ShutdownWriteInFinWait1) {
  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallSucceeds());
  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallSucceeds());
  absl::SleepFor(absl::Seconds(1));  // Wait to enter FIN-WAIT2.
  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallSucceeds());
}

TEST_P(TcpSocketTest, DataCoalesced) {
  char buf[10];

  // Write in two steps.
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf) / 2),
              SyscallSucceedsWithValue(sizeof(buf) / 2));
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf) / 2),
              SyscallSucceedsWithValue(sizeof(buf) / 2));

  // Allow stack to process both packets.
  absl::SleepFor(absl::Seconds(1));

  // Read in one shot.
  EXPECT_THAT(RetryEINTR(recv)(second_fd, buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(TcpSocketTest, SenderAddressIgnored) {
  char buf[3];
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));

  ASSERT_THAT(RetryEINTR(recvfrom)(second_fd, buf, sizeof(buf), 0,
                                   AsSockAddr(&addr), &addrlen),
              SyscallSucceedsWithValue(3));

  // Check that addr remains zeroed-out.
  const char* ptr = reinterpret_cast<char*>(&addr);
  for (size_t i = 0; i < sizeof(addr); i++) {
    EXPECT_EQ(ptr[i], 0);
  }
}

TEST_P(TcpSocketTest, SenderAddressIgnoredOnPeek) {
  char buf[3];
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));

  ASSERT_THAT(RetryEINTR(recvfrom)(second_fd, buf, sizeof(buf), MSG_PEEK,
                                   AsSockAddr(&addr), &addrlen),
              SyscallSucceedsWithValue(3));

  // Check that addr remains zeroed-out.
  const char* ptr = reinterpret_cast<char*>(&addr);
  for (size_t i = 0; i < sizeof(addr); i++) {
    EXPECT_EQ(ptr[i], 0);
  }
}

TEST_P(TcpSocketTest, SendtoAddressIgnored) {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  addr.ss_family = GetParam();  // FIXME(b/63803955)

  char data = '\0';
  EXPECT_THAT(RetryEINTR(sendto)(first_fd, &data, sizeof(data), 0,
                                 AsSockAddr(&addr), sizeof(addr)),
              SyscallSucceedsWithValue(1));
}

TEST_P(TcpSocketTest, WritevZeroIovec) {
  // 2 bytes just to be safe and have vecs[1] not point to something random
  // (even though length is 0).
  char buf[2];
  char recv_buf[1];

  // Construct a vec where the final vector is of length 0.
  iovec vecs[2] = {};
  vecs[0].iov_base = buf;
  vecs[0].iov_len = 1;
  vecs[1].iov_base = buf + 1;
  vecs[1].iov_len = 0;

  EXPECT_THAT(RetryEINTR(writev)(first_fd, vecs, 2),
              SyscallSucceedsWithValue(1));

  EXPECT_THAT(RetryEINTR(recv)(second_fd, recv_buf, 1, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(memcmp(recv_buf, buf, 1), 0);
}

TEST_P(TcpSocketTest, ZeroWriteAllowed) {
  char buf[3];
  // Send a zero length packet.
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, 0), SyscallSucceedsWithValue(0));
  // Verify that there is no packet available.
  EXPECT_THAT(RetryEINTR(recv)(second_fd, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that a non-blocking write with a buffer that is larger than the send
// buffer size will not actually write the whole thing at once. Regression test
// for b/64438887.
TEST_P(TcpSocketTest, NonblockingLargeWrite) {
  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(first_fd, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(first_fd, F_SETFL, opts), SyscallSucceeds());

  // Allocate a buffer three times the size of the send buffer. We do this with
  // a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> buf(size);

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = RetryEINTR(write)(first_fd, buf.data(), size),
              SyscallSucceeds());

  // We should have written something, but not the whole thing.
  EXPECT_GT(n, 0);
  EXPECT_LT(n, size);
}

// Test that a blocking write with a buffer that is larger than the send buffer
// will block until the entire buffer is sent.
TEST_P(TcpSocketTest, BlockingLargeWrite) {
  // Allocate a buffer three times the size of the send buffer on the heap. We
  // do this as a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> writebuf(size);

  // Start reading the response in a loop.
  int read_bytes = 0;
  ScopedThread t([this, &read_bytes]() {
    // Avoid interrupting the blocking write in main thread.
    const DisableSave disable_save;

    // Take ownership of the FD so that we close it on failure. This will
    // unblock the blocking write below.
    FileDescriptor fd(second_fd);
    second_fd = -1;

    char readbuf[2500] = {};
    int n = -1;
    while (n != 0) {
      ASSERT_THAT(n = RetryEINTR(read)(fd.get(), &readbuf, sizeof(readbuf)),
                  SyscallSucceeds());
      read_bytes += n;
    }
  });

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = WriteFd(first_fd, writebuf.data(), size), SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, size);
  EXPECT_THAT(close(first_fd), SyscallSucceedsWithValue(0));
  first_fd = -1;
  t.Join();

  // We should have read the whole thing.
  EXPECT_EQ(read_bytes, size);
}

// Test that a send with MSG_DONTWAIT flag and buffer that larger than the send
// buffer size will not write the whole thing.
TEST_P(TcpSocketTest, LargeSendDontWait) {
  // Allocate a buffer three times the size of the send buffer. We do this on
  // with a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> buf(size);

  // Try to write the whole thing with MSG_DONTWAIT flag, which can
  // return a partial write.
  int n;
  ASSERT_THAT(n = RetryEINTR(send)(first_fd, buf.data(), size, MSG_DONTWAIT),
              SyscallSucceeds());

  // We should have written something, but not the whole thing.
  EXPECT_GT(n, 0);
  EXPECT_LT(n, size);
}

// Test that a send on a non-blocking socket with a buffer that larger than the
// send buffer will not write the whole thing at once.
TEST_P(TcpSocketTest, NonblockingLargeSend) {
  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(first_fd, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(first_fd, F_SETFL, opts), SyscallSucceeds());

  // Allocate a buffer three times the size of the send buffer. We do this on
  // with a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> buf(size);

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = RetryEINTR(send)(first_fd, buf.data(), size, 0),
              SyscallSucceeds());

  // We should have written something, but not the whole thing.
  EXPECT_GT(n, 0);
  EXPECT_LT(n, size);
}

// Same test as above, but calls send instead of write.
TEST_P(TcpSocketTest, BlockingLargeSend) {
  // Allocate a buffer three times the size of the send buffer. We do this on
  // with a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> writebuf(size);

  // Start reading the response in a loop.
  int read_bytes = 0;
  ScopedThread t([this, &read_bytes]() {
    // Avoid interrupting the blocking write in main thread.
    const DisableSave disable_save;

    // Take ownership of the FD so that we close it on failure. This will
    // unblock the blocking write below.
    FileDescriptor fd(second_fd);
    second_fd = -1;

    char readbuf[2500] = {};
    int n = -1;
    while (n != 0) {
      ASSERT_THAT(n = RetryEINTR(read)(fd.get(), &readbuf, sizeof(readbuf)),
                  SyscallSucceeds());
      read_bytes += n;
    }
  });

  // Try to send the whole thing.
  int n;
  ASSERT_THAT(n = SendFd(first_fd, writebuf.data(), size, 0),
              SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, size);
  EXPECT_THAT(close(first_fd), SyscallSucceedsWithValue(0));
  first_fd = -1;
  t.Join();

  // We should have read the whole thing.
  EXPECT_EQ(read_bytes, size);
}

// Test that polling on a socket with a full send buffer will block.
TEST_P(TcpSocketTest, PollWithFullBufferBlocks) {
  FillSocketBuffers(first_fd, second_fd);
  // Now polling on the FD with a timeout should return 0 corresponding to no
  // FDs ready.
  struct pollfd poll_fd = {first_fd, POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10), SyscallSucceedsWithValue(0));
}

TEST_P(TcpSocketTest, ClosedWriteBlockingSocket) {
  FillSocketBuffers(first_fd, second_fd);
  constexpr int timeout = 10;
  struct timeval tv = {.tv_sec = timeout, .tv_usec = 0};
  EXPECT_THAT(setsockopt(first_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  struct timespec begin;
  struct timespec end;
  const DisableSave disable_save;  // Timing-related.
  EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &begin), SyscallSucceeds());

  ScopedThread send_thread([this]() {
    char send_byte;
    // Expect the send() to be blocked until receive timeout.
    ASSERT_THAT(RetryEINTR(send)(first_fd, &send_byte, sizeof(send_byte), 0),
                SyscallFailsWithErrno(EAGAIN));
  });

  // Wait for the thread to be blocked on write.
  absl::SleepFor(absl::Milliseconds(250));
  // Socket close does not have any effect on a blocked write.
  ASSERT_THAT(close(first_fd), SyscallSucceeds());
  // Indicate to the cleanup routine that we are already closed.
  first_fd = -1;

  send_thread.Join();

  EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &end), SyscallSucceeds());
  // Check the lower bound on the timeout.  Checking for an upper bound is
  // fragile because Linux can overrun the timeout due to scheduling delays.
  EXPECT_GT(ms_elapsed(begin, end), timeout * 1000 - 1);
}

TEST_P(TcpSocketTest, ClosedReadBlockingSocket) {
  constexpr int timeout = 10;
  struct timeval tv = {.tv_sec = timeout, .tv_usec = 0};
  EXPECT_THAT(setsockopt(first_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  struct timespec begin;
  struct timespec end;
  const DisableSave disable_save;  // Timing-related.
  EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &begin), SyscallSucceeds());

  ScopedThread read_thread([this]() {
    char read_byte;
    // Expect the read() to be blocked until receive timeout.
    ASSERT_THAT(read(first_fd, &read_byte, sizeof(read_byte)),
                SyscallFailsWithErrno(EAGAIN));
  });

  // Wait for the thread to be blocked on read.
  absl::SleepFor(absl::Milliseconds(250));
  // Socket close does not have any effect on a blocked read.
  ASSERT_THAT(close(first_fd), SyscallSucceeds());
  // Indicate to the cleanup routine that we are already closed.
  first_fd = -1;

  read_thread.Join();

  EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &end), SyscallSucceeds());
  // Check the lower bound on the timeout.  Checking for an upper bound is
  // fragile because Linux can overrun the timeout due to scheduling delays.
  EXPECT_GT(ms_elapsed(begin, end), timeout * 1000 - 1);
}

TEST_P(TcpSocketTest, MsgTrunc) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(first_fd, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(second_fd, received_data,
                               sizeof(received_data) / 2, MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));
}

// MSG_CTRUNC is a return flag but linux allows it to be set on input flags
// without returning an error.
TEST_P(TcpSocketTest, MsgTruncWithCtrunc) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(first_fd, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(second_fd, received_data, sizeof(received_data) / 2,
                       MSG_TRUNC | MSG_CTRUNC),
      SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));
}

// This test will verify that MSG_CTRUNC doesn't do anything when specified
// on input.
TEST_P(TcpSocketTest, MsgTruncWithCtruncOnly) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(first_fd, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(second_fd, received_data,
                               sizeof(received_data) / 2, MSG_CTRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Since MSG_CTRUNC here had no affect, it should not behave like MSG_TRUNC.
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));
}

TEST_P(TcpSocketTest, MsgTruncLargeSize) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(first_fd, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data) * 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(second_fd, received_data, sizeof(received_data),
                               MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));
}

TEST_P(TcpSocketTest, MsgTruncPeek) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(first_fd, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(second_fd, received_data,
                               sizeof(received_data) / 2, MSG_TRUNC | MSG_PEEK),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));

  // Check that we can still get all of the data.
  ASSERT_THAT(
      RetryEINTR(recv)(second_fd, received_data, sizeof(received_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(TcpSocketTest, NoDelayDefault) {
  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(first_fd, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TcpSocketTest, SetNoDelay) {
  ASSERT_THAT(setsockopt(first_fd, IPPROTO_TCP, TCP_NODELAY, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(first_fd, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(first_fd, IPPROTO_TCP, TCP_NODELAY, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceeds());

  EXPECT_THAT(getsockopt(first_fd, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

#ifndef TCP_INQ
#define TCP_INQ 36
#endif

TEST_P(TcpSocketTest, TcpInqSetSockOpt) {
  char buf[1024];
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  // TCP_INQ is disabled by default.
  int val = -1;
  socklen_t slen = sizeof(val);
  EXPECT_THAT(getsockopt(second_fd, SOL_TCP, TCP_INQ, &val, &slen),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(val, 0);

  // Try to set TCP_INQ.
  val = 1;
  EXPECT_THAT(setsockopt(second_fd, SOL_TCP, TCP_INQ, &val, sizeof(val)),
              SyscallSucceedsWithValue(0));
  val = -1;
  slen = sizeof(val);
  EXPECT_THAT(getsockopt(second_fd, SOL_TCP, TCP_INQ, &val, &slen),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(val, 1);

  // Try to unset TCP_INQ.
  val = 0;
  EXPECT_THAT(setsockopt(second_fd, SOL_TCP, TCP_INQ, &val, sizeof(val)),
              SyscallSucceedsWithValue(0));
  val = -1;
  slen = sizeof(val);
  EXPECT_THAT(getsockopt(second_fd, SOL_TCP, TCP_INQ, &val, &slen),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(val, 0);
}

TEST_P(TcpSocketTest, TcpInq) {
  char buf[1024];
  // Write more than one TCP segment.
  int size = sizeof(buf);
  int kChunk = sizeof(buf) / 4;
  for (int i = 0; i < size; i += kChunk) {
    ASSERT_THAT(RetryEINTR(write)(first_fd, buf, kChunk),
                SyscallSucceedsWithValue(kChunk));
  }

  int val = 1;
  kChunk = sizeof(buf) / 2;
  EXPECT_THAT(setsockopt(second_fd, SOL_TCP, TCP_INQ, &val, sizeof(val)),
              SyscallSucceedsWithValue(0));

  // Wait when all data will be in the received queue.
  while (true) {
    ASSERT_THAT(ioctl(second_fd, TIOCINQ, &size), SyscallSucceeds());
    if (size == sizeof(buf)) {
      break;
    }
    absl::SleepFor(absl::Milliseconds(10));
  }

  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(sizeof(int)));
  size = sizeof(buf);
  struct iovec iov;
  for (int i = 0; size != 0; i += kChunk) {
    msg.msg_control = &control[0];
    msg.msg_controllen = control.size();

    iov.iov_base = buf;
    iov.iov_len = kChunk;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ASSERT_THAT(RetryEINTR(recvmsg)(second_fd, &msg, 0),
                SyscallSucceedsWithValue(kChunk));
    size -= kChunk;

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cmsg, nullptr);
    ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
    ASSERT_EQ(cmsg->cmsg_level, SOL_TCP);
    ASSERT_EQ(cmsg->cmsg_type, TCP_INQ);

    int inq = 0;
    memcpy(&inq, CMSG_DATA(cmsg), sizeof(int));
    ASSERT_EQ(inq, size);
  }
}

TEST_P(TcpSocketTest, Tiocinq) {
  char buf[1024];
  size_t size = sizeof(buf);
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, size),
              SyscallSucceedsWithValue(size));

  uint32_t seed = time(nullptr);
  const size_t max_chunk = size / 10;
  while (size > 0) {
    size_t chunk = (rand_r(&seed) % max_chunk) + 1;
    ssize_t read =
        RetryEINTR(recvfrom)(second_fd, buf, chunk, 0, nullptr, nullptr);
    ASSERT_THAT(read, SyscallSucceeds());
    size -= read;

    int inq = 0;
    ASSERT_THAT(ioctl(second_fd, TIOCINQ, &inq), SyscallSucceeds());
    ASSERT_EQ(inq, size);
  }
}

TEST_P(TcpSocketTest, TcpSCMPriority) {
  char buf[1024];
  ASSERT_THAT(RetryEINTR(write)(first_fd, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  int val = 1;
  EXPECT_THAT(setsockopt(second_fd, SOL_TCP, TCP_INQ, &val, sizeof(val)),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(
      setsockopt(second_fd, SOL_SOCKET, SO_TIMESTAMP, &val, sizeof(val)),
      SyscallSucceedsWithValue(0));

  struct msghdr msg = {};
  std::vector<char> control(
      CMSG_SPACE(sizeof(struct timeval) + CMSG_SPACE(sizeof(int))));
  struct iovec iov;
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  ASSERT_THAT(RetryEINTR(recvmsg)(second_fd, &msg, 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  // TODO(b/78348848): SO_TIMESTAMP isn't implemented for TCP sockets.
  if (!IsRunningOnGvisor() || cmsg->cmsg_level == SOL_SOCKET) {
    ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
    ASSERT_EQ(cmsg->cmsg_type, SO_TIMESTAMP);
    ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(struct timeval)));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    ASSERT_NE(cmsg, nullptr);
  }
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_TCP);
  ASSERT_EQ(cmsg->cmsg_type, TCP_INQ);

  int inq = 0;
  memcpy(&inq, CMSG_DATA(cmsg), sizeof(int));
  ASSERT_EQ(inq, 0);

  cmsg = CMSG_NXTHDR(&msg, cmsg);
  ASSERT_EQ(cmsg, nullptr);
}

TEST_P(TcpSocketTest, TimeWaitPollHUP) {
  shutdown(first_fd, SHUT_RDWR);
  ScopedThread t([&]() {
    constexpr int kTimeout = 10000;
    constexpr int16_t want_events = POLLHUP;
    struct pollfd pfd = {
        .fd = first_fd,
        .events = want_events,
    };
    ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
  });
  shutdown(second_fd, SHUT_RDWR);
  t.Join();
  // At this point first_fd should be in TIME-WAIT and polling for POLLHUP
  // should return with 1 FD.
  constexpr int kTimeout = 10000;
  constexpr int16_t want_events = POLLHUP;
  struct pollfd pfd = {
      .fd = first_fd,
      .events = want_events,
  };
  ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, TcpSocketTest,
                         ::testing::Values(AF_INET, AF_INET6));

// Fixture for tests parameterized by address family that don't want the fixture
// to do things.
using SimpleTcpSocketTest = ::testing::TestWithParam<int>;

TEST_P(SimpleTcpSocketTest, SendUnconnected) {
  int fd;
  ASSERT_THAT(fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());
  FileDescriptor sock_fd(fd);

  char data = '\0';
  EXPECT_THAT(RetryEINTR(send)(fd, &data, sizeof(data), 0),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(SimpleTcpSocketTest, SendtoWithoutAddressUnconnected) {
  int fd;
  ASSERT_THAT(fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());
  FileDescriptor sock_fd(fd);

  char data = '\0';
  EXPECT_THAT(RetryEINTR(sendto)(fd, &data, sizeof(data), 0, nullptr, 0),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(SimpleTcpSocketTest, SendtoWithAddressUnconnected) {
  int fd;
  ASSERT_THAT(fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());
  FileDescriptor sock_fd(fd);

  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  char data = '\0';
  EXPECT_THAT(RetryEINTR(sendto)(fd, &data, sizeof(data), 0, AsSockAddr(&addr),
                                 sizeof(addr)),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(SimpleTcpSocketTest, GetPeerNameUnconnected) {
  int fd;
  ASSERT_THAT(fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());
  FileDescriptor sock_fd(fd);

  sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(fd, AsSockAddr(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(TcpSocketTest, FullBuffer) {
  // Set both FDs to be blocking.
  int flags = 0;
  ASSERT_THAT(flags = fcntl(first_fd, F_GETFL), SyscallSucceeds());
  EXPECT_THAT(fcntl(first_fd, F_SETFL, flags & ~O_NONBLOCK), SyscallSucceeds());
  flags = 0;
  ASSERT_THAT(flags = fcntl(second_fd, F_GETFL), SyscallSucceeds());
  EXPECT_THAT(fcntl(second_fd, F_SETFL, flags & ~O_NONBLOCK),
              SyscallSucceeds());

  // 2500 was chosen as a small value that can be set on Linux.
  int set_snd = 2500;
  EXPECT_THAT(
      setsockopt(first_fd, SOL_SOCKET, SO_SNDBUF, &set_snd, sizeof(set_snd)),
      SyscallSucceedsWithValue(0));
  int get_snd = -1;
  socklen_t get_snd_len = sizeof(get_snd);
  EXPECT_THAT(
      getsockopt(first_fd, SOL_SOCKET, SO_SNDBUF, &get_snd, &get_snd_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_snd_len, sizeof(get_snd));
  EXPECT_GT(get_snd, 0);

  // 2500 was chosen as a small value that can be set on Linux and gVisor.
  int set_rcv = 2500;
  EXPECT_THAT(
      setsockopt(second_fd, SOL_SOCKET, SO_RCVBUF, &set_rcv, sizeof(set_rcv)),
      SyscallSucceedsWithValue(0));
  int get_rcv = -1;
  socklen_t get_rcv_len = sizeof(get_rcv);
  EXPECT_THAT(
      getsockopt(second_fd, SOL_SOCKET, SO_RCVBUF, &get_rcv, &get_rcv_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_rcv_len, sizeof(get_rcv));
  EXPECT_GE(get_rcv, 2500);

  // Quick sanity test.
  EXPECT_LT(get_snd + get_rcv, 2500 * IOV_MAX);

  char data[2500] = {};
  std::vector<struct iovec> iovecs;
  for (int i = 0; i < IOV_MAX; i++) {
    struct iovec iov = {};
    iov.iov_base = data;
    iov.iov_len = sizeof(data);
    iovecs.push_back(iov);
  }
  ScopedThread t([this, &iovecs]() {
    int result = -1;
    EXPECT_THAT(
        result = RetryEINTR(writev)(first_fd, iovecs.data(), iovecs.size()),
        SyscallSucceeds());
    EXPECT_GT(result, 1);
    EXPECT_LT(result, sizeof(data) * iovecs.size());
  });

  char recv = 0;
  EXPECT_THAT(RetryEINTR(read)(second_fd, &recv, 1),
              SyscallSucceedsWithValue(1));
  EXPECT_THAT(close(second_fd), SyscallSucceedsWithValue(0));
  second_fd = -1;
}

TEST_P(TcpSocketTest, PollAfterShutdown) {
  ScopedThread client_thread([this]() {
    EXPECT_THAT(shutdown(first_fd, SHUT_WR), SyscallSucceedsWithValue(0));
    struct pollfd poll_fd = {first_fd, POLLIN | POLLERR | POLLHUP, 0};
    EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
                SyscallSucceedsWithValue(1));
  });

  EXPECT_THAT(shutdown(second_fd, SHUT_WR), SyscallSucceedsWithValue(0));
  struct pollfd poll_fd = {second_fd, POLLIN | POLLERR | POLLHUP, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectRetry) {
  const FileDescriptor listener =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port but don't listen yet.
  ASSERT_THAT(bind(listener.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  // Get the address we're bound to, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listener.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  FileDescriptor connector =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Verify that connect fails.
  ASSERT_THAT(RetryEINTR(connect)(connector.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(ECONNREFUSED));

  // Now start listening
  ASSERT_THAT(listen(listener.get(), SOMAXCONN), SyscallSucceeds());

  // TODO(gvisor.dev/issue/3828): Issuing connect() again on a socket that
  //   failed first connect should succeed.
  if (IsRunningOnGvisor()) {
    ASSERT_THAT(
        RetryEINTR(connect)(connector.get(), AsSockAddr(&addr), addrlen),
        SyscallFailsWithErrno(ECONNABORTED));
    return;
  }

  // Verify that connect now succeeds.
  ASSERT_THAT(RetryEINTR(connect)(connector.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  // Accept the connection.
  const FileDescriptor accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listener.get(), nullptr, nullptr));
}

// nonBlockingConnectNoListener returns a socket on which a connect that is
// expected to fail has been issued.
PosixErrorOr<FileDescriptor> nonBlockingConnectNoListener(const int family,
                                                          sockaddr_storage addr,
                                                          socklen_t addrlen) {
  // We will first create a socket and bind to ensure we bind a port but will
  // not call listen on this socket.
  // Then we will create a new socket that will connect to the port bound by
  // the first socket and that shoud fail.
  constexpr int sock_type = SOCK_STREAM | SOCK_NONBLOCK;
  int b_sock;
  RETURN_ERROR_IF_SYSCALL_FAIL(b_sock = socket(family, sock_type, IPPROTO_TCP));
  FileDescriptor b(b_sock);
  EXPECT_THAT(bind(b.get(), AsSockAddr(&addr), addrlen), SyscallSucceeds());

  // Get the address bound by the listening socket.
  EXPECT_THAT(getsockname(b.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  // Now create another socket and issue a connect on this one. This connect
  // should fail as there is no listener.
  int c_sock;
  RETURN_ERROR_IF_SYSCALL_FAIL(c_sock = socket(family, sock_type, IPPROTO_TCP));
  FileDescriptor s(c_sock);

  // Now connect to the bound address and this should fail as nothing
  // is listening on the bound address.
  EXPECT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  // Wait for the connect to fail.
  struct pollfd poll_fd = {s.get(), POLLERR, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 1000), SyscallSucceedsWithValue(1));
  return std::move(s);
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectNoListener) {
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      nonBlockingConnectNoListener(GetParam(), addr, addrlen).ValueOrDie();

  int err;
  socklen_t optlen = sizeof(err);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());
  ASSERT_THAT(optlen, sizeof(err));
  EXPECT_EQ(err, ECONNREFUSED);

  unsigned char c;
  ASSERT_THAT(read(s.get(), &c, sizeof(c)), SyscallSucceedsWithValue(0));
  int opts;
  EXPECT_THAT(opts = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  opts &= ~O_NONBLOCK;
  EXPECT_THAT(fcntl(s.get(), F_SETFL, opts), SyscallSucceeds());
  // Try connecting again.
  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(ECONNABORTED));
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectNoListenerRead) {
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      nonBlockingConnectNoListener(GetParam(), addr, addrlen).ValueOrDie();

  unsigned char c;
  ASSERT_THAT(read(s.get(), &c, 1), SyscallFailsWithErrno(ECONNREFUSED));
  ASSERT_THAT(read(s.get(), &c, 1), SyscallSucceedsWithValue(0));
  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(ECONNABORTED));
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectNoListenerPeek) {
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      nonBlockingConnectNoListener(GetParam(), addr, addrlen).ValueOrDie();

  unsigned char c;
  ASSERT_THAT(recv(s.get(), &c, 1, MSG_PEEK),
              SyscallFailsWithErrno(ECONNREFUSED));
  ASSERT_THAT(recv(s.get(), &c, 1, MSG_PEEK), SyscallSucceedsWithValue(0));
  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(ECONNABORTED));
}

TEST_P(SimpleTcpSocketTest, SelfConnectSendRecv) {
  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT((bind)(s.get(), AsSockAddr(&addr), addrlen), SyscallSucceeds());
  // Get the bound port.
  ASSERT_THAT(getsockname(s.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  constexpr int kBufSz = 1 << 20;  // 1 MiB
  std::vector<char> writebuf(kBufSz);

  // Start reading the response in a loop.
  int read_bytes = 0;
  ScopedThread t([&s, &read_bytes]() {
    // Too many syscalls.
    const DisableSave disable_save;

    char readbuf[2500] = {};
    int n = -1;
    while (n != 0) {
      ASSERT_THAT(n = RetryEINTR(read)(s.get(), &readbuf, sizeof(readbuf)),
                  SyscallSucceeds());
      read_bytes += n;
    }
  });

  // Try to send the whole thing.
  int n;
  ASSERT_THAT(n = SendFd(s.get(), writebuf.data(), kBufSz, 0),
              SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, kBufSz);
  EXPECT_THAT(shutdown(s.get(), SHUT_WR), SyscallSucceedsWithValue(0));
  t.Join();

  // We should have read the whole thing.
  EXPECT_EQ(read_bytes, kBufSz);
}

TEST_P(SimpleTcpSocketTest, SelfConnectSend) {
  // Ensure the write size is not larger than the write buffer.
  size_t write_size = 512 << 10;  // 512 KiB.
  constexpr char kWMem[] = "/proc/sys/net/ipv4/tcp_wmem";
  std::string wmem = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kWMem));
  std::vector<std::string> vals = absl::StrSplit(wmem, absl::ByAnyChar("\t "));
  size_t max_wmem;
  ASSERT_TRUE(absl::SimpleAtoi(vals.back(), &max_wmem));
  if (write_size > max_wmem) {
    write_size = max_wmem;
  }

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  constexpr int max_seg = 256;
  ASSERT_THAT(
      setsockopt(s.get(), SOL_TCP, TCP_MAXSEG, &max_seg, sizeof(max_seg)),
      SyscallSucceeds());

  ASSERT_THAT(bind(s.get(), AsSockAddr(&addr), addrlen), SyscallSucceeds());
  // Get the bound port.
  ASSERT_THAT(getsockname(s.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  std::vector<char> writebuf(write_size);

  // Try to send the whole thing.
  int n;
  ASSERT_THAT(n = SendFd(s.get(), writebuf.data(), writebuf.size(), 0),
              SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, writebuf.size());
  EXPECT_THAT(shutdown(s.get(), SHUT_WR), SyscallSucceedsWithValue(0));
}

void NonBlockingConnect(int family, int16_t pollMask) {
  const FileDescriptor listener =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(family, SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr = ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(family));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listener.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(listen(listener.get(), SOMAXCONN), SyscallSucceeds());

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(family, SOCK_STREAM, IPPROTO_TCP));

  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s.get(), F_SETFL, opts), SyscallSucceeds());

  ASSERT_THAT(getsockname(listener.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  int t;
  ASSERT_THAT(t = RetryEINTR(accept)(listener.get(), nullptr, nullptr),
              SyscallSucceeds());

  struct pollfd poll_fd = {s.get(), pollMask, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));

  int err;
  socklen_t optlen = sizeof(err);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());

  EXPECT_EQ(err, 0);

  EXPECT_THAT(close(t), SyscallSucceeds());
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnect_PollOut) {
  NonBlockingConnect(GetParam(), POLLOUT);
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnect_PollWrNorm) {
  NonBlockingConnect(GetParam(), POLLWRNORM);
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnect_PollWrNorm_PollOut) {
  NonBlockingConnect(GetParam(), POLLWRNORM | POLLOUT);
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectRemoteClose) {
  const FileDescriptor listener =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listener.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(listen(listener.get(), SOMAXCONN), SyscallSucceeds());

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(GetParam(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));

  ASSERT_THAT(getsockname(listener.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  int t;
  ASSERT_THAT(t = RetryEINTR(accept)(listener.get(), nullptr, nullptr),
              SyscallSucceeds());

  EXPECT_THAT(close(t), SyscallSucceeds());

  // Now polling on the FD with a timeout should return 0 corresponding to no
  // FDs ready.
  struct pollfd poll_fd = {s.get(), POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(EISCONN));
}

// Test that we get an ECONNREFUSED with a blocking socket when no one is
// listening on the other end.
TEST_P(SimpleTcpSocketTest, BlockingConnectRefused) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(ECONNREFUSED));

  // Avoiding triggering save in destructor of s.
  EXPECT_THAT(close(s.release()), SyscallSucceeds());
}

// Test that connecting to a non-listening port and thus receiving a RST is
// handled appropriately by the socket - the port that the socket was bound to
// is released and the expected error is returned.
TEST_P(SimpleTcpSocketTest, CleanupOnConnectionRefused) {
  // Create a socket that is known to not be listening. As is it bound but not
  // listening, when another socket connects to the port, it will refuse..
  FileDescriptor bound_s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  sockaddr_storage bound_addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t bound_addrlen = sizeof(bound_addr);

  ASSERT_THAT(bind(bound_s.get(), AsSockAddr(&bound_addr), bound_addrlen),
              SyscallSucceeds());

  // Get the addresses the socket is bound to because the port is chosen by the
  // stack.
  ASSERT_THAT(
      getsockname(bound_s.get(), AsSockAddr(&bound_addr), &bound_addrlen),
      SyscallSucceeds());

  // Create, initialize, and bind the socket that is used to test connecting to
  // the non-listening port.
  FileDescriptor client_s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  // Initialize client address to the loopback one.
  sockaddr_storage client_addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t client_addrlen = sizeof(client_addr);

  ASSERT_THAT(bind(client_s.get(), AsSockAddr(&client_addr), client_addrlen),
              SyscallSucceeds());

  ASSERT_THAT(
      getsockname(client_s.get(), AsSockAddr(&client_addr), &client_addrlen),
      SyscallSucceeds());

  // Now the test: connect to the bound but not listening socket with the
  // client socket. The bound socket should return a RST and cause the client
  // socket to return an error and clean itself up immediately.
  // The error being ECONNREFUSED diverges with RFC 793, page 37, but does what
  // Linux does.
  ASSERT_THAT(connect(client_s.get(),
                      reinterpret_cast<const struct sockaddr*>(&bound_addr),
                      bound_addrlen),
              SyscallFailsWithErrno(ECONNREFUSED));

  FileDescriptor new_s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Test binding to the address from the client socket. This should be okay
  // if it was dropped correctly.
  ASSERT_THAT(bind(new_s.get(), AsSockAddr(&client_addr), client_addrlen),
              SyscallSucceeds());

  // Attempt #2, with the new socket and reused addr our connect should fail in
  // the same way as before, not with an EADDRINUSE.
  //
  // TODO(gvisor.dev/issue/3828): 2nd connect on a socket which failed connect
  //   first time should succeed.
  // gVisor never issues the second connect and returns ECONNABORTED instead.
  // Linux actually sends a SYN again and gets a RST and correctly returns
  // ECONNREFUSED.
  if (IsRunningOnGvisor()) {
    ASSERT_THAT(connect(client_s.get(),
                        reinterpret_cast<const struct sockaddr*>(&bound_addr),
                        bound_addrlen),
                SyscallFailsWithErrno(ECONNABORTED));
    return;
  }
  ASSERT_THAT(connect(client_s.get(),
                      reinterpret_cast<const struct sockaddr*>(&bound_addr),
                      bound_addrlen),
              SyscallFailsWithErrno(ECONNREFUSED));
}

// Test that we get an ECONNREFUSED with a nonblocking socket.
TEST_P(SimpleTcpSocketTest, NonBlockingConnectRefused) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(GetParam(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  // We don't need to specify any events to get POLLHUP or POLLERR as these
  // are added before the poll.
  struct pollfd poll_fd = {s.get(), /*events=*/0, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 1000), SyscallSucceedsWithValue(1));

  // The ECONNREFUSED should cause us to be woken up with POLLHUP.
  EXPECT_NE(poll_fd.revents & (POLLHUP | POLLERR), 0);

  // Avoiding triggering save in destructor of s.
  EXPECT_THAT(close(s.release()), SyscallSucceeds());
}

// Test that setting a supported congestion control algorithm succeeds for an
// unconnected TCP socket
TEST_P(SimpleTcpSocketTest, SetCongestionControlSucceedsForSupported) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  {
    const char kSetCC[kTcpCaNameMax] = "reno";
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &kSetCC,
                           strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax];
    memset(got_cc, '1', sizeof(got_cc));
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &got_cc, &optlen),
        SyscallSucceedsWithValue(0));
    // We ignore optlen here as the linux kernel sets optlen to the lower of the
    // size of the buffer passed in or kTcpCaNameMax and not the length of the
    // congestion control algorithm's actual name.
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kTcpCaNameMax)));
  }
  {
    const char kSetCC[kTcpCaNameMax] = "cubic";
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &kSetCC,
                           strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax];
    memset(got_cc, '1', sizeof(got_cc));
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &got_cc, &optlen),
        SyscallSucceedsWithValue(0));
    // We ignore optlen here as the linux kernel sets optlen to the lower of the
    // size of the buffer passed in or kTcpCaNameMax and not the length of the
    // congestion control algorithm's actual name.
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kTcpCaNameMax)));
  }
}

// This test verifies that a getsockopt(...TCP_CONGESTION) behaviour is
// consistent between linux and gvisor when the passed in buffer is smaller than
// kTcpCaNameMax.
TEST_P(SimpleTcpSocketTest, SetGetTCPCongestionShortReadBuffer) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  {
    // Verify that getsockopt/setsockopt work with buffers smaller than
    // kTcpCaNameMax.
    const char kSetCC[] = "cubic";
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &kSetCC,
                           strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[sizeof(kSetCC)];
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &got_cc, &optlen),
        SyscallSucceedsWithValue(0));
    EXPECT_EQ(sizeof(got_cc), optlen);
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(got_cc)));
  }
}

// This test verifies that a getsockopt(...TCP_CONGESTION) behaviour is
// consistent between linux and gvisor when the passed in buffer is larger than
// kTcpCaNameMax.
TEST_P(SimpleTcpSocketTest, SetGetTCPCongestionLargeReadBuffer) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  {
    // Verify that getsockopt works with buffers larger than
    // kTcpCaNameMax.
    const char kSetCC[] = "cubic";
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &kSetCC,
                           strlen(kSetCC)),
                SyscallSucceedsWithValue(0));

    char got_cc[kTcpCaNameMax + 5];
    socklen_t optlen = sizeof(got_cc);
    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &got_cc, &optlen),
        SyscallSucceedsWithValue(0));
    // Linux copies the minimum of kTcpCaNameMax or the length of the passed in
    // buffer and sets optlen to the number of bytes actually copied
    // irrespective of the actual length of the congestion control name.
    EXPECT_EQ(kTcpCaNameMax, optlen);
    EXPECT_EQ(0, memcmp(got_cc, kSetCC, sizeof(kSetCC)));
  }
}

// Test that setting an unsupported congestion control algorithm fails for an
// unconnected TCP socket.
TEST_P(SimpleTcpSocketTest, SetCongestionControlFailsForUnsupported) {
  // This is Linux's net/tcp.h TCP_CA_NAME_MAX.
  const int kTcpCaNameMax = 16;

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  char old_cc[kTcpCaNameMax];
  socklen_t optlen = sizeof(old_cc);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &old_cc, &optlen),
      SyscallSucceedsWithValue(0));

  const char kSetCC[] = "invalid_ca_kSetCC";
  ASSERT_THAT(
      setsockopt(s.get(), SOL_TCP, TCP_CONGESTION, &kSetCC, strlen(kSetCC)),
      SyscallFailsWithErrno(ENOENT));

  char got_cc[kTcpCaNameMax];
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_CONGESTION, &got_cc, &optlen),
      SyscallSucceedsWithValue(0));
  // We ignore optlen here as the linux kernel sets optlen to the lower of the
  // size of the buffer passed in or kTcpCaNameMax and not the length of the
  // congestion control algorithm's actual name.
  EXPECT_EQ(0, memcmp(got_cc, old_cc, sizeof(kTcpCaNameMax)));
}

TEST_P(SimpleTcpSocketTest, MaxSegDefault) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  constexpr int kDefaultMSS = 536;
  int tcp_max_seg;
  socklen_t optlen = sizeof(tcp_max_seg);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_MAXSEG, &tcp_max_seg, &optlen),
      SyscallSucceedsWithValue(0));

  EXPECT_EQ(kDefaultMSS, tcp_max_seg);
  EXPECT_EQ(sizeof(tcp_max_seg), optlen);
}

TEST_P(SimpleTcpSocketTest, SetMaxSeg) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  constexpr int kDefaultMSS = 536;
  constexpr int kTCPMaxSeg = 1024;
  ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_MAXSEG, &kTCPMaxSeg,
                         sizeof(kTCPMaxSeg)),
              SyscallSucceedsWithValue(0));

  // Linux actually never returns the user_mss value. It will always return the
  // default MSS value defined above for an unconnected socket and always return
  // the actual current MSS for a connected one.
  int optval;
  socklen_t optlen = sizeof(optval);
  ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_MAXSEG, &optval, &optlen),
              SyscallSucceedsWithValue(0));

  EXPECT_EQ(kDefaultMSS, optval);
  EXPECT_EQ(sizeof(optval), optlen);
}

TEST_P(SimpleTcpSocketTest, SetMaxSegFailsForInvalidMSSValues) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  {
    constexpr int tcp_max_seg = 10;
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_MAXSEG, &tcp_max_seg,
                           sizeof(tcp_max_seg)),
                SyscallFailsWithErrno(EINVAL));
  }
  {
    constexpr int tcp_max_seg = 75000;
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_MAXSEG, &tcp_max_seg,
                           sizeof(tcp_max_seg)),
                SyscallFailsWithErrno(EINVAL));
  }
}

TEST_P(SimpleTcpSocketTest, SetTCPUserTimeout) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  {
    constexpr int kTCPUserTimeout = -1;
    EXPECT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_USER_TIMEOUT,
                           &kTCPUserTimeout, sizeof(kTCPUserTimeout)),
                SyscallFailsWithErrno(EINVAL));
  }

  // kTCPUserTimeout is in milliseconds.
  constexpr int kTCPUserTimeout = 100;
  ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_USER_TIMEOUT,
                         &kTCPUserTimeout, sizeof(kTCPUserTimeout)),
              SyscallSucceedsWithValue(0));
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kTCPUserTimeout);
}

TEST_P(SimpleTcpSocketTest, SetTCPDeferAcceptNeg) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // -ve TCP_DEFER_ACCEPT is same as setting it to zero.
  constexpr int kNeg = -1;
  EXPECT_THAT(
      setsockopt(s.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT, &kNeg, sizeof(kNeg)),
      SyscallSucceeds());
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 0);
}

TEST_P(SimpleTcpSocketTest, GetTCPDeferAcceptDefault) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 0);
}

TEST_P(SimpleTcpSocketTest, SetTCPDeferAcceptGreaterThanZero) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  // kTCPDeferAccept is in seconds.
  // NOTE: linux translates seconds to # of retries and back from
  //   #of retries to seconds. Which means only certain values
  //   translate back exactly. That's why we use 3 here, a value of
  //   5 will result in us getting back 7 instead of 5 in the
  //   getsockopt.
  constexpr int kTCPDeferAccept = 3;
  ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT,
                         &kTCPDeferAccept, sizeof(kTCPDeferAccept)),
              SyscallSucceeds());
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_DEFER_ACCEPT, &get, &get_len),
      SyscallSucceeds());
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kTCPDeferAccept);
}

TEST_P(SimpleTcpSocketTest, RecvOnClosedSocket) {
  auto s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  char buf[1];
  EXPECT_THAT(recv(s.get(), buf, 0, 0), SyscallFailsWithErrno(ENOTCONN));
  EXPECT_THAT(recv(s.get(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(SimpleTcpSocketTest, TCPConnectSoRcvBufRace) {
  auto s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(GetParam(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen);
  int buf_sz = 1 << 18;
  EXPECT_THAT(
      setsockopt(s.get(), SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz)),
      SyscallSucceedsWithValue(0));
}

TEST_P(SimpleTcpSocketTest, SetTCPSynCntLessThanOne) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  int default_syn_cnt = get;

  {
    // TCP_SYNCNT less than 1 should be rejected with an EINVAL.
    constexpr int kZero = 0;
    EXPECT_THAT(
        setsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &kZero, sizeof(kZero)),
        SyscallFailsWithErrno(EINVAL));

    // TCP_SYNCNT less than 1 should be rejected with an EINVAL.
    constexpr int kNeg = -1;
    EXPECT_THAT(
        setsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &kNeg, sizeof(kNeg)),
        SyscallFailsWithErrno(EINVAL));

    int get = -1;
    socklen_t get_len = sizeof(get);

    ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(get_len, sizeof(get));
    EXPECT_EQ(default_syn_cnt, get);
  }
}

TEST_P(SimpleTcpSocketTest, GetTCPSynCntDefault) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  int get = -1;
  socklen_t get_len = sizeof(get);
  constexpr int kDefaultSynCnt = 6;

  ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kDefaultSynCnt);
}

TEST_P(SimpleTcpSocketTest, SetTCPSynCntGreaterThanOne) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  constexpr int kTCPSynCnt = 20;
  ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &kTCPSynCnt,
                         sizeof(kTCPSynCnt)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
              SyscallSucceeds());
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kTCPSynCnt);
}

TEST_P(SimpleTcpSocketTest, SetTCPSynCntAboveMax) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  int default_syn_cnt = get;
  {
    constexpr int kTCPSynCnt = 256;
    ASSERT_THAT(setsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &kTCPSynCnt,
                           sizeof(kTCPSynCnt)),
                SyscallFailsWithErrno(EINVAL));

    int get = -1;
    socklen_t get_len = sizeof(get);
    ASSERT_THAT(getsockopt(s.get(), IPPROTO_TCP, TCP_SYNCNT, &get, &get_len),
                SyscallSucceeds());
    EXPECT_EQ(get_len, sizeof(get));
    EXPECT_EQ(get, default_syn_cnt);
  }
}

TEST_P(SimpleTcpSocketTest, SetTCPWindowClampBelowMinRcvBuf) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Discover minimum receive buf by setting a really low value
  // for the receive buffer.
  constexpr int kZero = 0;
  EXPECT_THAT(setsockopt(s.get(), SOL_SOCKET, SO_RCVBUF, &kZero, sizeof(kZero)),
              SyscallSucceeds());

  // Now retrieve the minimum value for SO_RCVBUF as the set above should
  // have caused SO_RCVBUF for the socket to be set to the minimum.
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_RCVBUF, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  int min_so_rcvbuf = get;

  {
    // TCP_WINDOW_CLAMP less than min_so_rcvbuf/2 should be set to
    // min_so_rcvbuf/2.
    int below_half_min_rcvbuf = min_so_rcvbuf / 2 - 1;
    EXPECT_THAT(
        setsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP,
                   &below_half_min_rcvbuf, sizeof(below_half_min_rcvbuf)),
        SyscallSucceeds());

    int get = -1;
    socklen_t get_len = sizeof(get);

    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &get, &get_len),
        SyscallSucceedsWithValue(0));
    EXPECT_EQ(get_len, sizeof(get));
    EXPECT_EQ(min_so_rcvbuf / 2, get);
  }
}

TEST_P(SimpleTcpSocketTest, SetTCPWindowClampZeroClosedSocket) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  constexpr int kZero = 0;
  ASSERT_THAT(
      setsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &kZero, sizeof(kZero)),
      SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &get, &get_len),
      SyscallSucceeds());
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kZero);
}

TEST_P(SimpleTcpSocketTest, SetTCPWindowClampAboveHalfMinRcvBuf) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Discover minimum receive buf by setting a really low value
  // for the receive buffer.
  constexpr int kZero = 0;
  EXPECT_THAT(setsockopt(s.get(), SOL_SOCKET, SO_RCVBUF, &kZero, sizeof(kZero)),
              SyscallSucceeds());

  // Now retrieve the minimum value for SO_RCVBUF as the set above should
  // have caused SO_RCVBUF for the socket to be set to the minimum.
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_RCVBUF, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  int min_so_rcvbuf = get;

  {
    int above_half_min_rcv_buf = min_so_rcvbuf / 2 + 1;
    EXPECT_THAT(
        setsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP,
                   &above_half_min_rcv_buf, sizeof(above_half_min_rcv_buf)),
        SyscallSucceeds());

    int get = -1;
    socklen_t get_len = sizeof(get);

    ASSERT_THAT(
        getsockopt(s.get(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &get, &get_len),
        SyscallSucceedsWithValue(0));
    EXPECT_EQ(get_len, sizeof(get));
    EXPECT_EQ(above_half_min_rcv_buf, get);
  }
}

#ifdef __linux__

// TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
// gVisor currently silently ignores attaching a filter.
TEST_P(SimpleTcpSocketTest, SetSocketAttachDetachFilter) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  // Program generated using sudo tcpdump -i lo tcp and port 1234 -dd
  struct sock_filter code[] = {
      {0x28, 0, 0, 0x0000000c},  {0x15, 0, 6, 0x000086dd},
      {0x30, 0, 0, 0x00000014},  {0x15, 0, 15, 0x00000006},
      {0x28, 0, 0, 0x00000036},  {0x15, 12, 0, 0x000004d2},
      {0x28, 0, 0, 0x00000038},  {0x15, 10, 11, 0x000004d2},
      {0x15, 0, 10, 0x00000800}, {0x30, 0, 0, 0x00000017},
      {0x15, 0, 8, 0x00000006},  {0x28, 0, 0, 0x00000014},
      {0x45, 6, 0, 0x00001fff},  {0xb1, 0, 0, 0x0000000e},
      {0x48, 0, 0, 0x0000000e},  {0x15, 2, 0, 0x000004d2},
      {0x48, 0, 0, 0x00000010},  {0x15, 0, 1, 0x000004d2},
      {0x6, 0, 0, 0x00040000},   {0x6, 0, 0, 0x00000000},
  };
  struct sock_fprog bpf = {
      .len = ABSL_ARRAYSIZE(code),
      .filter = code,
  };
  ASSERT_THAT(
      setsockopt(s.get(), SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)),
      SyscallSucceeds());

  constexpr int val = 0;
  ASSERT_THAT(
      setsockopt(s.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
      SyscallSucceeds());
}

#endif  // __linux__

TEST_P(SimpleTcpSocketTest, SetSocketDetachFilterNoInstalledFilter) {
  // TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
  SKIP_IF(IsRunningOnGvisor());
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  constexpr int val = 0;
  ASSERT_THAT(
      setsockopt(s.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
      SyscallFailsWithErrno(ENOENT));
}

TEST_P(SimpleTcpSocketTest, GetSocketDetachFilter) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, &val_len),
              SyscallFailsWithErrno(ENOPROTOOPT));
}

TEST_P(SimpleTcpSocketTest, CloseNonConnectedLingerOption) {
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  constexpr int kLingerTimeout = 10;  // Seconds.

  // Set the SO_LINGER option.
  struct linger sl = {
      .l_onoff = 1,
      .l_linger = kLingerTimeout,
  };
  ASSERT_THAT(setsockopt(s.get(), SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)),
              SyscallSucceeds());

  struct pollfd poll_fd = {
      .fd = s.get(),
      .events = POLLHUP,
  };
  constexpr int kPollTimeoutMs = 0;
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  auto const start_time = absl::Now();
  EXPECT_THAT(close(s.release()), SyscallSucceeds());
  auto const end_time = absl::Now();

  // Close() should not linger and return immediately.
  ASSERT_LT((end_time - start_time), absl::Seconds(kLingerTimeout));
}

// Tests that SO_ACCEPTCONN returns non zero value for listening sockets.
TEST_P(TcpSocketTest, GetSocketAcceptConnListener) {
  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(getsockopt(listener_, SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceeds());
  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 1);
}

// Tests that SO_ACCEPTCONN returns zero value for not listening sockets.
TEST_P(TcpSocketTest, GetSocketAcceptConnNonListener) {
  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(getsockopt(first_fd, SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceeds());
  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);

  ASSERT_THAT(getsockopt(second_fd, SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceeds());
  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

TEST_P(SimpleTcpSocketTest, GetSocketAcceptConnWithShutdown) {
  // TODO(b/171345701): Fix the TCP state for listening socket on shutdown.
  SKIP_IF(IsRunningOnGvisor());

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(s.get(), AsSockAddr(&addr), addrlen), SyscallSucceeds());

  ASSERT_THAT(listen(s.get(), SOMAXCONN), SyscallSucceeds());

  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceeds());
  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 1);

  EXPECT_THAT(shutdown(s.get(), SHUT_RD), SyscallSucceeds());
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceeds());
  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

// Tests that connecting to an unspecified address results in ECONNREFUSED.
TEST_P(SimpleTcpSocketTest, ConnectUnspecifiedAddress) {
  sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, addrlen);
  addr.ss_family = GetParam();
  auto do_connect = [&addr, addrlen]() {
    FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(RetryEINTR(connect)(s.get(), AsSockAddr(&addr), addrlen),
                SyscallFailsWithErrno(ECONNREFUSED));
  };
  do_connect();
  // Test the v4 mapped address as well.
  if (GetParam() == AF_INET6) {
    auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
    sin6->sin6_addr.s6_addr[10] = sin6->sin6_addr.s6_addr[11] = 0xff;
    do_connect();
  }
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, SimpleTcpSocketTest,
                         ::testing::Values(AF_INET, AF_INET6));

}  // namespace

}  // namespace testing
}  // namespace gvisor
