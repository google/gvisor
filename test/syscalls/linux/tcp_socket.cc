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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <limits>
#include <vector>

#include "gtest/gtest.h"
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
  int s_ = -1;

  // Socket connected via accept().
  int t_ = -1;

  // Initial size of the send buffer.
  int sendbuf_size_ = -1;
};

void TcpSocketTest::SetUp() {
  ASSERT_THAT(listener_ = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());

  ASSERT_THAT(s_ = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(
      bind(listener_, reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());

  ASSERT_THAT(listen(listener_, SOMAXCONN), SyscallSucceeds());

  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listener_, reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(s_, reinterpret_cast<struct sockaddr*>(&addr),
                                  addrlen),
              SyscallSucceeds());

  // Get the initial send buffer size.
  socklen_t optlen = sizeof(sendbuf_size_);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &sendbuf_size_, &optlen),
              SyscallSucceeds());

  // Accept the connection.
  ASSERT_THAT(t_ = RetryEINTR(accept)(listener_, nullptr, nullptr),
              SyscallSucceeds());
}

void TcpSocketTest::TearDown() {
  EXPECT_THAT(close(listener_), SyscallSucceeds());
  if (s_ >= 0) {
    EXPECT_THAT(close(s_), SyscallSucceeds());
  }
  if (t_ >= 0) {
    EXPECT_THAT(close(t_), SyscallSucceeds());
  }
}

TEST_P(TcpSocketTest, DataCoalesced) {
  char buf[10];

  // Write in two steps.
  ASSERT_THAT(RetryEINTR(write)(s_, buf, sizeof(buf) / 2),
              SyscallSucceedsWithValue(sizeof(buf) / 2));
  ASSERT_THAT(RetryEINTR(write)(s_, buf, sizeof(buf) / 2),
              SyscallSucceedsWithValue(sizeof(buf) / 2));

  // Allow stack to process both packets.
  absl::SleepFor(absl::Seconds(1));

  // Read in one shot.
  EXPECT_THAT(RetryEINTR(recv)(t_, buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(TcpSocketTest, SenderAddressIgnored) {
  char buf[3];
  ASSERT_THAT(RetryEINTR(write)(s_, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));

  ASSERT_THAT(
      RetryEINTR(recvfrom)(t_, buf, sizeof(buf), 0,
                           reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
      SyscallSucceedsWithValue(3));

  // Check that addr remains zeroed-out.
  const char* ptr = reinterpret_cast<char*>(&addr);
  for (size_t i = 0; i < sizeof(addr); i++) {
    EXPECT_EQ(ptr[i], 0);
  }
}

TEST_P(TcpSocketTest, SenderAddressIgnoredOnPeek) {
  char buf[3];
  ASSERT_THAT(RetryEINTR(write)(s_, buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));

  ASSERT_THAT(
      RetryEINTR(recvfrom)(t_, buf, sizeof(buf), MSG_PEEK,
                           reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
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
  EXPECT_THAT(
      RetryEINTR(sendto)(s_, &data, sizeof(data), 0,
                         reinterpret_cast<sockaddr*>(&addr), sizeof(addr)),
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

  EXPECT_THAT(RetryEINTR(writev)(s_, vecs, 2), SyscallSucceedsWithValue(1));

  EXPECT_THAT(RetryEINTR(recv)(t_, recv_buf, 1, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(memcmp(recv_buf, buf, 1), 0);
}

TEST_P(TcpSocketTest, ZeroWriteAllowed) {
  char buf[3];
  // Send a zero length packet.
  ASSERT_THAT(RetryEINTR(write)(s_, buf, 0), SyscallSucceedsWithValue(0));
  // Verify that there is no packet available.
  EXPECT_THAT(RetryEINTR(recv)(t_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that a non-blocking write with a buffer that is larger than the send
// buffer size will not actually write the whole thing at once.
TEST_P(TcpSocketTest, NonblockingLargeWrite) {
  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(s_, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s_, F_SETFL, opts), SyscallSucceeds());

  // Allocate a buffer three times the size of the send buffer. We do this with
  // a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> buf(size);

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = RetryEINTR(write)(s_, buf.data(), size), SyscallSucceeds());

  // We should have written something, but not the whole thing.
  EXPECT_GT(n, 0);
  EXPECT_LT(n, size);
}

// Test that a blocking write with a buffer that is larger than the send buffer
// will block until the entire buffer is sent.
TEST_P(TcpSocketTest, BlockingLargeWrite_NoRandomSave) {
  // Allocate a buffer three times the size of the send buffer on the heap. We
  // do this as a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> writebuf(size);

  // Start reading the response in a loop.
  int read_bytes = 0;
  ScopedThread t([this, &read_bytes]() {
    // Avoid interrupting the blocking write in main thread.
    const DisableSave ds;
    char readbuf[2500] = {};
    int n = -1;
    while (n != 0) {
      EXPECT_THAT(n = RetryEINTR(read)(t_, &readbuf, sizeof(readbuf)),
                  SyscallSucceeds());
      read_bytes += n;
    }
  });

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = WriteFd(s_, writebuf.data(), size), SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, size);
  EXPECT_THAT(close(s_), SyscallSucceedsWithValue(0));
  s_ = -1;
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
  ASSERT_THAT(n = RetryEINTR(send)(s_, buf.data(), size, MSG_DONTWAIT),
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
  ASSERT_THAT(opts = fcntl(s_, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s_, F_SETFL, opts), SyscallSucceeds());

  // Allocate a buffer three times the size of the send buffer. We do this on
  // with a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> buf(size);

  // Try to write the whole thing.
  int n;
  ASSERT_THAT(n = RetryEINTR(send)(s_, buf.data(), size, 0), SyscallSucceeds());

  // We should have written something, but not the whole thing.
  EXPECT_GT(n, 0);
  EXPECT_LT(n, size);
}

// Same test as above, but calls send instead of write.
TEST_P(TcpSocketTest, BlockingLargeSend_NoRandomSave) {
  // Allocate a buffer three times the size of the send buffer. We do this on
  // with a vector to avoid allocating on the stack.
  int size = 3 * sendbuf_size_;
  std::vector<char> writebuf(size);

  // Start reading the response in a loop.
  int read_bytes = 0;
  ScopedThread t([this, &read_bytes]() {
    // Avoid interrupting the blocking write in main thread.
    const DisableSave ds;
    char readbuf[2500] = {};
    int n = -1;
    while (n != 0) {
      EXPECT_THAT(n = RetryEINTR(read)(t_, &readbuf, sizeof(readbuf)),
                  SyscallSucceeds());
      read_bytes += n;
    }
  });

  // Try to send the whole thing.
  int n;
  ASSERT_THAT(n = SendFd(s_, writebuf.data(), size, 0), SyscallSucceeds());

  // We should have written the whole thing.
  EXPECT_EQ(n, size);
  EXPECT_THAT(close(s_), SyscallSucceedsWithValue(0));
  s_ = -1;
  t.Join();

  // We should have read the whole thing.
  EXPECT_EQ(read_bytes, size);
}

// Test that polling on a socket with a full send buffer will block.
TEST_P(TcpSocketTest, PollWithFullBufferBlocks) {
  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(s_, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s_, F_SETFL, opts), SyscallSucceeds());

  // Set TCP_NODELAY, which will cause linux to fill the receive buffer from the
  // send buffer as quickly as possibly. This way we can fill up both buffers
  // faster.
  constexpr int tcp_nodelay_flag = 1;
  ASSERT_THAT(setsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_flag,
                         sizeof(tcp_nodelay_flag)),
              SyscallSucceeds());

  // Create a large buffer that will be used for sending.
  std::vector<char> buf(10 * sendbuf_size_);

  // Write until we receive an error.
  while (RetryEINTR(send)(s_, buf.data(), buf.size(), 0) != -1) {
    // Sleep to give linux a chance to move data from the send buffer to the
    // receive buffer.
    usleep(10000);  // 10ms.
  }
  // The last error should have been EWOULDBLOCK.
  ASSERT_EQ(errno, EWOULDBLOCK);
}

TEST_P(TcpSocketTest, MsgTrunc) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(s_, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(t_, received_data, sizeof(received_data) / 2, MSG_TRUNC),
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
  ASSERT_THAT(RetryEINTR(send)(s_, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(t_, received_data, sizeof(received_data) / 2,
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
  ASSERT_THAT(RetryEINTR(send)(s_, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(t_, received_data, sizeof(received_data) / 2,
                               MSG_CTRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Since MSG_CTRUNC here had no affect, it should not behave like MSG_TRUNC.
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));
}

TEST_P(TcpSocketTest, MsgTruncLargeSize) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(s_, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data) * 2] = {};
  ASSERT_THAT(
      RetryEINTR(recv)(t_, received_data, sizeof(received_data), MSG_TRUNC),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));
}

TEST_P(TcpSocketTest, MsgTruncPeek) {
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(s_, sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(t_, received_data, sizeof(received_data) / 2,
                               MSG_TRUNC | MSG_PEEK),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  // Check that we didn't get anything.
  char zeros[sizeof(received_data)] = {};
  EXPECT_EQ(0, memcmp(zeros, received_data, sizeof(received_data)));

  // Check that we can still get all of the data.
  ASSERT_THAT(RetryEINTR(recv)(t_, received_data, sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(TcpSocketTest, NoDelayDefault) {
  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(TcpSocketTest, SetNoDelay) {
  ASSERT_THAT(
      setsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &kSockOptOn, sizeof(kSockOptOn)),
      SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceeds());

  EXPECT_THAT(getsockopt(s_, IPPROTO_TCP, TCP_NODELAY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
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
  EXPECT_THAT(
      RetryEINTR(sendto)(fd, &data, sizeof(data), 0,
                         reinterpret_cast<sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(EPIPE));
}

TEST_P(SimpleTcpSocketTest, GetPeerNameUnconnected) {
  int fd;
  ASSERT_THAT(fd = socket(GetParam(), SOCK_STREAM, IPPROTO_TCP),
              SyscallSucceeds());
  FileDescriptor sock_fd(fd);

  sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(TcpSocketTest, FullBuffer) {
  // Set both FDs to be blocking.
  int flags = 0;
  ASSERT_THAT(flags = fcntl(s_, F_GETFL), SyscallSucceeds());
  EXPECT_THAT(fcntl(s_, F_SETFL, flags & ~O_NONBLOCK), SyscallSucceeds());
  flags = 0;
  ASSERT_THAT(flags = fcntl(t_, F_GETFL), SyscallSucceeds());
  EXPECT_THAT(fcntl(t_, F_SETFL, flags & ~O_NONBLOCK), SyscallSucceeds());

  // 2500 was chosen as a small value that can be set on Linux.
  int set_snd = 2500;
  EXPECT_THAT(setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &set_snd, sizeof(set_snd)),
              SyscallSucceedsWithValue(0));
  int get_snd = -1;
  socklen_t get_snd_len = sizeof(get_snd);
  EXPECT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &get_snd, &get_snd_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_snd_len, sizeof(get_snd));
  EXPECT_GT(get_snd, 0);

  // 2500 was chosen as a small value that can be set on Linux and gVisor.
  int set_rcv = 2500;
  EXPECT_THAT(setsockopt(t_, SOL_SOCKET, SO_RCVBUF, &set_rcv, sizeof(set_rcv)),
              SyscallSucceedsWithValue(0));
  int get_rcv = -1;
  socklen_t get_rcv_len = sizeof(get_rcv);
  EXPECT_THAT(getsockopt(t_, SOL_SOCKET, SO_RCVBUF, &get_rcv, &get_rcv_len),
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
    EXPECT_THAT(result = RetryEINTR(writev)(s_, iovecs.data(), iovecs.size()),
                SyscallSucceeds());
    EXPECT_GT(result, 1);
    EXPECT_LT(result, sizeof(data) * iovecs.size());
  });

  char recv = 0;
  EXPECT_THAT(RetryEINTR(read)(t_, &recv, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(close(t_), SyscallSucceedsWithValue(0));
  t_ = -1;
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnectNoListener) {
  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  const FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s.get(), F_SETFL, opts), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(
                  s.get(), reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  // Now polling on the FD with a timeout should return 0 corresponding to no
  // FDs ready.
  struct pollfd poll_fd = {s.get(), POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));

  int err;
  socklen_t optlen = sizeof(err);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());

  EXPECT_EQ(err, ECONNREFUSED);
}

TEST_P(SimpleTcpSocketTest, NonBlockingConnect) {
  const FileDescriptor listener =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(
      bind(listener.get(), reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());

  ASSERT_THAT(listen(listener.get(), SOMAXCONN), SyscallSucceeds());

  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));

  // Set the FD to O_NONBLOCK.
  int opts;
  ASSERT_THAT(opts = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(s.get(), F_SETFL, opts), SyscallSucceeds());

  ASSERT_THAT(getsockname(listener.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(connect)(
                  s.get(), reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallFailsWithErrno(EINPROGRESS));

  int t;
  ASSERT_THAT(t = RetryEINTR(accept)(listener.get(), nullptr, nullptr),
              SyscallSucceeds());

  // Now polling on the FD with a timeout should return 0 corresponding to no
  // FDs ready.
  struct pollfd poll_fd = {s.get(), POLLOUT, 0};
  EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10000),
              SyscallSucceedsWithValue(1));

  int err;
  socklen_t optlen = sizeof(err);
  ASSERT_THAT(getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());

  EXPECT_EQ(err, 0);

  EXPECT_THAT(close(t), SyscallSucceeds());
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

  ASSERT_THAT(RetryEINTR(connect)(
                  s.get(), reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallFailsWithErrno(ECONNREFUSED));

  // Avoiding triggering save in destructor of s.
  EXPECT_THAT(close(s.release()), SyscallSucceeds());
}

// Test that we get an ECONNREFUSED with a nonblocking socket.
TEST_P(SimpleTcpSocketTest, NonBlockingConnectRefused) {
  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(GetParam(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(GetParam()));
  socklen_t addrlen = sizeof(addr);

  ASSERT_THAT(RetryEINTR(connect)(
                  s.get(), reinterpret_cast<struct sockaddr*>(&addr), addrlen),
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

INSTANTIATE_TEST_SUITE_P(AllInetTests, SimpleTcpSocketTest,
                         ::testing::Values(AF_INET, AF_INET6));

}  // namespace

}  // namespace testing
}  // namespace gvisor
