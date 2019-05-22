// Copyright 2019 The gVisor Authors.
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

#include <linux/capability.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

// Note: in order to run these tests, /proc/sys/net/ipv4/ping_group_range will
// need to be configured to let the superuser create ping sockets (see icmp(7)).

namespace gvisor {
namespace testing {

namespace {

// Fixture for tests parameterized by protocol.
class RawSocketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Sends buf via s_.
  void SendBuf(const char* buf, int buf_len);

  // Sends buf to the provided address via the provided socket.
  void SendBufTo(int sock, const struct sockaddr_in& addr, const char* buf,
                 int buf_len);

  // Reads from s_ into recv_buf.
  void ReceiveBuf(char* recv_buf, size_t recv_buf_len);

  int Protocol() { return GetParam(); }

  // The socket used for both reading and writing.
  int s_;

  // The loopback address.
  struct sockaddr_in addr_;
};

void RawSocketTest::SetUp() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(s_ = socket(AF_INET, SOCK_RAW, Protocol()), SyscallSucceeds());

  addr_ = {};

  // We don't set ports because raw sockets don't have a notion of ports.
  addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_.sin_family = AF_INET;
}

void RawSocketTest::TearDown() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  EXPECT_THAT(close(s_), SyscallSucceeds());
}

// We should be able to create multiple raw sockets for the same protocol.
// BasicRawSocket::Setup creates the first one, so we only have to create one
// more here.
TEST_P(RawSocketTest, MultipleCreation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int s2;
  ASSERT_THAT(s2 = socket(AF_INET, SOCK_RAW, Protocol()), SyscallSucceeds());

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Test that shutting down an unconnected socket fails.
TEST_P(RawSocketTest, FailShutdownWithoutConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));
}

// Shutdown is a no-op for raw sockets (and datagram sockets in general).
TEST_P(RawSocketTest, ShutdownWriteNoop) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "noop";
  ASSERT_THAT(RetryEINTR(write)(s_, kBuf, sizeof(kBuf)),
              SyscallSucceedsWithValue(sizeof(kBuf)));
}

// Shutdown is a no-op for raw sockets (and datagram sockets in general).
TEST_P(RawSocketTest, ShutdownReadNoop) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "gdg";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  constexpr size_t kReadSize = sizeof(kBuf) + sizeof(struct iphdr);
  char c[kReadSize];
  ASSERT_THAT(read(s_, &c, sizeof(c)), SyscallSucceedsWithValue(kReadSize));
}

// Test that listen() fails.
TEST_P(RawSocketTest, FailListen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(listen(s_, 1), SyscallFailsWithErrno(ENOTSUP));
}

// Test that accept() fails.
TEST_P(RawSocketTest, FailAccept) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(accept(s_, &saddr, &addrlen), SyscallFailsWithErrno(ENOTSUP));
}

// Test that getpeername() returns nothing before connect().
TEST_P(RawSocketTest, FailGetPeerNameBeforeConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr saddr;
  socklen_t addrlen = sizeof(saddr);
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

// Test that getpeername() returns something after connect().
TEST_P(RawSocketTest, GetPeerName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  struct sockaddr saddr;
  socklen_t addrlen = sizeof(saddr);
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
  ASSERT_GT(addrlen, 0);
}

// Test that the socket is writable immediately.
TEST_P(RawSocketTest, PollWritableImmediately) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLOUT;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 10000), SyscallSucceedsWithValue(1));
}

// Test that the socket isn't readable before receiving anything.
TEST_P(RawSocketTest, PollNotReadableInitially) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Try to receive data with MSG_DONTWAIT, which returns immediately if there's
  // nothing to be read.
  char buf[117];
  ASSERT_THAT(RetryEINTR(recv)(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that the socket becomes readable once something is written to it.
TEST_P(RawSocketTest, PollTriggeredOnWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Write something so that there's data to be read.
  // Arbitrary.
  constexpr char kBuf[] = "JP5";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 10000), SyscallSucceedsWithValue(1));
}

// Test that we can connect() to a valid IP (loopback).
TEST_P(RawSocketTest, ConnectToLoopback) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
}

// Test that calling send() without connect() fails.
TEST_P(RawSocketTest, SendWithoutConnectFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Arbitrary.
  constexpr char kBuf[] = "Endgame was good";
  ASSERT_THAT(send(s_, kBuf, sizeof(kBuf), 0),
              SyscallFailsWithErrno(EDESTADDRREQ));
}

// Bind to localhost.
TEST_P(RawSocketTest, BindToLocalhost) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
}

// Bind to a different address.
TEST_P(RawSocketTest, BindToInvalid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr = {1};  // 1.0.0.0 - An address that we can't bind to.
  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Send and receive an packet.
TEST_P(RawSocketTest, SendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Arbitrary.
  constexpr char kBuf[] = "TB12";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  char recv_buf[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf, sizeof(recv_buf)));
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), kBuf, sizeof(kBuf)), 0);
}

// We should be able to create multiple raw sockets for the same protocol and
// receive the same packet on both.
TEST_P(RawSocketTest, MultipleSocketReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int s2;
  ASSERT_THAT(s2 = socket(AF_INET, SOCK_RAW, Protocol()), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "TB10";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive it on socket 1.
  char recv_buf1[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf1, sizeof(recv_buf1)));

  // Receive it on socket 2.
  char recv_buf2[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(s2, recv_buf2, sizeof(recv_buf2)));

  EXPECT_EQ(memcmp(recv_buf1 + sizeof(struct iphdr),
                   recv_buf2 + sizeof(struct iphdr), sizeof(kBuf)),
            0);

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Test that connect sends packets to the right place.
TEST_P(RawSocketTest, SendAndReceiveViaConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "JH4";
  ASSERT_THAT(send(s_, kBuf, sizeof(kBuf), 0),
              SyscallSucceedsWithValue(sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  char recv_buf[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf, sizeof(recv_buf)));
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), kBuf, sizeof(kBuf)), 0);
}

// Bind to localhost, then send and receive packets.
TEST_P(RawSocketTest, BindSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "DR16";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  char recv_buf[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf, sizeof(recv_buf)));
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), kBuf, sizeof(kBuf)), 0);
}

// Bind and connect to localhost and send/receive packets.
TEST_P(RawSocketTest, BindConnectSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "DG88";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  char recv_buf[sizeof(kBuf) + sizeof(struct iphdr)];
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf, sizeof(recv_buf)));
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), kBuf, sizeof(kBuf)), 0);
}

void RawSocketTest::SendBuf(const char* buf, int buf_len) {
  ASSERT_NO_FATAL_FAILURE(SendBufTo(s_, addr_, buf, buf_len));
}

void RawSocketTest::SendBufTo(int sock, const struct sockaddr_in& addr,
                              const char* buf, int buf_len) {
  // It's safe to use const_cast here because sendmsg won't modify the iovec or
  // address.
  struct iovec iov = {};
  iov.iov_base = static_cast<void*>(const_cast<char*>(buf));
  iov.iov_len = static_cast<size_t>(buf_len);
  struct msghdr msg = {};
  msg.msg_name = static_cast<void*>(const_cast<struct sockaddr_in*>(&addr));
  msg.msg_namelen = sizeof(addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallSucceedsWithValue(buf_len));
}

void RawSocketTest::ReceiveBuf(char* recv_buf, size_t recv_buf_len) {
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(s_, recv_buf, recv_buf_len));
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, RawSocketTest,
                         ::testing::Values(IPPROTO_TCP, IPPROTO_UDP));

}  // namespace

}  // namespace testing
}  // namespace gvisor
