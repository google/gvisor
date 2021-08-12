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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include "gtest/gtest.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Note: in order to run these tests, /proc/sys/net/ipv4/ping_group_range will
// need to be configured to let the superuser create ping sockets (see icmp(7)).

namespace gvisor {
namespace testing {

namespace {

// Fixture for tests parameterized by protocol.
class RawSocketTest : public ::testing::TestWithParam<std::tuple<int, int>> {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Sends buf via s_.
  void SendBuf(const char* buf, int buf_len);

  // Reads from s_ into recv_buf.
  void ReceiveBuf(char* recv_buf, size_t recv_buf_len);

  void ReceiveBufFrom(int sock, char* recv_buf, size_t recv_buf_len);

  int Protocol() { return std::get<0>(GetParam()); }

  int Family() { return std::get<1>(GetParam()); }

  socklen_t AddrLen() {
    if (Family() == AF_INET) {
      return sizeof(sockaddr_in);
    }
    return sizeof(sockaddr_in6);
  }

  int HdrLen() {
    if (Family() == AF_INET) {
      return sizeof(struct iphdr);
    }
    // IPv6 raw sockets don't include the header.
    return 0;
  }

  uint16_t Port(struct sockaddr* s) {
    if (Family() == AF_INET) {
      return ntohs(reinterpret_cast<struct sockaddr_in*>(s)->sin_port);
    }
    return ntohs(reinterpret_cast<struct sockaddr_in6*>(s)->sin6_port);
  }

  void* Addr(struct sockaddr* s) {
    if (Family() == AF_INET) {
      return &(reinterpret_cast<struct sockaddr_in*>(s)->sin_addr);
    }
    return &(reinterpret_cast<struct sockaddr_in6*>(s)->sin6_addr);
  }

  // The socket used for both reading and writing.
  int s_;

  // The loopback address.
  struct sockaddr_storage addr_;
};

void RawSocketTest::SetUp() {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability())) {
    ASSERT_THAT(socket(Family(), SOCK_RAW, Protocol()),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  ASSERT_THAT(s_ = socket(Family(), SOCK_RAW, Protocol()), SyscallSucceeds());

  addr_ = {};

  // We don't set ports because raw sockets don't have a notion of ports.
  if (Family() == AF_INET) {
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&addr_);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else {
    struct sockaddr_in6* sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr_);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = in6addr_loopback;
  }
}

void RawSocketTest::TearDown() {
  // TearDown will be run even if we skip the test.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability())) {
    EXPECT_THAT(close(s_), SyscallSucceeds());
  }
}

// We should be able to create multiple raw sockets for the same protocol.
// BasicRawSocket::Setup creates the first one, so we only have to create one
// more here.
TEST_P(RawSocketTest, MultipleCreation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int s2;
  ASSERT_THAT(s2 = socket(Family(), SOCK_RAW, Protocol()), SyscallSucceeds());

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Test that shutting down an unconnected socket fails.
TEST_P(RawSocketTest, FailShutdownWithoutConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));
}

// Shutdown is a no-op for raw sockets (and datagram sockets in general).
TEST_P(RawSocketTest, ShutdownWriteNoop) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "noop";
  ASSERT_THAT(RetryEINTR(write)(s_, kBuf, sizeof(kBuf)),
              SyscallSucceedsWithValue(sizeof(kBuf)));
}

// Shutdown is a no-op for raw sockets (and datagram sockets in general).
TEST_P(RawSocketTest, ShutdownReadNoop) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "gdg";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  std::vector<char> c(sizeof(kBuf) + HdrLen());
  ASSERT_THAT(read(s_, c.data(), c.size()), SyscallSucceedsWithValue(c.size()));
}

// Test that listen() fails.
TEST_P(RawSocketTest, FailListen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(listen(s_, 1), SyscallFailsWithErrno(ENOTSUP));
}

// Test that accept() fails.
TEST_P(RawSocketTest, FailAccept) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(accept(s_, &saddr, &addrlen), SyscallFailsWithErrno(ENOTSUP));
}

TEST_P(RawSocketTest, BindThenGetSockName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_);
  ASSERT_THAT(bind(s_, addr, AddrLen()), SyscallSucceeds());
  struct sockaddr_storage saddr_storage;
  struct sockaddr* saddr = reinterpret_cast<struct sockaddr*>(&saddr_storage);
  socklen_t saddrlen = AddrLen();
  ASSERT_THAT(getsockname(s_, saddr, &saddrlen), SyscallSucceeds());
  ASSERT_EQ(saddrlen, AddrLen());

  // The port is expected to hold the protocol number.
  EXPECT_EQ(Port(saddr), Protocol());

  char addrbuf[INET6_ADDRSTRLEN], saddrbuf[INET6_ADDRSTRLEN];
  const char* addrstr =
      inet_ntop(addr->sa_family, Addr(addr), addrbuf, sizeof(addrbuf));
  ASSERT_NE(addrstr, nullptr);
  const char* saddrstr =
      inet_ntop(saddr->sa_family, Addr(saddr), saddrbuf, sizeof(saddrbuf));
  ASSERT_NE(saddrstr, nullptr);
  EXPECT_STREQ(saddrstr, addrstr);
}

TEST_P(RawSocketTest, ConnectThenGetSockName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_);
  ASSERT_THAT(connect(s_, addr, AddrLen()), SyscallSucceeds());
  struct sockaddr_storage saddr_storage;
  struct sockaddr* saddr = reinterpret_cast<struct sockaddr*>(&saddr_storage);
  socklen_t saddrlen = AddrLen();
  ASSERT_THAT(getsockname(s_, saddr, &saddrlen), SyscallSucceeds());
  ASSERT_EQ(saddrlen, AddrLen());

  // The port is expected to hold the protocol number.
  EXPECT_EQ(Port(saddr), Protocol());

  char addrbuf[INET6_ADDRSTRLEN], saddrbuf[INET6_ADDRSTRLEN];
  const char* addrstr =
      inet_ntop(addr->sa_family, Addr(addr), addrbuf, sizeof(addrbuf));
  ASSERT_NE(addrstr, nullptr);
  const char* saddrstr =
      inet_ntop(saddr->sa_family, Addr(saddr), saddrbuf, sizeof(saddrbuf));
  ASSERT_NE(saddrstr, nullptr);
  EXPECT_STREQ(saddrstr, addrstr);
}

// Test that getpeername() returns nothing before connect().
TEST_P(RawSocketTest, FailGetPeerNameBeforeConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct sockaddr saddr;
  socklen_t addrlen = sizeof(saddr);
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

// Test that getpeername() returns something after connect().
TEST_P(RawSocketTest, GetPeerName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());
  struct sockaddr saddr;
  socklen_t addrlen = sizeof(saddr);
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
  ASSERT_GT(addrlen, 0);
}

// Test that the socket is writable immediately.
TEST_P(RawSocketTest, PollWritableImmediately) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLOUT;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 10000), SyscallSucceedsWithValue(1));
}

// Test that the socket isn't readable before receiving anything.
TEST_P(RawSocketTest, PollNotReadableInitially) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Try to receive data with MSG_DONTWAIT, which returns immediately if there's
  // nothing to be read.
  char buf[117];
  ASSERT_THAT(RetryEINTR(recv)(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that the socket becomes readable once something is written to it.
TEST_P(RawSocketTest, PollTriggeredOnWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());
}

// Test that calling send() without connect() fails.
TEST_P(RawSocketTest, SendWithoutConnectFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Arbitrary.
  constexpr char kBuf[] = "Endgame was good";
  ASSERT_THAT(send(s_, kBuf, sizeof(kBuf), 0),
              SyscallFailsWithErrno(EDESTADDRREQ));
}

// Wildcard Bind.
TEST_P(RawSocketTest, BindToWildcard) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));
  struct sockaddr_storage addr;
  addr = {};

  // We don't set ports because raw sockets don't have a notion of ports.
  if (Family() == AF_INET) {
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
  } else {
    struct sockaddr_in6* sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = in6addr_any;
  }

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());
}

// Bind to localhost.
TEST_P(RawSocketTest, BindToLocalhost) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());
}

// Bind to a different address.
TEST_P(RawSocketTest, BindToInvalid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  struct sockaddr_storage bind_addr = addr_;
  if (Family() == AF_INET) {
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&bind_addr);
    sin->sin_addr = {1};  // 1.0.0.0 - An address that we can't bind to.
  } else {
    struct sockaddr_in6* sin6 =
        reinterpret_cast<struct sockaddr_in6*>(&bind_addr);
    memset(&sin6->sin6_addr.s6_addr, 0, sizeof(sin6->sin6_addr.s6_addr));
    sin6->sin6_addr.s6_addr[0] = 1;  // 1: - An address that we can't bind to.
  }
  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&bind_addr), AddrLen()),
      SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Send and receive an packet.
TEST_P(RawSocketTest, SendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Arbitrary.
  constexpr char kBuf[] = "TB12";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  std::vector<char> recv_buf(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
  EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), kBuf, sizeof(kBuf)), 0);
}

// We should be able to create multiple raw sockets for the same protocol and
// receive the same packet on both.
TEST_P(RawSocketTest, MultipleSocketReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int s2;
  ASSERT_THAT(s2 = socket(Family(), SOCK_RAW, Protocol()), SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "TB10";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive it on socket 1.
  std::vector<char> recv_buf1(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf1.data(), recv_buf1.size()));

  // Receive it on socket 2.
  std::vector<char> recv_buf2(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(
      ReceiveBufFrom(s2, recv_buf2.data(), recv_buf2.size()));

  EXPECT_EQ(memcmp(recv_buf1.data() + HdrLen(), recv_buf2.data() + HdrLen(),
                   sizeof(kBuf)),
            0);

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Test that connect sends packets to the right place.
TEST_P(RawSocketTest, SendAndReceiveViaConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "JH4";
  ASSERT_THAT(send(s_, kBuf, sizeof(kBuf), 0),
              SyscallSucceedsWithValue(sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  std::vector<char> recv_buf(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
  EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), kBuf, sizeof(kBuf)), 0);
}

// Bind to localhost, then send and receive packets.
TEST_P(RawSocketTest, BindSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "DR16";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  std::vector<char> recv_buf(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
  EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), kBuf, sizeof(kBuf)), 0);
}

// Bind and connect to localhost and send/receive packets.
TEST_P(RawSocketTest, BindConnectSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());
  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());

  // Arbitrary.
  constexpr char kBuf[] = "DG88";
  ASSERT_NO_FATAL_FAILURE(SendBuf(kBuf, sizeof(kBuf)));

  // Receive the packet and make sure it's identical.
  std::vector<char> recv_buf(sizeof(kBuf) + HdrLen());
  ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
  EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), kBuf, sizeof(kBuf)), 0);
}

// Check that setting SO_RCVBUF below min is clamped to the minimum
// receive buffer size.
TEST_P(RawSocketTest, SetSocketRecvBufBelowMin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Discover minimum receive buf size by trying to set it to zero.
  // See:
  // https://github.com/torvalds/linux/blob/a5dc8300df75e8b8384b4c82225f1e4a0b4d9b55/net/core/sock.c#L820
  constexpr int kRcvBufSz = 0;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
      SyscallSucceeds());

  int min = 0;
  socklen_t min_len = sizeof(min);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &min, &min_len),
              SyscallSucceeds());

  // Linux doubles the value so let's use a value that when doubled will still
  // be smaller than min.
  int below_min = min / 2 - 1;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &below_min, sizeof(below_min)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());

  ASSERT_EQ(min, val);
}

// Check that setting SO_RCVBUF above max is clamped to the maximum
// receive buffer size.
TEST_P(RawSocketTest, SetSocketRecvBufAboveMax) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Discover max buf size by trying to set the largest possible buffer size.
  constexpr int kRcvBufSz = 0xffffffff;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
      SyscallSucceeds());

  int max = 0;
  socklen_t max_len = sizeof(max);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &max, &max_len),
              SyscallSucceeds());

  int above_max = max + 1;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &above_max, sizeof(above_max)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());
  ASSERT_EQ(max, val);
}

// Check that setting SO_RCVBUF min <= kRcvBufSz <= max is honored.
TEST_P(RawSocketTest, SetSocketRecvBuf) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int max = 0;
  int min = 0;
  {
    // Discover max buf size by trying to set a really large buffer size.
    constexpr int kRcvBufSz = 0xffffffff;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by trying to set a zero size receive buffer
    // size.
    // See:
    // https://github.com/torvalds/linux/blob/a5dc8300df75e8b8384b4c82225f1e4a0b4d9b55/net/core/sock.c#L820
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &quarter_sz, sizeof(quarter_sz)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &val, &val_len),
              SyscallSucceeds());

  // Linux doubles the value set by SO_SNDBUF/SO_RCVBUF.
  quarter_sz *= 2;
  ASSERT_EQ(quarter_sz, val);
}

// Check that setting SO_SNDBUF below min is clamped to the minimum
// receive buffer size.
TEST_P(RawSocketTest, SetSocketSendBufBelowMin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Discover minimum buffer size by trying to set it to zero.
  constexpr int kSndBufSz = 0;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &kSndBufSz, sizeof(kSndBufSz)),
      SyscallSucceeds());

  int min = 0;
  socklen_t min_len = sizeof(min);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &min, &min_len),
              SyscallSucceeds());

  // Linux doubles the value so let's use a value that when doubled will still
  // be smaller than min.
  int below_min = min / 2 - 1;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &below_min, sizeof(below_min)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  ASSERT_EQ(min, val);
}

// Check that setting SO_SNDBUF above max is clamped to the maximum
// send buffer size.
TEST_P(RawSocketTest, SetSocketSendBufAboveMax) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  // Discover maximum buffer size by trying to set it to a large value.
  constexpr int kSndBufSz = 0xffffffff;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &kSndBufSz, sizeof(kSndBufSz)),
      SyscallSucceeds());

  int max = 0;
  socklen_t max_len = sizeof(max);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &max, &max_len),
              SyscallSucceeds());

  int above_max = max + 1;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &above_max, sizeof(above_max)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());
  ASSERT_EQ(max, val);
}

// Check that setting SO_SNDBUF min <= kSndBufSz <= max is honored.
TEST_P(RawSocketTest, SetSocketSendBuf) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int max = 0;
  int min = 0;
  {
    // Discover maximum buffer size by trying to set it to a large value.
    constexpr int kSndBufSz = 0xffffffff;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &kSndBufSz, sizeof(kSndBufSz)),
        SyscallSucceeds());

    max = 0;
    socklen_t max_len = sizeof(max);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &max, &max_len),
                SyscallSucceeds());
  }

  {
    // Discover minimum buffer size by trying to set it to zero.
    constexpr int kSndBufSz = 0;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &kSndBufSz, sizeof(kSndBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &min, &min_len),
                SyscallSucceeds());
  }

  int quarter_sz = min + (max - min) / 4;
  ASSERT_THAT(
      setsockopt(s_, SOL_SOCKET, SO_SNDBUF, &quarter_sz, sizeof(quarter_sz)),
      SyscallSucceeds());

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_SNDBUF, &val, &val_len),
              SyscallSucceeds());

  quarter_sz *= 2;
  ASSERT_EQ(quarter_sz, val);
}

// Test that receive buffer limits are not enforced when the recv buffer is
// empty.
TEST_P(RawSocketTest, RecvBufLimitsEmptyRecvBuffer) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());
  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());

  int min = 0;
  {
    // Discover minimum buffer size by trying to set it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &min, &min_len),
                SyscallSucceeds());
  }

  {
    // Send data of size min and verify that it's received.
    std::vector<char> buf(min);
    RandomizeBuffer(buf.data(), buf.size());
    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));

    // Receive the packet and make sure it's identical.
    std::vector<char> recv_buf(buf.size() + HdrLen());
    ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
    EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), buf.data(), buf.size()), 0);
  }

  {
    // Send data of size min + 1 and verify that its received. Both linux and
    // Netstack accept a dgram that exceeds rcvBuf limits if the receive buffer
    // is currently empty.
    std::vector<char> buf(min + 1);
    RandomizeBuffer(buf.data(), buf.size());
    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
    // Receive the packet and make sure it's identical.
    std::vector<char> recv_buf(buf.size() + HdrLen());
    ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
    EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), buf.data(), buf.size()), 0);
  }
}

TEST_P(RawSocketTest, RecvBufLimits) {
  // TCP stack generates RSTs for unknown endpoints and it complicates the test
  // as we have to deal with the RST packets as well. For testing the raw socket
  // endpoints buffer limit enforcement we can just test for UDP.
  //
  // We don't use SKIP_IF here because root_test_runner explicitly fails if a
  // test is skipped.
  if (Protocol() == IPPROTO_TCP) {
    return;
  }
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
              SyscallSucceeds());
  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), AddrLen()),
      SyscallSucceeds());

  int min = 0;
  {
    // Discover minimum buffer size by trying to set it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(
        setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &kRcvBufSz, sizeof(kRcvBufSz)),
        SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &min, &min_len),
                SyscallSucceeds());
  }

  // Now set the limit to min * 2.
  int new_rcv_buf_sz = min * 2;
  ASSERT_THAT(setsockopt(s_, SOL_SOCKET, SO_RCVBUF, &new_rcv_buf_sz,
                         sizeof(new_rcv_buf_sz)),
              SyscallSucceeds());
  int rcv_buf_sz = 0;
  {
    socklen_t rcv_buf_len = sizeof(rcv_buf_sz);
    ASSERT_THAT(
        getsockopt(s_, SOL_SOCKET, SO_RCVBUF, &rcv_buf_sz, &rcv_buf_len),
        SyscallSucceeds());
  }

  // Set a receive timeout so that we don't block forever on reads if the test
  // fails.
  struct timeval tv {
    .tv_sec = 1, .tv_usec = 0,
  };
  ASSERT_THAT(setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
              SyscallSucceeds());

  {
    std::vector<char> buf(min);
    RandomizeBuffer(buf.data(), buf.size());

    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
    ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
    int sent = 4;
    if (IsRunningOnGvisor()) {
      // Linux seems to drop the 4th packet even though technically it should
      // fit in the receive buffer.
      ASSERT_NO_FATAL_FAILURE(SendBuf(buf.data(), buf.size()));
      sent++;
    }

    // Verify that the expected number of packets are available to be read.
    for (int i = 0; i < sent - 1; i++) {
      // Receive the packet and make sure it's identical.
      std::vector<char> recv_buf(buf.size() + HdrLen());
      ASSERT_NO_FATAL_FAILURE(ReceiveBuf(recv_buf.data(), recv_buf.size()));
      EXPECT_EQ(memcmp(recv_buf.data() + HdrLen(), buf.data(), buf.size()), 0);
    }

    // Assert that the last packet is dropped because the receive buffer should
    // be full after the first four packets.
    std::vector<char> recv_buf(buf.size() + HdrLen());
    struct iovec iov = {};
    iov.iov_base = static_cast<void*>(const_cast<char*>(recv_buf.data()));
    iov.iov_len = buf.size();
    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    ASSERT_THAT(RetryEINTR(recvmsg)(s_, &msg, MSG_DONTWAIT),
                SyscallFailsWithErrno(EAGAIN));
  }
}

void RawSocketTest::SendBuf(const char* buf, int buf_len) {
  // It's safe to use const_cast here because sendmsg won't modify the iovec or
  // address.
  struct iovec iov = {};
  iov.iov_base = static_cast<void*>(const_cast<char*>(buf));
  iov.iov_len = static_cast<size_t>(buf_len);
  struct msghdr msg = {};
  msg.msg_name = static_cast<void*>(&addr_);
  msg.msg_namelen = AddrLen();
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  ASSERT_THAT(sendmsg(s_, &msg, 0), SyscallSucceedsWithValue(buf_len));
}

void RawSocketTest::ReceiveBuf(char* recv_buf, size_t recv_buf_len) {
  ASSERT_NO_FATAL_FAILURE(ReceiveBufFrom(s_, recv_buf, recv_buf_len));
}

void RawSocketTest::ReceiveBufFrom(int sock, char* recv_buf,
                                   size_t recv_buf_len) {
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(sock, recv_buf, recv_buf_len));
}

TEST_P(RawSocketTest, SetSocketDetachFilterNoInstalledFilter) {
  // TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
  if (IsRunningOnGvisor()) {
    constexpr int val = 0;
    ASSERT_THAT(setsockopt(s_, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
                SyscallSucceeds());
    return;
  }

  constexpr int val = 0;
  ASSERT_THAT(setsockopt(s_, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
              SyscallFailsWithErrno(ENOENT));
}

TEST_P(RawSocketTest, GetSocketDetachFilter) {
  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_DETACH_FILTER, &val, &val_len),
              SyscallFailsWithErrno(ENOPROTOOPT));
}

// AF_INET6+SOCK_RAW+IPPROTO_RAW sockets can be created, but not written to.
TEST(RawSocketTest, IPv6ProtoRaw) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW),
              SyscallSucceeds());

  // Verify that writing yields EINVAL.
  char buf[] = "This is such a weird little edge case";
  struct sockaddr_in6 sin6 = {};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_addr = in6addr_loopback;
  ASSERT_THAT(sendto(sock, buf, sizeof(buf), 0 /* flags */,
                     reinterpret_cast<struct sockaddr*>(&sin6), sizeof(sin6)),
              SyscallFailsWithErrno(EINVAL));
}

TEST(RawSocketTest, IPv6SendMsg) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP),
              SyscallSucceeds());

  char kBuf[] = "hello";
  struct iovec iov = {};
  iov.iov_base = static_cast<void*>(const_cast<char*>(kBuf));
  iov.iov_len = static_cast<size_t>(sizeof(kBuf));

  struct sockaddr_storage addr = {};
  struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&addr);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  struct msghdr msg = {};
  msg.msg_name = static_cast<void*>(&addr);
  msg.msg_namelen = sizeof(sockaddr_in);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallFailsWithErrno(EINVAL));
}

TEST_P(RawSocketTest, ConnectOnIPv6Socket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP),
              SyscallSucceeds());

  struct sockaddr_storage addr = {};
  struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&addr);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ASSERT_THAT(connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(sockaddr_in6)),
              SyscallFailsWithErrno(EAFNOSUPPORT));
}

INSTANTIATE_TEST_SUITE_P(
    AllInetTests, RawSocketTest,
    ::testing::Combine(::testing::Values(IPPROTO_TCP, IPPROTO_UDP),
                       ::testing::Values(AF_INET, AF_INET6)));

}  // namespace

}  // namespace testing
}  // namespace gvisor
