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
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Fixture for tests parameterized by address family (currently only AF_INET).
class RawSocketTest : public ::testing::Test {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Checks that both an ICMP echo request and reply are received. Calls should
  // be wrapped in ASSERT_NO_FATAL_FAILURE.
  void ExpectICMPSuccess(const struct icmphdr& icmp);

  void SendEmptyICMP(const struct icmphdr& icmp);

  void SendEmptyICMPTo(int sock, struct sockaddr_in* addr,
                       const struct icmphdr& icmp);

  void ReceiveICMP(char* recv_buf, size_t recv_buf_len, size_t expected_size,
                   struct sockaddr_in* src);

  void ReceiveICMPFrom(char* recv_buf, size_t recv_buf_len,
                       size_t expected_size, struct sockaddr_in* src, int sock);

  // The socket used for both reading and writing.
  int s_;

  // The loopback address.
  struct sockaddr_in addr_;
};

void RawSocketTest::SetUp() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(s_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), SyscallSucceeds());

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
TEST_F(RawSocketTest, MultipleCreation) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int s2;
  ASSERT_THAT(s2 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), SyscallSucceeds());

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Send and receive an ICMP packet.
TEST_F(RawSocketTest, SendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2011;
  icmp.un.echo.sequence = 2012;
  icmp.un.echo.id = 2014;
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// We should be able to create multiple raw sockets for the same protocol and
// receive the same packet on both.
TEST_F(RawSocketTest, MultipleSocketReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor s2 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2014;
  icmp.un.echo.sequence = 2016;
  icmp.un.echo.id = 2018;
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  // Both sockets will receive the echo request and reply in indeterminate
  // order, so we'll need to read 2 packets from each.

  // Receive on socket 1.
  constexpr int kBufSize = 256;
  std::vector<char[kBufSize]> recv_buf1(2);
  struct sockaddr_in src;
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(ReceiveICMP(recv_buf1[i],
                                        ABSL_ARRAYSIZE(recv_buf1[i]),
                                        sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
  }

  // Receive on socket 2.
  std::vector<char[kBufSize]> recv_buf2(2);
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(
        ReceiveICMPFrom(recv_buf2[i], ABSL_ARRAYSIZE(recv_buf2[i]),
                        sizeof(struct icmphdr), &src, s2.get()));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
  }

  // Ensure both sockets receive identical packets.
  int types[] = {ICMP_ECHO, ICMP_ECHOREPLY};
  for (int type : types) {
    auto match_type = [=](char buf[kBufSize]) {
      struct icmphdr* icmp =
          reinterpret_cast<struct icmphdr*>(buf + sizeof(struct iphdr));
      return icmp->type == type;
    };
    const char* icmp1 =
        *std::find_if(recv_buf1.begin(), recv_buf1.end(), match_type);
    const char* icmp2 =
        *std::find_if(recv_buf2.begin(), recv_buf2.end(), match_type);
    ASSERT_NE(icmp1, *recv_buf1.end());
    ASSERT_NE(icmp2, *recv_buf2.end());
    EXPECT_EQ(memcmp(icmp1 + sizeof(struct iphdr), icmp2 + sizeof(struct iphdr),
                     sizeof(icmp)),
              0);
  }
}

// A raw ICMP socket and ping socket should both receive the ICMP packets
// indended for the ping socket.
TEST_F(RawSocketTest, RawAndPingSockets) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor ping_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));

  // Ping sockets take care of the ICMP ID and checksum.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.un.echo.sequence = *static_cast<unsigned short*>(&icmp.un.echo.sequence);
  ASSERT_THAT(RetryEINTR(sendto)(ping_sock.get(), &icmp, sizeof(icmp), 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 sizeof(addr_)),
              SyscallSucceedsWithValue(sizeof(icmp)));

  // Both sockets will receive the echo request and reply in indeterminate
  // order, so we'll need to read 2 packets from each.

  // Receive on socket 1.
  constexpr int kBufSize = 256;
  std::vector<char[kBufSize]> recv_buf1(2);
  struct sockaddr_in src;
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(
        ReceiveICMP(recv_buf1[i], kBufSize, sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
  }

  // Receive on socket 2.
  std::vector<char[kBufSize]> recv_buf2(2);
  for (int i = 0; i < 2; i++) {
    ASSERT_THAT(RetryEINTR(recv)(ping_sock.get(), recv_buf2[i], kBufSize, 0),
                SyscallSucceedsWithValue(sizeof(struct icmphdr)));
  }

  // Ensure both sockets receive identical packets.
  int types[] = {ICMP_ECHO, ICMP_ECHOREPLY};
  for (int type : types) {
    auto match_type_ping = [=](char buf[kBufSize]) {
      struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(buf);
      return icmp->type == type;
    };
    auto match_type_raw = [=](char buf[kBufSize]) {
      struct icmphdr* icmp =
          reinterpret_cast<struct icmphdr*>(buf + sizeof(struct iphdr));
      return icmp->type == type;
    };

    char *icmp1 =
        *std::find_if(recv_buf1.begin(), recv_buf1.end(), match_type_raw);
    char *icmp2 =
        *std::find_if(recv_buf2.begin(), recv_buf2.end(), match_type_ping);
    ASSERT_NE(icmp1, *recv_buf1.end());
    ASSERT_NE(icmp2, *recv_buf2.end());
    EXPECT_EQ(memcmp(icmp1 + sizeof(struct iphdr), icmp2, sizeof(icmp)), 0);
  }
}

// Test that shutting down an unconnected socket fails.
TEST_F(RawSocketTest, FailShutdownWithoutConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));
}

// Test that writing to a shutdown write socket fails.
TEST_F(RawSocketTest, FailWritingToShutdown) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_WR), SyscallSucceeds());

  char c;
  ASSERT_THAT(RetryEINTR(write)(s_, &c, sizeof(c)),
              SyscallFailsWithErrno(EPIPE));
}

// Test that reading from a shutdown read socket gets nothing.
TEST_F(RawSocketTest, FailReadingFromShutdown) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  char c;
  ASSERT_THAT(read(s_, &c, sizeof(c)), SyscallSucceedsWithValue(0));
}

// Test that listen() fails.
TEST_F(RawSocketTest, FailListen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(listen(s_, 1), SyscallFailsWithErrno(ENOTSUP));
}

// Test that accept() fails.
TEST_F(RawSocketTest, FailAccept) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(accept(s_, &saddr, &addrlen), SyscallFailsWithErrno(ENOTSUP));
}

// Test that getpeername() returns nothing before connect().
TEST_F(RawSocketTest, FailGetPeerNameBeforeConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

// Test that getpeername() returns something after connect().
TEST_F(RawSocketTest, GetPeerName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(getpeername(s_, &saddr, &addrlen), SyscallSucceeds());
  ASSERT_GT(addrlen, 0);
}

// Test that the socket is writable immediately.
TEST_F(RawSocketTest, PollWritableImmediately) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLOUT;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 10000), SyscallSucceedsWithValue(1));
}

// Test that the socket isn't readable before receiving anything.
TEST_F(RawSocketTest, PollNotReadableInitially) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Try to receive data with MSG_DONTWAIT, which returns immediately if there's
  // nothing to be read.
  char buf[117];
  ASSERT_THAT(RetryEINTR(recv)(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that the socket becomes readable once something is written to it.
TEST_F(RawSocketTest, PollTriggeredOnWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Write something so that there's data to be read.
  struct icmphdr icmp = {};
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 10000), SyscallSucceedsWithValue(1));
}

// Test that we can connect() to a valid IP (loopback).
TEST_F(RawSocketTest, ConnectToLoopback) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
}

// Test that connect() sends packets to the right place.
TEST_F(RawSocketTest, SendAndReceiveViaConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2001;
  icmp.un.echo.sequence = 2003;
  icmp.un.echo.id = 2004;
  ASSERT_THAT(send(s_, &icmp, sizeof(icmp), 0),
              SyscallSucceedsWithValue(sizeof(icmp)));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// Test that calling send() without connect() fails.
TEST_F(RawSocketTest, SendWithoutConnectFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2015;
  icmp.un.echo.sequence = 2017;
  icmp.un.echo.id = 2019;
  ASSERT_THAT(send(s_, &icmp, sizeof(icmp), 0),
              SyscallFailsWithErrno(ENOTCONN));
}

// Bind to localhost.
TEST_F(RawSocketTest, BindToLocalhost) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
}

// Bind to a different address.
TEST_F(RawSocketTest, BindToInvalid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr = {1};  // 1.0.0.0 - An address that we can't bind to.
  ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Bind to localhost, then send and receive packets.
TEST_F(RawSocketTest, BindSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2001;
  icmp.un.echo.sequence = 2004;
  icmp.un.echo.id = 2007;
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// Bind and connect to localhost and send/receive packets.
TEST_F(RawSocketTest, BindConnectSendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      bind(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 2009;
  icmp.un.echo.sequence = 2010;
  icmp.un.echo.id = 7;
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

void RawSocketTest::ExpectICMPSuccess(const struct icmphdr& icmp) {
  // We're going to receive both the echo request and reply, but the order is
  // indeterminate.
  char recv_buf[512];
  struct sockaddr_in src;
  bool received_request = false;
  bool received_reply = false;

  for (int i = 0; i < 2; i++) {
    // Receive the packet.
    ASSERT_NO_FATAL_FAILURE(ReceiveICMP(recv_buf, ABSL_ARRAYSIZE(recv_buf),
                                        sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
    struct icmphdr* recvd_icmp =
        reinterpret_cast<struct icmphdr*>(recv_buf + sizeof(struct iphdr));
    switch (recvd_icmp->type) {
      case ICMP_ECHO:
        EXPECT_FALSE(received_request);
        received_request = true;
        // The packet should be identical to what we sent.
        EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), &icmp, sizeof(icmp)),
                  0);
        break;

      case ICMP_ECHOREPLY:
        EXPECT_FALSE(received_reply);
        received_reply = true;
        // Most fields should be the same.
        EXPECT_EQ(recvd_icmp->code, icmp.code);
        EXPECT_EQ(recvd_icmp->un.echo.sequence, icmp.un.echo.sequence);
        EXPECT_EQ(recvd_icmp->un.echo.id, icmp.un.echo.id);
        // A couple are different.
        EXPECT_EQ(recvd_icmp->type, ICMP_ECHOREPLY);
        // The checksum is computed in such a way that it is guaranteed to have
        // changed.
        EXPECT_NE(recvd_icmp->checksum, icmp.checksum);
        break;
    }
  }

  ASSERT_TRUE(received_request);
  ASSERT_TRUE(received_reply);
}

void RawSocketTest::SendEmptyICMP(const struct icmphdr& icmp) {
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMPTo(s_, &addr_, icmp));
}

void RawSocketTest::SendEmptyICMPTo(int sock, struct sockaddr_in* addr,
                                    const struct icmphdr& icmp) {
  // It's safe to use const_cast here because sendmsg won't modify the iovec.
  struct iovec iov = {};
  iov.iov_base = static_cast<void*>(const_cast<struct icmphdr*>(&icmp));
  iov.iov_len = sizeof(icmp);
  struct msghdr msg = {};
  msg.msg_name = addr;
  msg.msg_namelen = sizeof(*addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallSucceedsWithValue(sizeof(icmp)));
}

void RawSocketTest::ReceiveICMP(char* recv_buf, size_t recv_buf_len,
                                size_t expected_size, struct sockaddr_in* src) {
  ASSERT_NO_FATAL_FAILURE(
      ReceiveICMPFrom(recv_buf, recv_buf_len, expected_size, src, s_));
}

void RawSocketTest::ReceiveICMPFrom(char* recv_buf, size_t recv_buf_len,
                                    size_t expected_size,
                                    struct sockaddr_in* src, int sock) {
  struct iovec iov = {};
  iov.iov_base = recv_buf;
  iov.iov_len = recv_buf_len;
  struct msghdr msg = {};
  msg.msg_name = src;
  msg.msg_namelen = sizeof(*src);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  // We should receive the ICMP packet plus 20 bytes of IP header.
  ASSERT_THAT(recvmsg(sock, &msg, 0),
              SyscallSucceedsWithValue(expected_size + sizeof(struct iphdr)));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
