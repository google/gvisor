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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// The size of an empty ICMP packet and IP header together.
constexpr size_t kEmptyICMPSize = 28;

// ICMP raw sockets get their own special tests because Linux automatically
// responds to ICMP echo requests, and thus a single echo request sent via
// loopback leads to 2 received ICMP packets.

class RawSocketICMPTest : public ::testing::Test {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Checks that both an ICMP echo request and reply are received. Calls should
  // be wrapped in ASSERT_NO_FATAL_FAILURE.
  void ExpectICMPSuccess(const struct icmphdr& icmp);

  // Sends icmp via s_.
  void SendEmptyICMP(const struct icmphdr& icmp);

  // Sends icmp via s_ to the given address.
  void SendEmptyICMPTo(int sock, const struct sockaddr_in& addr,
                       const struct icmphdr& icmp);

  // Reads from s_ into recv_buf.
  void ReceiveICMP(char* recv_buf, size_t recv_buf_len, size_t expected_size,
                   struct sockaddr_in* src);

  // Reads from sock into recv_buf.
  void ReceiveICMPFrom(char* recv_buf, size_t recv_buf_len,
                       size_t expected_size, struct sockaddr_in* src, int sock);

  // The socket used for both reading and writing.
  int s_;

  // The loopback address.
  struct sockaddr_in addr_;
};

void RawSocketICMPTest::SetUp() {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  ASSERT_THAT(s_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), SyscallSucceeds());

  addr_ = {};

  // "On raw sockets sin_port is set to the IP protocol." - ip(7).
  addr_.sin_port = IPPROTO_IP;
  addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_.sin_family = AF_INET;
}

void RawSocketICMPTest::TearDown() {
  // TearDown will be run even if we skip the test.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    EXPECT_THAT(close(s_), SyscallSucceeds());
  }
}

// We'll only read an echo in this case, as the kernel won't respond to the
// malformed ICMP checksum.
TEST_F(RawSocketICMPTest, SendAndReceiveBadChecksum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Prepare and send an ICMP packet. Use arbitrary junk for checksum, sequence,
  // and ID. None of that should matter for raw sockets - the kernel should
  // still give us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2012;
  icmp.un.echo.id = 2014;
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  // Veryify that we get the echo, then that there's nothing else to read.
  char recv_buf[kEmptyICMPSize];
  struct sockaddr_in src;
  ASSERT_NO_FATAL_FAILURE(
      ReceiveICMP(recv_buf, sizeof(recv_buf), sizeof(struct icmphdr), &src));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(src)), 0);
  // The packet should be identical to what we sent.
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), &icmp, sizeof(icmp)), 0);

  // And there should be nothing left to read.
  EXPECT_THAT(RetryEINTR(recv)(s_, recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Send and receive an ICMP packet.
TEST_F(RawSocketICMPTest, SendAndReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  // Prepare and send an ICMP packet. Use arbitrary junk for sequence and ID.
  // None of that should matter for raw sockets - the kernel should still give
  // us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2012;
  icmp.un.echo.id = 2014;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// We should be able to create multiple raw sockets for the same protocol and
// receive the same packet on both.
TEST_F(RawSocketICMPTest, MultipleSocketReceive) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor s2 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));

  // Prepare and send an ICMP packet. Use arbitrary junk for sequence and ID.
  // None of that should matter for raw sockets - the kernel should still give
  // us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2016;
  icmp.un.echo.id = 2018;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  // Both sockets will receive the echo request and reply in indeterminate
  // order, so we'll need to read 2 packets from each.

  // Receive on socket 1.
  constexpr int kBufSize = kEmptyICMPSize;
  char recv_buf1[2][kBufSize];
  struct sockaddr_in src;
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(ReceiveICMP(recv_buf1[i],
                                        ABSL_ARRAYSIZE(recv_buf1[i]),
                                        sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(src)), 0);
  }

  // Receive on socket 2.
  char recv_buf2[2][kBufSize];
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(
        ReceiveICMPFrom(recv_buf2[i], ABSL_ARRAYSIZE(recv_buf2[i]),
                        sizeof(struct icmphdr), &src, s2.get()));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(src)), 0);
  }

  // Ensure both sockets receive identical packets.
  int types[] = {ICMP_ECHO, ICMP_ECHOREPLY};
  for (int type : types) {
    auto match_type = [=](char buf[kBufSize]) {
      struct icmphdr* icmp =
          reinterpret_cast<struct icmphdr*>(buf + sizeof(struct iphdr));
      return icmp->type == type;
    };
    auto icmp1_it =
        std::find_if(std::begin(recv_buf1), std::end(recv_buf1), match_type);
    auto icmp2_it =
        std::find_if(std::begin(recv_buf2), std::end(recv_buf2), match_type);
    ASSERT_NE(icmp1_it, std::end(recv_buf1));
    ASSERT_NE(icmp2_it, std::end(recv_buf2));
    EXPECT_EQ(memcmp(*icmp1_it + sizeof(struct iphdr),
                     *icmp2_it + sizeof(struct iphdr), sizeof(icmp)),
              0);
  }
}

// A raw ICMP socket and ping socket should both receive the ICMP packets
// intended for the ping socket.
TEST_F(RawSocketICMPTest, RawAndPingSockets) {
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

  // Receive on socket 1, which receives the echo request and reply in
  // indeterminate order.
  constexpr int kBufSize = kEmptyICMPSize;
  char recv_buf1[2][kBufSize];
  struct sockaddr_in src;
  for (int i = 0; i < 2; i++) {
    ASSERT_NO_FATAL_FAILURE(
        ReceiveICMP(recv_buf1[i], kBufSize, sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(src)), 0);
  }

  // Receive on socket 2. Ping sockets only get the echo reply, not the initial
  // echo.
  char ping_recv_buf[kBufSize];
  ASSERT_THAT(RetryEINTR(recv)(ping_sock.get(), ping_recv_buf, kBufSize, 0),
              SyscallSucceedsWithValue(sizeof(struct icmphdr)));

  // Ensure both sockets receive identical echo reply packets.
  auto match_type_raw = [=](char buf[kBufSize]) {
    struct icmphdr* icmp =
        reinterpret_cast<struct icmphdr*>(buf + sizeof(struct iphdr));
    return icmp->type == ICMP_ECHOREPLY;
  };
  auto raw_reply_it =
      std::find_if(std::begin(recv_buf1), std::end(recv_buf1), match_type_raw);
  ASSERT_NE(raw_reply_it, std::end(recv_buf1));
  EXPECT_EQ(
      memcmp(*raw_reply_it + sizeof(struct iphdr), ping_recv_buf, sizeof(icmp)),
      0);
}

// A raw ICMP socket should be able to send a malformed short ICMP Echo Request,
// while ping socket should not.
// Neither should be able to receieve a short malformed packet.
TEST_F(RawSocketICMPTest, ShortEchoRawAndPingSockets) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor ping_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));

  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.un.echo.sequence = 0;
  icmp.un.echo.id = 6789;
  icmp.checksum = 0;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);

  // Omit 2 bytes from ICMP packet.
  constexpr int kShortICMPSize = sizeof(icmp) - 2;

  // Sending a malformed short ICMP message to a ping socket should fail.
  ASSERT_THAT(RetryEINTR(sendto)(ping_sock.get(), &icmp, kShortICMPSize, 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 sizeof(addr_)),
              SyscallFailsWithErrno(EINVAL));

  // Sending a malformed short ICMP message to a raw socket should not fail.
  ASSERT_THAT(RetryEINTR(sendto)(s_, &icmp, kShortICMPSize, 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 sizeof(addr_)),
              SyscallSucceedsWithValue(kShortICMPSize));

  // Neither Ping nor Raw socket should have anything to read.
  char recv_buf[kEmptyICMPSize];
  EXPECT_THAT(RetryEINTR(recv)(ping_sock.get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
  EXPECT_THAT(RetryEINTR(recv)(s_, recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// A raw ICMP socket should be able to send a malformed short ICMP Echo Reply,
// while ping socket should not.
// Neither should be able to receieve a short malformed packet.
TEST_F(RawSocketICMPTest, ShortEchoReplyRawAndPingSockets) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor ping_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));

  struct icmphdr icmp;
  icmp.type = ICMP_ECHOREPLY;
  icmp.code = 0;
  icmp.un.echo.sequence = 0;
  icmp.un.echo.id = 6789;
  icmp.checksum = 0;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);

  // Omit 2 bytes from ICMP packet.
  constexpr int kShortICMPSize = sizeof(icmp) - 2;

  // Sending a malformed short ICMP message to a ping socket should fail.
  ASSERT_THAT(RetryEINTR(sendto)(ping_sock.get(), &icmp, kShortICMPSize, 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 sizeof(addr_)),
              SyscallFailsWithErrno(EINVAL));

  // Sending a malformed short ICMP message to a raw socket should not fail.
  ASSERT_THAT(RetryEINTR(sendto)(s_, &icmp, kShortICMPSize, 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 sizeof(addr_)),
              SyscallSucceedsWithValue(kShortICMPSize));

  // Neither Ping nor Raw socket should have anything to read.
  char recv_buf[kEmptyICMPSize];
  EXPECT_THAT(RetryEINTR(recv)(ping_sock.get(), recv_buf, sizeof(recv_buf),
                               MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
  EXPECT_THAT(RetryEINTR(recv)(s_, recv_buf, sizeof(recv_buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that connect() sends packets to the right place.
TEST_F(RawSocketICMPTest, SendAndReceiveViaConnect) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(
      connect(s_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());

  // Prepare and send an ICMP packet. Use arbitrary junk for sequence and ID.
  // None of that should matter for raw sockets - the kernel should still give
  // us the packet.
  struct icmphdr icmp;
  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2003;
  icmp.un.echo.id = 2004;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);
  ASSERT_THAT(send(s_, &icmp, sizeof(icmp), 0),
              SyscallSucceedsWithValue(sizeof(icmp)));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// Bind to localhost, then send and receive packets.
TEST_F(RawSocketICMPTest, BindSendAndReceive) {
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
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2004;
  icmp.un.echo.id = 2007;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// Bind and connect to localhost and send/receive packets.
TEST_F(RawSocketICMPTest, BindConnectSendAndReceive) {
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
  icmp.checksum = 0;
  icmp.un.echo.sequence = 2010;
  icmp.un.echo.id = 7;
  icmp.checksum = ICMPChecksum(icmp, NULL, 0);
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(icmp));

  ASSERT_NO_FATAL_FAILURE(ExpectICMPSuccess(icmp));
}

// Set and get SO_LINGER.
TEST_F(RawSocketICMPTest, SetAndGetSocketLinger) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int level = SOL_SOCKET;
  int type = SO_LINGER;

  struct linger sl;
  sl.l_onoff = 1;
  sl.l_linger = 5;
  ASSERT_THAT(setsockopt(s_, level, type, &sl, sizeof(sl)),
              SyscallSucceedsWithValue(0));

  struct linger got_linger = {};
  socklen_t length = sizeof(sl);
  ASSERT_THAT(getsockopt(s_, level, type, &got_linger, &length),
              SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got_linger));
  EXPECT_EQ(0, memcmp(&sl, &got_linger, length));
}

// Test getsockopt for SO_ACCEPTCONN.
TEST_F(RawSocketICMPTest, GetSocketAcceptConn) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
              SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

void RawSocketICMPTest::ExpectICMPSuccess(const struct icmphdr& icmp) {
  // We're going to receive both the echo request and reply, but the order is
  // indeterminate.
  char recv_buf[kEmptyICMPSize];
  struct sockaddr_in src;
  bool received_request = false;
  bool received_reply = false;

  for (int i = 0; i < 2; i++) {
    // Receive the packet.
    ASSERT_NO_FATAL_FAILURE(ReceiveICMP(recv_buf, ABSL_ARRAYSIZE(recv_buf),
                                        sizeof(struct icmphdr), &src));
    EXPECT_EQ(memcmp(&src, &addr_, sizeof(src)), 0);
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
        // The checksum computed over the reply should still be valid.
        EXPECT_EQ(ICMPChecksum(*recvd_icmp, NULL, 0), 0);
        break;
    }
  }

  ASSERT_TRUE(received_request);
  ASSERT_TRUE(received_reply);
}

void RawSocketICMPTest::SendEmptyICMP(const struct icmphdr& icmp) {
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMPTo(s_, addr_, icmp));
}

void RawSocketICMPTest::SendEmptyICMPTo(int sock,
                                        const struct sockaddr_in& addr,
                                        const struct icmphdr& icmp) {
  // It's safe to use const_cast here because sendmsg won't modify the iovec or
  // address.
  struct iovec iov = {};
  iov.iov_base = static_cast<void*>(const_cast<struct icmphdr*>(&icmp));
  iov.iov_len = sizeof(icmp);
  struct msghdr msg = {};
  msg.msg_name = static_cast<void*>(const_cast<struct sockaddr_in*>(&addr));
  msg.msg_namelen = sizeof(addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallSucceedsWithValue(sizeof(icmp)));
}

void RawSocketICMPTest::ReceiveICMP(char* recv_buf, size_t recv_buf_len,
                                    size_t expected_size,
                                    struct sockaddr_in* src) {
  ASSERT_NO_FATAL_FAILURE(
      ReceiveICMPFrom(recv_buf, recv_buf_len, expected_size, src, s_));
}

void RawSocketICMPTest::ReceiveICMPFrom(char* recv_buf, size_t recv_buf_len,
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
