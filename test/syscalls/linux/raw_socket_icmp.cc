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

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>

#include "gtest/gtest.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::FieldsAre;
using ::testing::Not;
using ::testing::Test;
using ::testing::Values;
using ::testing::WithParamInterface;

// The size of an empty ICMP packet and IP header together.
constexpr size_t kEmptyICMPSize = 28;

// ICMP raw sockets get their own special tests because Linux automatically
// responds to ICMP echo requests, and thus a single echo request sent via
// loopback leads to 2 received ICMP packets.

class RawSocketICMPTest : public Test {
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
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability())) {
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
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability())) {
    EXPECT_THAT(close(s_), SyscallSucceeds());
  }
}

TEST_F(RawSocketICMPTest, IPv6ChecksumNotSupported) {
  int v;
  EXPECT_THAT(setsockopt(s_, SOL_IPV6, IPV6_CHECKSUM, &v, sizeof(v)),
              SyscallFailsWithErrno(ENOPROTOOPT));
  socklen_t len = sizeof(v);
  EXPECT_THAT(getsockopt(s_, SOL_IPV6, IPV6_CHECKSUM, &v, &len),
              SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_EQ(len, sizeof(v));
}

TEST_F(RawSocketICMPTest, ICMPv6FilterNotSupported) {
  icmp6_filter v;
  EXPECT_THAT(setsockopt(s_, SOL_ICMPV6, ICMP6_FILTER, &v, sizeof(v)),
              SyscallFailsWithErrno(ENOPROTOOPT));
  socklen_t len = sizeof(v);
  EXPECT_THAT(getsockopt(s_, SOL_ICMPV6, ICMP6_FILTER, &v, &len),
              SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_EQ(len, sizeof(v));
}

// We'll only read an echo in this case, as the kernel won't respond to the
// malformed ICMP checksum.
TEST_F(RawSocketICMPTest, SendAndReceiveBadChecksum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
// while a ping socket should not. Neither should be able to receieve a short
// malformed packet.
TEST_F(RawSocketICMPTest, ShortEchoRawAndPingSockets) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

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

class RawSocketICMPv6Test : public Test {
 public:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability()));

    fd_ = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6));
  }

  void TearDown() override {
    if (!ASSERT_NO_ERRNO_AND_VALUE(HaveRawIPSocketCapability())) {
      return;
    }

    EXPECT_THAT(close(fd_.release()), SyscallSucceeds());
  }

 protected:
  const FileDescriptor& fd() { return fd_; }

 private:
  FileDescriptor fd_;
};

TEST_F(RawSocketICMPv6Test, InitialFilterPassesAll) {
  icmp6_filter got_filter;
  socklen_t got_filter_len = sizeof(got_filter);
  ASSERT_THAT(getsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &got_filter,
                         &got_filter_len),
              SyscallSucceeds());
  ASSERT_EQ(got_filter_len, sizeof(got_filter));
  icmp6_filter expected_filter;
  ICMP6_FILTER_SETPASSALL(&expected_filter);
  EXPECT_THAT(got_filter,
              FieldsAre(ElementsAreArray(expected_filter.icmp6_filt)));
}

TEST_F(RawSocketICMPv6Test, GetPartialFilterSucceeds) {
  icmp6_filter set_filter;
  ICMP6_FILTER_SETBLOCKALL(&set_filter);
  ASSERT_THAT(setsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &set_filter,
                         sizeof(set_filter)),
              SyscallSucceeds());

  icmp6_filter got_filter = {};
  // We use a length smaller than a full filter length and expect that
  // only the bytes up to the provided length are modified. The last element
  // should be unmodified when getsockopt returns.
  constexpr socklen_t kShortFilterLen =
      sizeof(got_filter) - sizeof(got_filter.icmp6_filt[0]);
  socklen_t got_filter_len = kShortFilterLen;
  ASSERT_THAT(getsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &got_filter,
                         &got_filter_len),
              SyscallSucceeds());
  ASSERT_EQ(got_filter_len, kShortFilterLen);
  icmp6_filter expected_filter = set_filter;
  expected_filter.icmp6_filt[std::size(expected_filter.icmp6_filt) - 1] = 0;
  EXPECT_THAT(got_filter,
              FieldsAre(ElementsAreArray(expected_filter.icmp6_filt)));
}

TEST_F(RawSocketICMPv6Test, SetSockOptIPv6ChecksumFails) {
  int v = 2;
  EXPECT_THAT(setsockopt(fd().get(), SOL_IPV6, IPV6_CHECKSUM, &v, sizeof(v)),
              SyscallFailsWithErrno(EINVAL));
  socklen_t len = sizeof(v);
  EXPECT_THAT(getsockopt(fd().get(), SOL_IPV6, IPV6_CHECKSUM, &v, &len),
              SyscallSucceeds());
  ASSERT_EQ(len, sizeof(v));
  EXPECT_EQ(v, offsetof(icmp6_hdr, icmp6_cksum));
}

TEST_F(RawSocketICMPv6Test, MsgTooSmallToFillChecksumFailsSend) {
  char buf[offsetof(icmp6_hdr, icmp6_cksum) +
           sizeof((icmp6_hdr{}).icmp6_cksum) - 1];

  const sockaddr_in6 addr = {
      .sin6_family = AF_INET6,
      .sin6_addr = IN6ADDR_LOOPBACK_INIT,
  };

  ASSERT_THAT(sendto(fd().get(), &buf, sizeof(buf), /*flags=*/0,
                     reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)),
              SyscallFailsWithErrno(EINVAL));
}

constexpr uint8_t kUnusedICMPCode = 0;

TEST_F(RawSocketICMPv6Test, PingSuccessfully) {
  // Only observe echo packets.
  {
    icmp6_filter set_filter;
    ICMP6_FILTER_SETBLOCKALL(&set_filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST, &set_filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &set_filter);
    ASSERT_THAT(setsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &set_filter,
                           sizeof(set_filter)),
                SyscallSucceeds());
  }

  const sockaddr_in6 addr = {
      .sin6_family = AF_INET6,
      .sin6_addr = IN6ADDR_LOOPBACK_INIT,
  };

  auto send_with_checksum = [&](uint16_t checksum) {
    const icmp6_hdr echo_request = {
        .icmp6_type = ICMP6_ECHO_REQUEST,
        .icmp6_code = kUnusedICMPCode,
        .icmp6_cksum = checksum,
    };

    ASSERT_THAT(RetryEINTR(sendto)(fd().get(), &echo_request,
                                   sizeof(echo_request), /*flags=*/0,
                                   reinterpret_cast<const sockaddr*>(&addr),
                                   sizeof(addr)),
                SyscallSucceedsWithValue(sizeof(echo_request)));
  };

  auto check_recv = [&](uint8_t expected_type) {
    icmp6_hdr got_echo;
    sockaddr_in6 sender;
    socklen_t sender_len = sizeof(sender);
    ASSERT_THAT(RetryEINTR(recvfrom)(
                    fd().get(), &got_echo, sizeof(got_echo), /*flags=*/0,
                    reinterpret_cast<sockaddr*>(&sender), &sender_len),
                SyscallSucceedsWithValue(sizeof(got_echo)));
    ASSERT_EQ(sender_len, sizeof(sender));
    EXPECT_EQ(memcmp(&sender, &addr, sizeof(addr)), 0);
    EXPECT_THAT(got_echo,
                FieldsAre(expected_type, kUnusedICMPCode,
                          // The stack should have populated the checksum.
                          /*icmp6_cksum=*/Not(0), /*icmp6_dataun=*/_));
    EXPECT_THAT(got_echo.icmp6_data32, ElementsAre(0));
  };

  // Send a request and observe the request followed by the response.
  ASSERT_NO_FATAL_FAILURE(send_with_checksum(0));
  ASSERT_NO_FATAL_FAILURE(check_recv(ICMP6_ECHO_REQUEST));
  ASSERT_NO_FATAL_FAILURE(check_recv(ICMP6_ECHO_REPLY));

  // The stack ignores the checksum set by the user.
  ASSERT_NO_FATAL_FAILURE(send_with_checksum(1));
  ASSERT_NO_FATAL_FAILURE(check_recv(ICMP6_ECHO_REQUEST));
  ASSERT_NO_FATAL_FAILURE(check_recv(ICMP6_ECHO_REPLY));
}

class RawSocketICMPv6TypeTest : public RawSocketICMPv6Test,
                                public WithParamInterface<uint8_t> {};

TEST_P(RawSocketICMPv6TypeTest, FilterDeliveredPackets) {
  const sockaddr_in6 addr = {
      .sin6_family = AF_INET6,
      .sin6_addr = IN6ADDR_LOOPBACK_INIT,
  };

  const uint8_t allowed_type = GetParam();

  // Pass only the allowed type.
  {
    icmp6_filter set_filter;
    ICMP6_FILTER_SETBLOCKALL(&set_filter);
    ICMP6_FILTER_SETPASS(allowed_type, &set_filter);
    ASSERT_THAT(setsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &set_filter,
                           sizeof(set_filter)),
                SyscallSucceeds());

    icmp6_filter got_filter;
    socklen_t got_filter_len = sizeof(got_filter);
    ASSERT_THAT(getsockopt(fd().get(), SOL_ICMPV6, ICMP6_FILTER, &got_filter,
                           &got_filter_len),
                SyscallSucceeds());
    ASSERT_EQ(got_filter_len, sizeof(got_filter));
    EXPECT_THAT(got_filter, FieldsAre(ElementsAreArray(set_filter.icmp6_filt)));
  }

  // Send an ICMP packet for each type.
  uint8_t icmp_type = 0;
  do {
    const icmp6_hdr packet = {
        .icmp6_type = icmp_type,
        .icmp6_code = kUnusedICMPCode,
        // The stack will calculate the checksum.
        .icmp6_cksum = 0,
    };

    ASSERT_THAT(RetryEINTR(sendto)(fd().get(), &packet, sizeof(packet), 0,
                                   reinterpret_cast<const sockaddr*>(&addr),
                                   sizeof(addr)),
                SyscallSucceedsWithValue(sizeof(packet)));
  } while (icmp_type++ != std::numeric_limits<uint8_t>::max());

  // Make sure only the allowed type was received.
  {
    icmp6_hdr got_packet;
    sockaddr_in6 sender;
    socklen_t sender_len = sizeof(sender);
    ASSERT_THAT(RetryEINTR(recvfrom)(
                    fd().get(), &got_packet, sizeof(got_packet), /*flags=*/0,
                    reinterpret_cast<sockaddr*>(&sender), &sender_len),
                SyscallSucceedsWithValue(sizeof(got_packet)));
    ASSERT_EQ(sender_len, sizeof(sender));
    EXPECT_EQ(memcmp(&sender, &addr, sizeof(addr)), 0);
    // The stack should have populated the checksum.
    EXPECT_THAT(got_packet,
                FieldsAre(allowed_type, kUnusedICMPCode,
                          /*icmp6_cksum=*/Not(0), /*icmp6_dataun=*/_));
    EXPECT_THAT(got_packet.icmp6_data32, ElementsAre(0));
  }
}

INSTANTIATE_TEST_SUITE_P(AllRawSocketTests, RawSocketICMPv6TypeTest,
                         Values(uint8_t{0},
                                std::numeric_limits<uint8_t>::max()));

}  // namespace

}  // namespace testing
}  // namespace gvisor
