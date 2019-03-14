// Copyright 2019 Google LLC
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

  // The socket used for both reading and writing.
  int s_;

  // The loopback address.
  struct sockaddr_in addr_;

  void SendEmptyICMP(struct icmphdr *icmp);

  void SendEmptyICMPTo(int sock, struct sockaddr_in *addr,
                       struct icmphdr *icmp);

  void ReceiveICMP(char *recv_buf, size_t recv_buf_len, size_t expected_size,
                   struct sockaddr_in *src);

  void ReceiveICMPFrom(char *recv_buf, size_t recv_buf_len,
                       size_t expected_size, struct sockaddr_in *src, int sock);
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
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(&icmp));

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
    struct icmphdr *recvd_icmp =
        reinterpret_cast<struct icmphdr *>(recv_buf + sizeof(struct iphdr));
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
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMP(&icmp));

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
      struct icmphdr *icmp =
          reinterpret_cast<struct icmphdr *>(buf + sizeof(struct iphdr));
      return icmp->type == type;
    };
    char *icmp1 = *std::find_if(recv_buf1.begin(), recv_buf1.end(), match_type);
    char *icmp2 = *std::find_if(recv_buf2.begin(), recv_buf2.end(), match_type);
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
  icmp.un.echo.sequence =
      *static_cast<unsigned short *>(&icmp.un.echo.sequence);
  ASSERT_THAT(RetryEINTR(sendto)(ping_sock.get(), &icmp, sizeof(icmp), 0,
                                 (struct sockaddr *)&addr_, sizeof(addr_)),
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
      struct icmphdr *icmp = reinterpret_cast<struct icmphdr *>(buf);
      return icmp->type == type;
    };
    auto match_type_raw = [=](char buf[kBufSize]) {
      struct icmphdr *icmp =
          reinterpret_cast<struct icmphdr *>(buf + sizeof(struct iphdr));
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

void RawSocketTest::SendEmptyICMP(struct icmphdr *icmp) {
  ASSERT_NO_FATAL_FAILURE(SendEmptyICMPTo(s_, &addr_, icmp));
}

void RawSocketTest::SendEmptyICMPTo(int sock, struct sockaddr_in *addr,
                                    struct icmphdr *icmp) {
  struct iovec iov = {.iov_base = icmp, .iov_len = sizeof(*icmp)};
  struct msghdr msg {
    .msg_name = addr, .msg_namelen = sizeof(*addr), .msg_iov = &iov,
    .msg_iovlen = 1, .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0,
  };
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallSucceedsWithValue(sizeof(*icmp)));
}

void RawSocketTest::ReceiveICMP(char *recv_buf, size_t recv_buf_len,
                                size_t expected_size, struct sockaddr_in *src) {
  ASSERT_NO_FATAL_FAILURE(
      ReceiveICMPFrom(recv_buf, recv_buf_len, expected_size, src, s_));
}

void RawSocketTest::ReceiveICMPFrom(char *recv_buf, size_t recv_buf_len,
                                    size_t expected_size,
                                    struct sockaddr_in *src, int sock) {
  struct iovec iov = {.iov_base = recv_buf, .iov_len = recv_buf_len};
  struct msghdr msg = {
      .msg_name = src,
      .msg_namelen = sizeof(*src),
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = NULL,
      .msg_controllen = 0,
      .msg_flags = 0,
  };
  // We should receive the ICMP packet plus 20 bytes of IP header.
  ASSERT_THAT(recvmsg(sock, &msg, 0),
              SyscallSucceedsWithValue(expected_size + sizeof(struct iphdr)));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
