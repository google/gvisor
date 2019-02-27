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

  void sendEmptyICMP(struct icmphdr *icmp);

  void sendEmptyICMPTo(int sock, struct sockaddr_in *addr,
                       struct icmphdr *icmp);

  void receiveICMP(char *recv_buf, size_t recv_buf_len, size_t expected_size,
                   struct sockaddr_in *src);

  void receiveICMPFrom(char *recv_buf, size_t recv_buf_len,
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
  icmp.checksum = *(unsigned short *)&icmp.checksum;
  icmp.un.echo.sequence = *(unsigned short *)&icmp.un.echo.sequence;
  icmp.un.echo.id = *(unsigned short *)&icmp.un.echo.id;
  ASSERT_NO_FATAL_FAILURE(sendEmptyICMP(&icmp));

  // Receive the packet and make sure it's identical.
  char recv_buf[512];
  struct sockaddr_in src;
  ASSERT_NO_FATAL_FAILURE(receiveICMP(recv_buf, ABSL_ARRAYSIZE(recv_buf),
                                      sizeof(struct icmphdr), &src));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), &icmp, sizeof(icmp)), 0);

  // We should also receive the automatically generated echo reply.
  ASSERT_NO_FATAL_FAILURE(receiveICMP(recv_buf, ABSL_ARRAYSIZE(recv_buf),
                                      sizeof(struct icmphdr), &src));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);
  struct icmphdr *reply_icmp =
      (struct icmphdr *)(recv_buf + sizeof(struct iphdr));
  // Most fields should be the same.
  EXPECT_EQ(reply_icmp->code, icmp.code);
  EXPECT_EQ(reply_icmp->un.echo.sequence, icmp.un.echo.sequence);
  EXPECT_EQ(reply_icmp->un.echo.id, icmp.un.echo.id);
  // A couple are different.
  EXPECT_EQ(reply_icmp->type, ICMP_ECHOREPLY);
  // The checksum is computed in such a way that it is guaranteed to have
  // changed.
  EXPECT_NE(reply_icmp->checksum, icmp.checksum);
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
  icmp.checksum = *(unsigned short *)&icmp.checksum;
  icmp.un.echo.sequence = *(unsigned short *)&icmp.un.echo.sequence;
  icmp.un.echo.id = *(unsigned short *)&icmp.un.echo.id;
  ASSERT_NO_FATAL_FAILURE(sendEmptyICMP(&icmp));

  // Receive it on socket 1.
  char recv_buf1[512];
  struct sockaddr_in src;
  ASSERT_NO_FATAL_FAILURE(receiveICMP(recv_buf1, ABSL_ARRAYSIZE(recv_buf1),
                                      sizeof(struct icmphdr), &src));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);

  // Receive it on socket 2.
  char recv_buf2[512];
  ASSERT_NO_FATAL_FAILURE(receiveICMPFrom(recv_buf2, ABSL_ARRAYSIZE(recv_buf2),
                                          sizeof(struct icmphdr), &src,
                                          s2.get()));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);

  EXPECT_EQ(memcmp(recv_buf1 + sizeof(struct iphdr),
                   recv_buf2 + sizeof(struct iphdr), sizeof(icmp)),
            0);
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
  icmp.un.echo.sequence = *(unsigned short *)&icmp.un.echo.sequence;
  ASSERT_THAT(RetryEINTR(sendto)(ping_sock.get(), &icmp, sizeof(icmp), 0,
                                 (struct sockaddr *)&addr_, sizeof(addr_)),
              SyscallSucceedsWithValue(sizeof(icmp)));

  // Receive the packet via raw socket.
  char recv_buf[512];
  struct sockaddr_in src;
  ASSERT_NO_FATAL_FAILURE(receiveICMP(recv_buf, ABSL_ARRAYSIZE(recv_buf),
                                      sizeof(struct icmphdr), &src));
  EXPECT_EQ(memcmp(&src, &addr_, sizeof(sockaddr_in)), 0);

  // Receive the packet via ping socket.
  struct icmphdr ping_header;
  ASSERT_THAT(
      RetryEINTR(recv)(ping_sock.get(), &ping_header, sizeof(ping_header), 0),
      SyscallSucceedsWithValue(sizeof(ping_header)));

  // Packets should be the same.
  EXPECT_EQ(memcmp(recv_buf + sizeof(struct iphdr), &ping_header,
                   sizeof(struct icmphdr)),
            0);
}

void RawSocketTest::sendEmptyICMP(struct icmphdr *icmp) {
  ASSERT_NO_FATAL_FAILURE(sendEmptyICMPTo(s_, &addr_, icmp));
}

void RawSocketTest::sendEmptyICMPTo(int sock, struct sockaddr_in *addr,
                                    struct icmphdr *icmp) {
  struct iovec iov = {.iov_base = icmp, .iov_len = sizeof(*icmp)};
  struct msghdr msg {
    .msg_name = addr, .msg_namelen = sizeof(*addr), .msg_iov = &iov,
    .msg_iovlen = 1, .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0,
  };
  ASSERT_THAT(sendmsg(sock, &msg, 0), SyscallSucceedsWithValue(sizeof(*icmp)));
}

void RawSocketTest::receiveICMP(char *recv_buf, size_t recv_buf_len,
                                size_t expected_size, struct sockaddr_in *src) {
  ASSERT_NO_FATAL_FAILURE(
      receiveICMPFrom(recv_buf, recv_buf_len, expected_size, src, s_));
}

void RawSocketTest::receiveICMPFrom(char *recv_buf, size_t recv_buf_len,
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
