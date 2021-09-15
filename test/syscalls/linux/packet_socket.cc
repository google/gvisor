// Copyright 2021 The gVisor Authors.
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

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <limits>

#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Eq;

class PacketSocketTest : public ::testing::TestWithParam<int> {
 protected:
  void SetUp() override {
    if (!ASSERT_NO_ERRNO_AND_VALUE(HavePacketSocketCapability())) {
      ASSERT_THAT(socket(AF_PACKET, GetParam(), 0),
                  SyscallFailsWithErrno(EPERM));
      GTEST_SKIP() << "Missing packet socket capability";
    }

    socket_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, GetParam(), 0));
  }

  FileDescriptor socket_;
};

TEST_P(PacketSocketTest, Creation) {
  auto test_creation = [](int protocol) {
    auto fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, GetParam(), protocol));
    EXPECT_GT(fd.release(), 0);
  };

  EXPECT_NO_FATAL_FAILURE(test_creation(0));
  EXPECT_NO_FATAL_FAILURE(test_creation(1));
  EXPECT_NO_FATAL_FAILURE(test_creation(255));
  EXPECT_NO_FATAL_FAILURE(test_creation(htons(ETH_P_IP)));
  EXPECT_NO_FATAL_FAILURE(test_creation(htons(ETH_P_IPV6)));
  EXPECT_NO_FATAL_FAILURE(
      test_creation(htons(std::numeric_limits<uint16_t>::max())));
  EXPECT_NO_FATAL_FAILURE(test_creation(std::numeric_limits<uint16_t>::max()));
}

TEST_P(PacketSocketTest, RebindProtocol) {
  constexpr char kPayload0[] = "payload0";
  constexpr char kPayload1[] = "payload1";
  constexpr char kPayload2[] = "payload2";
  constexpr char kPayload3[] = "payload3";

  sockaddr_in udp_bind_addr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };

  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  {
    // Bind the socket so that we have something to send packets to.
    //
    // If we didn't do this, the UDP packets we send will be responded to with
    // ICMP Destination Port Unreachable errors.
    ASSERT_THAT(
        bind(udp_sock.get(), reinterpret_cast<sockaddr*>(&udp_bind_addr),
             sizeof(udp_bind_addr)),
        SyscallSucceeds());
    socklen_t addrlen = sizeof(udp_bind_addr);
    ASSERT_THAT(
        getsockname(udp_sock.get(), reinterpret_cast<sockaddr*>(&udp_bind_addr),
                    &addrlen),
        SyscallSucceeds());
    ASSERT_THAT(addrlen, sizeof(udp_bind_addr));
  }

  auto send_message = [&](const char* buf, const size_t buflen) {
    SCOPED_TRACE(buf);

    ASSERT_THAT(sendto(udp_sock.get(), buf, buflen, 0 /* flags */,
                       reinterpret_cast<sockaddr*>(&udp_bind_addr),
                       sizeof(udp_bind_addr)),
                SyscallSucceeds());
  };

  const int loopback_index = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());

  auto test_recv = [&, this](const char* expected_payload,
                             const size_t expected_payloadlen) {
    SCOPED_TRACE(expected_payload);

    pollfd pfd = {
        .fd = socket_.get(),
        .events = POLLIN,
    };
    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, -1), SyscallSucceedsWithValue(1));

    // Read and verify the data.
    struct {
      ethhdr eth;
      iphdr ip;
      udphdr udp;
      char payload[std::max(sizeof(kPayload1),
                            std::max(sizeof(kPayload2), sizeof(kPayload3))) +
                   1];
    } ABSL_ATTRIBUTE_PACKED read_pkt;
    sockaddr_ll src;
    socklen_t src_len = sizeof(src);
    char* buf = reinterpret_cast<char*>(&read_pkt);
    size_t buflen = sizeof(read_pkt);
    size_t expected_read_len =
        sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr) + expected_payloadlen;
    if (GetParam() == SOCK_DGRAM) {
      buf += sizeof(ethhdr);
      buflen -= sizeof(ethhdr);
      expected_read_len -= sizeof(ethhdr);
    }
    ASSERT_THAT(recvfrom(socket_.get(), buf, buflen, 0,
                         reinterpret_cast<sockaddr*>(&src), &src_len),
                SyscallSucceedsWithValue(expected_read_len));
    // sockaddr_ll ends with an 8 byte physical address field, but ethernet
    // addresses only use 6 bytes.  Linux used to return sizeof(sockaddr_ll)-2
    // here, but since commit b2cf86e1563e33a14a1c69b3e508d15dc12f804c returns
    // sizeof(sockaddr_ll).
    ASSERT_THAT(src_len, AnyOf(Eq(sizeof(src)), Eq(sizeof(src) - 2)));
    EXPECT_EQ(src.sll_family, AF_PACKET);
    EXPECT_EQ(src.sll_ifindex, loopback_index);
    EXPECT_EQ(src.sll_halen, ETH_ALEN);
    EXPECT_EQ(ntohs(src.sll_protocol), ETH_P_IP);
    // This came from the loopback device, so the address is all 0s.
    for (int i = 0; i < src.sll_halen; i++) {
      EXPECT_EQ(src.sll_addr[i], 0);
    }
    EXPECT_EQ(memcmp(expected_payload, read_pkt.payload, expected_payloadlen),
              0);
  };

  // The packet socket is not bound to IPv4.
  ASSERT_NO_FATAL_FAILURE(send_message(kPayload0, sizeof(kPayload0)));

  // Bind to IPv4 and expect to receive the UDP packet we send after binding.
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = loopback_index,
  };
  ASSERT_THAT(bind(socket_.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(send_message(kPayload1, sizeof(kPayload1)));
  ASSERT_NO_FATAL_FAILURE(test_recv(kPayload1, sizeof(kPayload1)));

  // Bind the packet socket to a random protocol.
  bind_addr.sll_protocol = htons(255);
  ASSERT_THAT(bind(socket_.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(send_message(kPayload2, sizeof(kPayload2)));

  // Bind back to IPv4 and expect to the UDP packet we send after binding
  // back to IPv4.
  bind_addr.sll_protocol = htons(ETH_P_IP);
  ASSERT_THAT(bind(socket_.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(send_message(kPayload3, sizeof(kPayload3)));
  ASSERT_NO_FATAL_FAILURE(test_recv(kPayload3, sizeof(kPayload3)));
}

INSTANTIATE_TEST_SUITE_P(AllPacketSocketTests, PacketSocketTest,
                         ::testing::Values(SOCK_DGRAM, SOCK_RAW));

}  // namespace

}  // namespace testing
}  // namespace gvisor
