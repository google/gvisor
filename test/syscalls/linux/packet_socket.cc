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
using ::testing::Combine;
using ::testing::Eq;
using ::testing::Values;

class PacketSocketCreationTest
    : public ::testing::TestWithParam<std::tuple<int, int>> {
 protected:
  void SetUp() override {
    if (!ASSERT_NO_ERRNO_AND_VALUE(HavePacketSocketCapability())) {
      const auto [type, protocol] = GetParam();
      ASSERT_THAT(socket(AF_PACKET, type, htons(protocol)),
                  SyscallFailsWithErrno(EPERM));
      GTEST_SKIP() << "Missing packet socket capability";
    }
  }
};

TEST_P(PacketSocketCreationTest, Create) {
  const auto [type, protocol] = GetParam();
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, type, htons(protocol)));
  EXPECT_GE(fd.get(), 0);
}

INSTANTIATE_TEST_SUITE_P(AllPacketSocketTests, PacketSocketCreationTest,
                         Combine(Values(SOCK_DGRAM, SOCK_RAW),
                                 Values(0, 1, 255, ETH_P_IP, ETH_P_IPV6,
                                        std::numeric_limits<uint16_t>::max())));

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

TEST_P(PacketSocketTest, GetSockName) {
  {
    // First check the local address of an unbound packet socket.
    sockaddr_ll addr;
    socklen_t addrlen = sizeof(addr);
    ASSERT_THAT(getsockname(socket_.get(), reinterpret_cast<sockaddr*>(&addr),
                            &addrlen),
                SyscallSucceeds());
    // sockaddr_ll ends with an 8 byte physical address field, but only the
    // bytes that are used in the sockaddr_ll.sll_addr field are included in the
    // address length. Seems Linux used to return the size of sockaddr_ll, but
    // https://github.com/torvalds/linux/commit/0fb375fb9b93b7d822debc6a734052337ccfdb1f
    // changed things to only return `sizeof(sockaddr_ll) + sll.sll_addr`.
    ASSERT_THAT(addrlen, AnyOf(Eq(sizeof(addr)),
                               Eq(sizeof(addr) - sizeof(addr.sll_addr))));
    EXPECT_EQ(addr.sll_family, AF_PACKET);
    EXPECT_EQ(addr.sll_ifindex, 0);
    if (IsRunningOnGvisor() && !IsRunningWithHostinet()) {
      // TODO(https://gvisor.dev/issue/6530): Do not assume all interfaces have
      // an ethernet address.
      EXPECT_EQ(addr.sll_halen, ETH_ALEN);
    } else {
      EXPECT_EQ(addr.sll_halen, 0);
    }
    EXPECT_EQ(ntohs(addr.sll_protocol), 0);
    EXPECT_EQ(addr.sll_hatype, 0);
  }
  // Next we bind the socket to loopback before checking the local address.
  const sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
  };
  ASSERT_THAT(bind(socket_.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallSucceeds());
  {
    sockaddr_ll addr;
    socklen_t addrlen = sizeof(addr);
    ASSERT_THAT(getsockname(socket_.get(), reinterpret_cast<sockaddr*>(&addr),
                            &addrlen),
                SyscallSucceeds());
    ASSERT_THAT(addrlen,
                AnyOf(Eq(sizeof(addr)),
                      Eq(sizeof(addr) - sizeof(addr.sll_addr) + ETH_ALEN)));
    EXPECT_EQ(addr.sll_family, AF_PACKET);
    EXPECT_EQ(addr.sll_ifindex, bind_addr.sll_ifindex);
    EXPECT_EQ(addr.sll_halen, ETH_ALEN);
    // Bound to loopback which has the all zeroes address.
    for (int i = 0; i < addr.sll_halen; ++i) {
      EXPECT_EQ(addr.sll_addr[i], 0) << "byte mismatch @ idx = " << i;
    }
    EXPECT_EQ(ntohs(addr.sll_protocol), htons(addr.sll_protocol));
    if (IsRunningOnGvisor() && !IsRunningWithHostinet()) {
      // TODO(https://gvisor.dev/issue/6621): Support populating sll_hatype.
      EXPECT_EQ(addr.sll_hatype, 0);
    } else {
      EXPECT_EQ(addr.sll_hatype, ARPHRD_LOOPBACK);
    }
  }
}

TEST_P(PacketSocketTest, RebindProtocol) {
  const bool kEthHdrIncluded = GetParam() == SOCK_RAW;

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
        bind(udp_sock.get(), reinterpret_cast<const sockaddr*>(&udp_bind_addr),
             sizeof(udp_bind_addr)),
        SyscallSucceeds());
    socklen_t addrlen = sizeof(udp_bind_addr);
    ASSERT_THAT(
        getsockname(udp_sock.get(), reinterpret_cast<sockaddr*>(&udp_bind_addr),
                    &addrlen),
        SyscallSucceeds());
    ASSERT_THAT(addrlen, sizeof(udp_bind_addr));
  }

  const int loopback_index = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex());

  auto send_udp_message = [&](const uint64_t v) {
    ASSERT_THAT(
        sendto(udp_sock.get(), reinterpret_cast<const char*>(&v), sizeof(v),
               0 /* flags */, reinterpret_cast<const sockaddr*>(&udp_bind_addr),
               sizeof(udp_bind_addr)),
        SyscallSucceeds());
  };

  auto bind_to_network_protocol = [&](uint16_t protocol) {
    const sockaddr_ll packet_bind_addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(protocol),
        .sll_ifindex = loopback_index,
    };

    ASSERT_THAT(bind(socket_.get(),
                     reinterpret_cast<const sockaddr*>(&packet_bind_addr),
                     sizeof(packet_bind_addr)),
                SyscallSucceeds());
  };

  auto test_recv = [&, this](const uint64_t v) {
    constexpr int kInfiniteTimeout = -1;
    pollfd pfd = {
        .fd = socket_.get(),
        .events = POLLIN,
    };
    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kInfiniteTimeout),
                SyscallSucceedsWithValue(1));

    struct {
      ethhdr eth;
      iphdr ip;
      udphdr udp;
      uint64_t payload;
      char unused;
    } ABSL_ATTRIBUTE_PACKED read_pkt;
    sockaddr_ll src;
    socklen_t src_len = sizeof(src);

    char* buf = reinterpret_cast<char*>(&read_pkt);
    size_t buflen = sizeof(read_pkt);
    size_t expected_read_len = sizeof(read_pkt) - sizeof(read_pkt.unused);
    if (!kEthHdrIncluded) {
      buf += sizeof(read_pkt.eth);
      buflen -= sizeof(read_pkt.eth);
      expected_read_len -= sizeof(read_pkt.eth);
    }

    ASSERT_THAT(recvfrom(socket_.get(), buf, buflen, 0,
                         reinterpret_cast<sockaddr*>(&src), &src_len),
                SyscallSucceedsWithValue(expected_read_len));
    // sockaddr_ll ends with an 8 byte physical address field, but ethernet
    // addresses only use 6 bytes. Linux used to return sizeof(sockaddr_ll)-2
    // here, but returns sizeof(sockaddr_ll) since
    // https://github.com/torvalds/linux/commit/b2cf86e1563e33a14a1c69b3e508d15dc12f804c.
    ASSERT_THAT(src_len,
                AnyOf(Eq(sizeof(src)),
                      Eq(sizeof(src) - sizeof(src.sll_addr) + ETH_ALEN)));
    EXPECT_EQ(src.sll_family, AF_PACKET);
    EXPECT_EQ(src.sll_ifindex, loopback_index);
    EXPECT_EQ(src.sll_halen, ETH_ALEN);
    EXPECT_EQ(ntohs(src.sll_protocol), ETH_P_IP);
    // This came from the loopback device, so the address is all 0s.
    constexpr uint8_t allZeroesMAC[ETH_ALEN] = {};
    EXPECT_EQ(memcmp(src.sll_addr, allZeroesMAC, sizeof(allZeroesMAC)), 0);
    if (kEthHdrIncluded) {
      EXPECT_EQ(memcmp(read_pkt.eth.h_dest, allZeroesMAC, sizeof(allZeroesMAC)),
                0);
      EXPECT_EQ(
          memcmp(read_pkt.eth.h_source, allZeroesMAC, sizeof(allZeroesMAC)), 0);
      EXPECT_EQ(ntohs(read_pkt.eth.h_proto), ETH_P_IP);
    }
    // IHL hold the size of the header in 4 byte units.
    EXPECT_EQ(read_pkt.ip.ihl, sizeof(iphdr) / 4);
    EXPECT_EQ(read_pkt.ip.version, IPVERSION);
    const uint16_t ip_pkt_size =
        sizeof(read_pkt) - sizeof(read_pkt.eth) - sizeof(read_pkt.unused);
    EXPECT_EQ(ntohs(read_pkt.ip.tot_len), ip_pkt_size);
    EXPECT_EQ(read_pkt.ip.protocol, IPPROTO_UDP);
    EXPECT_EQ(ntohl(read_pkt.ip.daddr), INADDR_LOOPBACK);
    EXPECT_EQ(ntohl(read_pkt.ip.saddr), INADDR_LOOPBACK);
    EXPECT_EQ(read_pkt.udp.source, udp_bind_addr.sin_port);
    EXPECT_EQ(read_pkt.udp.dest, udp_bind_addr.sin_port);
    EXPECT_EQ(ntohs(read_pkt.udp.len), ip_pkt_size - sizeof(read_pkt.ip));
    EXPECT_EQ(read_pkt.payload, v);
  };

  // The packet socket is not bound to IPv4 so we should not receive the sent
  // message.
  uint64_t counter = 0;
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));

  // Bind to IPv4 and expect to receive the UDP packet we send after binding.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(ETH_P_IP));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(test_recv(counter));

  // Bind the packet socket to a random protocol.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(255));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));

  // Bind back to IPv4 and expect to the UDP packet we send after binding
  // back to IPv4.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(ETH_P_IP));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(test_recv(counter));

  // A zero valued protocol number should not change the bound network protocol.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(0));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(test_recv(counter));
}

INSTANTIATE_TEST_SUITE_P(AllPacketSocketTests, PacketSocketTest,
                         Values(SOCK_DGRAM, SOCK_RAW));

}  // namespace

}  // namespace testing
}  // namespace gvisor
