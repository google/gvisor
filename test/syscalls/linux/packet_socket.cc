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

    if (IsRunningOnGvisor() && !IsRunningWithHostinet() &&
        GvisorPlatform() != Platform::kFuchsia) {
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
    if (IsRunningOnGvisor() && !IsRunningWithHostinet() &&
        GvisorPlatform() != Platform::kFuchsia) {
      // TODO(https://gvisor.dev/issue/6621): Support populating sll_hatype.
      EXPECT_EQ(addr.sll_hatype, 0);
    } else {
      EXPECT_EQ(addr.sll_hatype, ARPHRD_LOOPBACK);
    }
  }
}

// Expects that a packet can be read from the given packet socket that contains
// a UDP packet whose source and destination port match the one in the given
// address, and whose payload matches the expected payload.
//
// On success, writes the link-layer source address for the packet into
// the provided output parameter (if it is non-null).
void ExpectReceiveOnPacketSocket(FileDescriptor& socket,
                                 bool ethernet_header_included,
                                 const sockaddr_in& expected_udp_addr,
                                 const uint64_t expected_udp_payload,
                                 sockaddr_ll* src_out = nullptr) {
  // Declare each section of the packet as a separate stack variable in order
  // to ensure all sections are 8-byte aligned.
  ethhdr eth;
  iphdr ip;
  udphdr udp;
  uint64_t payload;
  char unused;

  constexpr size_t kStorageLen =
      sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(payload) + sizeof(unused);
  char storage[kStorageLen];

  sockaddr_ll src;
  socklen_t src_len = sizeof(src);

  char* buf = storage;
  size_t buflen = kStorageLen;
  auto advance_buf = [&buf, &buflen](size_t amount) {
    buf += amount;
    buflen -= amount;
  };
  size_t expected_read_len = buflen - sizeof(unused);
  if (!ethernet_header_included) {
    advance_buf(sizeof(eth));
    expected_read_len -= sizeof(eth);
  }

  iovec received_iov = {
      .iov_base = buf,
      .iov_len = buflen,
  };
  msghdr received_msg = {
      .msg_name = &src,
      .msg_namelen = src_len,
      .msg_iov = &received_iov,
      .msg_iovlen = 1,
  };

  ASSERT_THAT(RecvMsgTimeout(socket.get(), &received_msg, 1 /*timeout*/),
              IsPosixErrorOkAndHolds(expected_read_len));

  // sockaddr_ll ends with an 8 byte physical address field, but ethernet
  // addresses only use 6 bytes. Linux used to return sizeof(sockaddr_ll)-2
  // here, but returns sizeof(sockaddr_ll) since
  // https://github.com/torvalds/linux/commit/b2cf86e1563e33a14a1c69b3e508d15dc12f804c.
  ASSERT_THAT(received_msg.msg_namelen,
              AnyOf(Eq(sizeof(src)),
                    Eq(sizeof(src) - sizeof(src.sll_addr) + ETH_ALEN)));
  EXPECT_EQ(src.sll_family, AF_PACKET);
  EXPECT_EQ(src.sll_ifindex, ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
  EXPECT_EQ(src.sll_halen, ETH_ALEN);
  EXPECT_EQ(ntohs(src.sll_protocol), ETH_P_IP);
  // This came from the loopback device, so the address is all 0s.
  constexpr uint8_t allZeroesMAC[ETH_ALEN] = {};
  EXPECT_EQ(memcmp(src.sll_addr, allZeroesMAC, sizeof(allZeroesMAC)), 0);

  if (ethernet_header_included) {
    memcpy(&eth, buf, sizeof(eth));
    EXPECT_EQ(memcmp(eth.h_dest, allZeroesMAC, sizeof(allZeroesMAC)), 0);
    EXPECT_EQ(memcmp(eth.h_source, allZeroesMAC, sizeof(allZeroesMAC)), 0);
    EXPECT_EQ(ntohs(eth.h_proto), ETH_P_IP);
    advance_buf(sizeof(eth));
  }

  // IHL hold the size of the header in 4 byte units.
  memcpy(&ip, buf, sizeof(ip));
  EXPECT_EQ(ip.ihl, sizeof(iphdr) / 4);
  EXPECT_EQ(ip.version, IPVERSION);
  const uint16_t ip_pkt_size = sizeof(ip) + sizeof(udp) + sizeof(payload);
  EXPECT_EQ(ntohs(ip.tot_len), ip_pkt_size);
  EXPECT_EQ(ip.protocol, IPPROTO_UDP);
  EXPECT_EQ(ntohl(ip.daddr), INADDR_LOOPBACK);
  EXPECT_EQ(ntohl(ip.saddr), INADDR_LOOPBACK);
  advance_buf(sizeof(ip));

  memcpy(&udp, buf, sizeof(udp));
  EXPECT_EQ(udp.source, expected_udp_addr.sin_port);
  EXPECT_EQ(udp.dest, expected_udp_addr.sin_port);
  EXPECT_EQ(ntohs(udp.len), ip_pkt_size - sizeof(ip));
  advance_buf(sizeof(udp));

  memcpy(&payload, buf, sizeof(payload));
  EXPECT_EQ(payload, expected_udp_payload);
  if (src_out) {
    *src_out = src;
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

    // Make sure the payload has been delivered (in case of asynchronous
    // delivery).
    char buf[sizeof(v)];
    EXPECT_THAT(RecvTimeout(udp_sock.get(), buf, sizeof(v), 1 /*timeout*/),
                IsPosixErrorOkAndHolds(sizeof(v)));
    ASSERT_EQ(*reinterpret_cast<uint64_t*>(buf), v);
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

  // The packet socket is not bound to IPv4 so we should not receive the sent
  // message.
  uint64_t counter = 0;
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));

  // Bind to IPv4 and expect to receive the UDP packet we send after binding.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(ETH_P_IP));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(ExpectReceiveOnPacketSocket(socket_, kEthHdrIncluded,
                                                      udp_bind_addr, counter));

  // Bind the packet socket to a random protocol.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(255));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));

  // Bind back to IPv4 and expect to the UDP packet we send after binding
  // back to IPv4.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(ETH_P_IP));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(ExpectReceiveOnPacketSocket(socket_, kEthHdrIncluded,
                                                      udp_bind_addr, counter));

  // A zero valued protocol number should not change the bound network protocol.
  ASSERT_NO_FATAL_FAILURE(bind_to_network_protocol(0));
  ASSERT_NO_FATAL_FAILURE(send_udp_message(++counter));
  ASSERT_NO_FATAL_FAILURE(ExpectReceiveOnPacketSocket(socket_, kEthHdrIncluded,
                                                      udp_bind_addr, counter));
}

// Receive sent frames when bound to ETH_P_ALL.
TEST_P(PacketSocketTest, ReceiveSentBoundToProtocolAll) {
  // If a packet socket is bound to the loopback interface with protocol
  // ETH_P_ALL, it should receive a frame that is sent twice: once on sending
  // and again on reception.

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
    ASSERT_NE(udp_bind_addr.sin_port, 0);
  }

  // Bind the packet socket to the loopback interface with ETH_P_ALL.
  const struct sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_ALL),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  ASSERT_THAT(bind(socket_.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallSucceeds());

  const uint64_t kContents = 0xAAAAAAAAAAAAAAAA;

  // Send to the same UDP socket so we don't interfere with other tests.
  ASSERT_THAT(sendto(udp_sock.get(), &kContents, sizeof(kContents), 0,
                     reinterpret_cast<const struct sockaddr*>(&udp_bind_addr),
                     sizeof(udp_bind_addr)),
              SyscallSucceeds());

  const bool kExpectEthernetHeader = GetParam() == SOCK_RAW;
  sockaddr_ll src_addr;

  // Receive the outgoing frame.
  ExpectReceiveOnPacketSocket(socket_, kExpectEthernetHeader, udp_bind_addr,
                              kContents, &src_addr);
  ASSERT_EQ(src_addr.sll_pkttype, PACKET_OUTGOING);

  // Then receive the incoming frame.
  ExpectReceiveOnPacketSocket(socket_, kExpectEthernetHeader, udp_bind_addr,
                              kContents, &src_addr);
  ASSERT_EQ(src_addr.sll_pkttype, PACKET_HOST);
}

INSTANTIATE_TEST_SUITE_P(AllPacketSocketTests, PacketSocketTest,
                         Values(SOCK_DGRAM, SOCK_RAW));

}  // namespace

}  // namespace testing
}  // namespace gvisor
