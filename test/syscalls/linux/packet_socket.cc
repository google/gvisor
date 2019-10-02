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
#include <linux/capability.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/base/internal/endian.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

// Some of these tests involve sending packets via AF_PACKET sockets and the
// loopback interface. Because AF_PACKET circumvents so much of the networking
// stack, Linux sees these packets as "martian", i.e. they claim to be to/from
// localhost but don't have the usual associated data. Thus Linux drops them by
// default. You can see where this happens by following the code at:
//
// - net/ipv4/ip_input.c:ip_rcv_finish, which calls
// - net/ipv4/route.c:ip_route_input_noref, which calls
// - net/ipv4/route.c:ip_route_input_slow, which finds and drops martian
//   packets.
//
// To tell Linux not to drop these packets, you need to tell it to accept our
// funny packets (which are completely valid and correct, but lack associated
// in-kernel data because we use AF_PACKET):
//
// echo 1 >> /proc/sys/net/ipv4/conf/lo/accept_local
// echo 1 >> /proc/sys/net/ipv4/conf/lo/route_localnet
//
// These tests require CAP_NET_RAW to run.

// TODO(gvisor.dev/issue/173): gVisor support.

namespace gvisor {
namespace testing {

namespace {

constexpr char kMessage[] = "soweoneul malhaebwa";
constexpr in_port_t kPort = 0x409c;  // htons(40000)

//
// "Cooked" tests. Cooked AF_PACKET sockets do not contain link layer
// headers, and provide link layer destination/source information via a
// returned struct sockaddr_ll.
//

// Send kMessage via sock to loopback
void SendUDPMessage(int sock) {
  struct sockaddr_in dest = {};
  dest.sin_port = kPort;
  dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dest.sin_family = AF_INET;
  EXPECT_THAT(sendto(sock, kMessage, sizeof(kMessage), 0,
                     reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)),
              SyscallSucceedsWithValue(sizeof(kMessage)));
}

// Send an IP packet and make sure ETH_P_<something else> doesn't pick it up.
TEST(BasicCookedPacketTest, WrongType) {
  // (b/129292371): Remove once we support packet sockets.
  SKIP_IF(IsRunningOnGvisor());

  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_DGRAM, ETH_P_PUP),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, ETH_P_PUP));

  // Let's use a simple IP payload: a UDP datagram.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  SendUDPMessage(udp_sock.get());

  // Wait and make sure the socket never becomes readable.
  struct pollfd pfd = {};
  pfd.fd = sock.get();
  pfd.events = POLLIN;
  EXPECT_THAT(RetryEINTR(poll)(&pfd, 1, 1000), SyscallSucceedsWithValue(0));
}

// Tests for "cooked" (SOCK_DGRAM) packet(7) sockets.
class CookedPacketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Gets the device index of the loopback device.
  int GetLoopbackIndex();

  // The socket used for both reading and writing.
  int socket_;
};

void CookedPacketTest::SetUp() {
  // (b/129292371): Remove once we support packet sockets.
  SKIP_IF(IsRunningOnGvisor());

  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_DGRAM, htons(GetParam())),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  ASSERT_THAT(socket_ = socket(AF_PACKET, SOCK_DGRAM, htons(GetParam())),
              SyscallSucceeds());
}

void CookedPacketTest::TearDown() {
  // (b/129292371): Remove once we support packet sockets.
  SKIP_IF(IsRunningOnGvisor());

  // TearDown will be run even if we skip the test.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    EXPECT_THAT(close(socket_), SyscallSucceeds());
  }
}

int CookedPacketTest::GetLoopbackIndex() {
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  EXPECT_THAT(ioctl(socket_, SIOCGIFINDEX, &ifr), SyscallSucceeds());
  EXPECT_NE(ifr.ifr_ifindex, 0);
  return ifr.ifr_ifindex;
}

// Receive via a packet socket.
TEST_P(CookedPacketTest, Receive) {
  // Let's use a simple IP payload: a UDP datagram.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  SendUDPMessage(udp_sock.get());

  // Wait for the socket to become readable.
  struct pollfd pfd = {};
  pfd.fd = socket_;
  pfd.events = POLLIN;
  EXPECT_THAT(RetryEINTR(poll)(&pfd, 1, 2000), SyscallSucceedsWithValue(1));

  // Read and verify the data.
  constexpr size_t packet_size =
      sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kMessage);
  char buf[64];
  struct sockaddr_ll src = {};
  socklen_t src_len = sizeof(src);
  ASSERT_THAT(recvfrom(socket_, buf, sizeof(buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len),
              SyscallSucceedsWithValue(packet_size));
  ASSERT_EQ(src_len, sizeof(src));

  // Verify the source address.
  EXPECT_EQ(src.sll_family, AF_PACKET);
  EXPECT_EQ(src.sll_protocol, htons(ETH_P_IP));
  EXPECT_EQ(src.sll_ifindex, GetLoopbackIndex());
  EXPECT_EQ(src.sll_hatype, ARPHRD_LOOPBACK);
  EXPECT_EQ(src.sll_halen, ETH_ALEN);
  // This came from the loopback device, so the address is all 0s.
  for (int i = 0; i < src.sll_halen; i++) {
    EXPECT_EQ(src.sll_addr[i], 0);
  }

  // Verify the IP header. We memcpy to deal with pointer aligment.
  struct iphdr ip = {};
  memcpy(&ip, buf, sizeof(ip));
  EXPECT_EQ(ip.ihl, 5);
  EXPECT_EQ(ip.version, 4);
  EXPECT_EQ(ip.tot_len, htons(packet_size));
  EXPECT_EQ(ip.protocol, IPPROTO_UDP);
  EXPECT_EQ(ip.daddr, htonl(INADDR_LOOPBACK));
  EXPECT_EQ(ip.saddr, htonl(INADDR_LOOPBACK));

  // Verify the UDP header. We memcpy to deal with pointer aligment.
  struct udphdr udp = {};
  memcpy(&udp, buf + sizeof(iphdr), sizeof(udp));
  EXPECT_EQ(udp.dest, kPort);
  EXPECT_EQ(udp.len, htons(sizeof(udphdr) + sizeof(kMessage)));

  // Verify the payload.
  char* payload = reinterpret_cast<char*>(buf + sizeof(iphdr) + sizeof(udphdr));
  EXPECT_EQ(strncmp(payload, kMessage, sizeof(kMessage)), 0);
}

// Send via a packet socket.
TEST_P(CookedPacketTest, Send) {
  // Let's send a UDP packet and receive it using a regular UDP socket.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = kPort;
  ASSERT_THAT(
      bind(udp_sock.get(), reinterpret_cast<struct sockaddr*>(&bind_addr),
           sizeof(bind_addr)),
      SyscallSucceeds());

  // Set up the destination physical address.
  struct sockaddr_ll dest = {};
  dest.sll_family = AF_PACKET;
  dest.sll_halen = ETH_ALEN;
  dest.sll_ifindex = GetLoopbackIndex();
  dest.sll_protocol = htons(ETH_P_IP);
  // We're sending to the loopback device, so the address is all 0s.
  memset(dest.sll_addr, 0x00, ETH_ALEN);

  // Set up the IP header.
  struct iphdr iphdr = {0};
  iphdr.ihl = 5;
  iphdr.version = 4;
  iphdr.tos = 0;
  iphdr.tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kMessage));
  // Get a pseudo-random ID. If we clash with an in-use ID the test will fail,
  // but we have no way of getting an ID we know to be good.
  srand(*reinterpret_cast<unsigned int*>(&iphdr));
  iphdr.id = rand();
  // Linux sets this bit ("do not fragment") for small packets.
  iphdr.frag_off = 1 << 6;
  iphdr.ttl = 64;
  iphdr.protocol = IPPROTO_UDP;
  iphdr.daddr = htonl(INADDR_LOOPBACK);
  iphdr.saddr = htonl(INADDR_LOOPBACK);
  iphdr.check = IPChecksum(iphdr);

  // Set up the UDP header.
  struct udphdr udphdr = {};
  udphdr.source = kPort;
  udphdr.dest = kPort;
  udphdr.len = htons(sizeof(udphdr) + sizeof(kMessage));
  udphdr.check = UDPChecksum(iphdr, udphdr, kMessage, sizeof(kMessage));

  // Copy both headers and the payload into our packet buffer.
  char send_buf[sizeof(iphdr) + sizeof(udphdr) + sizeof(kMessage)];
  memcpy(send_buf, &iphdr, sizeof(iphdr));
  memcpy(send_buf + sizeof(iphdr), &udphdr, sizeof(udphdr));
  memcpy(send_buf + sizeof(iphdr) + sizeof(udphdr), kMessage, sizeof(kMessage));

  // Send it.
  ASSERT_THAT(sendto(socket_, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Wait for the packet to become available on both sockets.
  struct pollfd pfd = {};
  pfd.fd = udp_sock.get();
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 5000), SyscallSucceedsWithValue(1));
  pfd.fd = socket_;
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 5000), SyscallSucceedsWithValue(1));

  // Receive on the packet socket.
  char recv_buf[sizeof(send_buf)];
  ASSERT_THAT(recv(socket_, recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  ASSERT_EQ(memcmp(recv_buf, send_buf, sizeof(send_buf)), 0);

  // Receive on the UDP socket.
  struct sockaddr_in src;
  socklen_t src_len = sizeof(src);
  ASSERT_THAT(recvfrom(udp_sock.get(), recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len),
              SyscallSucceedsWithValue(sizeof(kMessage)));
  // Check src and payload.
  EXPECT_EQ(strncmp(recv_buf, kMessage, sizeof(kMessage)), 0);
  EXPECT_EQ(src.sin_family, AF_INET);
  EXPECT_EQ(src.sin_port, kPort);
  EXPECT_EQ(src.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, CookedPacketTest,
                         ::testing::Values(ETH_P_IP, ETH_P_ALL));

}  // namespace

}  // namespace testing
}  // namespace gvisor
