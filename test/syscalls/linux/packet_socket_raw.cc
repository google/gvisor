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
#ifndef __fuchsia__
#include <linux/filter.h>
#endif  // __fuchsia__
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

#include "gmock/gmock.h"
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

using ::testing::AnyOf;
using ::testing::Eq;

constexpr char kMessage[] = "soweoneul malhaebwa";
constexpr in_port_t kPort = 0x409c;  // htons(40000)

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

//
// Raw tests. Packets sent with raw AF_PACKET sockets always include link layer
// headers.
//

// Tests for "raw" (SOCK_RAW) packet(7) sockets.
class RawPacketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Gets the device index of the loopback device.
  int GetLoopbackIndex();

  // The socket used for both reading and writing.
  int s_;
};

void RawPacketTest::SetUp() {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, htons(GetParam())),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  if (!IsRunningOnGvisor()) {
    // Ensure that looped back packets aren't rejected by the kernel.
    FileDescriptor acceptLocal = ASSERT_NO_ERRNO_AND_VALUE(
        Open("/proc/sys/net/ipv4/conf/lo/accept_local", O_RDWR));
    FileDescriptor routeLocalnet = ASSERT_NO_ERRNO_AND_VALUE(
        Open("/proc/sys/net/ipv4/conf/lo/route_localnet", O_RDWR));
    char enabled;
    ASSERT_THAT(read(acceptLocal.get(), &enabled, 1),
                SyscallSucceedsWithValue(1));
    if (enabled != '1') {
      enabled = '1';
      ASSERT_THAT(lseek(acceptLocal.get(), 0, SEEK_SET),
                  SyscallSucceedsWithValue(0));
      ASSERT_THAT(write(acceptLocal.get(), &enabled, 1),
                  SyscallSucceedsWithValue(1));
      ASSERT_THAT(lseek(acceptLocal.get(), 0, SEEK_SET),
                  SyscallSucceedsWithValue(0));
      ASSERT_THAT(read(acceptLocal.get(), &enabled, 1),
                  SyscallSucceedsWithValue(1));
      ASSERT_EQ(enabled, '1');
    }

    ASSERT_THAT(read(routeLocalnet.get(), &enabled, 1),
                SyscallSucceedsWithValue(1));
    if (enabled != '1') {
      enabled = '1';
      ASSERT_THAT(lseek(routeLocalnet.get(), 0, SEEK_SET),
                  SyscallSucceedsWithValue(0));
      ASSERT_THAT(write(routeLocalnet.get(), &enabled, 1),
                  SyscallSucceedsWithValue(1));
      ASSERT_THAT(lseek(routeLocalnet.get(), 0, SEEK_SET),
                  SyscallSucceedsWithValue(0));
      ASSERT_THAT(read(routeLocalnet.get(), &enabled, 1),
                  SyscallSucceedsWithValue(1));
      ASSERT_EQ(enabled, '1');
    }
  }

  ASSERT_THAT(s_ = socket(AF_PACKET, SOCK_RAW, htons(GetParam())),
              SyscallSucceeds());
}

void RawPacketTest::TearDown() {
  // TearDown will be run even if we skip the test.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    EXPECT_THAT(close(s_), SyscallSucceeds());
  }
}

int RawPacketTest::GetLoopbackIndex() {
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  EXPECT_THAT(ioctl(s_, SIOCGIFINDEX, &ifr), SyscallSucceeds());
  EXPECT_NE(ifr.ifr_ifindex, 0);
  return ifr.ifr_ifindex;
}

// Receive via a packet socket.
TEST_P(RawPacketTest, Receive) {
  // Let's use a simple IP payload: a UDP datagram.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  SendUDPMessage(udp_sock.get());

  // Wait for the socket to become readable.
  struct pollfd pfd = {};
  pfd.fd = s_;
  pfd.events = POLLIN;
  EXPECT_THAT(RetryEINTR(poll)(&pfd, 1, 2000), SyscallSucceedsWithValue(1));

  // Read and verify the data.
  constexpr size_t packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                                 sizeof(struct udphdr) + sizeof(kMessage);
  char buf[64];
  struct sockaddr_ll src = {};
  socklen_t src_len = sizeof(src);
  ASSERT_THAT(recvfrom(s_, buf, sizeof(buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_len),
              SyscallSucceedsWithValue(packet_size));
  // sockaddr_ll ends with an 8 byte physical address field, but ethernet
  // addresses only use 6 bytes.  Linux used to return sizeof(sockaddr_ll)-2
  // here, but since commit b2cf86e1563e33a14a1c69b3e508d15dc12f804c returns
  // sizeof(sockaddr_ll).
  ASSERT_THAT(src_len, AnyOf(Eq(sizeof(src)), Eq(sizeof(src) - 2)));

  // TODO(gvisor.dev/issue/173): Verify protocol once we return it.
  // Verify the source address.
  EXPECT_EQ(src.sll_family, AF_PACKET);
  EXPECT_EQ(src.sll_ifindex, GetLoopbackIndex());
  EXPECT_EQ(src.sll_halen, ETH_ALEN);
  EXPECT_EQ(ntohs(src.sll_protocol), ETH_P_IP);
  // This came from the loopback device, so the address is all 0s.
  for (int i = 0; i < src.sll_halen; i++) {
    EXPECT_EQ(src.sll_addr[i], 0);
  }

  // Verify the ethernet header. We memcpy to deal with pointer alignment.
  struct ethhdr eth = {};
  memcpy(&eth, buf, sizeof(eth));
  // The destination and source address should be 0, for loopback.
  for (int i = 0; i < ETH_ALEN; i++) {
    EXPECT_EQ(eth.h_dest[i], 0);
    EXPECT_EQ(eth.h_source[i], 0);
  }
  EXPECT_EQ(eth.h_proto, htons(ETH_P_IP));

  // Verify the IP header. We memcpy to deal with pointer aligment.
  struct iphdr ip = {};
  memcpy(&ip, buf + sizeof(ethhdr), sizeof(ip));
  EXPECT_EQ(ip.ihl, 5);
  EXPECT_EQ(ip.version, 4);
  EXPECT_EQ(ip.tot_len, htons(packet_size - sizeof(eth)));
  EXPECT_EQ(ip.protocol, IPPROTO_UDP);
  EXPECT_EQ(ip.daddr, htonl(INADDR_LOOPBACK));
  EXPECT_EQ(ip.saddr, htonl(INADDR_LOOPBACK));

  // Verify the UDP header. We memcpy to deal with pointer aligment.
  struct udphdr udp = {};
  memcpy(&udp, buf + sizeof(eth) + sizeof(iphdr), sizeof(udp));
  EXPECT_EQ(udp.dest, kPort);
  EXPECT_EQ(udp.len, htons(sizeof(udphdr) + sizeof(kMessage)));

  // Verify the payload.
  char* payload = reinterpret_cast<char*>(buf + sizeof(eth) + sizeof(iphdr) +
                                          sizeof(udphdr));
  EXPECT_EQ(strncmp(payload, kMessage, sizeof(kMessage)), 0);
}

// Send via a packet socket.
TEST_P(RawPacketTest, Send) {
  // TODO(gvisor.dev/issue/173): Remove once we support packet socket writing.
  SKIP_IF(IsRunningOnGvisor());

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

  // Set up the ethernet header. The kernel takes care of the footer.
  // We're sending to and from hardware address 0 (loopback).
  struct ethhdr eth = {};
  eth.h_proto = htons(ETH_P_IP);

  // Set up the IP header.
  struct iphdr iphdr = {};
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
  char
      send_buf[sizeof(eth) + sizeof(iphdr) + sizeof(udphdr) + sizeof(kMessage)];
  memcpy(send_buf, &eth, sizeof(eth));
  memcpy(send_buf + sizeof(ethhdr), &iphdr, sizeof(iphdr));
  memcpy(send_buf + sizeof(ethhdr) + sizeof(iphdr), &udphdr, sizeof(udphdr));
  memcpy(send_buf + sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr), kMessage,
         sizeof(kMessage));

  // Send it.
  ASSERT_THAT(sendto(s_, send_buf, sizeof(send_buf), 0,
                     reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  // Wait for the packet to become available on both sockets.
  struct pollfd pfd = {};
  pfd.fd = udp_sock.get();
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 5000), SyscallSucceedsWithValue(1));
  pfd.fd = s_;
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 5000), SyscallSucceedsWithValue(1));

  // Receive on the packet socket.
  char recv_buf[sizeof(send_buf)];
  ASSERT_THAT(recv(s_, recv_buf, sizeof(recv_buf), 0),
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

// Check that setting SO_RCVBUF below min is clamped to the minimum
// receive buffer size.
TEST_P(RawPacketTest, SetSocketRecvBufBelowMin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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
TEST_P(RawPacketTest, SetSocketRecvBufAboveMax) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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
TEST_P(RawPacketTest, SetSocketRecvBuf) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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
  // TODO(gvisor.dev/issue/2926): Remove when Netstack matches linux behavior.
  if (!IsRunningOnGvisor()) {
    quarter_sz *= 2;
  }
  ASSERT_EQ(quarter_sz, val);
}

// Check that setting SO_SNDBUF below min is clamped to the minimum
// receive buffer size.
TEST_P(RawPacketTest, SetSocketSendBufBelowMin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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
TEST_P(RawPacketTest, SetSocketSendBufAboveMax) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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
TEST_P(RawPacketTest, SetSocketSendBuf) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

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

  // Linux doubles the value set by SO_SNDBUF/SO_RCVBUF.
  // TODO(gvisor.dev/issue/2926): Remove the gvisor special casing when Netstack
  // matches linux behavior.
  if (!IsRunningOnGvisor()) {
    quarter_sz *= 2;
  }

  ASSERT_EQ(quarter_sz, val);
}

TEST_P(RawPacketTest, GetSocketError) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_ERROR, &val, &val_len),
              SyscallSucceeds());
  ASSERT_EQ(val, 0);
}

TEST_P(RawPacketTest, GetSocketErrorBind) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  {
    // Bind to the loopback device.
    struct sockaddr_ll bind_addr = {};
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(GetParam());
    bind_addr.sll_ifindex = GetLoopbackIndex();

    ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                     sizeof(bind_addr)),
                SyscallSucceeds());

    // SO_ERROR should return no errors.
    int val = 0;
    socklen_t val_len = sizeof(val);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_ERROR, &val, &val_len),
                SyscallSucceeds());
    ASSERT_EQ(val, 0);
  }

  {
    // Now try binding to an invalid interface.
    struct sockaddr_ll bind_addr = {};
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(GetParam());
    bind_addr.sll_ifindex = 0xffff;  // Just pick a really large number.

    // Binding should fail with EINVAL
    ASSERT_THAT(bind(s_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                     sizeof(bind_addr)),
                SyscallFailsWithErrno(ENODEV));

    // SO_ERROR does not return error when the device is invalid.
    // On Linux there is just one odd ball condition where this can return
    // an error where the device was valid and then removed or disabled
    // between the first check for index and the actual registration of
    // the packet endpoint. On Netstack this is not possible as the stack
    // global mutex is held during registration and check.
    int val = 0;
    socklen_t val_len = sizeof(val);
    ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_ERROR, &val, &val_len),
                SyscallSucceeds());
    ASSERT_EQ(val, 0);
  }
}

#ifndef __fuchsia__

TEST_P(RawPacketTest, SetSocketDetachFilterNoInstalledFilter) {
  // TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
  //
  // gVisor returns no error on SO_DETACH_FILTER even if there is no filter
  // attached unlike linux which does return ENOENT in such cases. This is
  // because gVisor doesn't support SO_ATTACH_FILTER and just silently returns
  // success.
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

TEST_P(RawPacketTest, GetSocketDetachFilter) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(getsockopt(s_, SOL_SOCKET, SO_DETACH_FILTER, &val, &val_len),
              SyscallFailsWithErrno(ENOPROTOOPT));
}

#endif  // __fuchsia__

INSTANTIATE_TEST_SUITE_P(AllInetTests, RawPacketTest,
                         ::testing::Values(ETH_P_IP, ETH_P_ALL));

}  // namespace

}  // namespace testing
}  // namespace gvisor
