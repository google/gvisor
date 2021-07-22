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
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "gtest/gtest.h"
#include "absl/base/internal/endian.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Tests for IPPROTO_RAW raw sockets, which implies IP_HDRINCL.
class RawHDRINCL : public ::testing::Test {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // Returns a valid looback IP header with no payload.
  struct iphdr LoopbackHeader();

  // Fills in buf with an IP header, UDP header, and payload. Returns false if
  // buf_size isn't large enough to hold everything.
  bool FillPacket(char* buf, size_t buf_size, int port, const char* payload,
                  uint16_t payload_size);

  // The socket used for both reading and writing.
  int socket_;

  // The loopback address.
  struct sockaddr_in addr_;
};

void RawHDRINCL::SetUp() {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_INET, SOCK_RAW, IPPROTO_RAW),
                SyscallFailsWithErrno(EPERM));
    GTEST_SKIP();
  }

  ASSERT_THAT(socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW),
              SyscallSucceeds());

  addr_ = {};

  addr_.sin_port = IPPROTO_IP;
  addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_.sin_family = AF_INET;
}

void RawHDRINCL::TearDown() {
  // TearDown will be run even if we skip the test.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    EXPECT_THAT(close(socket_), SyscallSucceeds());
  }
}

struct iphdr RawHDRINCL::LoopbackHeader() {
  struct iphdr hdr = {};
  hdr.ihl = 5;
  hdr.version = 4;
  hdr.tos = 0;
  hdr.tot_len = absl::gbswap_16(sizeof(hdr));
  hdr.id = 0;
  hdr.frag_off = 0;
  hdr.ttl = 7;
  hdr.protocol = 1;
  hdr.daddr = htonl(INADDR_LOOPBACK);
  // hdr.check is set by the network stack.
  // hdr.tot_len is set by the network stack.
  // hdr.saddr is set by the network stack.
  return hdr;
}

bool RawHDRINCL::FillPacket(char* buf, size_t buf_size, int port,
                            const char* payload, uint16_t payload_size) {
  if (buf_size < sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size) {
    return false;
  }

  struct iphdr ip = LoopbackHeader();
  ip.protocol = IPPROTO_UDP;

  struct udphdr udp = {};
  udp.source = absl::gbswap_16(port);
  udp.dest = absl::gbswap_16(port);
  udp.len = absl::gbswap_16(sizeof(udp) + payload_size);
  udp.check = 0;

  memcpy(buf, reinterpret_cast<char*>(&ip), sizeof(ip));
  memcpy(buf + sizeof(ip), reinterpret_cast<char*>(&udp), sizeof(udp));
  memcpy(buf + sizeof(ip) + sizeof(udp), payload, payload_size);

  return true;
}

// We should be able to create multiple IPPROTO_RAW sockets. RawHDRINCL::Setup
// creates the first one, so we only have to create one more here.
TEST_F(RawHDRINCL, MultipleCreation) {
  int s2;
  ASSERT_THAT(s2 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW), SyscallSucceeds());

  ASSERT_THAT(close(s2), SyscallSucceeds());
}

// Test that shutting down an unconnected socket fails.
TEST_F(RawHDRINCL, FailShutdownWithoutConnect) {
  ASSERT_THAT(shutdown(socket_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(shutdown(socket_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));
}

// Test that listen() fails.
TEST_F(RawHDRINCL, FailListen) {
  ASSERT_THAT(listen(socket_, 1), SyscallFailsWithErrno(ENOTSUP));
}

// Test that accept() fails.
TEST_F(RawHDRINCL, FailAccept) {
  struct sockaddr saddr;
  socklen_t addrlen;
  ASSERT_THAT(accept(socket_, &saddr, &addrlen),
              SyscallFailsWithErrno(ENOTSUP));
}

// Test that the socket is writable immediately.
TEST_F(RawHDRINCL, PollWritableImmediately) {
  struct pollfd pfd = {};
  pfd.fd = socket_;
  pfd.events = POLLOUT;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 0), SyscallSucceedsWithValue(1));
}

// Test that the socket isn't readable.
TEST_F(RawHDRINCL, NotReadable) {
  // Try to receive data with MSG_DONTWAIT, which returns immediately if there's
  // nothing to be read.
  char buf[117];
  ASSERT_THAT(RetryEINTR(recv)(socket_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// Test that we can connect() to a valid IP (loopback).
TEST_F(RawHDRINCL, ConnectToLoopback) {
  ASSERT_THAT(connect(socket_, reinterpret_cast<struct sockaddr*>(&addr_),
                      sizeof(addr_)),
              SyscallSucceeds());
}

TEST_F(RawHDRINCL, SendWithoutConnectFails) {
  struct iphdr hdr = LoopbackHeader();
  ASSERT_THAT(send(socket_, &hdr, sizeof(hdr), 0),
              SyscallFailsWithErrno(EDESTADDRREQ));
}

// HDRINCL implies write-only. Verify that we can't read a packet sent to
// loopback.
TEST_F(RawHDRINCL, NotReadableAfterWrite) {
  ASSERT_THAT(connect(socket_, reinterpret_cast<struct sockaddr*>(&addr_),
                      sizeof(addr_)),
              SyscallSucceeds());

  // Construct a packet with an IP header, UDP header, and payload.
  constexpr char kPayload[] = "odst";
  char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kPayload)];
  ASSERT_TRUE(FillPacket(packet, sizeof(packet), 40000 /* port */, kPayload,
                         sizeof(kPayload)));

  socklen_t addrlen = sizeof(addr_);
  ASSERT_NO_FATAL_FAILURE(
      sendto(socket_, reinterpret_cast<void*>(&packet), sizeof(packet), 0,
             reinterpret_cast<struct sockaddr*>(&addr_), addrlen));

  struct pollfd pfd = {};
  pfd.fd = socket_;
  pfd.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 1000), SyscallSucceedsWithValue(0));
}

TEST_F(RawHDRINCL, WriteTooSmall) {
  ASSERT_THAT(connect(socket_, reinterpret_cast<struct sockaddr*>(&addr_),
                      sizeof(addr_)),
              SyscallSucceeds());

  // This is smaller than the size of an IP header.
  constexpr char kBuf[] = "JP5";
  ASSERT_THAT(send(socket_, kBuf, sizeof(kBuf), 0),
              SyscallFailsWithErrno(EINVAL));
}

// Bind to localhost.
TEST_F(RawHDRINCL, BindToLocalhost) {
  ASSERT_THAT(
      bind(socket_, reinterpret_cast<struct sockaddr*>(&addr_), sizeof(addr_)),
      SyscallSucceeds());
}

// Bind to a different address.
TEST_F(RawHDRINCL, BindToInvalid) {
  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr = {1};  // 1.0.0.0 - An address that we can't bind to.
  ASSERT_THAT(bind(socket_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                   sizeof(bind_addr)),
              SyscallFailsWithErrno(EADDRNOTAVAIL));
}

// Send and receive a packet.
TEST_F(RawHDRINCL, SendAndReceive) {
  int port = 40000;
  if (!IsRunningOnGvisor()) {
    port = static_cast<short>(ASSERT_NO_ERRNO_AND_VALUE(
        PortAvailable(0, AddressFamily::kIpv4, SocketType::kUdp, false)));
  }

  // IPPROTO_RAW sockets are write-only. We'll have to open another socket to
  // read what we write.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_UDP));

  // Construct a packet with an IP header, UDP header, and payload.
  constexpr char kPayload[] = "toto";
  char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kPayload)];
  ASSERT_TRUE(
      FillPacket(packet, sizeof(packet), port, kPayload, sizeof(kPayload)));

  socklen_t addrlen = sizeof(addr_);
  ASSERT_NO_FATAL_FAILURE(sendto(socket_, &packet, sizeof(packet), 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 addrlen));

  // Receive the payload.
  char recv_buf[sizeof(packet)];
  struct sockaddr_in src;
  socklen_t src_size = sizeof(src);
  ASSERT_THAT(recvfrom(udp_sock.get(), recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_size),
              SyscallSucceedsWithValue(sizeof(packet)));
  EXPECT_EQ(
      memcmp(kPayload, recv_buf + sizeof(struct iphdr) + sizeof(struct udphdr),
             sizeof(kPayload)),
      0);
  // The network stack should have set the source address.
  EXPECT_EQ(src.sin_family, AF_INET);
  EXPECT_EQ(absl::gbswap_32(src.sin_addr.s_addr), INADDR_LOOPBACK);
  // The packet ID should not be 0, as the packet has DF=0.
  struct iphdr* iphdr = reinterpret_cast<struct iphdr*>(recv_buf);
  EXPECT_NE(iphdr->id, 0);
}

// Send and receive a packet where the sendto address is not the same as the
// provided destination.
TEST_F(RawHDRINCL, SendAndReceiveDifferentAddress) {
  int port = 40000;
  if (!IsRunningOnGvisor()) {
    port = static_cast<short>(ASSERT_NO_ERRNO_AND_VALUE(
        PortAvailable(0, AddressFamily::kIpv4, SocketType::kUdp, false)));
  }

  // IPPROTO_RAW sockets are write-only. We'll have to open another socket to
  // read what we write.
  FileDescriptor udp_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_UDP));

  // Construct a packet with an IP header, UDP header, and payload.
  constexpr char kPayload[] = "toto";
  char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kPayload)];
  ASSERT_TRUE(
      FillPacket(packet, sizeof(packet), port, kPayload, sizeof(kPayload)));
  // Overwrite the IP destination address with an IP we can't get to.
  constexpr int32_t kUnreachable = 42;
  struct iphdr iphdr = {};
  memcpy(&iphdr, packet, sizeof(iphdr));
  iphdr.daddr = kUnreachable;
  memcpy(packet, &iphdr, sizeof(iphdr));

  // Send to localhost via loopback.
  socklen_t addrlen = sizeof(addr_);
  ASSERT_NO_FATAL_FAILURE(sendto(socket_, &packet, sizeof(packet), 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 addrlen));

  // Receive the payload. Despite an unreachable destination address, sendto
  // should have sent the packet through loopback.
  char recv_buf[sizeof(packet)];
  struct sockaddr_in src;
  socklen_t src_size = sizeof(src);
  ASSERT_THAT(recvfrom(udp_sock.get(), recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_size),
              SyscallSucceedsWithValue(sizeof(packet)));
  EXPECT_EQ(
      memcmp(kPayload, recv_buf + sizeof(struct iphdr) + sizeof(struct udphdr),
             sizeof(kPayload)),
      0);
  // The network stack should have set the source address.
  EXPECT_EQ(src.sin_family, AF_INET);
  EXPECT_EQ(absl::gbswap_32(src.sin_addr.s_addr), INADDR_LOOPBACK);
  // The packet ID should not be 0, as the packet has DF=0.
  struct iphdr recv_iphdr = {};
  memcpy(&recv_iphdr, recv_buf, sizeof(recv_iphdr));
  EXPECT_NE(recv_iphdr.id, 0);
  // The destination address is kUnreachable despite arriving via loopback.
  EXPECT_EQ(recv_iphdr.daddr, kUnreachable);
}

// Send and receive a packet w/ the IP_HDRINCL option set.
TEST_F(RawHDRINCL, SendAndReceiveIPHdrIncl) {
  int port = 40000;
  if (!IsRunningOnGvisor()) {
    port = static_cast<short>(ASSERT_NO_ERRNO_AND_VALUE(
        PortAvailable(0, AddressFamily::kIpv4, SocketType::kUdp, false)));
  }

  FileDescriptor recv_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_UDP));

  FileDescriptor send_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_UDP));

  // Enable IP_HDRINCL option so that we can build and send w/ an IP
  // header.
  constexpr int kSockOptOn = 1;
  ASSERT_THAT(setsockopt(send_sock.get(), SOL_IP, IP_HDRINCL, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  // This is not strictly required but we do it to make sure that setting
  // IP_HDRINCL on a non IPPROTO_RAW socket does not prevent it from receiving
  // packets.
  ASSERT_THAT(setsockopt(recv_sock.get(), SOL_IP, IP_HDRINCL, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Construct a packet with an IP header, UDP header, and payload.
  constexpr char kPayload[] = "toto";
  char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(kPayload)];
  ASSERT_TRUE(
      FillPacket(packet, sizeof(packet), port, kPayload, sizeof(kPayload)));

  socklen_t addrlen = sizeof(addr_);
  ASSERT_NO_FATAL_FAILURE(sendto(send_sock.get(), &packet, sizeof(packet), 0,
                                 reinterpret_cast<struct sockaddr*>(&addr_),
                                 addrlen));

  // Receive the payload.
  char recv_buf[sizeof(packet)];
  struct sockaddr_in src;
  socklen_t src_size = sizeof(src);
  ASSERT_THAT(recvfrom(recv_sock.get(), recv_buf, sizeof(recv_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&src), &src_size),
              SyscallSucceedsWithValue(sizeof(packet)));
  EXPECT_EQ(
      memcmp(kPayload, recv_buf + sizeof(struct iphdr) + sizeof(struct udphdr),
             sizeof(kPayload)),
      0);
  // The network stack should have set the source address.
  EXPECT_EQ(src.sin_family, AF_INET);
  EXPECT_EQ(absl::gbswap_32(src.sin_addr.s_addr), INADDR_LOOPBACK);
  struct iphdr iphdr = {};
  memcpy(&iphdr, recv_buf, sizeof(iphdr));
  EXPECT_NE(iphdr.id, 0);

  // Also verify that the packet we just sent was not delivered to the
  // IPPROTO_RAW socket.
  {
    char recv_buf[sizeof(packet)];
    struct sockaddr_in src;
    socklen_t src_size = sizeof(src);
    ASSERT_THAT(recvfrom(socket_, recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
                         reinterpret_cast<struct sockaddr*>(&src), &src_size),
                SyscallFailsWithErrno(EAGAIN));
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
