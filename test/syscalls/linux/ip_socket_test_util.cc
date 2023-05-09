// Copyright 2018 The gVisor Authors.
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

#include "test/syscalls/linux/ip_socket_test_util.h"

#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

#include <cstring>

namespace gvisor {
namespace testing {

using ::testing::IsNull;
using ::testing::NotNull;

uint32_t IPFromInetSockaddr(const struct sockaddr* addr) {
  auto* in_addr = reinterpret_cast<const struct sockaddr_in*>(addr);
  return in_addr->sin_addr.s_addr;
}

uint16_t PortFromInetSockaddr(const struct sockaddr* addr) {
  auto* in_addr = reinterpret_cast<const struct sockaddr_in*>(addr);
  return ntohs(in_addr->sin_port);
}

PosixErrorOr<int> InterfaceIndex(std::string name) {
  int index = if_nametoindex(name.c_str());
  if (index) {
    return index;
  }
  return PosixError(errno);
}

namespace {

std::string DescribeSocketType(int type) {
  return absl::StrCat(((type & SOCK_NONBLOCK) != 0) ? "non-blocking " : "",
                      ((type & SOCK_CLOEXEC) != 0) ? "close-on-exec " : "");
}

}  // namespace

SocketPairKind IPv6TCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv6 TCP socket");
  return SocketPairKind{
      description, AF_INET6, type | SOCK_STREAM, IPPROTO_TCP,
      TCPAcceptBindSocketPairCreator(AF_INET6, type | SOCK_STREAM, 0,
                                     /* dual_stack = */ false)};
}

SocketPairKind IPv4TCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv4 TCP socket");
  return SocketPairKind{
      description, AF_INET, type | SOCK_STREAM, IPPROTO_TCP,
      TCPAcceptBindSocketPairCreator(AF_INET, type | SOCK_STREAM, 0,
                                     /* dual_stack = */ false)};
}

SocketPairKind DualStackTCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected dual stack TCP socket");
  return SocketPairKind{
      description, AF_INET6, type | SOCK_STREAM, IPPROTO_TCP,
      TCPAcceptBindSocketPairCreator(AF_INET6, type | SOCK_STREAM, 0,
                                     /* dual_stack = */ true)};
}

SocketPairKind IPv6TCPAcceptBindPersistentListenerSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv6 TCP socket");
  return SocketPairKind{description, AF_INET6, type | SOCK_STREAM, IPPROTO_TCP,
                        TCPAcceptBindPersistentListenerSocketPairCreator(
                            AF_INET6, type | SOCK_STREAM, 0,
                            /* dual_stack = */ false)};
}

SocketPairKind IPv4TCPAcceptBindPersistentListenerSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv4 TCP socket");
  return SocketPairKind{description, AF_INET, type | SOCK_STREAM, IPPROTO_TCP,
                        TCPAcceptBindPersistentListenerSocketPairCreator(
                            AF_INET, type | SOCK_STREAM, 0,
                            /* dual_stack = */ false)};
}

SocketPairKind DualStackTCPAcceptBindPersistentListenerSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected dual stack TCP socket");
  return SocketPairKind{description, AF_INET6, type | SOCK_STREAM, IPPROTO_TCP,
                        TCPAcceptBindPersistentListenerSocketPairCreator(
                            AF_INET6, type | SOCK_STREAM, 0,
                            /* dual_stack = */ true)};
}

SocketPairKind IPv6UDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv6 UDP socket");
  return SocketPairKind{
      description, AF_INET6, type | SOCK_DGRAM, IPPROTO_UDP,
      UDPBidirectionalBindSocketPairCreator(AF_INET6, type | SOCK_DGRAM, 0,
                                            /* dual_stack = */ false)};
}

SocketPairKind IPv4UDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected IPv4 UDP socket");
  return SocketPairKind{
      description, AF_INET, type | SOCK_DGRAM, IPPROTO_UDP,
      UDPBidirectionalBindSocketPairCreator(AF_INET, type | SOCK_DGRAM, 0,
                                            /* dual_stack = */ false)};
}

SocketPairKind DualStackUDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "connected dual stack UDP socket");
  return SocketPairKind{
      description, AF_INET6, type | SOCK_DGRAM, IPPROTO_UDP,
      UDPBidirectionalBindSocketPairCreator(AF_INET6, type | SOCK_DGRAM, 0,
                                            /* dual_stack = */ true)};
}

SocketPairKind IPv4UDPUnboundSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 UDP socket");
  return SocketPairKind{
      description, AF_INET, type | SOCK_DGRAM, IPPROTO_UDP,
      UDPUnboundSocketPairCreator(AF_INET, type | SOCK_DGRAM, 0,
                                  /* dual_stack = */ false)};
}

SocketKind ICMPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "ICMP socket");
  return SocketKind{
      description, AF_INET, type | SOCK_DGRAM, IPPROTO_ICMP,
      UnboundSocketCreator(AF_INET, type | SOCK_DGRAM, IPPROTO_ICMP)};
}

SocketKind ICMPv6UnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "ICMPv6 socket");
  return SocketKind{
      description, AF_INET6, type | SOCK_DGRAM, IPPROTO_ICMPV6,
      UnboundSocketCreator(AF_INET6, type | SOCK_DGRAM, IPPROTO_ICMPV6)};
}

SocketKind IPv4RawUDPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 Raw UDP socket");
  return SocketKind{
      description, AF_INET, type | SOCK_RAW, IPPROTO_UDP,
      UnboundSocketCreator(AF_INET, type | SOCK_RAW, IPPROTO_UDP)};
}

SocketKind IPv4UDPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 UDP socket");
  return SocketKind{
      description, AF_INET, type | SOCK_DGRAM, IPPROTO_UDP,
      UnboundSocketCreator(AF_INET, type | SOCK_DGRAM, IPPROTO_UDP)};
}

SocketKind IPv6UDPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv6 UDP socket");
  return SocketKind{
      description, AF_INET6, type | SOCK_DGRAM, IPPROTO_UDP,
      UnboundSocketCreator(AF_INET6, type | SOCK_DGRAM, IPPROTO_UDP)};
}

SocketKind IPv4TCPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 TCP socket");
  return SocketKind{
      description, AF_INET, type | SOCK_STREAM, IPPROTO_TCP,
      UnboundSocketCreator(AF_INET, type | SOCK_STREAM, IPPROTO_TCP)};
}

SocketKind IPv6TCPUnboundSocket(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv6 TCP socket");
  return SocketKind{
      description, AF_INET6, type | SOCK_STREAM, IPPROTO_TCP,
      UnboundSocketCreator(AF_INET6, type | SOCK_STREAM, IPPROTO_TCP)};
}

std::string GetAddr4Str(const in_addr* a) {
  char str[INET_ADDRSTRLEN];
  return inet_ntop(AF_INET, a, str, sizeof(str));
}

std::string GetAddr6Str(const in6_addr* a) {
  char str[INET6_ADDRSTRLEN];
  return inet_ntop(AF_INET6, a, str, sizeof(str));
}

std::string GetAddrStr(const sockaddr* a) {
  switch (a->sa_family) {
    case AF_INET: {
      return GetAddr4Str(&(reinterpret_cast<const sockaddr_in*>(a)->sin_addr));
    }
    case AF_INET6: {
      return GetAddr6Str(
          &(reinterpret_cast<const sockaddr_in6*>(a)->sin6_addr));
    }
    case AF_PACKET: {
      const sockaddr_ll& ll = *reinterpret_cast<const sockaddr_ll*>(a);
      std::ostringstream ss;
      ss << std::hex;
      ss << std::showbase;
      ss << '{';
      ss << " protocol=" << ntohs(ll.sll_protocol);
      ss << " ifindex=" << ll.sll_ifindex;
      ss << " hatype=" << ll.sll_hatype;
      ss << " pkttype=" << static_cast<unsigned short>(ll.sll_pkttype);
      if (ll.sll_halen != 0) {
        ss << " addr=";
        for (unsigned char i = 0; i < ll.sll_halen; ++i) {
          if (i != 0) {
            ss << ':';
          }
          ss << static_cast<unsigned short>(ll.sll_addr[i]);
        }
      }
      ss << " }";
      return ss.str();
    }
    default: {
      std::ostringstream ss;
      ss << "invalid(sa_family=" << a->sa_family << ")";
      return ss.str();
    }
  }
}

namespace {
template <typename T>
void RecvCmsg(int sock, int cmsg_level, int cmsg_type, char buf[],
              size_t* buf_size, T* out_cmsg_value) {
  iovec iov = {
      iov.iov_base = buf,
      iov.iov_len = *buf_size,
  };
  // Add an extra byte to confirm we only read what we expected.
  char control[CMSG_SPACE(sizeof(*out_cmsg_value)) + 1];
  msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };

  ASSERT_THAT(*buf_size = RetryEINTR(recvmsg)(sock, &msg, /*flags=*/0),
              SyscallSucceeds());
  ASSERT_EQ(msg.msg_controllen, CMSG_SPACE(sizeof(*out_cmsg_value)));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_THAT(cmsg, NotNull());
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(*out_cmsg_value)));
  ASSERT_EQ(cmsg->cmsg_level, cmsg_level);
  ASSERT_EQ(cmsg->cmsg_type, cmsg_type);
  ASSERT_THAT(CMSG_NXTHDR(&msg, cmsg), IsNull());

  std::copy_n(CMSG_DATA(cmsg), sizeof(*out_cmsg_value),
              reinterpret_cast<uint8_t*>(out_cmsg_value));
}

template <typename T>
void SendCmsg(int sock, int cmsg_level, int cmsg_type, char buf[],
              size_t buf_size, T cmsg_value) {
  iovec iov = {
      .iov_base = buf,
      .iov_len = buf_size,
  };

  std::vector<uint8_t> control(CMSG_SPACE(sizeof(cmsg_value)));
  msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.data(),
      .msg_controllen = CMSG_LEN(sizeof(cmsg_value)),
  };

  // Manually add control message.
  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_THAT(cmsg, NotNull());
  cmsg->cmsg_len = CMSG_LEN(sizeof(cmsg_value));
  cmsg->cmsg_level = cmsg_level;
  cmsg->cmsg_type = cmsg_type;
  std::copy_n(reinterpret_cast<uint8_t*>(&cmsg_value), sizeof(cmsg_value),
              CMSG_DATA(cmsg));

  ASSERT_THAT(RetryEINTR(sendmsg)(sock, &msg, 0),
              SyscallSucceedsWithValue(buf_size));
}
}  // namespace

void RecvTOS(int sock, char buf[], size_t* buf_size, uint8_t* out_tos) {
  RecvCmsg(sock, SOL_IP, IP_TOS, buf, buf_size, out_tos);
}

void SendTOS(int sock, char buf[], size_t buf_size, uint8_t tos) {
  SendCmsg(sock, SOL_IP, IP_TOS, buf, buf_size, tos);
}

void RecvTClass(int sock, char buf[], size_t* buf_size, int* out_tclass) {
  RecvCmsg(sock, SOL_IPV6, IPV6_TCLASS, buf, buf_size, out_tclass);
}

void SendTClass(int sock, char buf[], size_t buf_size, int tclass) {
  SendCmsg(sock, SOL_IPV6, IPV6_TCLASS, buf, buf_size, tclass);
}

void RecvTTL(int sock, char buf[], size_t* buf_size, int* out_ttl) {
  RecvCmsg(sock, SOL_IP, IP_TTL, buf, buf_size, out_ttl);
}

void SendTTL(int sock, char buf[], size_t buf_size, int ttl) {
  SendCmsg(sock, SOL_IP, IP_TTL, buf, buf_size, ttl);
}

void RecvHopLimit(int sock, char buf[], size_t* buf_size, int* out_hoplimit) {
  RecvCmsg(sock, SOL_IPV6, IPV6_HOPLIMIT, buf, buf_size, out_hoplimit);
}

void SendHopLimit(int sock, char buf[], size_t buf_size, int hoplimit) {
  SendCmsg(sock, SOL_IPV6, IPV6_HOPLIMIT, buf, buf_size, hoplimit);
}

void RecvPktInfo(int sock, char buf[], size_t* buf_size,
                 in_pktinfo* out_pktinfo) {
  RecvCmsg(sock, SOL_IP, IP_PKTINFO, buf, buf_size, out_pktinfo);
}

void RecvIPv6PktInfo(int sock, char buf[], size_t* buf_size,
                     in6_pktinfo* out_pktinfo) {
  RecvCmsg(sock, SOL_IPV6, IPV6_PKTINFO, buf, buf_size, out_pktinfo);
}

}  // namespace testing
}  // namespace gvisor
