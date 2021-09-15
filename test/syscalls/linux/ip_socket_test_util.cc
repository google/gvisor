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
#include <sys/socket.h>

#include <cstring>

namespace gvisor {
namespace testing {

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

PosixError IfAddrHelper::Load() {
  Release();
#ifndef ANDROID
  RETURN_ERROR_IF_SYSCALL_FAIL(getifaddrs(&ifaddr_));
#else
  // Android does not support getifaddrs in r22.
  return PosixError(ENOSYS, "getifaddrs");
#endif
  return NoError();
}

void IfAddrHelper::Release() {
  if (ifaddr_) {
#ifndef ANDROID
    // Android does not support freeifaddrs in r22.
    freeifaddrs(ifaddr_);
#endif
    ifaddr_ = nullptr;
  }
}

std::vector<std::string> IfAddrHelper::InterfaceList(int family) const {
  std::vector<std::string> names;
  for (auto ifa = ifaddr_; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != family) {
      continue;
    }
    names.emplace(names.end(), ifa->ifa_name);
  }
  return names;
}

const sockaddr* IfAddrHelper::GetAddr(int family, std::string name) const {
  for (auto ifa = ifaddr_; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != family) {
      continue;
    }
    if (name == ifa->ifa_name) {
      return ifa->ifa_addr;
    }
  }
  return nullptr;
}

PosixErrorOr<int> IfAddrHelper::GetIndex(std::string name) const {
  return InterfaceIndex(name);
}

std::string GetAddr4Str(const in_addr* a) {
  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, a, str, sizeof(str));
  return std::string(str);
}

std::string GetAddr6Str(const in6_addr* a) {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, a, str, sizeof(str));
  return std::string(str);
}

std::string GetAddrStr(const sockaddr* a) {
  if (a->sa_family == AF_INET) {
    auto src = &(reinterpret_cast<const sockaddr_in*>(a)->sin_addr);
    return GetAddr4Str(src);
  } else if (a->sa_family == AF_INET6) {
    auto src = &(reinterpret_cast<const sockaddr_in6*>(a)->sin6_addr);
    return GetAddr6Str(src);
  }
  return std::string("<invalid>");
}

}  // namespace testing
}  // namespace gvisor
