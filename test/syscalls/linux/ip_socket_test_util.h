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

#ifndef GVISOR_TEST_SYSCALLS_IP_SOCKET_TEST_UTIL_H_
#define GVISOR_TEST_SYSCALLS_IP_SOCKET_TEST_UTIL_H_

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/types.h>

#include <string>

#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

// Extracts the IP address from an inet sockaddr in network byte order.
uint32_t IPFromInetSockaddr(const struct sockaddr* addr);

// Extracts the port from an inet sockaddr in host byte order.
uint16_t PortFromInetSockaddr(const struct sockaddr* addr);

// InterfaceIndex returns the index of the named interface.
PosixErrorOr<int> InterfaceIndex(std::string name);

// GetLoopbackIndex returns the index of the loopback interface.
inline PosixErrorOr<int> GetLoopbackIndex() { return InterfaceIndex("lo"); }

// IPv6TCPAcceptBindSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and accept() syscalls with AF_INET6 and the
// given type bound to the IPv6 loopback.
SocketPairKind IPv6TCPAcceptBindSocketPair(int type);

// IPv4TCPAcceptBindSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and accept() syscalls with AF_INET and the
// given type bound to the IPv4 loopback.
SocketPairKind IPv4TCPAcceptBindSocketPair(int type);

// DualStackTCPAcceptBindSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and accept() syscalls with AF_INET6 and the
// given type bound to the IPv4 loopback.
SocketPairKind DualStackTCPAcceptBindSocketPair(int type);

// IPv6TCPAcceptBindPersistentListenerSocketPair is like
// IPv6TCPAcceptBindSocketPair except it uses a persistent listening socket to
// create all socket pairs.
SocketPairKind IPv6TCPAcceptBindPersistentListenerSocketPair(int type);

// IPv4TCPAcceptBindPersistentListenerSocketPair is like
// IPv4TCPAcceptBindSocketPair except it uses a persistent listening socket to
// create all socket pairs.
SocketPairKind IPv4TCPAcceptBindPersistentListenerSocketPair(int type);

// DualStackTCPAcceptBindPersistentListenerSocketPair is like
// DualStackTCPAcceptBindSocketPair except it uses a persistent listening socket
// to create all socket pairs.
SocketPairKind DualStackTCPAcceptBindPersistentListenerSocketPair(int type);

// IPv6UDPBidirectionalBindSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and connect() syscalls with AF_INET6 and the
// given type bound to the IPv6 loopback.
SocketPairKind IPv6UDPBidirectionalBindSocketPair(int type);

// IPv4UDPBidirectionalBindSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and connect() syscalls with AF_INET and the
// given type bound to the IPv4 loopback.
SocketPairKind IPv4UDPBidirectionalBindSocketPair(int type);

// DualStackUDPBidirectionalBindSocketPair returns a SocketPairKind that
// represents SocketPairs created with bind() and connect() syscalls with
// AF_INET6 and the given type bound to the IPv4 loopback.
SocketPairKind DualStackUDPBidirectionalBindSocketPair(int type);

// IPv4UDPUnboundSocketPair returns a SocketPairKind that represents
// SocketPairs created with AF_INET and the given type.
SocketPairKind IPv4UDPUnboundSocketPair(int type);

// ICMPUnboundSocket returns a SocketKind that represents a SimpleSocket created
// with AF_INET, SOCK_DGRAM, IPPROTO_ICMP, and the given type.
SocketKind ICMPUnboundSocket(int type);

// ICMPv6UnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, and the given type.
SocketKind ICMPv6UnboundSocket(int type);

// IPv4RawUDPUnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET, SOCK_RAW, IPPROTO_UDP, and the given type.
SocketKind IPv4RawUDPUnboundSocket(int type);

// IPv4UDPUnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET, SOCK_DGRAM, IPPROTO_UDP, and the given type.
SocketKind IPv4UDPUnboundSocket(int type);

// IPv6UDPUnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET6, SOCK_DGRAM, IPPROTO_UDP, and the given type.
SocketKind IPv6UDPUnboundSocket(int type);

// IPv4TCPUnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET, SOCK_STREAM, IPPROTO_TCP and the given type.
SocketKind IPv4TCPUnboundSocket(int type);

// IPv6TCPUnboundSocket returns a SocketKind that represents a SimpleSocket
// created with AF_INET6, SOCK_STREAM, IPPROTO_TCP and the given type.
SocketKind IPv6TCPUnboundSocket(int type);

// GetAddr4Str returns the given IPv4 network address structure as a string.
std::string GetAddr4Str(const in_addr* a);

// GetAddr6Str returns the given IPv6 network address structure as a string.
std::string GetAddr6Str(const in6_addr* a);

// GetAddrStr returns the given IPv4 or IPv6 network address structure as a
// string.
std::string GetAddrStr(const sockaddr* a);

// RecvTOS attempts to read buf_size bytes into buf, and then updates buf_size
// with the numbers of bytes actually read. It expects the IP_TOS cmsg to be
// received. The buffer must already be allocated with at least buf_size size.
void RecvTOS(int sock, char buf[], size_t* buf_size, uint8_t* out_tos);

// SendTOS sends a message using buf as payload and tos as IP_TOS control
// message.
void SendTOS(int sock, char buf[], size_t buf_size, uint8_t tos);

// RecvTClass attempts to read buf_size bytes into buf, and then updates
// buf_size with the numbers of bytes actually read. It expects the IPV6_TCLASS
// cmsg to be received. The buffer must already be allocated with at least
// buf_size size.
void RecvTClass(int sock, char buf[], size_t* buf_size, int* out_tclass);

// SendTClass sends a message using buf as payload and tclass as IP_TOS control
// message.
void SendTClass(int sock, char buf[], size_t buf_size, int tclass);

// RecvTTL attempts to read buf_size bytes into buf, and then updates buf_size
// with the numbers of bytes actually read. It expects the IP_TTL cmsg to be
// received. The buffer must already be allocated with at least buf_size size.
void RecvTTL(int sock, char buf[], size_t* buf_size, int* out_ttl);

// SendTTL sends a message using buf as payload and ttl as IP_TOS control
// message.
void SendTTL(int sock, char buf[], size_t buf_size, int ttl);

// RecvHopLimit attempts to read buf_size bytes into buf, and then updates
// buf_size with the numbers of bytes actually read. It expects the
// IPV6_HOPLIMIT cmsg to be received. The buffer must already be allocated with
// at least buf_size size.
void RecvHopLimit(int sock, char buf[], size_t* buf_size, int* out_hoplimit);

// SendHopLimit sends a message using buf as payload and hoplimit as IP_HOPLIMIT
// control message.
void SendHopLimit(int sock, char buf[], size_t buf_size, int hoplimit);
// RecvPktInfo attempts to read buf_size bytes into buf, and then updates
// buf_size with the numbers of bytes actually read. It expects the
// IP_PKTINFO cmsg to be received. The buffer must already be allocated with
// at least buf_size size.
void RecvPktInfo(int sock, char buf[], size_t* buf_size,
                 in_pktinfo* out_pktinfo);

// RecvIPv6PktInfo attempts to read buf_size bytes into buf, and then updates
// buf_size with the numbers of bytes actually read. It expects the
// IPV6_PKTINFO cmsg to be received. The buffer must already be allocated with
// at least buf_size size.
void RecvIPv6PktInfo(int sock, char buf[], size_t* buf_size,
                     in6_pktinfo* out_pktinfo);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_IP_SOCKET_TEST_UTIL_H_
