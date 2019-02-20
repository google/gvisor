// Copyright 2018 Google LLC
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

#include <string>
#include "test/syscalls/linux/socket_test_util.h"

namespace gvisor {
namespace testing {

// InterfaceIndex returns the index of the named interface.
PosixErrorOr<int> InterfaceIndex(std::string name);

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

// IPv4UDPUnboundSocketPair returns a SocketKind that represents
// a SimpleSocket created with AF_INET, SOCK_DGRAM, and the given type.
SocketKind IPv4UDPUnboundSocket(int type);

// IPv4TCPUnboundSocketPair returns a SocketKind that represents
// a SimpleSocket created with AF_INET, SOCK_STREAM and the given type.
SocketKind IPv4TCPUnboundSocket(int type);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_IP_SOCKET_TEST_UTIL_H_
