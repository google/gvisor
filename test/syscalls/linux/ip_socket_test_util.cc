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

#include "test/syscalls/linux/ip_socket_test_util.h"

namespace gvisor {
namespace testing {

namespace {

std::string DescribeSocketType(int type) {
  return absl::StrCat(((type & SOCK_NONBLOCK) != 0) ? "non-blocking " : "",
                      ((type & SOCK_CLOEXEC) != 0) ? "close-on-exec " : "");
}

}  // namespace

SocketPairKind IPv6TCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv6 TCP socket");
  return SocketPairKind{
      description, TCPAcceptBindSocketPairCreator(AF_INET6, type | SOCK_STREAM,
                                                  0, /* dual_stack = */ false)};
}

SocketPairKind IPv4TCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 TCP socket");
  return SocketPairKind{
      description, TCPAcceptBindSocketPairCreator(AF_INET, type | SOCK_STREAM,
                                                  0, /* dual_stack = */ false)};
}

SocketPairKind DualStackTCPAcceptBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "dual stack TCP socket");
  return SocketPairKind{
      description, TCPAcceptBindSocketPairCreator(AF_INET6, type | SOCK_STREAM,
                                                  0, /* dual_stack = */ true)};
}

SocketPairKind IPv6UDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv6 UDP socket");
  return SocketPairKind{description, UDPBidirectionalBindSocketPairCreator(
                                         AF_INET6, type | SOCK_DGRAM, 0,
                                         /* dual_stack = */ false)};
}

SocketPairKind IPv4UDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "IPv4 UDP socket");
  return SocketPairKind{description, UDPBidirectionalBindSocketPairCreator(
                                         AF_INET, type | SOCK_DGRAM, 0,
                                         /* dual_stack = */ false)};
}

SocketPairKind DualStackUDPBidirectionalBindSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeSocketType(type), "dual stack UDP socket");
  return SocketPairKind{description, UDPBidirectionalBindSocketPairCreator(
                                         AF_INET6, type | SOCK_DGRAM, 0,
                                         /* dual_stack = */ true)};
}

}  // namespace testing
}  // namespace gvisor
