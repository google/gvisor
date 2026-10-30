// Copyright 2023 The gVisor Authors.
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
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/filter.h>
#endif  // __linux__
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <cstdint>
#include <cstring>
#include <iterator>

#ifndef SIOCGSTAMP
#include <linux/sockios.h>
#endif

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Tests for UDP that require raw socket access.
class UdpSocketRawTest : public ::testing::TestWithParam<int> {};

TEST_P(UdpSocketRawTest, ReceiveWithZeroSourcePort) {
  // UDP sockets can't bind to port 0, so send a UDP packet via a raw IP
  // socket instead. If those aren't available, skip the test.
  if (!ASSERT_NO_ERRNO_AND_VALUE(
          HaveRawIPSocketCapability(GetParam(), IPPROTO_UDP))) {
    GTEST_SKIP();
  }

  FileDescriptor udp_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, 0));
  sockaddr_storage bind_addr = InetLoopbackAddr(GetParam());
  ASSERT_THAT(bind(udp_socket.get(), AsSockAddr(&bind_addr), sizeof(bind_addr)),
              SyscallSucceeds());
  socklen_t bind_addr_len = sizeof(bind_addr);
  ASSERT_THAT(
      getsockname(udp_socket.get(), AsSockAddr(&bind_addr), &bind_addr_len),
      SyscallSucceeds());
  uint16_t udp_port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(GetParam(), bind_addr));

  constexpr absl::string_view kMessage = "hi";

  // Set up the UDP body.
  struct udphdr udphdr = {
      .source = 0,
      .dest = udp_port,
      .len = htons(sizeof(udphdr) + kMessage.size()),
      .check = 0,
  };

  if (GetParam() == AF_INET) {
    udphdr.check = UDPChecksum(
        iphdr{
            .saddr = htonl(INADDR_LOOPBACK),
            .daddr = htonl(INADDR_LOOPBACK),
        },
        udphdr, kMessage.data(), kMessage.size());
  } else {
    udphdr.check = UDPChecksum(
        ip6_hdr{
            .ip6_src = in6addr_loopback,
            .ip6_dst = in6addr_loopback,
        },
        udphdr, kMessage.data(), kMessage.size());
  }
  // Copy the header and the payload into our packet buffer.
  char send_buf[sizeof(udphdr) + kMessage.size()];
  memcpy(send_buf, &udphdr, sizeof(udphdr));
  memcpy(send_buf + sizeof(udphdr), kMessage.data(), kMessage.size());

  {
    // Send the packet out a raw socket.
    struct sockaddr_storage raw_socket_addr = InetLoopbackAddr(GetParam());
    FileDescriptor raw_socket =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_RAW, IPPROTO_UDP));
    ASSERT_THAT(sendto(raw_socket.get(), send_buf, sizeof(send_buf), 0,
                       reinterpret_cast<struct sockaddr*>(&raw_socket_addr),
                       sizeof(raw_socket_addr)),
                SyscallSucceedsWithValue(sizeof(send_buf)));
  }

  // Receive and validate the data.
  char received[kMessage.size() + 1];
  struct sockaddr_storage src;
  socklen_t addr2len = sizeof(src);
  EXPECT_THAT(recvfrom(udp_socket.get(), received, sizeof(received), 0,
                       AsSockAddr(&src), &addr2len),
              SyscallSucceedsWithValue(kMessage.size()));
  ASSERT_EQ(src.ss_family, GetParam());
  ASSERT_EQ(ASSERT_NO_ERRNO_AND_VALUE(AddrPort(GetParam(), src)), 0);
  ASSERT_EQ(absl::string_view(received, kMessage.size()), kMessage);
}

enum class QuotedPacket {
  kPlain,
  kDestinationOptions,
  kFirstFragment,
  kAtomicFragment,
  kNoninitialFragment,
  kTruncatedOptions,
};

class QuotedUdpErrorTest : public ::testing::TestWithParam<QuotedPacket> {};

TEST_P(QuotedUdpErrorTest, PortUnreachable) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(
          HaveRawIPSocketCapability(AF_INET6, IPPROTO_ICMPV6))) {
    GTEST_SKIP();
  }
  auto pair = ASSERT_NO_ERRNO_AND_VALUE(UDPBidirectionalBindSocketPairCreator(
      AF_INET6, SOCK_DGRAM, IPPROTO_UDP, /*dual_stack=*/false)());
  const auto& src = *reinterpret_cast<const sockaddr_in6*>(pair->first_addr());
  const auto& dst = *reinterpret_cast<const sockaddr_in6*>(pair->second_addr());

  // A port-unreachable error may quote just enough of a packet to identify
  // the UDP socket. Leave the application payload out of every quote.
  const char payload[128] = {};
  const auto kind = GetParam();
  const bool has_options = kind != QuotedPacket::kPlain;
  const bool has_fragment = kind == QuotedPacket::kFirstFragment ||
                            kind == QuotedPacket::kAtomicFragment ||
                            kind == QuotedPacket::kNoninitialFragment;
  uint8_t options[8] = {};
  options[0] = has_fragment ? IPPROTO_FRAGMENT : IPPROTO_UDP;
  // The length counts eight-byte units after the first eight bytes.
  options[1] = kind == QuotedPacket::kTruncatedOptions ? 2 : 0;
  ip6_frag fragment = {};
  fragment.ip6f_nxt = IPPROTO_UDP;
  fragment.ip6f_ident = htonl(1);
  if (kind == QuotedPacket::kFirstFragment) {
    fragment.ip6f_offlg = htons(1);  // More fragments at offset zero.
  } else if (kind == QuotedPacket::kNoninitialFragment) {
    fragment.ip6f_offlg = htons(8);  // Nonzero fragment offset.
  }
  const size_t options_len = has_options ? sizeof(options) : 0;
  const size_t fragment_len = has_fragment ? sizeof(fragment) : 0;
  ip6_hdr ip = {};
  ip.ip6_vfc = 6 << 4;
  ip.ip6_plen =
      htons(options_len + fragment_len + sizeof(udphdr) + sizeof(payload));
  ip.ip6_nxt = has_options ? IPPROTO_DSTOPTS : IPPROTO_UDP;
  ip.ip6_hlim = 64;
  ip.ip6_src = src.sin6_addr;
  ip.ip6_dst = dst.sin6_addr;
  udphdr udp = {
      .source = src.sin6_port,
      .dest = dst.sin6_port,
      .len = htons(sizeof(udphdr) + sizeof(payload)),
  };
  udp.check = UDPChecksum(ip, udp, payload, sizeof(payload));
  if (udp.check == 0) {
    udp.check = 0xffff;  // A computed zero checksum is transmitted as all ones.
  }

  icmp6_hdr error = {};
  error.icmp6_type = ICMP6_DST_UNREACH;
  error.icmp6_code = ICMP6_DST_UNREACH_NOPORT;
  iovec vec[] = {{&error, sizeof(error)},
                 {&ip, sizeof(ip)},
                 {options, options_len},
                 {&fragment, fragment_len},
                 {&udp, sizeof(udp)}};
  sockaddr_in6 local = src;
  local.sin6_port = 0;
  msghdr message = {};
  message.msg_name = &local;
  message.msg_namelen = sizeof(local);
  message.msg_iov = vec;
  message.msg_iovlen = std::size(vec);
  FileDescriptor raw =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6));
  ASSERT_THAT(
      sendmsg(raw.get(), &message, 0),
      SyscallSucceedsWithValue(sizeof(error) + sizeof(ip) + options_len +
                               fragment_len + sizeof(udp)));

  pollfd pfd = {.fd = pair->first_fd(), .events = POLLERR};
  if (kind == QuotedPacket::kNoninitialFragment ||
      kind == QuotedPacket::kTruncatedOptions) {
    EXPECT_THAT(RetryEINTR(poll)(&pfd, 1, 1000), SyscallSucceedsWithValue(0));
    return;
  }
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 5000), SyscallSucceedsWithValue(1));
  ASSERT_EQ(pfd.revents, POLLERR);
  int socket_error;
  socklen_t len = sizeof(socket_error);
  ASSERT_THAT(getsockopt(pfd.fd, SOL_SOCKET, SO_ERROR, &socket_error, &len),
              SyscallSucceeds());
  EXPECT_EQ(socket_error, ECONNREFUSED);
}

INSTANTIATE_TEST_SUITE_P(Plain, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kPlain));
INSTANTIATE_TEST_SUITE_P(DestinationOptions, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kDestinationOptions));
INSTANTIATE_TEST_SUITE_P(FirstFragment, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kFirstFragment));
INSTANTIATE_TEST_SUITE_P(AtomicFragment, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kAtomicFragment));
INSTANTIATE_TEST_SUITE_P(NoninitialFragment, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kNoninitialFragment));
INSTANTIATE_TEST_SUITE_P(TruncatedOptions, QuotedUdpErrorTest,
                         ::testing::Values(QuotedPacket::kTruncatedOptions));
INSTANTIATE_TEST_SUITE_P(AllInetTests, UdpSocketRawTest,
                         ::testing::Values(AF_INET, AF_INET6));

}  // namespace
}  // namespace testing
}  // namespace gvisor
