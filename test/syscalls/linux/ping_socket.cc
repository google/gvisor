// Copyright 2020 The gVisor Authors.
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

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <vector>

#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/strings/str_join.h"
#include "absl/types/optional.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Note: These tests require /proc/sys/net/ipv4/ping_group_range to be
// configured to allow the tester to create ping sockets (see icmp(7)).

namespace gvisor {
namespace testing {
namespace {

// Test ICMP port exhaustion returns EAGAIN.
//
// We disable both random/cooperative S/R for this test as it makes way too many
// syscalls.
TEST(PingSocket, ICMPPortExhaustion) {
  DisableSave ds;

  {
    auto s = Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (!s.ok()) {
      ASSERT_EQ(s.error().errno_value(), EACCES);
      GTEST_SKIP() << "TODO(gvisor.dev/issue/6126): Buildkite does not allow "
                      "creation of ICMP or ICMPv6 sockets";
    }
  }

  const struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr =
          {
              .s_addr = htonl(INADDR_LOOPBACK),
          },
  };

  std::vector<FileDescriptor> sockets;
  constexpr int kSockets = 65536;
  for (int i = 0; i < kSockets; i++) {
    auto s =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
    int ret = connect(s.get(), reinterpret_cast<const struct sockaddr*>(&addr),
                      sizeof(addr));
    if (ret == 0) {
      sockets.push_back(std::move(s));
      continue;
    }
    ASSERT_THAT(ret, SyscallFailsWithErrno(EAGAIN));
    break;
  }
}

TEST(PingSocket, PayloadTooLarge) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  constexpr icmphdr kSendIcmp = {
      .type = ICMP_ECHO,
  };
  constexpr size_t kGiantSize = 1 << 21;  // 2MB.
  const sockaddr_in kAddr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, kGiantSize, 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallFailsWithErrno(EMSGSIZE));
}

TEST(PingSocket, ReceiveTOS) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in kAddr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr int kArbitraryTOS = 42;
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IP, IP_TOS, &kArbitraryTOS,
                         sizeof(kArbitraryTOS)),
              SyscallSucceeds());

  constexpr icmphdr kSendIcmp = {
      .type = ICMP_ECHO,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive TOS.
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IP, IP_RECVTOS, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  icmphdr recv_buf;
  size_t recv_buf_len = sizeof(recv_buf);
  uint8_t received_tos;
  ASSERT_NO_FATAL_FAILURE(RecvTOS(ping.get(),
                                  reinterpret_cast<char*>(&recv_buf),
                                  &recv_buf_len, &received_tos));
  ASSERT_EQ(recv_buf_len, sizeof(kSendIcmp));

  EXPECT_EQ(recv_buf.type, ICMP_ECHOREPLY);
  EXPECT_EQ(recv_buf.code, 0);

  EXPECT_EQ(received_tos, kArbitraryTOS);
}

TEST(PingSocket, ReceiveTClass) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in6 kAddr = {
      .sin6_family = AF_INET6,
      .sin6_addr = in6addr_loopback,
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr int kArbitraryTClass = 42;
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IPV6, IPV6_TCLASS,
                         &kArbitraryTClass, sizeof(kArbitraryTClass)),
              SyscallSucceeds());

  constexpr icmp6_hdr kSendIcmp = {
      .icmp6_type = ICMP6_ECHO_REQUEST,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive TCLASS.
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IPV6, IPV6_RECVTCLASS, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  struct {
    icmp6_hdr icmpv6;

    // Add an extra byte to confirm we did not read unexpected bytes.
    char unused;
  } ABSL_ATTRIBUTE_PACKED recv_buf;
  size_t recv_buf_len = sizeof(recv_buf);
  int received_tclass;
  ASSERT_NO_FATAL_FAILURE(RecvTClass(ping.get(),
                                     reinterpret_cast<char*>(&recv_buf),
                                     &recv_buf_len, &received_tclass));
  ASSERT_EQ(recv_buf_len, sizeof(kSendIcmp));

  EXPECT_EQ(recv_buf.icmpv6.icmp6_type, ICMP6_ECHO_REPLY);
  EXPECT_EQ(recv_buf.icmpv6.icmp6_code, 0);

  EXPECT_EQ(received_tclass, kArbitraryTClass);
}

TEST(PingSocket, ReceiveTTL) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in kAddr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr icmphdr kSendIcmp = {
      .type = ICMP_ECHO,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive TTL.
  constexpr int kOne = 1;
  ASSERT_THAT(
      setsockopt(ping.get(), IPPROTO_IP, IP_RECVTTL, &kOne, sizeof(kOne)),
      SyscallSucceeds());

  icmphdr recv_icmp;
  size_t recv_len = sizeof(recv_icmp);
  int received_ttl;
  ASSERT_NO_FATAL_FAILURE(RecvTTL(ping.get(),
                                  reinterpret_cast<char*>(&recv_icmp),
                                  &recv_len, &received_ttl));
  ASSERT_EQ(recv_len, sizeof(kSendIcmp));

  EXPECT_EQ(recv_icmp.type, ICMP_ECHOREPLY);
  EXPECT_EQ(recv_icmp.code, 0);

  constexpr int kDefaultTTL = 64;
  EXPECT_EQ(received_ttl, kDefaultTTL);
}

TEST(PingSocket, ReceiveHopLimit) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in6 kAddr = {
      .sin6_family = AF_INET6,
      .sin6_addr = in6addr_loopback,
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr icmp6_hdr kSendIcmp = {
      .icmp6_type = ICMP6_ECHO_REQUEST,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive HOPLIMIT.
  constexpr int kOne = 1;
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &kOne,
                         sizeof(kOne)),
              SyscallSucceeds());

  icmp6_hdr recv_icmpv6;
  size_t recv_len = sizeof(recv_icmpv6);
  int received_hoplimit;
  ASSERT_NO_FATAL_FAILURE(RecvHopLimit(ping.get(),
                                       reinterpret_cast<char*>(&recv_icmpv6),
                                       &recv_len, &received_hoplimit));
  ASSERT_EQ(recv_len, sizeof(kSendIcmp));

  EXPECT_EQ(recv_icmpv6.icmp6_type, ICMP6_ECHO_REPLY);
  EXPECT_EQ(recv_icmpv6.icmp6_code, 0);

  constexpr int kDefaultHopLimit = 64;
  EXPECT_EQ(received_hoplimit, kDefaultHopLimit);
}

TEST(PingSocket, ReceiveIPPacketInfo) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in kAddr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr icmphdr kSendIcmp = {
      .type = ICMP_ECHO,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive PKTINFO.
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IP, IP_PKTINFO, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  struct {
    icmphdr icmp;

    // Add an extra byte to confirm we did not read unexpected bytes.
    char unused;
  } ABSL_ATTRIBUTE_PACKED recv_buf;
  size_t recv_buf_len = sizeof(recv_buf);
  in_pktinfo received_pktinfo;
  ASSERT_NO_FATAL_FAILURE(RecvPktInfo(ping.get(),
                                      reinterpret_cast<char*>(&recv_buf),
                                      &recv_buf_len, &received_pktinfo));
  ASSERT_EQ(recv_buf_len, sizeof(icmphdr));

  EXPECT_EQ(recv_buf.icmp.type, ICMP_ECHOREPLY);
  EXPECT_EQ(recv_buf.icmp.code, 0);

  EXPECT_EQ(received_pktinfo.ipi_ifindex,
            ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
  EXPECT_EQ(ntohl(received_pktinfo.ipi_spec_dst.s_addr), INADDR_ANY);
  EXPECT_EQ(ntohl(received_pktinfo.ipi_addr.s_addr), INADDR_LOOPBACK);
}

TEST(PingSocket, ReceiveIPv6PktInfo) {
  PosixErrorOr<FileDescriptor> result =
      Socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
  if (!result.ok()) {
    int errno_value = result.error().errno_value();
    ASSERT_EQ(errno_value, EACCES) << strerror(errno_value);
    GTEST_SKIP() << "ping socket not supported";
  }
  FileDescriptor& ping = result.ValueOrDie();

  const sockaddr_in6 kAddr = {
      .sin6_family = AF_INET6,
      .sin6_addr = in6addr_loopback,
  };
  ASSERT_THAT(bind(ping.get(), reinterpret_cast<const sockaddr*>(&kAddr),
                   sizeof(kAddr)),
              SyscallSucceeds());

  constexpr icmp6_hdr kSendIcmp = {
      .icmp6_type = ICMP6_ECHO_REQUEST,
  };
  ASSERT_THAT(sendto(ping.get(), &kSendIcmp, sizeof(kSendIcmp), 0,
                     reinterpret_cast<const sockaddr*>(&kAddr), sizeof(kAddr)),
              SyscallSucceedsWithValue(sizeof(kSendIcmp)));

  // Register to receive PKTINFO.
  ASSERT_THAT(setsockopt(ping.get(), IPPROTO_IPV6, IPV6_RECVPKTINFO,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  struct {
    icmp6_hdr icmpv6;

    // Add an extra byte to confirm we did not read unexpected bytes.
    char unused;
  } ABSL_ATTRIBUTE_PACKED recv_buf;
  size_t recv_buf_len = sizeof(recv_buf);
  in6_pktinfo received_pktinfo;
  ASSERT_NO_FATAL_FAILURE(RecvIPv6PktInfo(ping.get(),
                                          reinterpret_cast<char*>(&recv_buf),
                                          &recv_buf_len, &received_pktinfo));
  ASSERT_EQ(recv_buf_len, sizeof(kSendIcmp));

  EXPECT_EQ(recv_buf.icmpv6.icmp6_type, ICMP6_ECHO_REPLY);
  EXPECT_EQ(recv_buf.icmpv6.icmp6_code, 0);

  EXPECT_EQ(received_pktinfo.ipi6_ifindex,
            ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
  ASSERT_EQ(memcmp(&received_pktinfo.ipi6_addr, &in6addr_loopback,
                   sizeof(in6addr_loopback)),
            0);
}

struct BindTestCase {
  TestAddress bind_to;
  int want = 0;
  absl::optional<int> want_gvisor;
};

// Test fixture for socket binding.
class Fixture
    : public ::testing::TestWithParam<std::tuple<SocketKind, BindTestCase>> {};

TEST_P(Fixture, Bind) {
  auto [socket_factory, test_case] = GetParam();
  auto socket = socket_factory.Create();
  if (!socket.ok()) {
    ASSERT_EQ(socket.error().errno_value(), EACCES);
    GTEST_SKIP() << "TODO(gvisor.dev/issue/6126): Buildkite does not allow "
                    "creation of ICMP or ICMPv6 sockets";
  }
  auto socket_fd = std::move(socket).ValueOrDie();

  const int want = test_case.want_gvisor.has_value() && IsRunningOnGvisor()
                       ? *test_case.want_gvisor
                       : test_case.want;
  if (want == 0) {
    EXPECT_THAT(bind(socket_fd->get(), AsSockAddr(&test_case.bind_to.addr),
                     test_case.bind_to.addr_len),
                SyscallSucceeds());
  } else {
    EXPECT_THAT(bind(socket_fd->get(), AsSockAddr(&test_case.bind_to.addr),
                     test_case.bind_to.addr_len),
                SyscallFailsWithErrno(want));
  }
}

std::vector<std::tuple<SocketKind, BindTestCase>> ICMPTestCases() {
  return ApplyVec<std::tuple<SocketKind, BindTestCase>>(
      [](const BindTestCase& test_case) {
        return std::make_tuple(ICMPUnboundSocket(0), test_case);
      },
      std::vector<BindTestCase>{
          {
              .bind_to = V4Any(),
              .want = 0,
              .want_gvisor = 0,
          },
          {
              .bind_to = V4Broadcast(),
              .want = EADDRNOTAVAIL,
          },
          {
              .bind_to = V4Loopback(),
              .want = 0,
          },
          {
              .bind_to = V4LoopbackSubnetBroadcast(),
              .want = EADDRNOTAVAIL,
          },
          {
              .bind_to = V4Multicast(),
              .want = EADDRNOTAVAIL,
          },
          {
              .bind_to = V4MulticastAllHosts(),
              .want = EADDRNOTAVAIL,
          },
          {
              .bind_to = V4AddrStr("IPv4UnknownUnicast", "192.168.1.1"),
              .want = EADDRNOTAVAIL,
          },
          {
              .bind_to = V6Any(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6Loopback(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6Multicast(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6MulticastInterfaceLocalAllNodes(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6MulticastLinkLocalAllNodes(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6MulticastLinkLocalAllRouters(),
              .want = EAFNOSUPPORT,
          },
          {
              .bind_to = V6AddrStr("IPv6UnknownUnicast", "fc00::1"),
              .want = EAFNOSUPPORT,
          },
      });
}

std::vector<std::tuple<SocketKind, BindTestCase>> ICMPv6TestCases() {
  return ApplyVec<std::tuple<SocketKind, BindTestCase>>(
      [](const BindTestCase& test_case) {
        return std::make_tuple(ICMPv6UnboundSocket(0), test_case);
      },
      std::vector<BindTestCase>{
          {
              .bind_to = V4Any(),
              .want = EINVAL,
          },
          {
              .bind_to = V4Broadcast(),
              .want = EINVAL,
          },
          {
              .bind_to = V4Loopback(),
              .want = EINVAL,
          },
          {
              .bind_to = V4LoopbackSubnetBroadcast(),
              .want = EINVAL,
          },
          {
              .bind_to = V4Multicast(),
              .want = EINVAL,
          },
          {
              .bind_to = V4MulticastAllHosts(),
              .want = EINVAL,
          },
          {
              .bind_to = V4AddrStr("IPv4UnknownUnicast", "192.168.1.1"),
              .want = EINVAL,
          },
          {
              .bind_to = V6Any(),
              .want = 0,
          },
          {
              .bind_to = V6Loopback(),
              .want = 0,
          },
          // TODO(gvisor.dev/issue/6021): Remove want_gvisor from all the
          // multicast test cases below once ICMPv6 sockets return EINVAL when
          // binding to IPv6 multicast addresses.
          {
              .bind_to = V6Multicast(),
              .want = EINVAL,
              .want_gvisor = EADDRNOTAVAIL,
          },
          {
              .bind_to = V6MulticastInterfaceLocalAllNodes(),
              .want = EINVAL,
              .want_gvisor = EADDRNOTAVAIL,
          },
          {
              .bind_to = V6MulticastLinkLocalAllNodes(),
              .want = EINVAL,
              .want_gvisor = EADDRNOTAVAIL,
          },
          {
              .bind_to = V6MulticastLinkLocalAllRouters(),
              .want = EINVAL,
              .want_gvisor = EADDRNOTAVAIL,
          },
          {
              .bind_to = V6AddrStr("IPv6UnknownUnicast", "fc00::1"),
              .want = EADDRNOTAVAIL,
          },
      });
}

std::vector<std::tuple<SocketKind, BindTestCase>> AllTestCases() {
  return VecCat<std::tuple<SocketKind, BindTestCase>>(ICMPTestCases(),
                                                      ICMPv6TestCases());
}

std::string TestDescription(
    const ::testing::TestParamInfo<Fixture::ParamType>& info) {
  auto [socket_factory, test_case] = info.param;
  std::string name = absl::StrJoin(
      {socket_factory.description, test_case.bind_to.description}, "_");
  absl::c_replace_if(
      name, [](char c) { return !std::isalnum(c); }, '_');
  return name;
}

INSTANTIATE_TEST_SUITE_P(PingSockets, Fixture,
                         ::testing::ValuesIn(AllTestCases()), TestDescription);

}  // namespace
}  // namespace testing
}  // namespace gvisor
