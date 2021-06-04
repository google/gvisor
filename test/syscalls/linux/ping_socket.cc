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
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
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
              // TODO(gvisor.dev/issue/5711): Remove want_gvisor once ICMP
              // sockets are no longer allowed to bind to broadcast addresses.
              .want_gvisor = 0,
          },
          {
              .bind_to = V4Loopback(),
              .want = 0,
          },
          {
              .bind_to = V4LoopbackSubnetBroadcast(),
              .want = EADDRNOTAVAIL,
              // TODO(gvisor.dev/issue/5711): Remove want_gvisor once ICMP
              // sockets are no longer allowed to bind to broadcast addresses.
              .want_gvisor = 0,
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
          // TODO(gvisor.dev/issue/6021): Remove want_gvisor from all the test
          // cases below once ICMP sockets return EAFNOSUPPORT when binding to
          // IPv6 addresses.
          {
              .bind_to = V6Any(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6Loopback(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6Multicast(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6MulticastInterfaceLocalAllNodes(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6MulticastLinkLocalAllNodes(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6MulticastLinkLocalAllRouters(),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
          },
          {
              .bind_to = V6AddrStr("IPv6UnknownUnicast", "fc00::1"),
              .want = EAFNOSUPPORT,
              .want_gvisor = EINVAL,
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
