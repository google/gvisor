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

#include <asm-generic/errno.h>
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
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

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
      GTEST_SKIP();
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
  int want;
  int want_gvisor;

  BindTestCase() {}

  BindTestCase(TestAddress bind_to, int want)
      : bind_to(bind_to), want(want), want_gvisor(want) {}

  BindTestCase(TestAddress bind_to, int want, int want_gvisor)
      : bind_to(bind_to), want(want), want_gvisor(want_gvisor) {}
};

// Test fixture for socket binding.
class GenericSocket
    : public ::testing::TestWithParam<std::tuple<SocketKind, BindTestCase>> {
 protected:
  void SetUp() override {
    socket_factory_ = std::get<0>(GetParam());
    test_case_ = std::get<1>(GetParam());

    // gUnit uses printf, so will we.
    printf("Testing binding an %s with %s (want Linux=%d, gVisor=%d))\n",
           socket_factory_.description.c_str(),
           test_case_.bind_to.description.c_str(), test_case_.want,
           test_case_.want_gvisor);
  }

  PosixErrorOr<std::unique_ptr<FileDescriptor>> NewSocket() const {
    return socket_factory_.Create();
  }

  struct BindTestCase TestCase() const {
    return test_case_;
  }

 private:
  SocketKind socket_factory_;
  struct BindTestCase test_case_;
};

TEST_P(GenericSocket, Bind) {
  auto socket_fd = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto tc = TestCase();

  int want = IsRunningOnGvisor() ? tc.want_gvisor : tc.want;
  if (want == 0) {
    ASSERT_THAT(bind(socket_fd->get(), AsSockAddr(&tc.bind_to.addr),
                     tc.bind_to.addr_len),
                SyscallSucceeds());
  } else {
    ASSERT_THAT(bind(socket_fd->get(), AsSockAddr(&tc.bind_to.addr),
                     tc.bind_to.addr_len),
                SyscallFailsWithErrno(want));
  }
}

INSTANTIATE_TEST_SUITE_P(
    ICMP, GenericSocket,
    ::testing::Combine(
        ::testing::Values(ICMPUnboundSocket(0)),
        ::testing::ValuesIn({
            BindTestCase(V4Any(), 0),

            // TODO(gvisor.dev/issue/5711): Remove the third parameter from the
            // test case below once ICMP sockets are no longer allowed to bind
            // to broadcast addresses.
            BindTestCase(V4Broadcast(), EADDRNOTAVAIL, 0),

            BindTestCase(V4Loopback(), 0),

            // TODO(gvisor.dev/issue/5711): Remove the third parameter from the
            // test case below once ICMP sockets are no longer allowed to bind
            // to broadcast addresses.
            BindTestCase(V4LoopbackSubnetBroadcast(), EADDRNOTAVAIL, 0),

            BindTestCase(V4Multicast(), EADDRNOTAVAIL),
            BindTestCase(V4MulticastAllHosts(), EADDRNOTAVAIL),
            BindTestCase(V4AddrStr("IPv4UnknownUnicast", "192.168.1.1"),
                         EADDRNOTAVAIL),

            // TODO(gvisor.dev/issue/6021): Remove the third parameter from all
            // the test cases below once ICMP sockets return EAFNOSUPPORT when
            // binding to IPv6 addresses.
            BindTestCase(V6Any(), EAFNOSUPPORT, EINVAL),
            BindTestCase(V6Loopback(), EAFNOSUPPORT, EINVAL),
            BindTestCase(V6Multicast(), EAFNOSUPPORT, EINVAL),
            BindTestCase(V6MulticastInterfaceLocalAllNodes(), EAFNOSUPPORT,
                         EINVAL),
            BindTestCase(V6MulticastLinkLocalAllNodes(), EAFNOSUPPORT, EINVAL),
            BindTestCase(V6MulticastLinkLocalAllRouters(), EAFNOSUPPORT,
                         EINVAL),
            BindTestCase(V6AddrStr("IPv6UnknownUnicast", "fc00::1"),
                         EAFNOSUPPORT, EINVAL),
        })),
    [](const ::testing::TestParamInfo<GenericSocket::ParamType>& info) {
      auto tc = std::get<1>(info.param);
      return tc.bind_to.description;
    });

INSTANTIATE_TEST_SUITE_P(
    ICMPv6, GenericSocket,
    ::testing::Combine(
        ::testing::Values(ICMPv6UnboundSocket(0)),
        ::testing::ValuesIn({
            BindTestCase(V4Any(), EINVAL),
            BindTestCase(V4Broadcast(), EINVAL),
            BindTestCase(V4Loopback(), EINVAL),
            BindTestCase(V4LoopbackSubnetBroadcast(), EINVAL),
            BindTestCase(V4Multicast(), EINVAL),
            BindTestCase(V4MulticastAllHosts(), EINVAL),
            BindTestCase(V4AddrStr("IPv4UnknownUnicast", "192.168.1.1"),
                         EINVAL),
            BindTestCase(V6Any(), 0),
            BindTestCase(V6Loopback(), 0),

            // TODO(gvisor.dev/issue/6022): Remove the third parameter from the
            // test cases below once ICMPv6 sockets return EINVAL when binding
            // to IPv6 multicast addresses.
            BindTestCase(V6Multicast(), EINVAL, EADDRNOTAVAIL),
            BindTestCase(V6MulticastInterfaceLocalAllNodes(), EINVAL,
                         EADDRNOTAVAIL),
            BindTestCase(V6MulticastLinkLocalAllNodes(), EINVAL, EADDRNOTAVAIL),
            BindTestCase(V6MulticastLinkLocalAllRouters(), EINVAL,
                         EADDRNOTAVAIL),

            BindTestCase(V6AddrStr("IPv6UnknownUnicast", "fc00::1"),
                         EADDRNOTAVAIL),
        })),
    [](const ::testing::TestParamInfo<GenericSocket::ParamType>& info) {
      auto tc = std::get<1>(info.param);
      return tc.bind_to.description;
    });
}  // namespace

}  // namespace testing
}  // namespace gvisor
