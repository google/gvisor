// Copyright 2026 The gVisor Authors.
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
#include <linux/capability.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Binding an AF_INET or AF_INET6 port below net.ipv4.ip_unprivileged_port_start
// requires CAP_NET_BIND_SERVICE in the user namespace that owns the socket's
// network namespace; without it bind(2) fails with EACCES. See
// inet_port_requires_bind_service(), called from __inet_bind() in
// net/ipv4/af_inet.c.
namespace gvisor {
namespace testing {
namespace {

// A privileged port that is unlikely to already be bound on a test machine.
constexpr uint16_t kPrivilegedPort = 1015;
constexpr uint16_t kUnprivilegedPort = 18015;

constexpr char kStartFile[] = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
constexpr char kRangeFile[] = "/proc/sys/net/ipv4/ip_local_port_range";

PosixErrorOr<FileDescriptor> MakeSocket(int domain, int type) {
  return Socket(domain, type, 0);
}

// Binds fd to `addr` (already in network byte order) and `port`.
PosixError BindToV4(int fd, in_addr_t addr, uint16_t port) {
  sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = addr;
  return RetryEINTR(bind)(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0
             ? NoError()
             : PosixError(errno, "bind");
}

PosixError BindToV6(int fd, const in6_addr& addr, uint16_t port) {
  sockaddr_in6 a = {};
  a.sin6_family = AF_INET6;
  a.sin6_port = htons(port);
  a.sin6_addr = addr;
  return RetryEINTR(bind)(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0
             ? NoError()
             : PosixError(errno, "bind");
}

// Binds fd to `port` on the loopback address of `domain`.
PosixError BindToPort(int fd, int domain, uint16_t port) {
  if (domain == AF_INET) {
    return BindToV4(fd, htonl(INADDR_LOOPBACK), port);
  }
  return BindToV6(fd, in6addr_loopback, port);
}

class BindPrivilegedPortTest
    : public ::testing::TestWithParam<std::tuple<int, int>> {
 protected:
  int domain() const { return std::get<0>(GetParam()); }
  int type() const { return std::get<1>(GetParam()); }
};

// Without CAP_NET_BIND_SERVICE, a privileged port is refused with EACCES.
TEST_P(BindPrivilegedPortTest, PrivilegedPortDeniedWithoutCapability) {
  AutoCapability cap(CAP_NET_BIND_SERVICE, false);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  EXPECT_THAT(BindToPort(fd.get(), domain(), kPrivilegedPort),
              PosixErrorIs(EACCES, ::testing::_));
}

// With CAP_NET_BIND_SERVICE, the same bind succeeds.
TEST_P(BindPrivilegedPortTest, PrivilegedPortAllowedWithCapability) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_BIND_SERVICE)));
  AutoCapability cap(CAP_NET_BIND_SERVICE, true);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  EXPECT_NO_ERRNO(BindToPort(fd.get(), domain(), kPrivilegedPort));
}

// A port at or above the boundary is unaffected by the capability.
TEST_P(BindPrivilegedPortTest, UnprivilegedPortAllowedWithoutCapability) {
  AutoCapability cap(CAP_NET_BIND_SERVICE, false);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  EXPECT_NO_ERRNO(BindToPort(fd.get(), domain(), kUnprivilegedPort));
}

// Port 0 asks the kernel to pick an ephemeral port, which is never privileged,
// so it must succeed without the capability.
TEST_P(BindPrivilegedPortTest, EphemeralPortAllowedWithoutCapability) {
  AutoCapability cap(CAP_NET_BIND_SERVICE, false);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  EXPECT_NO_ERRNO(BindToPort(fd.get(), domain(), 0));
}

// The wildcard address (INADDR_ANY / in6addr_any) is always a valid bind
// address, so a privileged port on it is refused with EACCES, not
// EADDRNOTAVAIL.
TEST_P(BindPrivilegedPortTest, WildcardPrivilegedPortDeniedWithoutCapability) {
  AutoCapability cap(CAP_NET_BIND_SERVICE, false);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  PosixError got =
      domain() == AF_INET
          ? BindToV4(fd.get(), htonl(INADDR_ANY), kPrivilegedPort)
          : BindToV6(fd.get(), in6addr_any, kPrivilegedPort);
  EXPECT_THAT(got, PosixErrorIs(EACCES, ::testing::_));
}

// A non-local address is rejected before the capability check for AF_INET
// (__inet_bind() validates the address first, so EADDRNOTAVAIL), but after it
// for AF_INET6 (__inet6_bind() checks the port first, so EACCES). The addresses
// used are reserved for documentation (RFC 5737 / RFC 3849) and never local.
TEST_P(BindPrivilegedPortTest, NonLocalPrivilegedPortErrno) {
  AutoCapability cap(CAP_NET_BIND_SERVICE, false);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(domain(), type()));
  if (domain() == AF_INET) {
    in_addr addr = {};
    ASSERT_EQ(inet_pton(AF_INET, "192.0.2.1", &addr), 1);
    EXPECT_THAT(BindToV4(fd.get(), addr.s_addr, kPrivilegedPort),
                PosixErrorIs(EADDRNOTAVAIL, ::testing::_));
  } else {
    in6_addr addr = {};
    ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::1", &addr), 1);
    EXPECT_THAT(BindToV6(fd.get(), addr, kPrivilegedPort),
                PosixErrorIs(EACCES, ::testing::_));
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllInetSockets, BindPrivilegedPortTest,
    ::testing::Combine(::testing::Values(AF_INET, AF_INET6),
                       ::testing::Values(SOCK_STREAM, SOCK_DGRAM)));

// Exercises the writable net.ipv4.ip_unprivileged_port_start sysctl and its
// overlap rules against ip_local_port_range. Gated on CAP_NET_ADMIN; saves and
// restores both sysctls. The native runner uses a private netns, so the writes
// do not affect the host.
TEST(BindUnprivilegedPortStartSysctl, BoundaryAndOverlap) {
  // hostinet forwards bind(2) to the host and does not enforce this boundary.
  SKIP_IF(IsRunningWithHostinet());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_BIND_SERVICE)));
  SKIP_IF(access(kStartFile, W_OK) != 0 || access(kRangeFile, W_OK) != 0);

  const std::string saved_start =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kStartFile));
  const std::string saved_range =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kRangeFile));
  Cleanup restore([saved_start, saved_range] {
    SetContents(kStartFile, saved_start).IgnoreError();
    SetContents(kRangeFile, saved_range).IgnoreError();
  });

  // Pin the ephemeral range high so the boundary moves below are unambiguous.
  ASSERT_NO_ERRNO(SetContents(kRangeFile, "16000 65535\n"));

  // Lowering the boundary to 0 lets an unprivileged process bind a low port.
  ASSERT_NO_ERRNO(SetContents(kStartFile, "0\n"));
  {
    AutoCapability cap(CAP_NET_BIND_SERVICE, false);
    auto fd = ASSERT_NO_ERRNO_AND_VALUE(MakeSocket(AF_INET, SOCK_STREAM));
    EXPECT_NO_ERRNO(BindToPort(fd.get(), AF_INET, kPrivilegedPort));
  }

  // The privileged range may not overlap the ephemeral one. A boundary above
  // the start of ip_local_port_range is rejected (ipv4_privileged_ports()).
  EXPECT_THAT(SetContents(kStartFile, "20000\n"),
              PosixErrorIs(EINVAL, ::testing::_));

  // Conversely, an ip_local_port_range starting below the boundary is rejected
  // (ipv4_local_port_range()).
  ASSERT_NO_ERRNO(SetContents(kStartFile, "1024\n"));
  EXPECT_THAT(SetContents(kRangeFile, "500 600\n"),
              PosixErrorIs(EINVAL, ::testing::_));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
