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

#include <linux/capability.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
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

PosixErrorOr<FileDescriptor> MakeSocket(int domain, int type) {
  return Socket(domain, type, 0);
}

// Binds fd to `port` on the loopback address of `domain`.
PosixError BindToPort(int fd, int domain, uint16_t port) {
  if (domain == AF_INET) {
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return RetryEINTR(bind)(fd, reinterpret_cast<sockaddr*>(&addr),
                            sizeof(addr)) == 0
               ? NoError()
               : PosixError(errno, "bind");
  }
  sockaddr_in6 addr = {};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  addr.sin6_addr = in6addr_loopback;
  return RetryEINTR(bind)(fd, reinterpret_cast<sockaddr*>(&addr),
                          sizeof(addr)) == 0
             ? NoError()
             : PosixError(errno, "bind");
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

INSTANTIATE_TEST_SUITE_P(
    AllInetSockets, BindPrivilegedPortTest,
    ::testing::Combine(::testing::Values(AF_INET, AF_INET6),
                       ::testing::Values(SOCK_STREAM, SOCK_DGRAM)));

}  // namespace
}  // namespace testing
}  // namespace gvisor
