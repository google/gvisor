// Copyright 2025 The gVisor Authors.
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

// Tests for the --restrict-bind-to-loopback runsc flag. When the flag is
// enabled, bind(2) must return EACCES for any address that is not a loopback
// address (127.x.x.x or ::1). These tests skip automatically when the flag is
// not active.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Detect whether --restrict-bind-to-loopback is active by probing a bind to
// INADDR_ANY. On a normal kernel or a gVisor instance without the flag, this
// bind will succeed (or fail with something other than EACCES).
bool RestrictBindToLoopbackEnabled() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return false;
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  int ret =
      bind(sock, reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr));
  int saved_errno = errno;
  close(sock);
  return ret < 0 && saved_errno == EACCES;
}

// IPv4: binding to INADDR_ANY (0.0.0.0) must fail with EACCES.
TEST(RestrictBindLoopback, IPv4_INADDR_ANY_Rejected) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallFailsWithErrno(EACCES));
}

// IPv4: binding to a non-loopback unicast address must fail with EACCES.
TEST(RestrictBindLoopback, IPv4_NonLoopback_Rejected) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, "192.0.2.1", &addr.sin_addr);  // TEST-NET-1, RFC 5737
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallFailsWithErrno(EACCES));
}

// IPv4: binding to 127.0.0.1 must succeed.
TEST(RestrictBindLoopback, IPv4_Loopback_Allowed) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallSucceeds());
}

// IPv4: binding to 127.x.x.x (any loopback block address) must succeed.
TEST(RestrictBindLoopback, IPv4_LoopbackBlock_Allowed) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  inet_pton(AF_INET, "127.0.0.2", &addr.sin_addr);
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallSucceeds());
}

// IPv6: binding to IN6ADDR_ANY (::) must fail with EACCES.
TEST(RestrictBindLoopback, IPv6_IN6ADDR_ANY_Rejected) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
  struct sockaddr_in6 addr = {};
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallFailsWithErrno(EACCES));
}

// IPv6: binding to ::1 must succeed.
TEST(RestrictBindLoopback, IPv6_Loopback_Allowed) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
  struct sockaddr_in6 addr = {};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = 0;
  addr.sin6_addr = in6addr_loopback;
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallSucceeds());
}

// IPv6: binding to ::ffff:127.0.0.1 (IPv4-mapped loopback) must succeed.
// Dual-stack sockets can bind to IPv4 addresses in mapped form; rejecting this
// would break applications that use IPv6 sockets for both IPv4 and IPv6.
TEST(RestrictBindLoopback, IPv6_IPv4MappedLoopback_Allowed) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
  struct sockaddr_in6 addr = {};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = 0;
  // ::ffff:127.0.0.1
  inet_pton(AF_INET6, "::ffff:127.0.0.1", &addr.sin6_addr);
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallSucceeds());
}

// IPv6: binding to ::ffff:0.0.0.0 (IPv4-mapped INADDR_ANY) must fail.
TEST(RestrictBindLoopback, IPv6_IPv4MappedAny_Rejected) {
  SKIP_IF(!RestrictBindToLoopbackEnabled());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
  struct sockaddr_in6 addr = {};
  addr.sin6_family = AF_INET6;
  // ::ffff:0.0.0.0
  inet_pton(AF_INET6, "::ffff:0.0.0.0", &addr.sin6_addr);
  EXPECT_THAT(
      bind(sock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)),
      SyscallFailsWithErrno(EACCES));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
