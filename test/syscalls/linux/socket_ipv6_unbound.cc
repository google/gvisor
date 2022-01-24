// Copyright 2021 The gVisor Authors.
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

#include <netinet/in.h>
#ifdef __linux__
#include <linux/in6.h>
#endif  //  __linux__
#include <sys/socket.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr int kDefaultHopLimit = 64;
constexpr int kDefaultTtl = 64;

using ::testing::ValuesIn;
using IPv6UnboundSocketTest = SimpleSocketTest;

TEST_P(IPv6UnboundSocketTest, HopLimitDefault) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  const int set = -1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &set,
                         sizeof(set)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  ASSERT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, kDefaultTtl);
}

TEST_P(IPv6UnboundSocketTest, SetHopLimit) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get1 = -1;
  socklen_t get1_sz = sizeof(get1);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get1,
                         &get1_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get1_sz, sizeof(get1));
  EXPECT_EQ(get1, kDefaultHopLimit);

  const int set = (get1 % 255) + 1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &set,
                         sizeof(set)),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get2,
                         &get2_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, set);
}

TEST_P(IPv6UnboundSocketTest, ResetHopLimitToDefault) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get1 = -1;
  socklen_t get1_sz = sizeof(get1);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get1,
                         &get1_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get1_sz, sizeof(get1));
  EXPECT_EQ(get1, kDefaultHopLimit);

  const int set = (get1 % 255) + 1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &set,
                         sizeof(set)),
              SyscallSucceedsWithValue(0));

  constexpr int kUseDefaultHopLimit = -1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                         &kUseDefaultHopLimit, sizeof(kUseDefaultHopLimit)),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get2,
                         &get2_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, get1);
}

TEST_P(IPv6UnboundSocketTest, ZeroHopLimit) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  constexpr int kZero = 0;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &kZero,
                         sizeof(kZero)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  ASSERT_EQ(get, kZero);
  EXPECT_EQ(get_sz, sizeof(get));
}

TEST_P(IPv6UnboundSocketTest, InvalidLargeHopLimit) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  constexpr int kInvalidLarge = 256;
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                         &kInvalidLarge, sizeof(kInvalidLarge)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPv6UnboundSocketTest, InvalidNegativeHopLimit) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  constexpr int kInvalidNegative = -2;
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                         &kInvalidNegative, sizeof(kInvalidNegative)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPv6UnboundSocketTest, SetTtlDoesNotAffectHopLimit) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  ASSERT_EQ(get_sz, sizeof(get));

  const int set = (get % 255) + 1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set, sizeof(set)),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &get2,
                         &get2_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, get);
}

TEST_P(IPv6UnboundSocketTest, SetHopLimitDoesNotAffectTtl) {
  std::unique_ptr<FileDescriptor> socket =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get_sz, sizeof(get));

  const int set = (get % 255) + 1;
  ASSERT_THAT(setsockopt(socket->get(), IPPROTO_IPV6, IPV6_UNICAST_HOPS, &set,
                         sizeof(set)),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  ASSERT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get2, &get2_sz),
              SyscallSucceedsWithValue(0));
  ASSERT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, get);
}

INSTANTIATE_TEST_SUITE_P(
    IPv6UnboundSockets, IPv6UnboundSocketTest,
    ValuesIn(VecCat<SocketKind>(
        ApplyVec<SocketKind>(IPv6UDPUnboundSocket,
                             std::vector<int>{0, SOCK_NONBLOCK}),
        ApplyVec<SocketKind>(IPv6TCPUnboundSocket,
                             std::vector{0, SOCK_NONBLOCK}))));

}  // namespace
}  // namespace testing
}  // namespace gvisor
