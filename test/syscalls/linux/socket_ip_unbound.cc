// Copyright 2019 The gVisor Authors.
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Test fixture for tests that apply to pairs of IP sockets.
using IPUnboundSocketTest = SimpleSocketTest;

TEST_P(IPUnboundSocketTest, TtlDefault) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get = -1;
  socklen_t get_sz = sizeof(get);
  EXPECT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, 64);
  EXPECT_EQ(get_sz, sizeof(get));
}

TEST_P(IPUnboundSocketTest, SetTtl) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get1 = -1;
  socklen_t get1_sz = sizeof(get1);
  EXPECT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get1, &get1_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get1_sz, sizeof(get1));

  int set = 100;
  if (set == get1) {
    set += 1;
  }
  socklen_t set_sz = sizeof(set);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set, set_sz),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  EXPECT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get2, &get2_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, set);
}

TEST_P(IPUnboundSocketTest, ResetTtlToDefault) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get1 = -1;
  socklen_t get1_sz = sizeof(get1);
  EXPECT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get1, &get1_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get1_sz, sizeof(get1));

  int set1 = 100;
  if (set1 == get1) {
    set1 += 1;
  }
  socklen_t set1_sz = sizeof(set1);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set1, set1_sz),
              SyscallSucceedsWithValue(0));

  int set2 = -1;
  socklen_t set2_sz = sizeof(set2);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set2, set2_sz),
              SyscallSucceedsWithValue(0));

  int get2 = -1;
  socklen_t get2_sz = sizeof(get2);
  EXPECT_THAT(getsockopt(socket->get(), IPPROTO_IP, IP_TTL, &get2, &get2_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get2_sz, sizeof(get2));
  EXPECT_EQ(get2, get1);
}

TEST_P(IPUnboundSocketTest, ZeroTtl) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int set = 0;
  socklen_t set_sz = sizeof(set);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set, set_sz),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPUnboundSocketTest, InvalidLargeTtl) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int set = 256;
  socklen_t set_sz = sizeof(set);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set, set_sz),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPUnboundSocketTest, InvalidNegativeTtl) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int set = -2;
  socklen_t set_sz = sizeof(set);
  EXPECT_THAT(setsockopt(socket->get(), IPPROTO_IP, IP_TTL, &set, set_sz),
              SyscallFailsWithErrno(EINVAL));
}

INSTANTIATE_TEST_SUITE_P(
    IPUnboundSockets, IPUnboundSocketTest,
    ::testing::ValuesIn(VecCat<SocketKind>(VecCat<SocketKind>(
        ApplyVec<SocketKind>(IPv4UDPUnboundSocket,
                             AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                                    List<int>{0,
                                                              SOCK_NONBLOCK})),
        ApplyVec<SocketKind>(IPv6UDPUnboundSocket,
                             AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                                    List<int>{0,
                                                              SOCK_NONBLOCK})),
        ApplyVec<SocketKind>(IPv4TCPUnboundSocket,
                             AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                    List<int>{0,
                                                              SOCK_NONBLOCK})),
        ApplyVec<SocketKind>(IPv6TCPUnboundSocket,
                             AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                    List<int>{
                                                        0, SOCK_NONBLOCK}))))));

}  // namespace testing
}  // namespace gvisor
