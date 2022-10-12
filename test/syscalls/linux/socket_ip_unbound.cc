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
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/socket_util.h"
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
  EXPECT_TRUE(get == 64 || get == 127);
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
  EXPECT_TRUE(get2 == 64 || get2 == 127);
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

struct TOSOption {
  int level;
  int option;
  int cmsg_level;
};

constexpr int INET_ECN_MASK = 3;

static TOSOption GetTOSOption(int domain) {
  TOSOption opt;
  switch (domain) {
    case AF_INET:
      opt.level = IPPROTO_IP;
      opt.option = IP_TOS;
      opt.cmsg_level = SOL_IP;
      break;
    case AF_INET6:
      opt.level = IPPROTO_IPV6;
      opt.option = IPV6_TCLASS;
      opt.cmsg_level = SOL_IPV6;
      break;
  }
  return opt;
}

TEST_P(IPUnboundSocketTest, TOSDefault) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  TOSOption t = GetTOSOption(GetParam().domain);
  int get = -1;
  socklen_t get_sz = sizeof(get);
  constexpr int kDefaultTOS = 0;
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, kDefaultTOS);
}

TEST_P(IPUnboundSocketTest, SetTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0xC0;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, set);
}

TEST_P(IPUnboundSocketTest, ZeroTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
              SyscallSucceedsWithValue(0));
  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, set);
}

TEST_P(IPUnboundSocketTest, InvalidLargeTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  // Test with exceeding the byte space.
  int set = 256;
  constexpr int kDefaultTOS = 0;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  if (GetParam().domain == AF_INET) {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallSucceedsWithValue(0));
  } else {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallFailsWithErrno(EINVAL));
  }
  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, kDefaultTOS);
}

TEST_P(IPUnboundSocketTest, CheckSkipECN) {
  // Test is inconsistant on different kernels.
  SKIP_IF(!IsRunningOnGvisor());
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0xFF;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
              SyscallSucceedsWithValue(0));
  int expect = static_cast<uint8_t>(set);
  if (GetParam().protocol == IPPROTO_TCP) {
    expect &= ~INET_ECN_MASK;
  }
  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, expect);
}

TEST_P(IPUnboundSocketTest, ZeroTOSOptionSize) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0xC0;
  socklen_t set_sz = 0;
  TOSOption t = GetTOSOption(GetParam().domain);
  if (GetParam().domain == AF_INET) {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallSucceedsWithValue(0));
  } else {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallFailsWithErrno(EINVAL));
  }
  int get = -1;
  socklen_t get_sz = 0;
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, 0);
  EXPECT_EQ(get, -1);
}

TEST_P(IPUnboundSocketTest, SmallTOSOptionSize) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0xC0;
  constexpr int kDefaultTOS = 0;
  TOSOption t = GetTOSOption(GetParam().domain);
  for (socklen_t i = 1; i < sizeof(int); i++) {
    int expect_tos;
    socklen_t expect_sz;
    if (GetParam().domain == AF_INET) {
      EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, i),
                  SyscallSucceedsWithValue(0));
      expect_tos = set;
      expect_sz = sizeof(uint8_t);
    } else {
      EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, i),
                  SyscallFailsWithErrno(EINVAL));
      expect_tos = kDefaultTOS;
      expect_sz = i;
    }
    uint get = -1;
    socklen_t get_sz = i;
    ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(get_sz, expect_sz);
    // Account for partial copies by getsockopt, retrieve the lower
    // bits specified by get_sz, while comparing against expect_tos.
    EXPECT_EQ(get & ~(~static_cast<uint>(0) << (get_sz * 8)), expect_tos);
  }
}

TEST_P(IPUnboundSocketTest, LargeTOSOptionSize) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = 0xC0;
  TOSOption t = GetTOSOption(GetParam().domain);
  for (socklen_t i = sizeof(int); i < 10; i++) {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, i),
                SyscallSucceedsWithValue(0));
    int get = -1;
    socklen_t get_sz = i;
    // We expect the system call handler to only copy atmost sizeof(int) bytes
    // as asserted by the check below. Hence, we do not expect the copy to
    // overflow in getsockopt.
    ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(get_sz, sizeof(int));
    EXPECT_EQ(get, set);
  }
}

TEST_P(IPUnboundSocketTest, NegativeTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int set = -1;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
              SyscallSucceedsWithValue(0));
  int expect;
  if (GetParam().domain == AF_INET) {
    expect = static_cast<uint8_t>(set);
    if (GetParam().protocol == IPPROTO_TCP) {
      expect &= ~INET_ECN_MASK;
    }
  } else {
    // On IPv6 TCLASS, setting -1 has the effect of resetting the
    // TrafficClass.
    expect = 0;
  }
  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, expect);
}

TEST_P(IPUnboundSocketTest, InvalidNegativeTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  int set = -2;
  socklen_t set_sz = sizeof(set);
  TOSOption t = GetTOSOption(GetParam().domain);
  int expect;
  if (GetParam().domain == AF_INET) {
    ASSERT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallSucceedsWithValue(0));
    expect = static_cast<uint8_t>(set);
    if (GetParam().protocol == IPPROTO_TCP) {
      expect &= ~INET_ECN_MASK;
    }
  } else {
    ASSERT_THAT(setsockopt(socket->get(), t.level, t.option, &set, set_sz),
                SyscallFailsWithErrno(EINVAL));
    expect = 0;
  }
  int get = 0;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(getsockopt(socket->get(), t.level, t.option, &get, &get_sz),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_sz, sizeof(get));
  EXPECT_EQ(get, expect);
}

TEST_P(IPUnboundSocketTest, NullTOS) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  TOSOption t = GetTOSOption(GetParam().domain);
  int set_sz = sizeof(int);
  if (GetParam().domain == AF_INET) {
    EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, nullptr, set_sz),
                SyscallFailsWithErrno(EFAULT));
  } else {  // AF_INET6
    // The AF_INET6 behavior is not yet compatible. gVisor will try to read
    // optval from user memory at syscall handler, it needs substantial
    // refactoring to implement this behavior just for IPv6.
    if (IsRunningOnGvisor()) {
      EXPECT_THAT(setsockopt(socket->get(), t.level, t.option, nullptr, set_sz),
                  SyscallFailsWithErrno(EFAULT));
    } else {
      // Linux's IPv6 stack treats nullptr optval as input of 0, so the call
      // succeeds. (net/ipv6/ipv6_sockglue.c, do_ipv6_setsockopt())
      //
      // Linux's implementation would need fixing as passing a nullptr as optval
      // and non-zero optlen may not be valid.
      // TODO(b/158666797): Combine the gVisor and linux cases for IPv6.
      // Some kernel versions return EFAULT, so we handle both.
      EXPECT_THAT(
          setsockopt(socket->get(), t.level, t.option, nullptr, set_sz),
          AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(0)));
    }
  }
  socklen_t get_sz = sizeof(int);
  EXPECT_THAT(getsockopt(socket->get(), t.level, t.option, nullptr, &get_sz),
              SyscallFailsWithErrno(EFAULT));
  int get = -1;
  EXPECT_THAT(getsockopt(socket->get(), t.level, t.option, &get, nullptr),
              SyscallFailsWithErrno(EFAULT));
}

TEST_P(IPUnboundSocketTest, InsufficientBufferTOS) {
  SKIP_IF(GetParam().protocol == IPPROTO_TCP);

  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  TOSOption t = GetTOSOption(GetParam().domain);

  in_addr addr4;
  in6_addr addr6;
  ASSERT_THAT(inet_pton(AF_INET, "127.0.0.1", &addr4), ::testing::Eq(1));
  ASSERT_THAT(inet_pton(AF_INET6, "fe80::", &addr6), ::testing::Eq(1));

  cmsghdr cmsg = {};
  cmsg.cmsg_len = sizeof(cmsg);
  cmsg.cmsg_level = t.cmsg_level;
  cmsg.cmsg_type = t.option;

  msghdr msg = {};
  msg.msg_control = &cmsg;
  msg.msg_controllen = sizeof(cmsg);
  if (GetParam().domain == AF_INET) {
    msg.msg_name = &addr4;
    msg.msg_namelen = sizeof(addr4);
  } else {
    msg.msg_name = &addr6;
    msg.msg_namelen = sizeof(addr6);
  }

  EXPECT_THAT(sendmsg(socket->get(), &msg, 0), SyscallFailsWithErrno(EINVAL));
}

TEST_P(IPUnboundSocketTest, ReuseAddrDefault) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket->get(), SOL_SOCKET, SO_REUSEADDR, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOff);
  EXPECT_EQ(get_sz, sizeof(get));
}

TEST_P(IPUnboundSocketTest, SetReuseAddr) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  ASSERT_THAT(setsockopt(socket->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  int get = -1;
  socklen_t get_sz = sizeof(get);
  ASSERT_THAT(
      getsockopt(socket->get(), SOL_SOCKET, SO_REUSEADDR, &get, &get_sz),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOn);
  EXPECT_EQ(get_sz, sizeof(get));
}

INSTANTIATE_TEST_SUITE_P(
    IPUnboundSockets, IPUnboundSocketTest,
    ::testing::ValuesIn(VecCat<SocketKind>(
        ApplyVec<SocketKind>(IPv4UDPUnboundSocket,
                             std::vector<int>{0, SOCK_NONBLOCK}),
        ApplyVec<SocketKind>(IPv6UDPUnboundSocket,
                             std::vector<int>{0, SOCK_NONBLOCK}),
        ApplyVec<SocketKind>(IPv4TCPUnboundSocket,
                             std::vector{0, SOCK_NONBLOCK}),
        ApplyVec<SocketKind>(IPv6TCPUnboundSocket,
                             std::vector{0, SOCK_NONBLOCK}))));

}  // namespace testing
}  // namespace gvisor
