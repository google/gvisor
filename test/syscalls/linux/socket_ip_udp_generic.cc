// Copyright 2018 Google LLC
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

#include "test/syscalls/linux/socket_ip_udp_generic.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(UDPSocketPairTest, MulticastTTLDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 1);
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLMin) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kMin = 0;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kMin, sizeof(kMin)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kMin);
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kMax = 255;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kMax, sizeof(kMax)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kMax);
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLNegativeOne) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kArbitrary = 6;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kArbitrary, sizeof(kArbitrary)),
              SyscallSucceeds());

  constexpr int kNegOne = -1;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kNegOne, sizeof(kNegOne)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 1);
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLBelowMin) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kBelowMin = -2;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kBelowMin, sizeof(kBelowMin)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLAboveMax) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr int kAboveMax = 256;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kAboveMax, sizeof(kAboveMax)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UDPSocketPairTest, SetUDPMulticastTTLChar) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr char kArbitrary = 6;
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &kArbitrary, sizeof(kArbitrary)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kArbitrary);
}

TEST_P(UDPSocketPairTest, SetEmptyIPAddMembership) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct ip_mreqn req = {};
  EXPECT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &req, sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UDPSocketPairTest, MulticastLoopDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(UDPSocketPairTest, SetMulticastLoop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(UDPSocketPairTest, SetMulticastLoopChar) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  constexpr char kSockOptOnChar = kSockOptOn;
  constexpr char kSockOptOffChar = kSockOptOff;

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOffChar, sizeof(kSockOptOffChar)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOnChar, sizeof(kSockOptOnChar)),
              SyscallSucceeds());

  EXPECT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

}  // namespace testing
}  // namespace gvisor
