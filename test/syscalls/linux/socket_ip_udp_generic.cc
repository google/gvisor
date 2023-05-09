// Copyright 2018 The gVisor Authors.
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

#include <errno.h>
#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/in6.h>
#endif  // __linux__
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(UDPSocketPairTest, MulticastTTLDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_TTL,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
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
  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &kSockOptOnChar, sizeof(kSockOptOnChar)),
              SyscallSucceeds());

  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IP, IP_MULTICAST_LOOP,
                         &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

TEST_P(UDPSocketPairTest, ReuseAddrDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(UDPSocketPairTest, SetReuseAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(UDPSocketPairTest, ReusePortDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(UDPSocketPairTest, SetReusePort) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT,
                         &kSockOptOff, sizeof(kSockOptOff)),
              SyscallSucceeds());

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

TEST_P(UDPSocketPairTest, SetReuseAddrReusePort) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT,
                         &kSockOptOn, sizeof(kSockOptOn)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEADDR, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_REUSEPORT, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

// Test getsockopt for a socket which is not set with IP_PKTINFO option.
TEST_P(UDPSocketPairTest, IPPKTINFODefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_IP, IP_PKTINFO, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

// Test setsockopt and getsockopt for a socket with IP_PKTINFO option.
TEST_P(UDPSocketPairTest, SetAndGetIPPKTINFO) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int level = SOL_IP;
  int type = IP_PKTINFO;

  // Check getsockopt before IP_PKTINFO is set.
  int get = -1;
  socklen_t get_len = sizeof(get);

  ASSERT_THAT(setsockopt(sockets->first_fd(), level, type, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(getsockopt(sockets->first_fd(), level, type, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOn);
  EXPECT_EQ(get_len, sizeof(get));

  ASSERT_THAT(setsockopt(sockets->first_fd(), level, type, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(getsockopt(sockets->first_fd(), level, type, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOff);
  EXPECT_EQ(get_len, sizeof(get));
}

// Test getsockopt for a socket which is not set with IP_RECVORIGDSTADDR option.
TEST_P(UDPSocketPairTest, ReceiveOrigDstAddrDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);
  int level = SOL_IP;
  int type = IP_RECVORIGDSTADDR;
  if (sockets->first_addr()->sa_family == AF_INET6) {
    level = SOL_IPV6;
    type = IPV6_RECVORIGDSTADDR;
  }
  ASSERT_THAT(getsockopt(sockets->first_fd(), level, type, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

// Test setsockopt and getsockopt for a socket with IP_RECVORIGDSTADDR option.
TEST_P(UDPSocketPairTest, SetAndGetReceiveOrigDstAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int level = SOL_IP;
  int type = IP_RECVORIGDSTADDR;
  if (sockets->first_addr()->sa_family == AF_INET6) {
    level = SOL_IPV6;
    type = IPV6_RECVORIGDSTADDR;
  }

  // Check getsockopt before IP_PKTINFO is set.
  int get = -1;
  socklen_t get_len = sizeof(get);

  ASSERT_THAT(setsockopt(sockets->first_fd(), level, type, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(getsockopt(sockets->first_fd(), level, type, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOn);
  EXPECT_EQ(get_len, sizeof(get));

  ASSERT_THAT(setsockopt(sockets->first_fd(), level, type, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(getsockopt(sockets->first_fd(), level, type, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get, kSockOptOff);
  EXPECT_EQ(get_len, sizeof(get));
}

// Holds TOS or TClass information for IPv4 or IPv6 respectively.
struct RecvTosOption {
  int level;
  int option;
};

RecvTosOption GetRecvTosOption(int domain) {
  TEST_CHECK(domain == AF_INET || domain == AF_INET6);
  RecvTosOption opt;
  switch (domain) {
    case AF_INET:
      opt.level = IPPROTO_IP;
      opt.option = IP_RECVTOS;
      break;
    case AF_INET6:
      opt.level = IPPROTO_IPV6;
      opt.option = IPV6_RECVTCLASS;
      break;
  }
  return opt;
}

// Ensure that Receiving TOS or TCLASS is off by default.
TEST_P(UDPSocketPairTest, RecvTosDefault) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  RecvTosOption t = GetRecvTosOption(GetParam().domain);
  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), t.level, t.option, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);
}

// Test that setting and getting IP_RECVTOS or IPV6_RECVTCLASS works as
// expected.
TEST_P(UDPSocketPairTest, SetRecvTos) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  RecvTosOption t = GetRecvTosOption(GetParam().domain);

  ASSERT_THAT(setsockopt(sockets->first_fd(), t.level, t.option, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), t.level, t.option, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOff);

  ASSERT_THAT(setsockopt(sockets->first_fd(), t.level, t.option, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), t.level, t.option, &get, &get_len),
      SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, kSockOptOn);
}

// Test that any socket (including IPv6 only) accepts the IPv4 TOS option: this
// mirrors behavior in linux.
TEST_P(UDPSocketPairTest, TOSRecvMismatch) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  RecvTosOption t = GetRecvTosOption(AF_INET);
  int get = -1;
  socklen_t get_len = sizeof(get);

  ASSERT_THAT(
      getsockopt(sockets->first_fd(), t.level, t.option, &get, &get_len),
      SyscallSucceedsWithValue(0));
}

// Test that an IPv4 socket does not support the IPv6 TClass option.
TEST_P(UDPSocketPairTest, TClassRecvMismatch) {
  // This should only test AF_INET6 sockets for the mismatch behavior.
  SKIP_IF(GetParam().domain != AF_INET6);
  // IPV6_RECVTCLASS is only valid for SOCK_DGRAM and SOCK_RAW.
  SKIP_IF((GetParam().type != SOCK_DGRAM) || (GetParam().type != SOCK_RAW));

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int get = -1;
  socklen_t get_len = sizeof(get);

  ASSERT_THAT(getsockopt(sockets->first_fd(), IPPROTO_IPV6, IPV6_RECVTCLASS,
                         &get, &get_len),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

// Test the SO_LINGER option can be set/get on udp socket.
TEST_P(UDPSocketPairTest, SetAndGetSocketLinger) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int level = SOL_SOCKET;
  int type = SO_LINGER;

  struct linger sl;
  sl.l_onoff = 1;
  sl.l_linger = 5;
  ASSERT_THAT(setsockopt(sockets->first_fd(), level, type, &sl, sizeof(sl)),
              SyscallSucceedsWithValue(0));

  struct linger got_linger = {};
  socklen_t length = sizeof(sl);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), level, type, &got_linger, &length),
      SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got_linger));
  EXPECT_EQ(0, memcmp(&sl, &got_linger, length));
}

// Test getsockopt for SO_ACCEPTCONN on udp socket.
TEST_P(UDPSocketPairTest, GetSocketAcceptConn) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int got = -1;
  socklen_t length = sizeof(got);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_ACCEPTCONN, &got, &length),
      SyscallSucceedsWithValue(0));

  ASSERT_EQ(length, sizeof(got));
  EXPECT_EQ(got, 0);
}

#ifdef __linux__
TEST_P(UDPSocketPairTest, PayloadTooBig) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set IP_RECVERR socket option to enable error queueing.
  int v = kSockOptOn;
  socklen_t optlen = sizeof(v);
  int opt_level = SOL_IP;
  int opt_type = IP_RECVERR;
  if (sockets->first_addr()->sa_family == AF_INET6) {
    opt_level = SOL_IPV6;
    opt_type = IPV6_RECVERR;
  }
  ASSERT_THAT(setsockopt(sockets->first_fd(), opt_level, opt_type, &v, optlen),
              SyscallSucceeds());

  // Buffers bigger than 0xffff should receive an error.
  const int kBufLen = 0x10000;
  char buf[kBufLen];
  RandomizeBuffer(buf, sizeof(buf));

  EXPECT_THAT(send(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EMSGSIZE));

  // Dequeue error using recvmsg(MSG_ERRQUEUE). Give a buffer big-enough for
  // the original message just in case.
  char got[kBufLen];
  struct iovec iov;
  iov.iov_base = reinterpret_cast<void*>(got);
  iov.iov_len = kBufLen;

  const int addrlen_ = sockets->second_addr_size();
  size_t control_buf_len = CMSG_SPACE(sizeof(sock_extended_err) + addrlen_);
  std::vector<char> control_buf(control_buf_len);
  struct sockaddr_storage remote;
  memset(&remote, 0, sizeof(remote));
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = control_buf.data();
  msg.msg_controllen = control_buf_len;
  msg.msg_name = reinterpret_cast<void*>(&remote);
  msg.msg_namelen = addrlen_;

  struct sockaddr_storage addr;
  optlen = sizeof(addr);
  EXPECT_THAT(getpeername(sockets->first_fd(), AsSockAddr(&addr), &optlen),
              SyscallSucceeds());
  bool ipv6 = false;
  if (addr.ss_family == AF_INET6) {
    auto ipv6addr = reinterpret_cast<struct sockaddr_in6*>(&addr);

    // Exclude IPv4-mapped addresses.
    uint8_t v4MappedPrefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    ipv6 = memcmp(&ipv6addr->sin6_addr.s6_addr[0], v4MappedPrefix,
                  sizeof(v4MappedPrefix)) != 0;
  }
  // Native behaviour for IPv4 packets is to not report to ERRQUEUE.
  if (!ipv6) {
    EXPECT_THAT(recvmsg(sockets->first_fd(), &msg, MSG_ERRQUEUE),
                SyscallFailsWithErrno(EAGAIN));
    return;
  }

  ASSERT_THAT(recvmsg(sockets->first_fd(), &msg, MSG_ERRQUEUE),
              SyscallSucceedsWithValue(0));

  EXPECT_NE(msg.msg_flags & MSG_ERRQUEUE, 0);
  EXPECT_EQ(memcmp(&remote, sockets->second_addr(), addrlen_), 0);

  // Check the contents of the control message.
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(CMSG_NXTHDR(&msg, cmsg), nullptr);
  EXPECT_EQ(cmsg->cmsg_level, opt_level);
  EXPECT_EQ(cmsg->cmsg_type, opt_type);
  EXPECT_EQ(cmsg->cmsg_len,
            sizeof(sock_extended_err) + addrlen_ + sizeof(cmsghdr));

  // Check the contents of socket error.
  struct sock_extended_err* sock_err =
      reinterpret_cast<sock_extended_err*>(CMSG_DATA(cmsg));
  EXPECT_EQ(sock_err->ee_errno, EMSGSIZE);
  EXPECT_EQ(sock_err->ee_origin, SO_EE_ORIGIN_LOCAL);
  EXPECT_EQ(sock_err->ee_type, ICMP_ECHOREPLY);
  EXPECT_EQ(sock_err->ee_code, ICMP_NET_UNREACH);
  EXPECT_EQ(sock_err->ee_info, kBufLen);
  EXPECT_EQ(sock_err->ee_data, 0);

  // Verify that no socket error was put on the queue.
  int err;
  optlen = sizeof(err);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_ERROR, &err, &optlen),
      SyscallSucceeds());
  ASSERT_EQ(err, 0);
  ASSERT_EQ(optlen, sizeof(err));
}
#endif  // __linux__

}  // namespace testing
}  // namespace gvisor
