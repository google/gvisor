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

#include "test/syscalls/linux/udp_socket_test_cases.h"

#include <arpa/inet.h>
#include <fcntl.h>
#ifndef __fuchsia__
#include <linux/filter.h>
#endif  // __fuchsia__
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "absl/strings/str_format.h"
#ifndef SIOCGSTAMP
#include <linux/sockios.h>
#endif

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

// Gets a pointer to the port component of the given address.
uint16_t* Port(struct sockaddr_storage* addr) {
  switch (addr->ss_family) {
    case AF_INET: {
      auto sin = reinterpret_cast<struct sockaddr_in*>(addr);
      return &sin->sin_port;
    }
    case AF_INET6: {
      auto sin6 = reinterpret_cast<struct sockaddr_in6*>(addr);
      return &sin6->sin6_port;
    }
  }

  return nullptr;
}

// Sets addr port to "port".
void SetPort(struct sockaddr_storage* addr, uint16_t port) {
  switch (addr->ss_family) {
    case AF_INET: {
      auto sin = reinterpret_cast<struct sockaddr_in*>(addr);
      sin->sin_port = port;
      break;
    }
    case AF_INET6: {
      auto sin6 = reinterpret_cast<struct sockaddr_in6*>(addr);
      sin6->sin6_port = port;
      break;
    }
  }
}

void UdpSocketTest::SetUp() {
  addrlen_ = GetAddrLength();

  bind_ =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetFamily(), SOCK_DGRAM, IPPROTO_UDP));
  memset(&bind_addr_storage_, 0, sizeof(bind_addr_storage_));
  bind_addr_ = reinterpret_cast<struct sockaddr*>(&bind_addr_storage_);

  sock_ =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetFamily(), SOCK_DGRAM, IPPROTO_UDP));
}

int UdpSocketTest::GetFamily() {
  if (GetParam() == AddressFamily::kIpv4) {
    return AF_INET;
  }
  return AF_INET6;
}

PosixError UdpSocketTest::BindLoopback() {
  bind_addr_storage_ = InetLoopbackAddr();
  struct sockaddr* bind_addr_ =
      reinterpret_cast<struct sockaddr*>(&bind_addr_storage_);
  return BindSocket(bind_.get(), bind_addr_);
}

PosixError UdpSocketTest::BindAny() {
  bind_addr_storage_ = InetAnyAddr();
  struct sockaddr* bind_addr_ =
      reinterpret_cast<struct sockaddr*>(&bind_addr_storage_);
  return BindSocket(bind_.get(), bind_addr_);
}

PosixError UdpSocketTest::BindSocket(int socket, struct sockaddr* addr) {
  socklen_t len = sizeof(bind_addr_storage_);

  // Bind, then check that we get the right address.
  RETURN_ERROR_IF_SYSCALL_FAIL(bind(socket, addr, addrlen_));

  RETURN_ERROR_IF_SYSCALL_FAIL(getsockname(socket, addr, &len));

  if (addrlen_ != len) {
    return PosixError(
        EINVAL,
        absl::StrFormat("getsockname len: %u expected: %u", len, addrlen_));
  }
  return PosixError(0);
}

socklen_t UdpSocketTest::GetAddrLength() {
  struct sockaddr_storage addr;
  if (GetFamily() == AF_INET) {
    auto sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    return sizeof(*sin);
  }

  auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
  return sizeof(*sin6);
}

sockaddr_storage UdpSocketTest::InetAnyAddr() {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  reinterpret_cast<struct sockaddr*>(&addr)->sa_family = GetFamily();

  if (GetFamily() == AF_INET) {
    auto sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    sin->sin_port = htons(0);
    return addr;
  }

  auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
  sin6->sin6_addr = IN6ADDR_ANY_INIT;
  sin6->sin6_port = htons(0);
  return addr;
}

sockaddr_storage UdpSocketTest::InetLoopbackAddr() {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  reinterpret_cast<struct sockaddr*>(&addr)->sa_family = GetFamily();

  if (GetFamily() == AF_INET) {
    auto sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(0);
    return addr;
  }
  auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
  sin6->sin6_addr = in6addr_loopback;
  sin6->sin6_port = htons(0);
  return addr;
}

void UdpSocketTest::Disconnect(int sockfd) {
  sockaddr_storage addr_storage = InetAnyAddr();
  sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  socklen_t addrlen = sizeof(addr_storage);

  addr->sa_family = AF_UNSPEC;
  ASSERT_THAT(connect(sockfd, addr, addrlen), SyscallSucceeds());

  // Check that after disconnect the socket is bound to the ANY address.
  EXPECT_THAT(getsockname(sockfd, addr, &addrlen), SyscallSucceeds());
  if (GetParam() == AddressFamily::kIpv4) {
    auto addr_out = reinterpret_cast<struct sockaddr_in*>(addr);
    EXPECT_EQ(addrlen, sizeof(*addr_out));
    EXPECT_EQ(addr_out->sin_addr.s_addr, htonl(INADDR_ANY));
  } else {
    auto addr_out = reinterpret_cast<struct sockaddr_in6*>(addr);
    EXPECT_EQ(addrlen, sizeof(*addr_out));
    struct in6_addr loopback = IN6ADDR_ANY_INIT;

    EXPECT_EQ(memcmp(&addr_out->sin6_addr, &loopback, sizeof(in6_addr)), 0);
  }
}

TEST_P(UdpSocketTest, Creation) {
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetFamily(), SOCK_DGRAM, IPPROTO_UDP));
  EXPECT_THAT(close(sock.release()), SyscallSucceeds());

  sock = ASSERT_NO_ERRNO_AND_VALUE(Socket(GetFamily(), SOCK_DGRAM, 0));
  EXPECT_THAT(close(sock.release()), SyscallSucceeds());

  ASSERT_THAT(socket(GetFamily(), SOCK_STREAM, IPPROTO_UDP), SyscallFails());
}

TEST_P(UdpSocketTest, Getsockname) {
  // Check that we're not bound.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getsockname(bind_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_EQ(memcmp(&addr, reinterpret_cast<struct sockaddr*>(&any), addrlen_),
            0);

  ASSERT_NO_ERRNO(BindLoopback());

  EXPECT_THAT(
      getsockname(bind_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, bind_addr_, addrlen_), 0);
}

TEST_P(UdpSocketTest, Getpeername) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Check that we're not connected.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallFailsWithErrno(ENOTCONN));

  // Connect, then check that we get the right address.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, bind_addr_, addrlen_), 0);
}

TEST_P(UdpSocketTest, SendNotConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Do send & write, they must fail.
  char buf[512];
  EXPECT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EDESTADDRREQ));

  EXPECT_THAT(write(sock_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EDESTADDRREQ));

  // Use sendto.
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Check that we're bound now.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr), 0);
}

TEST_P(UdpSocketTest, ConnectBinds) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect the socket.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Check that we're bound now.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr), 0);
}

TEST_P(UdpSocketTest, ReceiveNotBound) {
  char buf[512];
  EXPECT_THAT(recv(sock_.get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, Bind) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Try to bind again.
  EXPECT_THAT(bind(bind_.get(), bind_addr_, addrlen_),
              SyscallFailsWithErrno(EINVAL));

  // Check that we're still bound to the original address.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getsockname(bind_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, bind_addr_, addrlen_), 0);
}

TEST_P(UdpSocketTest, BindInUse) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Try to bind again.
  EXPECT_THAT(bind(sock_.get(), bind_addr_, addrlen_),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(UdpSocketTest, ReceiveAfterConnect) {
  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Send from sock_ to bind_
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[sizeof(buf)];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, ReceiveAfterDisconnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  for (int i = 0; i < 2; i++) {
    // Connet sock_ to bound address.
    ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    EXPECT_THAT(
        getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
        SyscallSucceeds());
    EXPECT_EQ(addrlen, addrlen_);

    // Send from sock to bind_.
    char buf[512];
    RandomizeBuffer(buf, sizeof(buf));

    ASSERT_THAT(sendto(bind_.get(), buf, sizeof(buf), 0,
                       reinterpret_cast<sockaddr*>(&addr), addrlen),
                SyscallSucceedsWithValue(sizeof(buf)));

    // Receive the data.
    char received[sizeof(buf)];
    EXPECT_THAT(recv(sock_.get(), received, sizeof(received), 0),
                SyscallSucceedsWithValue(sizeof(received)));
    EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);

    // Disconnect sock_.
    struct sockaddr unspec = {};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_THAT(connect(sock_.get(), &unspec, sizeof(unspec.sa_family)),
                SyscallSucceeds());
  }
}

TEST_P(UdpSocketTest, Connect) {
  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Check that we're connected to the right peer.
  struct sockaddr_storage peer;
  socklen_t peerlen = sizeof(peer);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&peer), &peerlen),
      SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, bind_addr_, addrlen_), 0);

  // Try to bind after connect.
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(
      bind(sock_.get(), reinterpret_cast<struct sockaddr*>(&any), addrlen_),
      SyscallFailsWithErrno(EINVAL));

  struct sockaddr_storage bind2_storage = InetLoopbackAddr();
  struct sockaddr* bind2_addr =
      reinterpret_cast<struct sockaddr*>(&bind2_storage);
  FileDescriptor bind2 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetFamily(), SOCK_DGRAM, IPPROTO_UDP));
  ASSERT_NO_ERRNO(BindSocket(bind2.get(), bind2_addr));

  // Try to connect again.
  EXPECT_THAT(connect(sock_.get(), bind2_addr, addrlen_), SyscallSucceeds());

  // Check that peer name changed.
  peerlen = sizeof(peer);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&peer), &peerlen),
      SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, bind2_addr, addrlen_), 0);
}

TEST_P(UdpSocketTest, ConnectAnyZero) {
  // TODO(138658473): Enable when we can connect to port 0 with gVisor.
  SKIP_IF(IsRunningOnGvisor());

  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(
      connect(sock_.get(), reinterpret_cast<struct sockaddr*>(&any), addrlen_),
      SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, ConnectAnyWithPort) {
  ASSERT_NO_ERRNO(BindAny());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());
}

TEST_P(UdpSocketTest, DisconnectAfterConnectAny) {
  // TODO(138658473): Enable when we can connect to port 0 with gVisor.
  SKIP_IF(IsRunningOnGvisor());
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(
      connect(sock_.get(), reinterpret_cast<struct sockaddr*>(&any), addrlen_),
      SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallFailsWithErrno(ENOTCONN));

  Disconnect(sock_.get());
}

TEST_P(UdpSocketTest, DisconnectAfterConnectAnyWithPort) {
  ASSERT_NO_ERRNO(BindAny());
  EXPECT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(*Port(&bind_addr_storage_), *Port(&addr));

  Disconnect(sock_.get());
}

TEST_P(UdpSocketTest, DisconnectAfterBind) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Bind to the next port above bind_.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect the socket.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage unspec = {};
  unspec.ss_family = AF_UNSPEC;
  EXPECT_THAT(connect(sock_.get(), reinterpret_cast<sockaddr*>(&unspec),
                      sizeof(unspec.ss_family)),
              SyscallSucceeds());

  // Check that we're still bound.
  socklen_t addrlen = sizeof(unspec);
  EXPECT_THAT(
      getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&unspec), &addrlen),
      SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(addr, &unspec, addrlen_), 0);

  addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), addr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, BindToAnyConnnectToLocalhost) {
  ASSERT_NO_ERRNO(BindAny());

  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  socklen_t addrlen = sizeof(addr);

  // Connect the socket.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  EXPECT_THAT(getsockname(bind_.get(), addr, &addrlen), SyscallSucceeds());

  // If the socket is bound to ANY and connected to a loopback address,
  // getsockname() has to return the loopback address.
  if (GetParam() == AddressFamily::kIpv4) {
    auto addr_out = reinterpret_cast<struct sockaddr_in*>(addr);
    EXPECT_EQ(addrlen, sizeof(*addr_out));
    EXPECT_EQ(addr_out->sin_addr.s_addr, htonl(INADDR_LOOPBACK));
  } else {
    auto addr_out = reinterpret_cast<struct sockaddr_in6*>(addr);
    struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
    EXPECT_EQ(addrlen, sizeof(*addr_out));
    EXPECT_EQ(memcmp(&addr_out->sin6_addr, &loopback, sizeof(in6_addr)), 0);
  }
}

TEST_P(UdpSocketTest, DisconnectAfterBindToAny) {
  ASSERT_NO_ERRNO(BindLoopback());

  struct sockaddr_storage any_storage = InetAnyAddr();
  struct sockaddr* any = reinterpret_cast<struct sockaddr*>(&any_storage);
  SetPort(&any_storage, *Port(&bind_addr_storage_) + 1);

  ASSERT_NO_ERRNO(BindSocket(sock_.get(), any));

  // Connect the socket.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  Disconnect(sock_.get());

  // Check that we're still bound.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(
      getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, any, addrlen), 0);

  addrlen = sizeof(addr);
  EXPECT_THAT(
      getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
      SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, Disconnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  struct sockaddr_storage any_storage = InetAnyAddr();
  struct sockaddr* any = reinterpret_cast<struct sockaddr*>(&any_storage);
  SetPort(&any_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), any));

  for (int i = 0; i < 2; i++) {
    // Try to connect again.
    EXPECT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

    // Check that we're connected to the right peer.
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    EXPECT_THAT(
        getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&peer), &peerlen),
        SyscallSucceeds());
    EXPECT_EQ(peerlen, addrlen_);
    EXPECT_EQ(memcmp(&peer, bind_addr_, addrlen_), 0);

    // Try to disconnect.
    struct sockaddr_storage addr = {};
    addr.ss_family = AF_UNSPEC;
    EXPECT_THAT(connect(sock_.get(), reinterpret_cast<sockaddr*>(&addr),
                        sizeof(addr.ss_family)),
                SyscallSucceeds());

    peerlen = sizeof(peer);
    EXPECT_THAT(
        getpeername(sock_.get(), reinterpret_cast<sockaddr*>(&peer), &peerlen),
        SyscallFailsWithErrno(ENOTCONN));

    // Check that we're still bound.
    socklen_t addrlen = sizeof(addr);
    EXPECT_THAT(
        getsockname(sock_.get(), reinterpret_cast<sockaddr*>(&addr), &addrlen),
        SyscallSucceeds());
    EXPECT_EQ(addrlen, addrlen_);
    EXPECT_EQ(*Port(&addr), *Port(&any_storage));
  }
}

TEST_P(UdpSocketTest, ConnectBadAddress) {
  struct sockaddr addr = {};
  addr.sa_family = GetFamily();
  ASSERT_THAT(connect(sock_.get(), &addr, sizeof(addr.sa_family)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UdpSocketTest, SendToAddressOtherThanConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  struct sockaddr_storage addr_storage = InetAnyAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);

  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Send to a different destination than we're connected to.
  char buf[512];
  EXPECT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, addr, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(UdpSocketTest, ZerolengthWriteAllowed) {
  // TODO(gvisor.dev/issue/1202): Hostinet does not support zero length writes.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  // Connect to loopback:bind_addr_+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind sock to loopback:bind_addr_+1.
  ASSERT_THAT(bind(sock_.get(), addr, addrlen_), SyscallSucceeds());

  char buf[3];
  // Send zero length packet from bind_ to sock_.
  ASSERT_THAT(write(bind_.get(), buf, 0), SyscallSucceedsWithValue(0));

  struct pollfd pfd = {sock_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout*/ 1000),
              SyscallSucceedsWithValue(1));

  // Receive the packet.
  char received[3];
  EXPECT_THAT(read(sock_.get(), received, sizeof(received)),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, ZerolengthWriteAllowedNonBlockRead) {
  // TODO(gvisor.dev/issue/1202): Hostinet does not support zero length writes.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind sock to loopback:bind_addr_port+1.
  ASSERT_THAT(bind(sock_.get(), addr, addrlen_), SyscallSucceeds());

  // Set sock to non-blocking.
  int opts = 0;
  ASSERT_THAT(opts = fcntl(sock_.get(), F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(sock_.get(), F_SETFL, opts | O_NONBLOCK),
              SyscallSucceeds());

  char buf[3];
  // Send zero length packet from bind_ to sock_.
  ASSERT_THAT(write(bind_.get(), buf, 0), SyscallSucceedsWithValue(0));

  struct pollfd pfd = {sock_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  // Receive the packet.
  char received[3];
  EXPECT_THAT(read(sock_.get(), received, sizeof(received)),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(read(sock_.get(), received, sizeof(received)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(UdpSocketTest, SendAndReceiveNotConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Send some data to bind_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[sizeof(buf)];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, SendAndReceiveConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind sock to loopback:TestPort+1.
  ASSERT_THAT(bind(sock_.get(), addr, addrlen_), SyscallSucceeds());

  // Send some data from sock to bind_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[sizeof(buf)];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, ReceiveFromNotConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind sock to loopback:bind_addr_port+2.
  struct sockaddr_storage addr2_storage = InetLoopbackAddr();
  struct sockaddr* addr2 = reinterpret_cast<struct sockaddr*>(&addr2_storage);
  SetPort(&addr2_storage, *Port(&bind_addr_storage_) + 2);
  ASSERT_THAT(bind(sock_.get(), addr2, addrlen_), SyscallSucceeds());

  // Send some data from sock to bind_.
  char buf[512];
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Check that the data isn't received because it was sent from a different
  // address than we're connected.
  EXPECT_THAT(recv(sock_.get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveBeforeConnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Bind sock to loopback:bind_addr_port+2.
  struct sockaddr_storage addr2_storage = InetLoopbackAddr();
  struct sockaddr* addr2 = reinterpret_cast<struct sockaddr*>(&addr2_storage);
  SetPort(&addr2_storage, *Port(&bind_addr_storage_) + 2);
  ASSERT_THAT(bind(sock_.get(), addr2, addrlen_), SyscallSucceeds());

  // Send some data from sock to bind_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Connect to loopback:TestPort+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Receive the data. It works because it was sent before the connect.
  char received[sizeof(buf)];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);

  // Send again. This time it should not be received.
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_THAT(recv(bind_.get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveFrom) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind sock to loopback:TestPort+1.
  ASSERT_THAT(bind(sock_.get(), addr, addrlen_), SyscallSucceeds());

  // Send some data from sock to bind_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data and sender address.
  char received[sizeof(buf)];
  struct sockaddr_storage addr2;
  socklen_t addr2len = sizeof(addr2);
  EXPECT_THAT(recvfrom(bind_.get(), received, sizeof(received), 0,
                       reinterpret_cast<sockaddr*>(&addr2), &addr2len),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
  EXPECT_EQ(addr2len, addrlen_);
  EXPECT_EQ(memcmp(addr, &addr2, addrlen_), 0);
}

TEST_P(UdpSocketTest, Listen) {
  ASSERT_THAT(listen(sock_.get(), SOMAXCONN),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST_P(UdpSocketTest, Accept) {
  ASSERT_THAT(accept(sock_.get(), nullptr, nullptr),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

// This test validates that a read shutdown with pending data allows the read
// to proceed with the data before returning EAGAIN.
TEST_P(UdpSocketTest, ReadShutdownNonblockPendingData) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Bind to loopback:bind_addr_port+1 and connect to bind_addr_.
  ASSERT_THAT(bind(sock_.get(), addr, addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Verify that we get EWOULDBLOCK when there is nothing to read.
  char received[512];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  const char* buf = "abc";
  EXPECT_THAT(write(sock_.get(), buf, 3), SyscallSucceedsWithValue(3));

  int opts = 0;
  ASSERT_THAT(opts = fcntl(bind_.get(), F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(bind_.get(), F_SETFL, opts | O_NONBLOCK),
              SyscallSucceeds());
  ASSERT_THAT(opts = fcntl(bind_.get(), F_GETFL), SyscallSucceeds());
  ASSERT_NE(opts & O_NONBLOCK, 0);

  EXPECT_THAT(shutdown(bind_.get(), SHUT_RD), SyscallSucceeds());

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  // We should get the data even though read has been shutdown.
  EXPECT_THAT(recv(bind_.get(), received, 2, 0), SyscallSucceedsWithValue(2));

  // Because we read less than the entire packet length, since it's a packet
  // based socket any subsequent reads should return EWOULDBLOCK.
  EXPECT_THAT(recv(bind_.get(), received, 1, 0),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

// This test is validating that even after a socket is shutdown if it's
// reconnected it will reset the shutdown state.
TEST_P(UdpSocketTest, ReadShutdownSameSocketResetsShutdownState) {
  char received[512];
  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(bind_.get(), SHUT_RD), SyscallFailsWithErrno(ENOTCONN));

  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then try to shutdown again.
  ASSERT_NO_ERRNO(BindLoopback());

  // Connect to loopback:bind_addr_port+1.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(bind_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReadShutdown) {
  // TODO(gvisor.dev/issue/1202): Calling recv() after shutdown without
  // MSG_DONTWAIT blocks indefinitely.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());

  char received[512];
  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(sock_.get(), SHUT_RD), SyscallFailsWithErrno(ENOTCONN));

  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then try to shutdown again.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(sock_.get(), SHUT_RD), SyscallSucceeds());

  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, ReadShutdownDifferentThread) {
  // TODO(gvisor.dev/issue/1202): Calling recv() after shutdown without
  // MSG_DONTWAIT blocks indefinitely.
  SKIP_IF(IsRunningWithHostinet());
  ASSERT_NO_ERRNO(BindLoopback());

  char received[512];
  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then shutdown from another thread.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(sock_.get(), received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  ScopedThread t([&] {
    absl::SleepFor(absl::Milliseconds(200));
    EXPECT_THAT(shutdown(sock_.get(), SHUT_RD), SyscallSucceeds());
  });
  EXPECT_THAT(RetryEINTR(recv)(sock_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
  t.Join();

  EXPECT_THAT(RetryEINTR(recv)(sock_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, WriteShutdown) {
  ASSERT_NO_ERRNO(BindLoopback());
  EXPECT_THAT(shutdown(sock_.get(), SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());
  EXPECT_THAT(shutdown(sock_.get(), SHUT_WR), SyscallSucceeds());
}

TEST_P(UdpSocketTest, SynchronousReceive) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Send some data to bind_ from another thread.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  // Receive the data prior to actually starting the other thread.
  char received[512];
  EXPECT_THAT(
      RetryEINTR(recv)(bind_.get(), received, sizeof(received), MSG_DONTWAIT),
      SyscallFailsWithErrno(EWOULDBLOCK));

  // Start the thread.
  ScopedThread t([&] {
    absl::SleepFor(absl::Milliseconds(200));
    ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, this->bind_addr_,
                       this->addrlen_),
                SyscallSucceedsWithValue(sizeof(buf)));
  });

  EXPECT_THAT(RetryEINTR(recv)(bind_.get(), received, sizeof(received), 0),
              SyscallSucceedsWithValue(512));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_SendRecv) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Send 3 packets from sock to bind_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(
        sendto(sock_.get(), buf + i * psize, psize, 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(psize));
  }

  // Receive the data as 3 separate packets.
  char received[6 * psize];
  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(recv(bind_.get(), received + i * psize, 3 * psize, 0),
                SyscallSucceedsWithValue(psize));
  }
  EXPECT_EQ(memcmp(buf, received, 3 * psize), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_WritevReadv) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Direct writes from sock to bind_.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Send 2 packets from sock to bind_, where each packet's data consists of
  // 2 discontiguous iovecs.
  constexpr size_t kPieceSize = 100;
  char buf[4 * kPieceSize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 2; i++) {
    struct iovec iov[2];
    for (int j = 0; j < 2; j++) {
      iov[j].iov_base = reinterpret_cast<void*>(
          reinterpret_cast<uintptr_t>(buf) + (i + 2 * j) * kPieceSize);
      iov[j].iov_len = kPieceSize;
    }
    ASSERT_THAT(writev(sock_.get(), iov, 2),
                SyscallSucceedsWithValue(2 * kPieceSize));
  }

  // Receive the data as 2 separate packets.
  char received[6 * kPieceSize];
  for (int i = 0; i < 2; i++) {
    struct iovec iov[3];
    for (int j = 0; j < 3; j++) {
      iov[j].iov_base = reinterpret_cast<void*>(
          reinterpret_cast<uintptr_t>(received) + (i + 2 * j) * kPieceSize);
      iov[j].iov_len = kPieceSize;
    }
    ASSERT_THAT(readv(bind_.get(), iov, 3),
                SyscallSucceedsWithValue(2 * kPieceSize));
  }
  EXPECT_EQ(memcmp(buf, received, 4 * kPieceSize), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_SendMsgRecvMsg) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Send 2 packets from sock to bind_, where each packet's data consists of
  // 2 discontiguous iovecs.
  constexpr size_t kPieceSize = 100;
  char buf[4 * kPieceSize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 2; i++) {
    struct iovec iov[2];
    for (int j = 0; j < 2; j++) {
      iov[j].iov_base = reinterpret_cast<void*>(
          reinterpret_cast<uintptr_t>(buf) + (i + 2 * j) * kPieceSize);
      iov[j].iov_len = kPieceSize;
    }
    struct msghdr msg = {};
    msg.msg_name = bind_addr_;
    msg.msg_namelen = addrlen_;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    ASSERT_THAT(sendmsg(sock_.get(), &msg, 0),
                SyscallSucceedsWithValue(2 * kPieceSize));
  }

  // Receive the data as 2 separate packets.
  char received[6 * kPieceSize];
  for (int i = 0; i < 2; i++) {
    struct iovec iov[3];
    for (int j = 0; j < 3; j++) {
      iov[j].iov_base = reinterpret_cast<void*>(
          reinterpret_cast<uintptr_t>(received) + (i + 2 * j) * kPieceSize);
      iov[j].iov_len = kPieceSize;
    }
    struct msghdr msg = {};
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;
    ASSERT_THAT(recvmsg(bind_.get(), &msg, 0),
                SyscallSucceedsWithValue(2 * kPieceSize));
  }
  EXPECT_EQ(memcmp(buf, received, 4 * kPieceSize), 0);
}

TEST_P(UdpSocketTest, FIONREADShutdown) {
  ASSERT_NO_ERRNO(BindLoopback());

  int n = -1;
  EXPECT_THAT(ioctl(sock_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(sock_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  EXPECT_THAT(shutdown(sock_.get(), SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(sock_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
}

TEST_P(UdpSocketTest, FIONREADWriteShutdown) {
  int n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  ASSERT_NO_ERRNO(BindLoopback());

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(bind_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  const char str[] = "abc";
  ASSERT_THAT(send(bind_.get(), str, sizeof(str), 0),
              SyscallSucceedsWithValue(sizeof(str)));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(str));

  EXPECT_THAT(shutdown(bind_.get(), SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(str));
}

// NOTE: Do not use `FIONREAD` as test name because it will be replaced by the
// corresponding macro and become `0x541B`.
TEST_P(UdpSocketTest, Fionread) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Check that the bound socket with an empty buffer reports an empty first
  // packet.
  int n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Send 3 packets from sock to bind_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(
        sendto(sock_.get(), buf + i * psize, psize, 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(psize));

    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
                SyscallSucceedsWithValue(1));

    // Check that regardless of how many packets are in the queue, the size
    // reported is that of a single packet.
    n = -1;
    EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
    EXPECT_EQ(n, psize);
  }
}

TEST_P(UdpSocketTest, FIONREADZeroLengthPacket) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Check that the bound socket with an empty buffer reports an empty first
  // packet.
  int n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Send 3 packets from sock to bind_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(
        sendto(sock_.get(), buf + i * psize, 0, 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(0));

    // TODO(gvisor.dev/issue/2726): sending a zero-length message to a hostinet
    // socket does not cause a poll event to be triggered.
    if (!IsRunningWithHostinet()) {
      ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
                  SyscallSucceedsWithValue(1));
    }

    // Check that regardless of how many packets are in the queue, the size
    // reported is that of a single packet.
    n = -1;
    EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
    EXPECT_EQ(n, 0);
  }
}

TEST_P(UdpSocketTest, FIONREADZeroLengthWriteShutdown) {
  int n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  ASSERT_NO_ERRNO(BindLoopback());

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(bind_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  const char str[] = "abc";
  ASSERT_THAT(send(bind_.get(), str, 0, 0), SyscallSucceedsWithValue(0));

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  EXPECT_THAT(shutdown(bind_.get(), SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(bind_.get(), FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
}

TEST_P(UdpSocketTest, SoNoCheckOffByDefault) {
  // TODO(gvisor.dev/issue/1202): SO_NO_CHECK socket option not supported by
  // hostinet.
  SKIP_IF(IsRunningWithHostinet());

  int v = -1;
  socklen_t optlen = sizeof(v);
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_NO_CHECK, &v, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(v, kSockOptOff);
  ASSERT_EQ(optlen, sizeof(v));
}

TEST_P(UdpSocketTest, SoNoCheck) {
  // TODO(gvisor.dev/issue/1202): SO_NO_CHECK socket option not supported by
  // hostinet.
  SKIP_IF(IsRunningWithHostinet());

  int v = kSockOptOn;
  socklen_t optlen = sizeof(v);
  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_NO_CHECK, &v, optlen),
              SyscallSucceeds());
  v = -1;
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_NO_CHECK, &v, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(v, kSockOptOn);
  ASSERT_EQ(optlen, sizeof(v));

  v = kSockOptOff;
  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_NO_CHECK, &v, optlen),
              SyscallSucceeds());
  v = -1;
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_NO_CHECK, &v, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(v, kSockOptOff);
  ASSERT_EQ(optlen, sizeof(v));
}

TEST_P(UdpSocketTest, SoTimestampOffByDefault) {
  // TODO(gvisor.dev/issue/1202): SO_TIMESTAMP socket option not supported by
  // hostinet.
  SKIP_IF(IsRunningWithHostinet());

  int v = -1;
  socklen_t optlen = sizeof(v);
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_TIMESTAMP, &v, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(v, kSockOptOff);
  ASSERT_EQ(optlen, sizeof(v));
}

TEST_P(UdpSocketTest, SoTimestamp) {
  // TODO(gvisor.dev/issue/1202): ioctl() and SO_TIMESTAMP socket option are not
  // supported by hostinet.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  int v = 1;
  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_TIMESTAMP, &v, sizeof(v)),
              SyscallSucceeds());

  char buf[3];
  // Send zero length packet from sock to bind_.
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, 0),
              SyscallSucceedsWithValue(0));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  char cmsgbuf[CMSG_SPACE(sizeof(struct timeval))];
  msghdr msg;
  memset(&msg, 0, sizeof(msg));
  iovec iov;
  memset(&iov, 0, sizeof(iov));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  ASSERT_THAT(RetryEINTR(recvmsg)(bind_.get(), &msg, 0),
              SyscallSucceedsWithValue(0));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SO_TIMESTAMP);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(struct timeval)));

  struct timeval tv = {};
  memcpy(&tv, CMSG_DATA(cmsg), sizeof(struct timeval));

  ASSERT_TRUE(tv.tv_sec != 0 || tv.tv_usec != 0);

  // There should be nothing to get via ioctl.
  ASSERT_THAT(ioctl(bind_.get(), SIOCGSTAMP, &tv),
              SyscallFailsWithErrno(ENOENT));
}

TEST_P(UdpSocketTest, WriteShutdownNotConnected) {
  EXPECT_THAT(shutdown(bind_.get(), SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, TimestampIoctl) {
  // TODO(gvisor.dev/issue/1202): ioctl() is not supported by hostinet.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  char buf[3];
  // Send packet from sock to bind_.
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  // There should be no control messages.
  char recv_buf[sizeof(buf)];
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(bind_.get(), recv_buf, sizeof(recv_buf)));

  // A nonzero timeval should be available via ioctl.
  struct timeval tv = {};
  ASSERT_THAT(ioctl(bind_.get(), SIOCGSTAMP, &tv), SyscallSucceeds());
  ASSERT_TRUE(tv.tv_sec != 0 || tv.tv_usec != 0);
}

TEST_P(UdpSocketTest, TimestampIoctlNothingRead) {
  // TODO(gvisor.dev/issue/1202): ioctl() is not supported by hostinet.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct timeval tv = {};
  ASSERT_THAT(ioctl(sock_.get(), SIOCGSTAMP, &tv),
              SyscallFailsWithErrno(ENOENT));
}

// Test that the timestamp accessed via SIOCGSTAMP is still accessible after
// SO_TIMESTAMP is enabled and used to retrieve a timestamp.
TEST_P(UdpSocketTest, TimestampIoctlPersistence) {
  // TODO(gvisor.dev/issue/1202): ioctl() and SO_TIMESTAMP socket option are not
  // supported by hostinet.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  char buf[3];
  // Send packet from sock to bind_.
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, 0),
              SyscallSucceedsWithValue(0));

  struct pollfd pfd = {bind_.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  // There should be no control messages.
  char recv_buf[sizeof(buf)];
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(bind_.get(), recv_buf, sizeof(recv_buf)));

  // A nonzero timeval should be available via ioctl.
  struct timeval tv = {};
  ASSERT_THAT(ioctl(bind_.get(), SIOCGSTAMP, &tv), SyscallSucceeds());
  ASSERT_TRUE(tv.tv_sec != 0 || tv.tv_usec != 0);

  // Enable SO_TIMESTAMP and send a message.
  int v = 1;
  EXPECT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_TIMESTAMP, &v, sizeof(v)),
              SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, 0),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
              SyscallSucceedsWithValue(1));

  // There should be a message for SO_TIMESTAMP.
  char cmsgbuf[CMSG_SPACE(sizeof(struct timeval))];
  msghdr msg = {};
  iovec iov = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  ASSERT_THAT(RetryEINTR(recvmsg)(bind_.get(), &msg, 0),
              SyscallSucceedsWithValue(0));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);

  // The ioctl should return the exact same values as before.
  struct timeval tv2 = {};
  ASSERT_THAT(ioctl(bind_.get(), SIOCGSTAMP, &tv2), SyscallSucceeds());
  ASSERT_EQ(tv.tv_sec, tv2.tv_sec);
  ASSERT_EQ(tv.tv_usec, tv2.tv_usec);
}

// Test that a socket with IP_TOS or IPV6_TCLASS set will set the TOS byte on
// outgoing packets, and that a receiving socket with IP_RECVTOS or
// IPV6_RECVTCLASS will create the corresponding control message.
TEST_P(UdpSocketTest, SetAndReceiveTOS) {
  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Allow socket to receive control message.
  int recv_level = SOL_IP;
  int recv_type = IP_RECVTOS;
  if (GetParam() != AddressFamily::kIpv4) {
    recv_level = SOL_IPV6;
    recv_type = IPV6_RECVTCLASS;
  }
  ASSERT_THAT(setsockopt(bind_.get(), recv_level, recv_type, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  // Set socket TOS.
  int sent_level = recv_level;
  int sent_type = IP_TOS;
  if (sent_level == SOL_IPV6) {
    sent_type = IPV6_TCLASS;
  }
  int sent_tos = IPTOS_LOWDELAY;  // Choose some TOS value.
  ASSERT_THAT(setsockopt(sock_.get(), sent_level, sent_type, &sent_tos,
                         sizeof(sent_tos)),
              SyscallSucceeds());

  // Prepare message to send.
  constexpr size_t kDataLength = 1024;
  struct msghdr sent_msg = {};
  struct iovec sent_iov = {};
  char sent_data[kDataLength];
  sent_iov.iov_base = &sent_data[0];
  sent_iov.iov_len = kDataLength;
  sent_msg.msg_iov = &sent_iov;
  sent_msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(sock_.get(), &sent_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  // Receive message.
  struct msghdr received_msg = {};
  struct iovec received_iov = {};
  char received_data[kDataLength];
  received_iov.iov_base = &received_data[0];
  received_iov.iov_len = kDataLength;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;
  size_t cmsg_data_len = sizeof(int8_t);
  if (sent_type == IPV6_TCLASS) {
    cmsg_data_len = sizeof(int);
  }
  std::vector<char> received_cmsgbuf(CMSG_SPACE(cmsg_data_len));
  received_msg.msg_control = &received_cmsgbuf[0];
  received_msg.msg_controllen = received_cmsgbuf.size();
  ASSERT_THAT(RetryEINTR(recvmsg)(bind_.get(), &received_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&received_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, sent_level);
  EXPECT_EQ(cmsg->cmsg_type, sent_type);
  int8_t received_tos = 0;
  memcpy(&received_tos, CMSG_DATA(cmsg), sizeof(received_tos));
  EXPECT_EQ(received_tos, sent_tos);
}

// Test that sendmsg with IP_TOS and IPV6_TCLASS control messages will set the
// TOS byte on outgoing packets, and that a receiving socket with IP_RECVTOS or
// IPV6_RECVTCLASS will create the corresponding control message.
TEST_P(UdpSocketTest, SendAndReceiveTOS) {
  // TODO(b/146661005): Setting TOS via cmsg not supported for netstack.
  SKIP_IF(IsRunningOnGvisor() && !IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Allow socket to receive control message.
  int recv_level = SOL_IP;
  int recv_type = IP_RECVTOS;
  if (GetParam() != AddressFamily::kIpv4) {
    recv_level = SOL_IPV6;
    recv_type = IPV6_RECVTCLASS;
  }
  int recv_opt = kSockOptOn;
  ASSERT_THAT(setsockopt(bind_.get(), recv_level, recv_type, &recv_opt,
                         sizeof(recv_opt)),
              SyscallSucceeds());

  // Prepare message to send.
  constexpr size_t kDataLength = 1024;
  int sent_level = recv_level;
  int sent_type = IP_TOS;
  int sent_tos = IPTOS_LOWDELAY;  // Choose some TOS value.

  struct msghdr sent_msg = {};
  struct iovec sent_iov = {};
  char sent_data[kDataLength];
  sent_iov.iov_base = &sent_data[0];
  sent_iov.iov_len = kDataLength;
  sent_msg.msg_iov = &sent_iov;
  sent_msg.msg_iovlen = 1;
  size_t cmsg_data_len = sizeof(int8_t);
  if (sent_level == SOL_IPV6) {
    sent_type = IPV6_TCLASS;
    cmsg_data_len = sizeof(int);
  }
  std::vector<char> sent_cmsgbuf(CMSG_SPACE(cmsg_data_len));
  sent_msg.msg_control = &sent_cmsgbuf[0];
  sent_msg.msg_controllen = CMSG_LEN(cmsg_data_len);

  // Manually add control message.
  struct cmsghdr* sent_cmsg = CMSG_FIRSTHDR(&sent_msg);
  sent_cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
  sent_cmsg->cmsg_level = sent_level;
  sent_cmsg->cmsg_type = sent_type;
  *(int8_t*)CMSG_DATA(sent_cmsg) = sent_tos;

  ASSERT_THAT(RetryEINTR(sendmsg)(sock_.get(), &sent_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  // Receive message.
  struct msghdr received_msg = {};
  struct iovec received_iov = {};
  char received_data[kDataLength];
  received_iov.iov_base = &received_data[0];
  received_iov.iov_len = kDataLength;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;
  std::vector<char> received_cmsgbuf(CMSG_SPACE(cmsg_data_len));
  received_msg.msg_control = &received_cmsgbuf[0];
  received_msg.msg_controllen = CMSG_LEN(cmsg_data_len);
  ASSERT_THAT(RetryEINTR(recvmsg)(bind_.get(), &received_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&received_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, sent_level);
  EXPECT_EQ(cmsg->cmsg_type, sent_type);
  int8_t received_tos = 0;
  memcpy(&received_tos, CMSG_DATA(cmsg), sizeof(received_tos));
  EXPECT_EQ(received_tos, sent_tos);
}

TEST_P(UdpSocketTest, RecvBufLimitsEmptyRcvBuf) {
  // Discover minimum buffer size by setting it to zero.
  constexpr int kRcvBufSz = 0;
  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                         sizeof(kRcvBufSz)),
              SyscallSucceeds());

  int min = 0;
  socklen_t min_len = sizeof(min);
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &min, &min_len),
              SyscallSucceeds());

  // Bind bind_ to loopback.
  ASSERT_NO_ERRNO(BindLoopback());

  {
    // Send data of size min and verify that it's received.
    std::vector<char> buf(min);
    RandomizeBuffer(buf.data(), buf.size());
    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));
    std::vector<char> received(buf.size());
    EXPECT_THAT(
        recv(bind_.get(), received.data(), received.size(), MSG_DONTWAIT),
        SyscallSucceedsWithValue(received.size()));
  }

  {
    // Send data of size min + 1 and verify that its received. Both linux and
    // Netstack accept a dgram that exceeds rcvBuf limits if the receive buffer
    // is currently empty.
    std::vector<char> buf(min + 1);
    RandomizeBuffer(buf.data(), buf.size());
    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));

    std::vector<char> received(buf.size());
    EXPECT_THAT(
        recv(bind_.get(), received.data(), received.size(), MSG_DONTWAIT),
        SyscallSucceedsWithValue(received.size()));
  }
}

// Test that receive buffer limits are enforced.
TEST_P(UdpSocketTest, RecvBufLimits) {
  // Bind s_ to loopback.
  ASSERT_NO_ERRNO(BindLoopback());

  int min = 0;
  {
    // Discover minimum buffer size by trying to set it to zero.
    constexpr int kRcvBufSz = 0;
    ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &kRcvBufSz,
                           sizeof(kRcvBufSz)),
                SyscallSucceeds());

    socklen_t min_len = sizeof(min);
    ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &min, &min_len),
                SyscallSucceeds());
  }

  // Now set the limit to min * 4.
  int new_rcv_buf_sz = min * 4;
  if (!IsRunningOnGvisor() || IsRunningWithHostinet()) {
    // Linux doubles the value specified so just set to min * 2.
    new_rcv_buf_sz = min * 2;
  }

  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &new_rcv_buf_sz,
                         sizeof(new_rcv_buf_sz)),
              SyscallSucceeds());
  int rcv_buf_sz = 0;
  {
    socklen_t rcv_buf_len = sizeof(rcv_buf_sz);
    ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_RCVBUF, &rcv_buf_sz,
                           &rcv_buf_len),
                SyscallSucceeds());
  }

  {
    std::vector<char> buf(min);
    RandomizeBuffer(buf.data(), buf.size());

    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));
    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));
    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));
    ASSERT_THAT(
        sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
        SyscallSucceedsWithValue(buf.size()));
    int sent = 4;
    if (IsRunningOnGvisor() && !IsRunningWithHostinet()) {
      // Linux seems to drop the 4th packet even though technically it should
      // fit in the receive buffer.
      ASSERT_THAT(
          sendto(sock_.get(), buf.data(), buf.size(), 0, bind_addr_, addrlen_),
          SyscallSucceedsWithValue(buf.size()));
      sent++;
    }

    for (int i = 0; i < sent - 1; i++) {
      // Receive the data.
      std::vector<char> received(buf.size());
      EXPECT_THAT(
          recv(bind_.get(), received.data(), received.size(), MSG_DONTWAIT),
          SyscallSucceedsWithValue(received.size()));
      EXPECT_EQ(memcmp(buf.data(), received.data(), buf.size()), 0);
    }

    // The last receive should fail with EAGAIN as the last packet should have
    // been dropped due to lack of space in the receive buffer.
    std::vector<char> received(buf.size());
    EXPECT_THAT(
        recv(bind_.get(), received.data(), received.size(), MSG_DONTWAIT),
        SyscallFailsWithErrno(EAGAIN));
  }
}

#ifndef __fuchsia__

// TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
// gVisor currently silently ignores attaching a filter.
TEST_P(UdpSocketTest, SetSocketDetachFilter) {
  // Program generated using sudo tcpdump -i lo udp and port 1234 -dd
  struct sock_filter code[] = {
      {0x28, 0, 0, 0x0000000c},  {0x15, 0, 6, 0x000086dd},
      {0x30, 0, 0, 0x00000014},  {0x15, 0, 15, 0x00000011},
      {0x28, 0, 0, 0x00000036},  {0x15, 12, 0, 0x000004d2},
      {0x28, 0, 0, 0x00000038},  {0x15, 10, 11, 0x000004d2},
      {0x15, 0, 10, 0x00000800}, {0x30, 0, 0, 0x00000017},
      {0x15, 0, 8, 0x00000011},  {0x28, 0, 0, 0x00000014},
      {0x45, 6, 0, 0x00001fff},  {0xb1, 0, 0, 0x0000000e},
      {0x48, 0, 0, 0x0000000e},  {0x15, 2, 0, 0x000004d2},
      {0x48, 0, 0, 0x00000010},  {0x15, 0, 1, 0x000004d2},
      {0x6, 0, 0, 0x00040000},   {0x6, 0, 0, 0x00000000},
  };
  struct sock_fprog bpf = {
      .len = ABSL_ARRAYSIZE(code),
      .filter = code,
  };
  ASSERT_THAT(
      setsockopt(sock_.get(), SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)),
      SyscallSucceeds());

  constexpr int val = 0;
  ASSERT_THAT(
      setsockopt(sock_.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
      SyscallSucceeds());
}

TEST_P(UdpSocketTest, SetSocketDetachFilterNoInstalledFilter) {
  // TODO(gvisor.dev/2746): Support SO_ATTACH_FILTER/SO_DETACH_FILTER.
  SKIP_IF(IsRunningOnGvisor());
  constexpr int val = 0;
  ASSERT_THAT(
      setsockopt(sock_.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)),
      SyscallFailsWithErrno(ENOENT));
}

TEST_P(UdpSocketTest, GetSocketDetachFilter) {
  int val = 0;
  socklen_t val_len = sizeof(val);
  ASSERT_THAT(
      getsockopt(sock_.get(), SOL_SOCKET, SO_DETACH_FILTER, &val, &val_len),
      SyscallFailsWithErrno(ENOPROTOOPT));
}

#endif  // __fuchsia__

}  // namespace testing
}  // namespace gvisor
