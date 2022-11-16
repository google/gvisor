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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include <ctime>
#include <utility>
#include <vector>

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/filter.h>
#endif  // __linux__
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
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr size_t kIcmpTimeout = 2000;

// Fixture for tests parameterized by the address family to use (AF_INET and
// AF_INET6) when creating sockets.
class UdpSocketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates two sockets that will be used by test cases.
  void SetUp() override;

  // Binds the socket bind_ to the loopback and updates bind_addr_.
  PosixError BindLoopback();

  // Binds the socket bind_ to Any and updates bind_addr_.
  PosixError BindAny();

  // Binds given socket to address addr and updates.
  PosixError BindSocket(int socket, struct sockaddr* addr);

  // Return initialized Any address to port 0.
  struct sockaddr_storage InetAnyAddr();

  // Return initialized Loopback address to port 0.
  struct sockaddr_storage InetLoopbackAddr();

  // Disconnects socket sockfd.
  void Disconnect(int sockfd);

  // Socket used by Bind methods
  FileDescriptor bind_;

  // Second socket used for tests.
  FileDescriptor sock_;

  // Address for bind_ socket.
  struct sockaddr* bind_addr_;

  // Initialized to the length based on GetParam().
  socklen_t addrlen_;

  // Storage for bind_addr_.
  struct sockaddr_storage bind_addr_storage_;

 private:
  // Helper to initialize addrlen_ for the test case.
  socklen_t GetAddrLength();
};

// Blocks until POLLIN is signaled on fd.
void BlockUntilPollin(int fd) {
  constexpr int kInfiniteTimeout = -1;
  pollfd pfd = {
      .fd = fd,
      .events = POLLIN,
  };
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kInfiniteTimeout),
              SyscallSucceedsWithValue(1));
  ASSERT_EQ(pfd.revents, POLLIN);
}

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
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
  memset(&bind_addr_storage_, 0, sizeof(bind_addr_storage_));
  bind_addr_ = AsSockAddr(&bind_addr_storage_);

  sock_ =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
}

PosixError UdpSocketTest::BindLoopback() {
  bind_addr_storage_ = InetLoopbackAddr();
  struct sockaddr* bind_addr_ = AsSockAddr(&bind_addr_storage_);
  return BindSocket(bind_.get(), bind_addr_);
}

PosixError UdpSocketTest::BindAny() {
  bind_addr_storage_ = InetAnyAddr();
  struct sockaddr* bind_addr_ = AsSockAddr(&bind_addr_storage_);
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
  if (GetParam() == AF_INET) {
    auto sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    return sizeof(*sin);
  }

  auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
  return sizeof(*sin6);
}

sockaddr_storage UdpSocketTest::InetAnyAddr() {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  AsSockAddr(&addr)->sa_family = GetParam();

  if (GetParam() == AF_INET) {
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
  AsSockAddr(&addr)->sa_family = GetParam();

  if (GetParam() == AF_INET) {
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
  sockaddr* addr = AsSockAddr(&addr_storage);
  socklen_t addrlen = sizeof(addr_storage);

  addr->sa_family = AF_UNSPEC;
  ASSERT_THAT(connect(sockfd, addr, addrlen), SyscallSucceeds());

  // Check that after disconnect the socket is bound to the ANY address.
  EXPECT_THAT(getsockname(sockfd, addr, &addrlen), SyscallSucceeds());
  if (GetParam() == AF_INET) {
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
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
  EXPECT_THAT(close(sock.release()), SyscallSucceeds());

  sock = ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, 0));
  EXPECT_THAT(close(sock.release()), SyscallSucceeds());

  ASSERT_THAT(socket(GetParam(), SOCK_STREAM, IPPROTO_UDP), SyscallFails());
}

TEST_P(UdpSocketTest, Getsockname) {
  // Check that we're not bound.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(bind_.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_EQ(memcmp(&addr, AsSockAddr(&any), addrlen_), 0);

  ASSERT_NO_ERRNO(BindLoopback());

  EXPECT_THAT(getsockname(bind_.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, bind_addr_, addrlen_), 0);
}

TEST_P(UdpSocketTest, Getpeername) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Check that we're not connected.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));

  // Connect, then check that we get the right address.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
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
  EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &addrlen),
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
  EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &addrlen),
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
  EXPECT_THAT(getsockname(bind_.get(), AsSockAddr(&addr), &addrlen),
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

TEST_P(UdpSocketTest, ConnectWriteToInvalidPort) {
  // Discover a free unused port by creating a new UDP socket, binding it
  // recording the just bound port and closing it. This is not guaranteed as it
  // can still race with other port UDP sockets trying to bind a port at the
  // same time.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  socklen_t addrlen = sizeof(addr_storage);
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
  ASSERT_THAT(bind(s.get(), addr, addrlen), SyscallSucceeds());
  ASSERT_THAT(getsockname(s.get(), addr, &addrlen), SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr_storage), 0);
  ASSERT_THAT(close(s.release()), SyscallSucceeds());

  // Now connect to the port that we just released. This should generate an
  // ECONNREFUSED error.
  ASSERT_THAT(connect(sock_.get(), addr, addrlen_), SyscallSucceeds());
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));
  // Send from sock_ to an unbound port.
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, addr, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Poll to make sure we get the ICMP error back.
  struct pollfd pfd = {sock_.get(), POLLERR, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kIcmpTimeout),
              SyscallSucceedsWithValue(1));

  // Now verify that we got an ICMP error back of ECONNREFUSED.
  int err;
  socklen_t optlen = sizeof(err);
  ASSERT_THAT(getsockopt(sock_.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(err, ECONNREFUSED);
  ASSERT_EQ(optlen, sizeof(err));
}

TEST_P(UdpSocketTest, ConnectSimultaneousWriteToInvalidPort) {
  // Discover a free unused port by creating a new UDP socket, binding it
  // recording the just bound port and closing it. This is not guaranteed as it
  // can still race with other port UDP sockets trying to bind a port at the
  // same time.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  socklen_t addrlen = sizeof(addr_storage);
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  FileDescriptor s =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
  ASSERT_THAT(bind(s.get(), addr, addrlen), SyscallSucceeds());
  ASSERT_THAT(getsockname(s.get(), addr, &addrlen), SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr_storage), 0);
  ASSERT_THAT(close(s.release()), SyscallSucceeds());

  // Now connect to the port that we just released.
  ScopedThread t([&] {
    ASSERT_THAT(connect(sock_.get(), addr, addrlen_), SyscallSucceeds());
  });

  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));
  // Send from sock_ to an unbound port.
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, addr, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));
  t.Join();
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
    EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &addrlen),
                SyscallSucceeds());
    EXPECT_EQ(addrlen, addrlen_);

    // Send from sock to bind_.
    char buf[512];
    RandomizeBuffer(buf, sizeof(buf));

    ASSERT_THAT(
        sendto(bind_.get(), buf, sizeof(buf), 0, AsSockAddr(&addr), addrlen),
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
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&peer), &peerlen),
              SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, bind_addr_, addrlen_), 0);

  // Try to bind after connect.
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(bind(sock_.get(), AsSockAddr(&any), addrlen_),
              SyscallFailsWithErrno(EINVAL));

  struct sockaddr_storage bind2_storage = InetLoopbackAddr();
  struct sockaddr* bind2_addr = AsSockAddr(&bind2_storage);
  FileDescriptor bind2 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP));
  ASSERT_NO_ERRNO(BindSocket(bind2.get(), bind2_addr));

  // Try to connect again.
  EXPECT_THAT(connect(sock_.get(), bind2_addr, addrlen_), SyscallSucceeds());

  // Check that peer name changed.
  peerlen = sizeof(peer);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&peer), &peerlen),
              SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, bind2_addr, addrlen_), 0);
}

TEST_P(UdpSocketTest, ConnectAnyZero) {
  // TODO(138658473): Enable when we can connect to port 0 with gVisor.
  SKIP_IF(IsRunningOnGvisor());

  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(connect(sock_.get(), AsSockAddr(&any), addrlen_),
              SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, ConnectAnyWithPort) {
  ASSERT_NO_ERRNO(BindAny());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());
}

TEST_P(UdpSocketTest, DisconnectAfterConnectAny) {
  // TODO(138658473): Enable when we can connect to port 0 with gVisor.
  SKIP_IF(IsRunningOnGvisor());
  struct sockaddr_storage any = InetAnyAddr();
  EXPECT_THAT(connect(sock_.get(), AsSockAddr(&any), addrlen_),
              SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));

  Disconnect(sock_.get());
}

TEST_P(UdpSocketTest, DisconnectAfterConnectAnyWithPort) {
  ASSERT_NO_ERRNO(BindAny());
  EXPECT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  ASSERT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(*Port(&bind_addr_storage_), *Port(&addr));

  Disconnect(sock_.get());
}

TEST_P(UdpSocketTest, DisconnectAfterBind) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Bind to the next port above bind_.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect the socket.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  struct sockaddr_storage unspec = {};
  unspec.ss_family = AF_UNSPEC;
  EXPECT_THAT(
      connect(sock_.get(), AsSockAddr(&unspec), sizeof(unspec.ss_family)),
      SyscallSucceeds());

  // Check that we're still bound.
  socklen_t addrlen = sizeof(unspec);
  EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&unspec), &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(addr, &unspec, addrlen_), 0);

  addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), addr, &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

void ConnectThenDisconnect(const FileDescriptor& sock,
                           const sockaddr* bind_addr,
                           const socklen_t expected_addrlen) {
  // Connect the bound socket.
  ASSERT_THAT(connect(sock.get(), bind_addr, expected_addrlen),
              SyscallSucceeds());

  // Disconnect.
  {
    sockaddr_storage unspec = {.ss_family = AF_UNSPEC};
    ASSERT_THAT(connect(sock.get(), AsSockAddr(&unspec), sizeof(unspec)),
                SyscallSucceeds());
  }
  {
    // Check that we're not in a bound state.
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    ASSERT_THAT(getsockname(sock.get(), AsSockAddr(&addr), &addrlen),
                SyscallSucceeds());
    ASSERT_EQ(addrlen, expected_addrlen);
    // Everything should be the zero value except the address family.
    sockaddr_storage expected = {
        .ss_family = bind_addr->sa_family,
    };
    EXPECT_EQ(memcmp(&expected, &addr, expected_addrlen), 0);
  }

  {
    // We are not connected so we have no peer.
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    EXPECT_THAT(getpeername(sock.get(), AsSockAddr(&addr), &addrlen),
                SyscallFailsWithErrno(ENOTCONN));
  }
}

TEST_P(UdpSocketTest, DisconnectAfterBindToUnspecAndConnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  sockaddr_storage unspec = {.ss_family = AF_UNSPEC};
  int bind_res = bind(sock_.get(), AsSockAddr(&unspec), sizeof(unspec));
  if ((!IsRunningOnGvisor() || IsRunningWithHostinet()) &&
      GetParam() == AF_INET) {
    // Linux allows this for undocumented compatibility reasons:
    // https://github.com/torvalds/linux/commit/29c486df6a208432b370bd4be99ae1369ede28d8.
    //
    // TODO(https://gvisor.dev/issue/6575): Match Linux's behaviour.
    ASSERT_THAT(bind_res, SyscallSucceeds());
  } else {
    ASSERT_THAT(bind_res, SyscallFailsWithErrno(EAFNOSUPPORT));
  }

  ASSERT_NO_FATAL_FAILURE(ConnectThenDisconnect(sock_, bind_addr_, addrlen_));
}

TEST_P(UdpSocketTest, DisconnectAfterConnectWithoutBind) {
  ASSERT_NO_ERRNO(BindLoopback());

  ASSERT_NO_FATAL_FAILURE(ConnectThenDisconnect(sock_, bind_addr_, addrlen_));
}

TEST_P(UdpSocketTest, BindToAnyConnnectToLocalhost) {
  ASSERT_NO_ERRNO(BindAny());

  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);
  socklen_t addrlen = sizeof(addr);

  // Connect the socket.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  EXPECT_THAT(getsockname(bind_.get(), addr, &addrlen), SyscallSucceeds());

  // If the socket is bound to ANY and connected to a loopback address,
  // getsockname() has to return the loopback address.
  if (GetParam() == AF_INET) {
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
  struct sockaddr* any = AsSockAddr(&any_storage);
  SetPort(&any_storage, *Port(&bind_addr_storage_) + 1);

  ASSERT_NO_ERRNO(BindSocket(sock_.get(), any));

  // Connect the socket.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  Disconnect(sock_.get());

  // Check that we're still bound.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, any, addrlen), 0);

  addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UdpSocketTest, Disconnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  struct sockaddr_storage any_storage = InetAnyAddr();
  struct sockaddr* any = AsSockAddr(&any_storage);
  SetPort(&any_storage, *Port(&bind_addr_storage_) + 1);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), any));

  for (int i = 0; i < 2; i++) {
    // Try to connect again.
    EXPECT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

    // Check that we're connected to the right peer.
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&peer), &peerlen),
                SyscallSucceeds());
    EXPECT_EQ(peerlen, addrlen_);
    EXPECT_EQ(memcmp(&peer, bind_addr_, addrlen_), 0);

    // Try to disconnect.
    struct sockaddr_storage addr = {};
    addr.ss_family = AF_UNSPEC;
    EXPECT_THAT(connect(sock_.get(), AsSockAddr(&addr), sizeof(addr.ss_family)),
                SyscallSucceeds());

    peerlen = sizeof(peer);
    EXPECT_THAT(getpeername(sock_.get(), AsSockAddr(&peer), &peerlen),
                SyscallFailsWithErrno(ENOTCONN));

    // Check that we're still bound.
    socklen_t addrlen = sizeof(addr);
    EXPECT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &addrlen),
                SyscallSucceeds());
    EXPECT_EQ(addrlen, addrlen_);
    EXPECT_EQ(*Port(&addr), *Port(&any_storage));
  }
}

TEST_P(UdpSocketTest, ConnectBadAddress) {
  struct sockaddr addr = {};
  addr.sa_family = GetParam();
  ASSERT_THAT(connect(sock_.get(), &addr, sizeof(addr.sa_family)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UdpSocketTest, SendToAddressOtherThanConnected) {
  ASSERT_NO_ERRNO(BindLoopback());

  struct sockaddr_storage addr_storage = InetAnyAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_) + 1);

  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Send to a different destination than we're connected to.
  char buf[512];
  EXPECT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, addr, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(UdpSocketTest, ConnectAndSendNoReceiver) {
  ASSERT_NO_ERRNO(BindLoopback());
  // Close the socket to release the port so that we get an ICMP error.
  ASSERT_THAT(close(bind_.release()), SyscallSucceeds());

  // Connect to loopback:bind_addr_ which should *hopefully* not be bound by an
  // UDP socket. There is no easy way to ensure that the UDP port is not bound
  // by another conncurrently running test. *This is potentially flaky*.
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  char buf[512];
  EXPECT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Poll to make sure we get the ICMP error back before issuing more writes.
  struct pollfd pfd = {sock_.get(), POLLERR, 0};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kIcmpTimeout),
              SyscallSucceedsWithValue(1));

  // Next write should fail with ECONNREFUSED due to the ICMP error generated in
  // response to the previous write.
  ASSERT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ECONNREFUSED));

  // The next write should succeed again since the last write call would have
  // retrieved and cleared the socket error.
  ASSERT_THAT(send(sock_.get(), buf, sizeof(buf), 0), SyscallSucceeds());

  // Poll to make sure we get the ICMP error back before issuing more writes.
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kIcmpTimeout),
              SyscallSucceedsWithValue(1));

  // Next write should fail with ECONNREFUSED due to the ICMP error generated in
  // response to the previous write.
  ASSERT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(ECONNREFUSED));
}

#ifdef __linux__
TEST_P(UdpSocketTest, RecvErrorConnRefusedOtherAFSockOpt) {
  int got;
  socklen_t got_len = sizeof(got);
  if (GetParam() == AF_INET) {
    EXPECT_THAT(setsockopt(sock_.get(), SOL_IPV6, IPV6_RECVERR, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallFailsWithErrno(ENOPROTOOPT));
    EXPECT_THAT(getsockopt(sock_.get(), SOL_IPV6, IPV6_RECVERR, &got, &got_len),
                SyscallFailsWithErrno(ENOTSUP));
    ASSERT_THAT(got_len, sizeof(got));
    return;
  }
  ASSERT_THAT(setsockopt(sock_.get(), SOL_IP, IP_RECVERR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  {
    EXPECT_THAT(getsockopt(sock_.get(), SOL_IP, IP_RECVERR, &got, &got_len),
                SyscallSucceeds());
    ASSERT_THAT(got_len, sizeof(got));
    EXPECT_THAT(got, kSockOptOn);
  }

  // We will simulate an ICMP error and verify that we don't receive that error
  // via recvmsg(MSG_ERRQUEUE) since we set another address family's RECVERR
  // flag.
  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());
  // Close the bind socket to release the port so that we get an ICMP error
  // when sending packets to it.
  ASSERT_THAT(close(bind_.release()), SyscallSucceeds());

  // Send to an unbound port which should trigger a port unreachable error.
  char buf[1];
  EXPECT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Should not have the error since we did not set the right socket option.
  msghdr msg = {};
  EXPECT_THAT(recvmsg(sock_.get(), &msg, MSG_ERRQUEUE),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(UdpSocketTest, RecvErrorConnRefused) {
  // We will simulate an ICMP error and verify that we do receive that error via
  // recvmsg(MSG_ERRQUEUE).
  ASSERT_NO_ERRNO(BindLoopback());
  // Close the socket to release the port so that we get an ICMP error.
  ASSERT_THAT(close(bind_.release()), SyscallSucceeds());

  // Set IP_RECVERR socket option to enable error queueing.
  int v = kSockOptOn;
  socklen_t optlen = sizeof(v);
  int opt_level = SOL_IP;
  int opt_type = IP_RECVERR;
  if (GetParam() == AF_INET6) {
    opt_level = SOL_IPV6;
    opt_type = IPV6_RECVERR;
  }
  ASSERT_THAT(setsockopt(sock_.get(), opt_level, opt_type, &v, optlen),
              SyscallSucceeds());
  {
    int got;
    socklen_t got_len = sizeof(got);
    EXPECT_THAT(getsockopt(sock_.get(), opt_level, opt_type, &got, &got_len),
                SyscallSucceeds());
    ASSERT_THAT(got_len, sizeof(got));
    EXPECT_THAT(got, kSockOptOn);
  }

  // Connect to loopback:bind_addr_ which should *hopefully* not be bound by an
  // UDP socket. There is no easy way to ensure that the UDP port is not bound
  // by another conncurrently running test. *This is potentially flaky*.
  const int kBufLen = 300;
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());
  char buf[kBufLen];
  RandomizeBuffer(buf, sizeof(buf));
  // Send from sock_ to an unbound port. This should cause ECONNREFUSED.
  EXPECT_THAT(send(sock_.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Dequeue error using recvmsg(MSG_ERRQUEUE).
  char got[kBufLen];
  struct iovec iov;
  iov.iov_base = reinterpret_cast<void*>(got);
  iov.iov_len = kBufLen;

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
  ASSERT_THAT(recvmsg(sock_.get(), &msg, MSG_ERRQUEUE),
              SyscallSucceedsWithValue(kBufLen));

  // Check the contents of msg.
  EXPECT_EQ(memcmp(got, buf, sizeof(buf)), 0);  // iovec check
  EXPECT_NE(msg.msg_flags & MSG_ERRQUEUE, 0);
  EXPECT_EQ(memcmp(&remote, bind_addr_, addrlen_), 0);

  // Check the contents of the control message.
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(CMSG_NXTHDR(&msg, cmsg), nullptr);
  EXPECT_EQ(cmsg->cmsg_level, opt_level);
  EXPECT_EQ(cmsg->cmsg_type, opt_type);

  // Check the contents of socket error.
  struct sock_extended_err* sock_err =
      (struct sock_extended_err*)CMSG_DATA(cmsg);
  EXPECT_EQ(sock_err->ee_errno, ECONNREFUSED);
  if (GetParam() == AF_INET) {
    EXPECT_EQ(sock_err->ee_origin, SO_EE_ORIGIN_ICMP);
    EXPECT_EQ(sock_err->ee_type, ICMP_DEST_UNREACH);
    EXPECT_EQ(sock_err->ee_code, ICMP_PORT_UNREACH);
  } else {
    EXPECT_EQ(sock_err->ee_origin, SO_EE_ORIGIN_ICMP6);
    EXPECT_EQ(sock_err->ee_type, ICMP6_DST_UNREACH);
    EXPECT_EQ(sock_err->ee_code, ICMP6_DST_UNREACH_NOPORT);
  }

  // Now verify that the socket error was cleared by recvmsg(MSG_ERRQUEUE).
  int err;
  optlen = sizeof(err);
  ASSERT_THAT(getsockopt(sock_.get(), SOL_SOCKET, SO_ERROR, &err, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(err, 0);
  ASSERT_EQ(optlen, sizeof(err));
}
#endif  // __linux__

TEST_P(UdpSocketTest, ZerolengthWriteAllowed) {
  // TODO(gvisor.dev/issue/1202): Hostinet does not support zero length writes.
  SKIP_IF(IsRunningWithHostinet());

  ASSERT_NO_ERRNO(BindLoopback());

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to `sock_`.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

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

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to `sock_`.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

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

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to `sock_`.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

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

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to itself.
  ASSERT_THAT(connect(bind_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Send some data from sock to bind_.
  char buf[512];
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Check that the data isn't received because it was sent from a different
  // address than we're connected.
  EXPECT_THAT(recv(bind_.get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveBeforeConnect) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Send some data from sock to bind_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Wait for the data to arrive.
  ASSERT_NO_FATAL_FAILURE(BlockUntilPollin(bind_.get()));

  // Connect `bind_` to itself.
  ASSERT_THAT(connect(bind_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  // Receive the data. It works because it was sent before the connect.
  char received[sizeof(buf)];
  EXPECT_THAT(
      RecvTimeout(bind_.get(), received, sizeof(received), 1 /*timeout*/),
      IsPosixErrorOkAndHolds(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);

  // Send again. This time it should not be received.
  ASSERT_THAT(sendto(sock_.get(), buf, sizeof(buf), 0, bind_addr_, addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_THAT(recv(bind_.get(), buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveFrom) {
  ASSERT_NO_ERRNO(BindLoopback());

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to `sock_`.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

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
                       AsSockAddr(&addr2), &addr2len),
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

  // Bind `sock_` to loopback.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), addr));

  // Connect `bind_` to `sock_`.
  ASSERT_THAT(connect(bind_.get(), addr, addrlen_), SyscallSucceeds());

  // Connect `sock_` to `bind_addr_`.
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

  // Wait for the data to arrive.
  ASSERT_NO_FATAL_FAILURE(BlockUntilPollin(bind_.get()));

  EXPECT_THAT(shutdown(bind_.get(), SHUT_RD), SyscallSucceeds());

  // We should get the data even though read has been shutdown.
  EXPECT_THAT(RecvTimeout(bind_.get(), received, 2 /*buf_size*/, 1 /*timeout*/),
              IsPosixErrorOkAndHolds(2));

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

  // Connect `bind_` to itself since we know the port number is valid.
  struct sockaddr_storage addr_storage = InetLoopbackAddr();
  struct sockaddr* addr = AsSockAddr(&addr_storage);
  SetPort(&addr_storage, *Port(&bind_addr_storage_));
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

    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, /*timeout=*/1000),
                SyscallSucceedsWithValue(1));

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

#ifdef __linux__
TEST_P(UdpSocketTest, ErrorQueue) {
  char cmsgbuf[CMSG_SPACE(sizeof(sock_extended_err))];
  msghdr msg;
  memset(&msg, 0, sizeof(msg));
  iovec iov;
  memset(&iov, 0, sizeof(iov));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  // recv*(MSG_ERRQUEUE) never blocks, even without MSG_DONTWAIT.
  EXPECT_THAT(RetryEINTR(recvmsg)(bind_.get(), &msg, MSG_ERRQUEUE),
              SyscallFailsWithErrno(EAGAIN));
}
#endif  // __linux__

TEST_P(UdpSocketTest, SoTimestampOffByDefault) {
  int v = -1;
  socklen_t optlen = sizeof(v);
  ASSERT_THAT(getsockopt(bind_.get(), SOL_SOCKET, SO_TIMESTAMP, &v, &optlen),
              SyscallSucceeds());
  ASSERT_EQ(v, kSockOptOff);
  ASSERT_EQ(optlen, sizeof(v));
}

TEST_P(UdpSocketTest, SoTimestamp) {
  ASSERT_NO_ERRNO(BindLoopback());
  ASSERT_THAT(connect(sock_.get(), bind_addr_, addrlen_), SyscallSucceeds());

  int v = 1;
  ASSERT_THAT(setsockopt(bind_.get(), SOL_SOCKET, SO_TIMESTAMP, &v, sizeof(v)),
              SyscallSucceeds());

  char buf[3];
  // Send zero length packet from sock to bind_.
  ASSERT_THAT(RetryEINTR(write)(sock_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

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

  // TODO(gvisor.dev/issue/1202): ioctl(SIOCGSTAMP) is not supported by
  // hostinet.
  if (!IsRunningWithHostinet()) {
    // There should be nothing to get via ioctl.
    ASSERT_THAT(ioctl(bind_.get(), SIOCGSTAMP, &tv),
                SyscallFailsWithErrno(ENOENT));
  }
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
    EXPECT_THAT(RecvTimeout(bind_.get(), received.data(), received.size(),
                            1 /*timeout*/),
                IsPosixErrorOkAndHolds(received.size()));
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
    ASSERT_THAT(RecvTimeout(bind_.get(), received.data(), received.size(),
                            1 /*timeout*/),
                IsPosixErrorOkAndHolds(received.size()));
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

  // Now set the limit to min * 2.
  int new_rcv_buf_sz = min * 2;
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
      EXPECT_THAT(RecvTimeout(bind_.get(), received.data(), received.size(),
                              1 /*timeout*/),
                  IsPosixErrorOkAndHolds(received.size()));
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

#ifdef __linux__

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

#endif  // __linux__

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

TEST_P(UdpSocketTest, SendToZeroPort) {
  char buf[8];
  struct sockaddr_storage addr = InetLoopbackAddr();

  // Sending to an invalid port should fail.
  SetPort(&addr, 0);
  EXPECT_THAT(
      sendto(sock_.get(), buf, sizeof(buf), 0, AsSockAddr(&addr), sizeof(addr)),
      SyscallFailsWithErrno(EINVAL));

  SetPort(&addr, 1234);
  EXPECT_THAT(
      sendto(sock_.get(), buf, sizeof(buf), 0, AsSockAddr(&addr), sizeof(addr)),
      SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(UdpSocketTest, ConnectToZeroPortUnbound) {
  struct sockaddr_storage addr = InetLoopbackAddr();
  SetPort(&addr, 0);
  ASSERT_THAT(connect(sock_.get(), AsSockAddr(&addr), addrlen_),
              SyscallSucceeds());
}

TEST_P(UdpSocketTest, ConnectToZeroPortBound) {
  struct sockaddr_storage addr = InetLoopbackAddr();
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), AsSockAddr(&addr)));

  SetPort(&addr, 0);
  ASSERT_THAT(connect(sock_.get(), AsSockAddr(&addr), addrlen_),
              SyscallSucceeds());
  socklen_t len = sizeof(sockaddr_storage);
  ASSERT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &len),
              SyscallSucceeds());
  ASSERT_EQ(len, addrlen_);
}

TEST_P(UdpSocketTest, ConnectToZeroPortConnected) {
  struct sockaddr_storage addr = InetLoopbackAddr();
  ASSERT_NO_ERRNO(BindSocket(sock_.get(), AsSockAddr(&addr)));

  // Connect to an address with non-zero port should succeed.
  ASSERT_THAT(connect(sock_.get(), AsSockAddr(&addr), addrlen_),
              SyscallSucceeds());
  sockaddr_storage peername;
  socklen_t peerlen = sizeof(peername);
  ASSERT_THAT(getpeername(sock_.get(), AsSockAddr(&peername), &peerlen),
              SyscallSucceeds());
  ASSERT_EQ(peerlen, addrlen_);
  ASSERT_EQ(memcmp(&peername, &addr, addrlen_), 0);

  // However connect() to an address with port 0 will make the following
  // getpeername() fail.
  SetPort(&addr, 0);
  ASSERT_THAT(connect(sock_.get(), AsSockAddr(&addr), addrlen_),
              SyscallSucceeds());
  ASSERT_THAT(getpeername(sock_.get(), AsSockAddr(&peername), &peerlen),
              SyscallFailsWithErrno(ENOTCONN));
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, UdpSocketTest,
                         ::testing::Values(AF_INET, AF_INET6));

class UdpSocketControlMessagesTest
    : public ::testing::TestWithParam<gvisor::testing::AddressFamily> {
 protected:
  void SetUp() override {
    switch (GetParam()) {
      case AddressFamily::kIpv4: {
        server_ =
            ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        TestAddress addr = V4Loopback().WithPort(port_);
        ASSERT_THAT(
            bind(server_.get(), reinterpret_cast<const sockaddr*>(&addr.addr),
                 addr.addr_len),
            SyscallSucceeds());

        client_ =
            ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        ASSERT_THAT(connect(client_.get(),
                            reinterpret_cast<const sockaddr*>(&addr.addr),
                            addr.addr_len),
                    SyscallSucceeds());
        break;
      }

      case AddressFamily::kIpv6: {
        server_ = ASSERT_NO_ERRNO_AND_VALUE(
            Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));
        TestAddress addr = V6Loopback().WithPort(port_);
        ASSERT_THAT(
            bind(server_.get(), reinterpret_cast<const sockaddr*>(&addr.addr),
                 addr.addr_len),
            SyscallSucceeds());

        client_ = ASSERT_NO_ERRNO_AND_VALUE(
            Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));
        ASSERT_THAT(connect(client_.get(),
                            reinterpret_cast<const sockaddr*>(&addr.addr),
                            addr.addr_len),
                    SyscallSucceeds());
        break;
      }

      case AddressFamily::kDualStack: {
        server_ = ASSERT_NO_ERRNO_AND_VALUE(
            Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

        TestAddress bind_addr = V4MappedLoopback().WithPort(port_);
        ASSERT_THAT(bind(server_.get(),
                         reinterpret_cast<const sockaddr*>(&bind_addr.addr),
                         bind_addr.addr_len),
                    SyscallSucceeds());

        client_ =
            ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        TestAddress connect_addr = V4Loopback().WithPort(port_);
        ASSERT_THAT(
            connect(client_.get(),
                    reinterpret_cast<const sockaddr*>(&connect_addr.addr),
                    connect_addr.addr_len),
            SyscallSucceeds());
        break;
      }

      default:
        FAIL() << "unknown address family: " << static_cast<int>(GetParam());
    }
  }

  int ClientAddressFamily() const {
    if (GetParam() == AddressFamily::kIpv6) {
      return AF_INET6;
    }
    return AF_INET;
  }

  int ServerAddressFamily() const {
    if (GetParam() == AddressFamily::kIpv4) {
      return AF_INET;
    }
    return AF_INET6;
  }

  FileDescriptor server_;
  FileDescriptor client_;

 private:
  static constexpr uint16_t port_ = 1337;
};

TEST_P(UdpSocketControlMessagesTest, SetAndReceiveTOSOrTClass) {
  // Enable receiving TOS and maybe TClass on the receiver.
  ASSERT_THAT(setsockopt(server_.get(), SOL_IP, IP_RECVTOS, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  if (ServerAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(server_.get(), SOL_IPV6, IPV6_RECVTCLASS,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }

  // Set custom TOS and maybe TClass on the sender.
  constexpr int kTOS = IPTOS_LOWDELAY;
  constexpr int kTClass = IPTOS_THROUGHPUT;
  ASSERT_NE(kTOS, kTClass);

  ASSERT_THAT(setsockopt(client_.get(), SOL_IP, IP_TOS, &kTOS, sizeof(kTOS)),
              SyscallSucceeds());
  if (ClientAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(client_.get(), SOL_IPV6, IPV6_TCLASS, &kTClass,
                           sizeof(kTClass)),
                SyscallSucceeds());
  }

  constexpr size_t kArbitrarySendSize = 1042;
  constexpr char sent_data[kArbitrarySendSize] = {};
  ASSERT_THAT(RetryEINTR(send)(client_.get(), sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char recv_data[sizeof(sent_data) + 1];
  size_t recv_data_len = sizeof(recv_data);

  if (ClientAddressFamily() == AF_INET) {
    uint8_t tos;
    ASSERT_NO_FATAL_FAILURE(
        RecvTOS(server_.get(), recv_data, &recv_data_len, &tos));
    EXPECT_EQ(static_cast<int>(tos), kTOS);
  } else {
    int tclass;
    ASSERT_NO_FATAL_FAILURE(
        RecvTClass(server_.get(), recv_data, &recv_data_len, &tclass));
    EXPECT_EQ(tclass, kTClass);
  }
  EXPECT_EQ(recv_data_len, sizeof(sent_data));
}

TEST_P(UdpSocketControlMessagesTest, SendAndReceiveTOSorTClass) {
  // TODO(b/146661005): Setting TOS via sendmsg is not supported by netstack.
  SKIP_IF(IsRunningOnGvisor() && !IsRunningWithHostinet());

  // Enable receiving TOS and maybe TClass on the receiver.
  ASSERT_THAT(setsockopt(server_.get(), SOL_IP, IP_RECVTOS, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  if (ServerAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(server_.get(), SOL_IPV6, IPV6_RECVTCLASS,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }

  constexpr uint8_t kSendCmsgValue = IPTOS_LOWDELAY;
  constexpr size_t kArbitrarySendSize = 1024;
  char sent_data[kArbitrarySendSize];
  char recv_data[sizeof(sent_data) + 1];
  size_t recv_data_len = sizeof(recv_data);

  if (ClientAddressFamily() == AF_INET) {
    ASSERT_NO_FATAL_FAILURE(SendTOS(client_.get(), sent_data,
                                    size_t(sizeof(sent_data)), kSendCmsgValue));
    uint8_t tos;
    ASSERT_NO_FATAL_FAILURE(
        RecvTOS(server_.get(), recv_data, &recv_data_len, &tos));
    EXPECT_EQ(static_cast<int>(tos), kSendCmsgValue);
  } else {
    ASSERT_NO_FATAL_FAILURE(SendTClass(
        client_.get(), sent_data, size_t(sizeof(sent_data)), kSendCmsgValue));
    int tclass;
    ASSERT_NO_FATAL_FAILURE(
        RecvTClass(server_.get(), recv_data, &recv_data_len, &tclass));
    EXPECT_EQ(tclass, kSendCmsgValue);
  }
  EXPECT_EQ(recv_data_len, sizeof(sent_data));
}

TEST_P(UdpSocketControlMessagesTest, SetAndReceiveTTLOrHopLimit) {
  // Enable receiving TTL and maybe HOPLIMIT on the receiver.
  ASSERT_THAT(setsockopt(server_.get(), SOL_IP, IP_RECVTTL, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  if (ServerAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(server_.get(), SOL_IPV6, IPV6_RECVHOPLIMIT,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }

  // Set custom TTL and maybe HOPLIMIT on the sender.
  constexpr int kTTL = 21;
  constexpr int kHopLimit = 42;
  ASSERT_NE(kTTL, kHopLimit);

  ASSERT_THAT(setsockopt(client_.get(), SOL_IP, IP_TTL, &kTTL, sizeof(kTTL)),
              SyscallSucceeds());
  if (ClientAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(client_.get(), SOL_IPV6, IPV6_UNICAST_HOPS,
                           &kHopLimit, sizeof(kHopLimit)),
                SyscallSucceeds());
  }

  constexpr size_t kArbitrarySendSize = 1042;
  constexpr char sent_data[kArbitrarySendSize] = {};
  ASSERT_THAT(RetryEINTR(send)(client_.get(), sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char recv_data[sizeof(sent_data)];
  size_t recv_data_len = sizeof(recv_data);

  if (ClientAddressFamily() == AF_INET) {
    int ttl;
    ASSERT_NO_FATAL_FAILURE(
        RecvTTL(server_.get(), recv_data, &recv_data_len, &ttl));
    EXPECT_EQ(ttl, kTTL);
  } else {
    int hoplimit;
    ASSERT_NO_FATAL_FAILURE(
        RecvHopLimit(server_.get(), recv_data, &recv_data_len, &hoplimit));
    EXPECT_EQ(hoplimit, kHopLimit);
  }
  EXPECT_EQ(recv_data_len, sizeof(sent_data));
}

TEST_P(UdpSocketControlMessagesTest, SendAndReceiveTTLOrHopLimit) {
  // Enable receiving TTL and maybe HOPLIMIT on the receiver.
  ASSERT_THAT(setsockopt(server_.get(), SOL_IP, IP_RECVTTL, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  if (ServerAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(server_.get(), SOL_IPV6, IPV6_RECVHOPLIMIT,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }

  constexpr int kSendCmsgValue = 42;
  constexpr size_t kArbitrarySendSize = 1024;
  char sent_data[kArbitrarySendSize];
  char recv_data[sizeof(sent_data) + 1];
  size_t recv_data_len = sizeof(recv_data);

  if (ClientAddressFamily() == AF_INET) {
    ASSERT_NO_FATAL_FAILURE(SendTTL(client_.get(), sent_data,
                                    size_t(sizeof(sent_data)), kSendCmsgValue));
    int ttl;
    ASSERT_NO_FATAL_FAILURE(
        RecvTTL(server_.get(), recv_data, &recv_data_len, &ttl));
    EXPECT_EQ(ttl, kSendCmsgValue);
  } else {
    ASSERT_NO_FATAL_FAILURE(SendHopLimit(
        client_.get(), sent_data, size_t(sizeof(sent_data)), kSendCmsgValue));
    int hoplimit;
    ASSERT_NO_FATAL_FAILURE(
        RecvHopLimit(server_.get(), recv_data, &recv_data_len, &hoplimit));
    EXPECT_EQ(hoplimit, kSendCmsgValue);
  }
  EXPECT_EQ(recv_data_len, sizeof(sent_data));
}

TEST_P(UdpSocketControlMessagesTest, SetAndReceivePktInfo) {
  // Enable receiving IP_PKTINFO and maybe IPV6_PKTINFO on the receiver.
  ASSERT_THAT(setsockopt(server_.get(), SOL_IP, IP_PKTINFO, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  if (ServerAddressFamily() == AF_INET6) {
    ASSERT_THAT(setsockopt(server_.get(), SOL_IPV6, IPV6_RECVPKTINFO,
                           &kSockOptOn, sizeof(kSockOptOn)),
                SyscallSucceeds());
  }

  constexpr size_t kArbitrarySendSize = 1042;
  constexpr char sent_data[kArbitrarySendSize] = {};
  ASSERT_THAT(RetryEINTR(send)(client_.get(), sent_data, sizeof(sent_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char recv_data[sizeof(sent_data) + 1];
  size_t recv_data_len = sizeof(recv_data);
  switch (GetParam()) {
    case AddressFamily::kIpv4: {
      in_pktinfo received_pktinfo;
      ASSERT_NO_FATAL_FAILURE(RecvPktInfo(server_.get(), recv_data,
                                          &recv_data_len, &received_pktinfo));
      EXPECT_EQ(recv_data_len, sizeof(sent_data));
      EXPECT_EQ(received_pktinfo.ipi_ifindex,
                ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
      EXPECT_EQ(ntohl(received_pktinfo.ipi_spec_dst.s_addr), INADDR_LOOPBACK);
      EXPECT_EQ(ntohl(received_pktinfo.ipi_addr.s_addr), INADDR_LOOPBACK);
      break;
    }

    case AddressFamily::kIpv6: {
      in6_pktinfo received_pktinfo;
      ASSERT_NO_FATAL_FAILURE(RecvIPv6PktInfo(
          server_.get(), recv_data, &recv_data_len, &received_pktinfo));
      EXPECT_EQ(recv_data_len, sizeof(sent_data));
      EXPECT_EQ(received_pktinfo.ipi6_ifindex,
                ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
      ASSERT_EQ(memcmp(&received_pktinfo.ipi6_addr, &in6addr_loopback,
                       sizeof(in6addr_loopback)),
                0);
      break;
    }

    case AddressFamily::kDualStack: {
      // TODO(https://gvisor.dev/issue/7144): On dual stack sockets, Linux can
      // receive both the IPv4 and IPv6 packet info. gVisor should do the same.
      iovec iov = {
          iov.iov_base = recv_data,
          iov.iov_len = recv_data_len,
      };
      // Add an extra byte to confirm we only read what we expected.
      char control[CMSG_SPACE(sizeof(in_pktinfo)) +
                   CMSG_SPACE(sizeof(in6_pktinfo)) + 1];
      msghdr msg = {
          .msg_iov = &iov,
          .msg_iovlen = 1,
          .msg_control = control,
          .msg_controllen = sizeof(control),
      };

      ASSERT_THAT(
          recv_data_len = RetryEINTR(recvmsg)(server_.get(), &msg, /*flags=*/0),
          SyscallSucceeds());
      EXPECT_EQ(recv_data_len, sizeof(sent_data));
      size_t expected_controllen = CMSG_SPACE(sizeof(in_pktinfo));
      if (!IsRunningOnGvisor() || IsRunningWithHostinet()) {
        expected_controllen += CMSG_SPACE(sizeof(in6_pktinfo));
      }
      EXPECT_EQ(msg.msg_controllen, expected_controllen);

      std::pair<in_pktinfo, bool> received_pktinfo;
      std::pair<in6_pktinfo, bool> received_pktinfo6;

      struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      while (cmsg != nullptr) {
        ASSERT_TRUE(cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == SOL_IPV6);
        if (cmsg->cmsg_level == SOL_IP) {
          ASSERT_FALSE(received_pktinfo.second);
          ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(in_pktinfo)));
          ASSERT_EQ(cmsg->cmsg_type, IP_PKTINFO);
          received_pktinfo.second = true;
          std::copy_n(CMSG_DATA(cmsg), sizeof(received_pktinfo.first),
                      reinterpret_cast<uint8_t*>(&received_pktinfo.first));
        } else {  // SOL_IPV6
          ASSERT_FALSE(received_pktinfo6.second);
          ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(in6_pktinfo)));
          ASSERT_EQ(cmsg->cmsg_type, IPV6_PKTINFO);
          received_pktinfo6.second = true;
          std::copy_n(CMSG_DATA(cmsg), sizeof(received_pktinfo6.first),
                      reinterpret_cast<uint8_t*>(&received_pktinfo6.first));
        }
        cmsg = CMSG_NXTHDR(&msg, cmsg);
      }

      ASSERT_TRUE(received_pktinfo.second);
      EXPECT_EQ(received_pktinfo.first.ipi_ifindex,
                ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
      EXPECT_EQ(ntohl(received_pktinfo.first.ipi_spec_dst.s_addr),
                INADDR_LOOPBACK);
      EXPECT_EQ(ntohl(received_pktinfo.first.ipi_addr.s_addr), INADDR_LOOPBACK);

      if (!IsRunningOnGvisor() || IsRunningWithHostinet()) {
        ASSERT_TRUE(received_pktinfo6.second);
        EXPECT_EQ(received_pktinfo6.first.ipi6_ifindex,
                  ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()));
        struct in6_addr expected;
        inet_pton(AF_INET6, "::ffff:127.0.0.1", &expected);
        EXPECT_EQ(memcmp(&received_pktinfo6.first.ipi6_addr, &expected,
                         sizeof(expected)),
                  0);
      } else {
        ASSERT_FALSE(received_pktinfo6.second);
      }

      break;
    }
  }
}

TEST_P(UdpSocketTest, SendPacketLargerThanSendBufOnNonBlockingSocket) {
  constexpr int kSendBufSize = 4096;
  ASSERT_THAT(setsockopt(sock_.get(), SOL_SOCKET, SO_SNDBUF, &kSendBufSize,
                         sizeof(kSendBufSize)),
              SyscallSucceeds());

  // Set sock to non-blocking.
  {
    int opts = 0;
    ASSERT_THAT(opts = fcntl(sock_.get(), F_GETFL), SyscallSucceeds());
    ASSERT_THAT(fcntl(sock_.get(), F_SETFL, opts | O_NONBLOCK),
                SyscallSucceeds());
  }

  {
    sockaddr_storage addr = InetLoopbackAddr();
    ASSERT_NO_ERRNO(BindSocket(sock_.get(), AsSockAddr(&addr)));
  }

  sockaddr_storage addr;
  socklen_t len = sizeof(sockaddr_storage);
  ASSERT_THAT(getsockname(sock_.get(), AsSockAddr(&addr), &len),
              SyscallSucceeds());
  ASSERT_EQ(len, addrlen_);

  // We are allowed to send packets as large as we want as long as there is
  // space in the send buffer, even if the new packet will result in more bytes
  // being used than available in the send buffer.
  char buf[kSendBufSize + 1];
  ASSERT_THAT(
      sendto(sock_.get(), buf, sizeof(buf), 0, AsSockAddr(&addr), sizeof(addr)),
      SyscallSucceedsWithValue(sizeof(buf)));

  // The second write may fail with EAGAIN if the previous send is still
  // in-flight.
  ASSERT_THAT(
      sendto(sock_.get(), buf, sizeof(buf), 0, AsSockAddr(&addr), sizeof(addr)),
      AnyOf(SyscallSucceedsWithValue(sizeof(buf)),
            SyscallFailsWithErrno(EAGAIN)));
}

INSTANTIATE_TEST_SUITE_P(AllInetTests, UdpSocketControlMessagesTest,
                         ::testing::Values(AddressFamily::kIpv4,
                                           AddressFamily::kIpv6,
                                           AddressFamily::kDualStack));

TEST(UdpInet6SocketTest, ConnectInet4Sockaddr) {
  // glibc getaddrinfo expects the invariant expressed by this test to be held.
  const sockaddr_in connect_sockaddr = {
      .sin_family = AF_INET, .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
  auto sock_ =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));
  ASSERT_THAT(
      connect(sock_.get(),
              reinterpret_cast<const struct sockaddr*>(&connect_sockaddr),
              sizeof(sockaddr_in)),
      SyscallSucceeds());
  sockaddr_storage sockname;
  socklen_t len = sizeof(sockaddr_storage);
  ASSERT_THAT(getsockname(sock_.get(), AsSockAddr(&sockname), &len),
              SyscallSucceeds());
  ASSERT_EQ(sockname.ss_family, AF_INET6);
  ASSERT_EQ(len, sizeof(sockaddr_in6));
  auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&sockname);
  char addr_buf[INET6_ADDRSTRLEN];
  const char* addr;
  ASSERT_NE(addr = inet_ntop(sockname.ss_family, &sockname, addr_buf,
                             sizeof(addr_buf)),
            nullptr);
  ASSERT_TRUE(IN6_IS_ADDR_V4MAPPED(sin6->sin6_addr.s6_addr)) << addr;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
