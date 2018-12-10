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

#include <fcntl.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// The initial port to be be used on gvisor.
constexpr int TestPort = 40000;

// Fixture for tests parameterized by the address family to use (AF_INET and
// AF_INET6) when creating sockets.
class UdpSocketTest : public ::testing::TestWithParam<int> {
 protected:
  // Creates two sockets that will be used by test cases.
  void SetUp() override;

  // Closes the sockets created by SetUp().
  void TearDown() override {
    EXPECT_THAT(close(s_), SyscallSucceeds());
    EXPECT_THAT(close(t_), SyscallSucceeds());

    for (size_t i = 0; i < ABSL_ARRAYSIZE(ports_); ++i) {
      ASSERT_NO_ERRNO(FreeAvailablePort(ports_[i]));
    }
  }

  // First UDP socket.
  int s_;

  // Second UDP socket.
  int t_;

  // The length of the socket address.
  socklen_t addrlen_;

  // Initialized address pointing to loopback and port TestPort+i.
  struct sockaddr* addr_[3];

  // Initialize "any" address.
  struct sockaddr* anyaddr_;

  // Used ports.
  int ports_[3];

 private:
  // Storage for the loopback addresses.
  struct sockaddr_storage addr_storage_[3];

  // Storage for the "any" address.
  struct sockaddr_storage anyaddr_storage_;
};

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

void UdpSocketTest::SetUp() {
  ASSERT_THAT(s_ = socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP),
              SyscallSucceeds());

  ASSERT_THAT(t_ = socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP),
              SyscallSucceeds());

  memset(&anyaddr_storage_, 0, sizeof(anyaddr_storage_));
  anyaddr_ = reinterpret_cast<struct sockaddr*>(&anyaddr_storage_);
  anyaddr_->sa_family = GetParam();

  // Initialize address-family-specific values.
  switch (GetParam()) {
    case AF_INET: {
      auto sin = reinterpret_cast<struct sockaddr_in*>(&anyaddr_storage_);
      addrlen_ = sizeof(*sin);
      sin->sin_addr.s_addr = htonl(INADDR_ANY);
      break;
    }
    case AF_INET6: {
      auto sin6 = reinterpret_cast<struct sockaddr_in6*>(&anyaddr_storage_);
      addrlen_ = sizeof(*sin6);
      sin6->sin6_addr = in6addr_any;
      break;
    }
  }

  if (gvisor::testing::IsRunningOnGvisor()) {
    for (size_t i = 0; i < ABSL_ARRAYSIZE(ports_); ++i) {
      ports_[i] = TestPort + i;
    }
  } else {
    // When not under gvisor, use utility function to pick port. Assert that
    // all ports are different.
    std::string error;
    for (size_t i = 0; i < ABSL_ARRAYSIZE(ports_); ++i) {
      // Find an unused port, we specify port 0 to allow the kernel to provide
      // the port.
      bool unique = true;
      do {
        ports_[i] = ASSERT_NO_ERRNO_AND_VALUE(PortAvailable(
            0, AddressFamily::kDualStack, SocketType::kUdp, false));
        ASSERT_GT(ports_[i], 0);
        for (size_t j = 0; j < i; ++j) {
          if (ports_[j] == ports_[i]) {
            unique = false;
            break;
          }
        }
      } while (!unique);
    }
  }

  // Initialize the sockaddrs.
  for (size_t i = 0; i < ABSL_ARRAYSIZE(addr_); ++i) {
    memset(&addr_storage_[i], 0, sizeof(addr_storage_[i]));

    addr_[i] = reinterpret_cast<struct sockaddr*>(&addr_storage_[i]);
    addr_[i]->sa_family = GetParam();

    switch (GetParam()) {
      case AF_INET: {
        auto sin = reinterpret_cast<struct sockaddr_in*>(addr_[i]);
        sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin->sin_port = htons(ports_[i]);
        break;
      }
      case AF_INET6: {
        auto sin6 = reinterpret_cast<struct sockaddr_in6*>(addr_[i]);
        sin6->sin6_addr = in6addr_loopback;
        sin6->sin6_port = htons(ports_[i]);
        break;
      }
    }
  }
}

TEST_P(UdpSocketTest, Creation) {
  int s_;

  ASSERT_THAT(s_ = socket(GetParam(), SOCK_DGRAM, IPPROTO_UDP),
              SyscallSucceeds());
  EXPECT_THAT(close(s_), SyscallSucceeds());

  ASSERT_THAT(s_ = socket(GetParam(), SOCK_DGRAM, 0), SyscallSucceeds());
  EXPECT_THAT(close(s_), SyscallSucceeds());

  ASSERT_THAT(s_ = socket(GetParam(), SOCK_STREAM, IPPROTO_UDP),
              SyscallFails());
}

TEST_P(UdpSocketTest, Getsockname) {
  // Check that we're not bound.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, anyaddr_, addrlen_), 0);

  // Bind, then check that we get the right address.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, addr_[0], addrlen_), 0);
}

TEST_P(UdpSocketTest, Getpeername) {
  // Check that we're not connected.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallFailsWithErrno(ENOTCONN));

  // Connect, then check that we get the right address.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(getpeername(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, addr_[0], addrlen_), 0);
}

TEST_P(UdpSocketTest, SendNotConnected) {
  // Do send & write, they must fail.
  char buf[512];
  EXPECT_THAT(send(s_, buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EDESTADDRREQ));

  EXPECT_THAT(write(s_, buf, sizeof(buf)), SyscallFailsWithErrno(EDESTADDRREQ));

  // Use sendto.
  ASSERT_THAT(sendto(s_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Check that we're bound now.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr), 0);
}

TEST_P(UdpSocketTest, ConnectBinds) {
  // Connect the socket.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Check that we're bound now.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_NE(*Port(&addr), 0);
}

TEST_P(UdpSocketTest, ReceiveNotBound) {
  char buf[512];
  EXPECT_THAT(recv(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, Bind) {
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Try to bind again.
  EXPECT_THAT(bind(s_, addr_[1], addrlen_), SyscallFailsWithErrno(EINVAL));

  // Check that we're still bound to the original address.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, addr_[0], addrlen_), 0);
}

TEST_P(UdpSocketTest, BindInUse) {
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Try to bind again.
  EXPECT_THAT(bind(t_, addr_[0], addrlen_), SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(UdpSocketTest, ReceiveAfterConnect) {
  // Connect s_ to loopback:TestPort, and bind t_ to loopback:TestPort.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(bind(t_, addr_[0], addrlen_), SyscallSucceeds());

  // Get the address s_ was bound to during connect.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(s_, reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, addrlen_);

  // Send from t_ to s_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));
  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0,
                     reinterpret_cast<sockaddr*>(&addr), addrlen),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, Connect) {
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Check that we're connected to the right peer.
  struct sockaddr_storage peer;
  socklen_t peerlen = sizeof(peer);
  EXPECT_THAT(getpeername(s_, reinterpret_cast<sockaddr*>(&peer), &peerlen),
              SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, addr_[0], addrlen_), 0);

  // Try to bind after connect.
  EXPECT_THAT(bind(s_, addr_[1], addrlen_), SyscallFailsWithErrno(EINVAL));

  // Try to connect again.
  EXPECT_THAT(connect(s_, addr_[2], addrlen_), SyscallSucceeds());

  // Check that peer name changed.
  peerlen = sizeof(peer);
  EXPECT_THAT(getpeername(s_, reinterpret_cast<sockaddr*>(&peer), &peerlen),
              SyscallSucceeds());
  EXPECT_EQ(peerlen, addrlen_);
  EXPECT_EQ(memcmp(&peer, addr_[2], addrlen_), 0);
}

TEST_P(UdpSocketTest, SendToAddressOtherThanConnected) {
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Send to a different destination than we're connected to.
  char buf[512];
  EXPECT_THAT(sendto(s_, buf, sizeof(buf), 0, addr_[1], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(UdpSocketTest, ZerolengthWriteAllowed) {
  // Bind s_ to loopback:TestPort, and connect to loopback:TestPort+1.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+1.
  ASSERT_THAT(bind(t_, addr_[1], addrlen_), SyscallSucceeds());

  char buf[3];
  // Send zero length packet from s_ to t_.
  ASSERT_THAT(write(s_, buf, 0), SyscallSucceedsWithValue(0));
  // Receive the packet.
  char received[3];
  EXPECT_THAT(read(t_, received, sizeof(received)),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, ZerolengthWriteAllowedNonBlockRead) {
  // Bind s_ to loopback:TestPort, and connect to loopback:TestPort+1.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+1.
  ASSERT_THAT(bind(t_, addr_[1], addrlen_), SyscallSucceeds());

  // Set t_ to non-blocking.
  int opts = 0;
  ASSERT_THAT(opts = fcntl(t_, F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(t_, F_SETFL, opts | O_NONBLOCK), SyscallSucceeds());

  char buf[3];
  // Send zero length packet from s_ to t_.
  ASSERT_THAT(write(s_, buf, 0), SyscallSucceedsWithValue(0));
  // Receive the packet.
  char received[3];
  EXPECT_THAT(read(t_, received, sizeof(received)),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(read(t_, received, sizeof(received)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(UdpSocketTest, SendAndReceiveNotConnected) {
  // Bind s_ to loopback.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Send some data to s_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, SendAndReceiveConnected) {
  // Bind s_ to loopback:TestPort, and connect to loopback:TestPort+1.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+1.
  ASSERT_THAT(bind(t_, addr_[1], addrlen_), SyscallSucceeds());

  // Send some data from t_ to s_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data.
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, ReceiveFromNotConnected) {
  // Bind s_ to loopback:TestPort, and connect to loopback:TestPort+1.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+2.
  ASSERT_THAT(bind(t_, addr_[2], addrlen_), SyscallSucceeds());

  // Send some data from t_ to s_.
  char buf[512];
  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Check that the data isn't_ received because it was sent from a different
  // address than we're connected.
  EXPECT_THAT(recv(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveBeforeConnect) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+2.
  ASSERT_THAT(bind(t_, addr_[2], addrlen_), SyscallSucceeds());

  // Send some data from t_ to s_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Connect to loopback:TestPort+1.
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Receive the data. It works because it was sent before the connect.
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);

  // Send again. This time it should not be received.
  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_THAT(recv(s_, buf, sizeof(buf), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReceiveFrom) {
  // Bind s_ to loopback:TestPort, and connect to loopback:TestPort+1.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[1], addrlen_), SyscallSucceeds());

  // Bind t_ to loopback:TestPort+1.
  ASSERT_THAT(bind(t_, addr_[1], addrlen_), SyscallSucceeds());

  // Send some data from t_ to s_.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  ASSERT_THAT(sendto(t_, buf, sizeof(buf), 0, addr_[0], addrlen_),
              SyscallSucceedsWithValue(sizeof(buf)));

  // Receive the data and sender address.
  char received[512];
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(recvfrom(s_, received, sizeof(received), 0,
                       reinterpret_cast<sockaddr*>(&addr), &addrlen),
              SyscallSucceedsWithValue(sizeof(received)));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
  EXPECT_EQ(addrlen, addrlen_);
  EXPECT_EQ(memcmp(&addr, addr_[1], addrlen_), 0);
}

TEST_P(UdpSocketTest, Listen) {
  ASSERT_THAT(listen(s_, SOMAXCONN), SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST_P(UdpSocketTest, Accept) {
  ASSERT_THAT(accept(s_, nullptr, nullptr), SyscallFailsWithErrno(EOPNOTSUPP));
}

// This test validates that a read shutdown with pending data allows the read
// to proceed with the data before returning EAGAIN.
TEST_P(UdpSocketTest, ReadShutdownNonblockPendingData) {
  char received[512];

  // Bind t_ to loopback:TestPort+2.
  ASSERT_THAT(bind(t_, addr_[2], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(t_, addr_[1], addrlen_), SyscallSucceeds());

  // Connect the socket, then try to shutdown again.
  ASSERT_THAT(bind(s_, addr_[1], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[2], addrlen_), SyscallSucceeds());

  // Verify that we get EWOULDBLOCK when there is nothing to read.
  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  const char* buf = "abc";
  EXPECT_THAT(write(t_, buf, 3), SyscallSucceedsWithValue(3));

  int opts = 0;
  ASSERT_THAT(opts = fcntl(s_, F_GETFL), SyscallSucceeds());
  ASSERT_THAT(fcntl(s_, F_SETFL, opts | O_NONBLOCK), SyscallSucceeds());
  ASSERT_THAT(opts = fcntl(s_, F_GETFL), SyscallSucceeds());
  ASSERT_NE(opts & O_NONBLOCK, 0);

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  // We should get the data even though read has been shutdown.
  EXPECT_THAT(recv(s_, received, 2, 0), SyscallSucceedsWithValue(2));

  // Because we read less than the entire packet length, since it's a packet
  // based socket any subsequent reads should return EWOULDBLOCK.
  EXPECT_THAT(recv(s_, received, 1, 0), SyscallFailsWithErrno(EWOULDBLOCK));
}

// This test is validating that even after a socket is shutdown if it's
// reconnected it will reset the shutdown state.
TEST_P(UdpSocketTest, ReadShutdownSameSocketResetsShutdownState) {
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));

  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then try to shutdown again.
  ASSERT_THAT(bind(s_, addr_[1], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(s_, addr_[2], addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST_P(UdpSocketTest, ReadShutdown) {
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallFailsWithErrno(ENOTCONN));

  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then try to shutdown again.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  EXPECT_THAT(recv(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, ReadShutdownDifferentThread) {
  char received[512];
  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Connect the socket, then shutdown from another thread.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  EXPECT_THAT(recv(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  ScopedThread t([&] {
    absl::SleepFor(absl::Milliseconds(200));
    EXPECT_THAT(shutdown(this->s_, SHUT_RD), SyscallSucceeds());
  });
  EXPECT_THAT(RetryEINTR(recv)(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
  t.Join();

  EXPECT_THAT(RetryEINTR(recv)(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(0));
}

TEST_P(UdpSocketTest, WriteShutdown) {
  EXPECT_THAT(shutdown(s_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());
  EXPECT_THAT(shutdown(s_, SHUT_WR), SyscallSucceeds());
}

TEST_P(UdpSocketTest, SynchronousReceive) {
  // Bind s_ to loopback.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Send some data to s_ from another thread.
  char buf[512];
  RandomizeBuffer(buf, sizeof(buf));

  // Receive the data prior to actually starting the other thread.
  char received[512];
  EXPECT_THAT(RetryEINTR(recv)(s_, received, sizeof(received), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Start the thread.
  ScopedThread t([&] {
    absl::SleepFor(absl::Milliseconds(200));
    ASSERT_THAT(
        sendto(this->t_, buf, sizeof(buf), 0, this->addr_[0], this->addrlen_),
        SyscallSucceedsWithValue(sizeof(buf)));
  });

  EXPECT_THAT(RetryEINTR(recv)(s_, received, sizeof(received), 0),
              SyscallSucceedsWithValue(512));
  EXPECT_EQ(memcmp(buf, received, sizeof(buf)), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_SendRecv) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Send 3 packets from t_ to s_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(sendto(t_, buf + i * psize, psize, 0, addr_[0], addrlen_),
                SyscallSucceedsWithValue(psize));
  }

  // Receive the data as 3 separate packets.
  char received[6 * psize];
  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(recv(s_, received + i * psize, 3 * psize, 0),
                SyscallSucceedsWithValue(psize));
  }
  EXPECT_EQ(memcmp(buf, received, 3 * psize), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_WritevReadv) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Direct writes from t_ to s_.
  ASSERT_THAT(connect(t_, addr_[0], addrlen_), SyscallSucceeds());

  // Send 2 packets from t_ to s_, where each packet's data consists of 2
  // discontiguous iovecs.
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
    ASSERT_THAT(writev(t_, iov, 2), SyscallSucceedsWithValue(2 * kPieceSize));
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
    ASSERT_THAT(readv(s_, iov, 3), SyscallSucceedsWithValue(2 * kPieceSize));
  }
  EXPECT_EQ(memcmp(buf, received, 4 * kPieceSize), 0);
}

TEST_P(UdpSocketTest, BoundaryPreserved_SendMsgRecvMsg) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Send 2 packets from t_ to s_, where each packet's data consists of 2
  // discontiguous iovecs.
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
    msg.msg_name = addr_[0];
    msg.msg_namelen = addrlen_;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    ASSERT_THAT(sendmsg(t_, &msg, 0), SyscallSucceedsWithValue(2 * kPieceSize));
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
    ASSERT_THAT(recvmsg(s_, &msg, 0), SyscallSucceedsWithValue(2 * kPieceSize));
  }
  EXPECT_EQ(memcmp(buf, received, 4 * kPieceSize), 0);
}

TEST_P(UdpSocketTest, FIONREADShutdown) {
  int n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
}

TEST_P(UdpSocketTest, FIONREADWriteShutdown) {
  int n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  const char str[] = "abc";
  ASSERT_THAT(send(s_, str, sizeof(str), 0),
              SyscallSucceedsWithValue(sizeof(str)));

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(str));

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, sizeof(str));
}

TEST_P(UdpSocketTest, FIONREAD) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Check that the bound socket with an empty buffer reports an empty first
  // packet.
  int n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Send 3 packets from t_ to s_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(sendto(t_, buf + i * psize, psize, 0, addr_[0], addrlen_),
                SyscallSucceedsWithValue(psize));

    // Check that regardless of how many packets are in the queue, the size
    // reported is that of a single packet.
    n = -1;
    EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
    EXPECT_EQ(n, psize);
  }
}

TEST_P(UdpSocketTest, FIONREADZeroLengthPacket) {
  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // Check that the bound socket with an empty buffer reports an empty first
  // packet.
  int n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Send 3 packets from t_ to s_.
  constexpr int psize = 100;
  char buf[3 * psize];
  RandomizeBuffer(buf, sizeof(buf));

  for (int i = 0; i < 3; ++i) {
    ASSERT_THAT(sendto(t_, buf + i * psize, 0, 0, addr_[0], addrlen_),
                SyscallSucceedsWithValue(0));

    // Check that regardless of how many packets are in the queue, the size
    // reported is that of a single packet.
    n = -1;
    EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
    EXPECT_EQ(n, 0);
  }
}

TEST_P(UdpSocketTest, FIONREADZeroLengthWriteShutdown) {
  int n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  // Bind s_ to loopback:TestPort.
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());

  // A UDP socket must be connected before it can be shutdown.
  ASSERT_THAT(connect(s_, addr_[0], addrlen_), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  const char str[] = "abc";
  ASSERT_THAT(send(s_, str, 0, 0), SyscallSucceedsWithValue(0));

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);

  EXPECT_THAT(shutdown(s_, SHUT_RD), SyscallSucceeds());

  n = -1;
  EXPECT_THAT(ioctl(s_, FIONREAD, &n), SyscallSucceedsWithValue(0));
  EXPECT_EQ(n, 0);
}

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
  EXPECT_THAT(RetryEINTR(recvmsg)(s_, &msg, MSG_ERRQUEUE),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(UdpSocketTest, SoTimestamp) {
  ASSERT_THAT(bind(s_, addr_[0], addrlen_), SyscallSucceeds());
  ASSERT_THAT(connect(t_, addr_[0], addrlen_), SyscallSucceeds());

  int v = 1;
  EXPECT_THAT(setsockopt(s_, SOL_SOCKET, SO_TIMESTAMP, &v, sizeof(v)),
              SyscallSucceeds());

  char buf[3];
  // Send zero length packet from t_ to s_.
  ASSERT_THAT(RetryEINTR(write)(t_, buf, 0), SyscallSucceedsWithValue(0));

  char cmsgbuf[CMSG_SPACE(sizeof(struct timeval))];
  msghdr msg;
  memset(&msg, 0, sizeof(msg));
  iovec iov;
  memset(&iov, 0, sizeof(iov));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  ASSERT_THAT(RetryEINTR(recvmsg)(s_, &msg, 0), SyscallSucceedsWithValue(0));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SO_TIMESTAMP);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(struct timeval)));

  struct timeval tv = {};
  memcpy(&tv, CMSG_DATA(cmsg), sizeof(struct timeval));

  ASSERT_TRUE(tv.tv_sec != 0 || tv.tv_usec != 0);
}

TEST_P(UdpSocketTest, WriteShutdownNotConnected) {
  EXPECT_THAT(shutdown(s_, SHUT_WR), SyscallFailsWithErrno(ENOTCONN));
}

INSTANTIATE_TEST_CASE_P(AllInetTests, UdpSocketTest,
                        ::testing::Values(AF_INET, AF_INET6));

}  // namespace

}  // namespace testing
}  // namespace gvisor
