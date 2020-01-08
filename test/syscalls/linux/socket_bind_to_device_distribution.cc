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
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_bind_to_device_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

using std::string;
using std::vector;

struct EndpointConfig {
  std::string bind_to_device;
  double expected_ratio;
};

struct DistributionTestCase {
  std::string name;
  std::vector<EndpointConfig> endpoints;
};

struct ListenerConnector {
  TestAddress listener;
  TestAddress connector;
};

// Test fixture for SO_BINDTODEVICE tests the distribution of packets received
// with varying SO_BINDTODEVICE settings.
class BindToDeviceDistributionTest
    : public ::testing::TestWithParam<
          ::testing::tuple<ListenerConnector, DistributionTestCase>> {
 protected:
  void SetUp() override {
    printf("Testing case: %s, listener=%s, connector=%s\n",
           ::testing::get<1>(GetParam()).name.c_str(),
           ::testing::get<0>(GetParam()).listener.description.c_str(),
           ::testing::get<0>(GetParam()).connector.description.c_str());
    ASSERT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)))
        << "CAP_NET_RAW is required to use SO_BINDTODEVICE";
  }
};

PosixErrorOr<uint16_t> AddrPort(int family, sockaddr_storage const& addr) {
  switch (family) {
    case AF_INET:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in const*>(&addr)->sin_port);
    case AF_INET6:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in6 const*>(&addr)->sin6_port);
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

PosixError SetAddrPort(int family, sockaddr_storage* addr, uint16_t port) {
  switch (family) {
    case AF_INET:
      reinterpret_cast<sockaddr_in*>(addr)->sin_port = port;
      return NoError();
    case AF_INET6:
      reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = port;
      return NoError();
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

// Binds sockets to different devices and then creates many TCP connections.
// Checks that the distribution of connections received on the sockets matches
// the expectation.
//
// TODO(gvisor.dev/issue/940): Remove _NoRandomSave when portHint/stack.Seed is
// saved/restored.
TEST_P(BindToDeviceDistributionTest, Tcp_NoRandomSave) {
  auto const& [listener_connector, test] = GetParam();

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;
  constexpr int kConnectAttempts = 4096;

  auto interface_names = GetInterfaceNames();

  // Create the listening sockets.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (auto const& endpoint : test.endpoints) {
    if (!endpoint.bind_to_device.empty() &&
        interface_names.find(endpoint.bind_to_device) ==
            interface_names.end()) {
      all_tunnels.push_back(
          ASSERT_NO_ERRNO_AND_VALUE(Tunnel::New(endpoint.bind_to_device)));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());
    ASSERT_THAT(listen(fd, kConnectAttempts), SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  std::atomic<int> connects_received = ATOMIC_VAR_INIT(0);
  std::vector<int> accept_counts(listener_fds.size(), 0);
  std::vector<std::unique_ptr<ScopedThread>> listen_threads(
      listener_fds.size());

  for (int i = 0; i < listener_fds.size(); i++) {
    listen_threads[i] = absl::make_unique<ScopedThread>(
        [&listener_fds, &accept_counts, &connects_received, i,
         kConnectAttempts]() {
          do {
            auto fd = Accept(listener_fds[i].get(), nullptr, nullptr);
            if (!fd.ok()) {
              // Another thread has shutdown our read side causing the accept to
              // fail.
              ASSERT_GE(connects_received, kConnectAttempts)
                  << "errno = " << fd.error();
              return;
            }
            // Receive some data from a socket to be sure that the connect()
            // system call has been completed on another side.
            int data;
            EXPECT_THAT(
                RetryEINTR(recv)(fd.ValueOrDie().get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
            accept_counts[i]++;
          } while (++connects_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (auto const& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        });
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    FileDescriptor const fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(
        RetryEINTR(connect)(fd.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                            connector.addr_len),
        SyscallSucceeds());

    EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                SyscallSucceedsWithValue(sizeof(i)));
  }

  // Join threads to be sure that all connections have been counted.
  for (auto const& listen_thread : listen_threads) {
    listen_thread->Join();
  }
  // Check that connections are distributed correctly among listening sockets.
  for (int i = 0; i < accept_counts.size(); i++) {
    EXPECT_THAT(
        accept_counts[i],
        EquivalentWithin(static_cast<int>(kConnectAttempts *
                                          test.endpoints[i].expected_ratio),
                         0.10))
        << "endpoint " << i << " got the wrong number of packets";
  }
}

// Binds sockets to different devices and then sends many UDP packets.  Checks
// that the distribution of packets received on the sockets matches the
// expectation.
TEST_P(BindToDeviceDistributionTest, Udp) {
  auto const& [listener_connector, test] = GetParam();

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;

  auto interface_names = GetInterfaceNames();

  // Create the listening socket.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (auto const& endpoint : test.endpoints) {
    if (!endpoint.bind_to_device.empty() &&
        interface_names.find(endpoint.bind_to_device) ==
            interface_names.end()) {
      all_tunnels.push_back(
          ASSERT_NO_ERRNO_AND_VALUE(Tunnel::New(endpoint.bind_to_device)));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(
        ASSERT_NO_ERRNO_AND_VALUE(Socket(listener.family(), SOCK_DGRAM, 0)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> packets_received = ATOMIC_VAR_INIT(0);
  std::vector<int> packets_per_socket(listener_fds.size(), 0);
  std::vector<std::unique_ptr<ScopedThread>> receiver_threads(
      listener_fds.size());

  for (int i = 0; i < listener_fds.size(); i++) {
    receiver_threads[i] = absl::make_unique<ScopedThread>(
        [&listener_fds, &packets_per_socket, &packets_received, i]() {
          do {
            struct sockaddr_storage addr = {};
            socklen_t addrlen = sizeof(addr);
            int data;

            auto ret = RetryEINTR(recvfrom)(
                listener_fds[i].get(), &data, sizeof(data), 0,
                reinterpret_cast<struct sockaddr*>(&addr), &addrlen);

            if (packets_received < kConnectAttempts) {
              ASSERT_THAT(ret, SyscallSucceedsWithValue(sizeof(data)));
            }

            if (ret != sizeof(data)) {
              // Another thread may have shutdown our read side causing the
              // recvfrom to fail.
              break;
            }

            packets_received++;
            packets_per_socket[i]++;

            // A response is required to synchronize with the main thread,
            // otherwise the main thread can send more than can fit into receive
            // queues.
            EXPECT_THAT(RetryEINTR(sendto)(
                            listener_fds[i].get(), &data, sizeof(data), 0,
                            reinterpret_cast<sockaddr*>(&addr), addrlen),
                        SyscallSucceedsWithValue(sizeof(data)));
          } while (packets_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (auto const& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        });
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    FileDescriptor const fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(connector.family(), SOCK_DGRAM, 0));
    EXPECT_THAT(RetryEINTR(sendto)(fd.get(), &i, sizeof(i), 0,
                                   reinterpret_cast<sockaddr*>(&conn_addr),
                                   connector.addr_len),
                SyscallSucceedsWithValue(sizeof(i)));
    int data;
    EXPECT_THAT(RetryEINTR(recv)(fd.get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
  }

  // Join threads to be sure that all connections have been counted.
  for (auto const& receiver_thread : receiver_threads) {
    receiver_thread->Join();
  }
  // Check that packets are distributed correctly among listening sockets.
  for (int i = 0; i < packets_per_socket.size(); i++) {
    EXPECT_THAT(
        packets_per_socket[i],
        EquivalentWithin(static_cast<int>(kConnectAttempts *
                                          test.endpoints[i].expected_ratio),
                         0.10))
        << "endpoint " << i << " got the wrong number of packets";
  }
}

std::vector<DistributionTestCase> GetDistributionTestCases() {
  return std::vector<DistributionTestCase>{
      {"Even distribution among sockets not bound to device",
       {{"", 1. / 3}, {"", 1. / 3}, {"", 1. / 3}}},
      {"Sockets bound to other interfaces get no packets",
       {{"eth1", 0}, {"", 1. / 2}, {"", 1. / 2}}},
      {"Bound has priority over unbound", {{"eth1", 0}, {"", 0}, {"lo", 1}}},
      {"Even distribution among sockets bound to device",
       {{"eth1", 0}, {"lo", 1. / 2}, {"lo", 1. / 2}}},
  };
}

INSTANTIATE_TEST_SUITE_P(
    BindToDeviceTest, BindToDeviceDistributionTest,
    ::testing::Combine(::testing::Values(
                           // Listeners bound to IPv4 addresses refuse
                           // connections using IPv6 addresses.
                           ListenerConnector{V4Any(), V4Loopback()},
                           ListenerConnector{V4Loopback(), V4MappedLoopback()}),
                       ::testing::ValuesIn(GetDistributionTestCases())));

}  // namespace testing
}  // namespace gvisor
