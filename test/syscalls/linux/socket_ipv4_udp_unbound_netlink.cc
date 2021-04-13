// Copyright 2020 The gVisor Authors.
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

#include "test/syscalls/linux/socket_ipv4_udp_unbound_netlink.h"

#include <arpa/inet.h>
#include <poll.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"

namespace gvisor {
namespace testing {

constexpr size_t kSendBufSize = 200;

// Checks that the loopback interface considers itself bound to all IPs in an
// associated subnet.
TEST_P(IPv4UDPUnboundSocketNetlinkTest, JoinSubnet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Add an IP address to the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  struct in_addr addr;
  ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.1", &addr));
  ASSERT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET,
                                   /*prefixlen=*/24, &addr, sizeof(addr)));
  Cleanup defer_addr_removal = Cleanup(
      [loopback_link = std::move(loopback_link), addr = std::move(addr)] {
        EXPECT_NO_ERRNO(LinkDelLocalAddr(loopback_link.index, AF_INET,
                                         /*prefixlen=*/24, &addr,
                                         sizeof(addr)));
      });

  auto snd_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcv_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Send from an unassigned address but an address that is in the subnet
  // associated with the loopback interface.
  TestAddress sender_addr("V4NotAssignd1");
  sender_addr.addr.ss_family = AF_INET;
  sender_addr.addr_len = sizeof(sockaddr_in);
  ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.2",
                         &(reinterpret_cast<sockaddr_in*>(&sender_addr.addr)
                               ->sin_addr.s_addr)));
  ASSERT_THAT(bind(snd_sock->get(), AsSockAddr(&sender_addr.addr),
                   sender_addr.addr_len),
              SyscallSucceeds());

  // Send the packet to an unassigned address but an address that is in the
  // subnet associated with the loopback interface.
  TestAddress receiver_addr("V4NotAssigned2");
  receiver_addr.addr.ss_family = AF_INET;
  receiver_addr.addr_len = sizeof(sockaddr_in);
  ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.254",
                         &(reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)
                               ->sin_addr.s_addr)));
  ASSERT_THAT(bind(rcv_sock->get(), AsSockAddr(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(rcv_sock->get(), AsSockAddr(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  ASSERT_EQ(receiver_addr_len, receiver_addr.addr_len);
  char send_buf[kSendBufSize];
  RandomizeBuffer(send_buf, kSendBufSize);
  ASSERT_THAT(RetryEINTR(sendto)(snd_sock->get(), send_buf, kSendBufSize, 0,
                                 AsSockAddr(&receiver_addr.addr),
                                 receiver_addr.addr_len),
              SyscallSucceedsWithValue(kSendBufSize));

  // Check that we received the packet.
  char recv_buf[kSendBufSize] = {};
  ASSERT_THAT(RetryEINTR(recv)(rcv_sock->get(), recv_buf, kSendBufSize, 0),
              SyscallSucceedsWithValue(kSendBufSize));
  ASSERT_EQ(0, memcmp(send_buf, recv_buf, kSendBufSize));
}

// Tests that broadcast packets are delivered to all interested sockets
// (wildcard and broadcast address specified sockets).
//
// Note, we cannot test the IPv4 Broadcast (255.255.255.255) because we do
// not have a route to it.
TEST_P(IPv4UDPUnboundSocketNetlinkTest, ReuseAddrSubnetDirectedBroadcast) {
  constexpr uint16_t kPort = 9876;
  // Wait up to 20 seconds for the data.
  constexpr int kPollTimeoutMs = 20000;
  // Number of sockets per socket type.
  constexpr int kNumSocketsPerType = 2;

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Add an IP address to the loopback interface.
  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  struct in_addr addr;
  ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.1", &addr));
  ASSERT_NO_ERRNO(LinkAddLocalAddr(loopback_link.index, AF_INET,
                                   24 /* prefixlen */, &addr, sizeof(addr)));
  Cleanup defer_addr_removal = Cleanup(
      [loopback_link = std::move(loopback_link), addr = std::move(addr)] {
        EXPECT_NO_ERRNO(LinkDelLocalAddr(loopback_link.index, AF_INET,
                                         /*prefixlen=*/24, &addr,
                                         sizeof(addr)));
      });

  TestAddress broadcast_address("SubnetBroadcastAddress");
  broadcast_address.addr.ss_family = AF_INET;
  broadcast_address.addr_len = sizeof(sockaddr_in);
  auto broadcast_address_in =
      reinterpret_cast<sockaddr_in*>(&broadcast_address.addr);
  ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.255",
                         &broadcast_address_in->sin_addr.s_addr));
  broadcast_address_in->sin_port = htons(kPort);

  TestAddress any_address = V4Any();
  reinterpret_cast<sockaddr_in*>(&any_address.addr)->sin_port = htons(kPort);

  // We create sockets bound to both the wildcard address and the broadcast
  // address to make sure both of these types of "broadcast interested" sockets
  // receive broadcast packets.
  std::vector<std::unique_ptr<FileDescriptor>> socks;
  for (bool bind_wildcard : {false, true}) {
    // Create multiple sockets for each type of "broadcast interested"
    // socket so we can test that all sockets receive the broadcast packet.
    for (int i = 0; i < kNumSocketsPerType; i++) {
      auto sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
      auto idx = socks.size();

      ASSERT_THAT(setsockopt(sock->get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                             sizeof(kSockOptOn)),
                  SyscallSucceedsWithValue(0))
          << "socks[" << idx << "]";

      ASSERT_THAT(setsockopt(sock->get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                             sizeof(kSockOptOn)),
                  SyscallSucceedsWithValue(0))
          << "socks[" << idx << "]";

      if (bind_wildcard) {
        ASSERT_THAT(bind(sock->get(), AsSockAddr(&any_address.addr),
                         any_address.addr_len),
                    SyscallSucceeds())
            << "socks[" << idx << "]";
      } else {
        ASSERT_THAT(bind(sock->get(), AsSockAddr(&broadcast_address.addr),
                         broadcast_address.addr_len),
                    SyscallSucceeds())
            << "socks[" << idx << "]";
      }

      socks.push_back(std::move(sock));
    }
  }

  char send_buf[kSendBufSize];
  RandomizeBuffer(send_buf, kSendBufSize);

  // Broadcasts from each socket should be received by every socket (including
  // the sending socket).
  for (long unsigned int w = 0; w < socks.size(); w++) {
    auto& w_sock = socks[w];
    ASSERT_THAT(RetryEINTR(sendto)(w_sock->get(), send_buf, kSendBufSize, 0,
                                   AsSockAddr(&broadcast_address.addr),
                                   broadcast_address.addr_len),
                SyscallSucceedsWithValue(kSendBufSize))
        << "write socks[" << w << "]";

    // Check that we received the packet on all sockets.
    for (long unsigned int r = 0; r < socks.size(); r++) {
      auto& r_sock = socks[r];

      struct pollfd poll_fd = {r_sock->get(), POLLIN, 0};
      EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
                  SyscallSucceedsWithValue(1))
          << "write socks[" << w << "] & read socks[" << r << "]";

      char recv_buf[kSendBufSize] = {};
      EXPECT_THAT(RetryEINTR(recv)(r_sock->get(), recv_buf, kSendBufSize, 0),
                  SyscallSucceedsWithValue(kSendBufSize))
          << "write socks[" << w << "] & read socks[" << r << "]";
      EXPECT_EQ(0, memcmp(send_buf, recv_buf, kSendBufSize))
          << "write socks[" << w << "] & read socks[" << r << "]";
    }
  }
}

}  // namespace testing
}  // namespace gvisor
