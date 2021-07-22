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

#include "test/syscalls/linux/socket_ipv6_udp_unbound.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/in6.h>
#endif  //  __linux__
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Test that socket will receive IP_RECVORIGDSTADDR control message.
TEST_P(IPv6UDPUnboundSocketTest, SetAndReceiveIPReceiveOrigDstAddr) {
  auto sender = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto receiver_addr = V6Loopback();
  int level = SOL_IPV6;
  int type = IPV6_RECVORIGDSTADDR;

  ASSERT_THAT(bind(receiver->get(), AsSockAddr(&receiver_addr.addr),
                   receiver_addr.addr_len),
              SyscallSucceeds());

  // Retrieve the port bound by the receiver.
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver->get(), AsSockAddr(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  ASSERT_THAT(connect(sender->get(), AsSockAddr(&receiver_addr.addr),
                      receiver_addr.addr_len),
              SyscallSucceeds());

  // Get address and port bound by the sender.
  sockaddr_storage sender_addr_storage;
  socklen_t sender_addr_len = sizeof(sender_addr_storage);
  ASSERT_THAT(getsockname(sender->get(), AsSockAddr(&sender_addr_storage),
                          &sender_addr_len),
              SyscallSucceeds());
  ASSERT_EQ(sender_addr_len, sizeof(struct sockaddr_in6));

  // Enable IP_RECVORIGDSTADDR on socket so that we get the original destination
  // address of the datagram as auxiliary information in the control message.
  ASSERT_THAT(
      setsockopt(receiver->get(), level, type, &kSockOptOn, sizeof(kSockOptOn)),
      SyscallSucceeds());

  // Prepare message to send.
  constexpr size_t kDataLength = 1024;
  msghdr sent_msg = {};
  iovec sent_iov = {};
  char sent_data[kDataLength];
  sent_iov.iov_base = sent_data;
  sent_iov.iov_len = kDataLength;
  sent_msg.msg_iov = &sent_iov;
  sent_msg.msg_iovlen = 1;
  sent_msg.msg_flags = 0;

  ASSERT_THAT(RetryEINTR(sendmsg)(sender->get(), &sent_msg, 0),
              SyscallSucceedsWithValue(kDataLength));

  msghdr received_msg = {};
  iovec received_iov = {};
  char received_data[kDataLength];
  char received_cmsg_buf[CMSG_SPACE(sizeof(sockaddr_in6))] = {};
  size_t cmsg_data_len = sizeof(sockaddr_in6);
  received_iov.iov_base = received_data;
  received_iov.iov_len = kDataLength;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;
  received_msg.msg_controllen = CMSG_LEN(cmsg_data_len);
  received_msg.msg_control = received_cmsg_buf;

  ASSERT_THAT(RecvMsgTimeout(receiver->get(), &received_msg, 1 /*timeout*/),
              IsPosixErrorOkAndHolds(kDataLength));

  cmsghdr* cmsg = CMSG_FIRSTHDR(&received_msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(cmsg_data_len));
  EXPECT_EQ(cmsg->cmsg_level, level);
  EXPECT_EQ(cmsg->cmsg_type, type);

  // Check that the received address in the control message matches the expected
  // receiver's address.
  sockaddr_in6 received_addr = {};
  memcpy(&received_addr, CMSG_DATA(cmsg), sizeof(received_addr));
  auto orig_receiver_addr =
      reinterpret_cast<sockaddr_in6*>(&receiver_addr.addr);
  EXPECT_EQ(memcmp(&received_addr.sin6_addr, &orig_receiver_addr->sin6_addr,
                   sizeof(in6_addr)),
            0);
  EXPECT_EQ(received_addr.sin6_port, orig_receiver_addr->sin6_port);
}

}  // namespace testing
}  // namespace gvisor
