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

#include "test/syscalls/linux/socket_ip_udp_unbound_netlink_util.h"

namespace gvisor {
namespace testing {

const size_t kSendBufSize = 200;

void IPUDPUnboundSocketNetlinkTest::TestSendRecv(TestAddress sender_addr,
                                                 TestAddress receiver_addr) {
  auto snd_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcv_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  EXPECT_THAT(
      bind(snd_sock->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  EXPECT_THAT(
      bind(rcv_sock->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(rcv_sock->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
  char send_buf[kSendBufSize];
  RandomizeBuffer(send_buf, kSendBufSize);
  EXPECT_THAT(
      RetryEINTR(sendto)(snd_sock->get(), send_buf, kSendBufSize, 0,
                         reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                         receiver_addr.addr_len),
      SyscallSucceedsWithValue(kSendBufSize));

  // Check that we received the packet.
  char recv_buf[kSendBufSize] = {};
  ASSERT_THAT(RetryEINTR(recv)(rcv_sock->get(), recv_buf, kSendBufSize, 0),
              SyscallSucceedsWithValue(kSendBufSize));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, kSendBufSize));
}

}  // namespace testing
}  // namespace gvisor
