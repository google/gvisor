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

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST(BindToDeviceBroadcast, UdpDoesntReceiveBroadcastOnAnyFromUnboundSender) {
  const FileDescriptor receiver =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
  string if_name = "eth1";
  ASSERT_THAT(setsockopt(receiver.get(), SOL_SOCKET, SO_BINDTODEVICE,
                         if_name.c_str(), if_name.size() + 1),
              SyscallSucceeds());
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver.get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver.get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  const FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  ASSERT_THAT(setsockopt(sender.get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  ASSERT_THAT(fcntl(receiver.get(), F_SETFL, O_NONBLOCK), SyscallSucceeds());

  auto sendto_addr = V4Broadcast();
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  EXPECT_THAT(RetryEINTR(sendto)(sender.get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(receiver.get(), &recv_buf, sizeof(recv_buf), 0),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

TEST(BindToDeviceBroadcast, UdpDoesntReceiveBroadcastOnAnyFromBoundSender) {
  const FileDescriptor receiver =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
  string if_name = "eth1";
  ASSERT_THAT(setsockopt(receiver.get(), SOL_SOCKET, SO_BINDTODEVICE,
                         if_name.c_str(), if_name.size() + 1),
              SyscallSucceeds());
  auto receiver_addr = V4Any();
  ASSERT_THAT(
      bind(receiver.get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(receiver.get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);

  const FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  ASSERT_THAT(setsockopt(sender.get(), SOL_SOCKET, SO_BROADCAST, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

  auto sender_bind_addr = V4Loopback();
  ASSERT_THAT(
      bind(sender.get(), reinterpret_cast<sockaddr*>(&sender_bind_addr.addr),
           sender_bind_addr.addr_len),
      SyscallSucceeds());

  ASSERT_THAT(fcntl(receiver.get(), F_SETFL, O_NONBLOCK), SyscallSucceeds());

  auto sendto_addr = V4Broadcast();
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  reinterpret_cast<sockaddr_in*>(&sendto_addr.addr)->sin_port =
      reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_port;
  EXPECT_THAT(RetryEINTR(sendto)(sender.get(), send_buf, sizeof(send_buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr.addr),
                                 sendto_addr.addr_len),
              SyscallSucceedsWithValue(sizeof(send_buf)));

  char recv_buf[sizeof(send_buf)] = {};
  EXPECT_THAT(RetryEINTR(recv)(receiver.get(), &recv_buf, sizeof(recv_buf), 0),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

}  // namespace testing
}  // namespace gvisor
