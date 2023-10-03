// Copyright 2023 The gVisor Authors.
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
#include <ifaddrs.h>
#include <linux/fib_rules.h>
#include <linux/if.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Tests for NETLINK_SOCK_DIAG sockets.

namespace gvisor {
namespace testing {

namespace {

constexpr uint32_t kSeq = 12345;

class NetlinkSockDiagTest : public ::testing::TestWithParam<int> {};

TEST_P(NetlinkSockDiagTest, NetlinkSendRecvSingleMsg) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_SOCK_DIAG));
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  auto listen_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  // Initialize address to the loopback one.
  sockaddr_storage src_addr = InetLoopbackAddr(GetParam());
  socklen_t addrlen = sizeof(src_addr);
  // Bind to some port then start listening.
  ASSERT_THAT(bind(listen_socket.get(),
                   reinterpret_cast<struct sockaddr*>(&src_addr), addrlen),
              SyscallSucceeds());
  ASSERT_THAT(listen(listen_socket.get(), SOMAXCONN), SyscallSucceeds());
  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(
      getsockname(listen_socket.get(),
                  reinterpret_cast<struct sockaddr*>(&src_addr), &addrlen),
      SyscallSucceeds());

  auto send_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(GetParam(), SOCK_STREAM, IPPROTO_TCP));
  // Initialize address to the loopback one.
  sockaddr_storage dst_addr =
      ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddrZeroPort(GetParam()));
  addrlen = sizeof(dst_addr);
  auto reservation = ReserveLocalPort(GetParam(), dst_addr, addrlen);
  ASSERT_NE(GetPort(dst_addr).value(), 0);
  ASSERT_THAT(RetryEINTR(connect)(send_socket.get(),
                                  reinterpret_cast<struct sockaddr*>(&src_addr),
                                  addrlen),
              SyscallSucceeds());
  // Accept the connection.
  auto recv_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_socket.get(), nullptr, nullptr));

  struct request {
    struct nlmsghdr hdr;
    struct inet_diag_req_v2 r;
  };
  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;

  req.r.sdiag_family = GetParam();
  req.r.sdiag_protocol = IPPROTO_TCP;
  if (GetParam() == AF_INET) {
    struct sockaddr_in* src = (struct sockaddr_in*)&src_addr;
    struct sockaddr_in* dst = (struct sockaddr_in*)&dst_addr;
    req.r.id.idiag_sport = htons(src->sin_port);
    req.r.id.idiag_dport = htons(dst->sin_port);
    req.r.id.idiag_src[0] = htonl(src->sin_addr.s_addr);
    req.r.id.idiag_dst[0] = htonl(dst->sin_addr.s_addr);
  } else {
    struct sockaddr_in6* src = (struct sockaddr_in6*)&src_addr;
    struct sockaddr_in6* dst = (struct sockaddr_in6*)&dst_addr;
    req.r.id.idiag_sport = htons(src->sin6_port);
    req.r.id.idiag_dport = htons(dst->sin6_port);

    uint8_t* saddr = src->sin6_addr.s6_addr;
    req.r.id.idiag_src[0] = htonl(*((uint32_t*)&saddr[0]));
    req.r.id.idiag_src[1] = htonl(*((uint32_t*)&saddr[4]));
    req.r.id.idiag_src[2] = htonl(*((uint32_t*)&saddr[8]));
    req.r.id.idiag_src[3] = htonl(*((uint32_t*)&saddr[12]));

    uint8_t* daddr = dst->sin6_addr.s6_addr;
    req.r.id.idiag_dst[0] = htonl(*((uint32_t*)&daddr[0]));
    req.r.id.idiag_dst[1] = htonl(*((uint32_t*)&daddr[4]));
    req.r.id.idiag_dst[2] = htonl(*((uint32_t*)&daddr[8]));
    req.r.id.idiag_dst[3] = htonl(*((uint32_t*)&daddr[12]));
  }
  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  constexpr size_t kBufferSize = 4096;
  std::vector<char> buf(kBufferSize);
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  int ret = RetryEINTR(recvmsg)(fd.get(), &msg, 0);
  for (struct nlmsghdr* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
       NLMSG_OK(hdr, ret); hdr = NLMSG_NEXT(hdr, ret)) {
    EXPECT_THAT(hdr->nlmsg_type, SOCK_DIAG_BY_FAMILY);
    EXPECT_TRUE(hdr->nlmsg_flags == 0) << std::hex << hdr->nlmsg_flags;
    EXPECT_EQ(hdr->nlmsg_seq, kSeq);
    EXPECT_EQ(hdr->nlmsg_pid, port);

    // Message contains at least the header and inet_diag_msg.
    ASSERT_GE(hdr->nlmsg_len, NLMSG_SPACE(sizeof(struct inet_diag_msg)));
    const struct inet_diag_msg* r =
        reinterpret_cast<const struct inet_diag_msg*>(NLMSG_DATA(hdr));
    EXPECT_EQ(r->idiag_uid, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(AllNetlinkSockDiagTests, NetlinkSockDiagTest,
                         ::testing::Values(AF_INET, AF_INET6));
}  // namespace

}  // namespace testing
}  // namespace gvisor
