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

#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

// Tests for NETLINK_ROUTE sockets.

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Eq;

// Netlink sockets must be SOCK_DGRAM or SOCK_RAW.
TEST(NetlinkRouteTest, Types) {
  EXPECT_THAT(socket(AF_NETLINK, SOCK_STREAM, NETLINK_ROUTE),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_SEQPACKET, NETLINK_ROUTE),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_RDM, NETLINK_ROUTE),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_DCCP, NETLINK_ROUTE),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));
  EXPECT_THAT(socket(AF_NETLINK, SOCK_PACKET, NETLINK_ROUTE),
              SyscallFailsWithErrno(ESOCKTNOSUPPORT));

  int fd;
  EXPECT_THAT(fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());

  EXPECT_THAT(fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE),
              SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST(NetlinkRouteTest, AutomaticPort) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  struct sockaddr_nl addr = {};
  addr.nl_family = AF_NETLINK;

  EXPECT_THAT(
      bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());

  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));
  // This is the only netlink socket in the process, so it should get the PID as
  // the port id.
  //
  // N.B. Another process could theoretically have explicitly reserved our pid
  // as a port ID, but that is very unlikely.
  EXPECT_EQ(addr.nl_pid, getpid());
}

// Calling connect automatically binds to an automatic port.
TEST(NetlinkRouteTest, ConnectBinds) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  struct sockaddr_nl addr = {};
  addr.nl_family = AF_NETLINK;

  EXPECT_THAT(connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  socklen_t addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));

  // Each test is running in a pid namespace, so another process can explicitly
  // reserve our pid as a port ID. In this case, a negative portid value will be
  // set.
  if (static_cast<pid_t>(addr.nl_pid) > 0) {
    EXPECT_EQ(addr.nl_pid, getpid());
  }

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;

  // Connecting again is allowed, but keeps the same port.
  EXPECT_THAT(connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  addrlen = sizeof(addr);
  EXPECT_THAT(getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());
  EXPECT_EQ(addrlen, sizeof(addr));
  EXPECT_EQ(addr.nl_pid, getpid());
}

TEST(NetlinkRouteTest, GetPeerName) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  struct sockaddr_nl addr = {};
  socklen_t addrlen = sizeof(addr);

  EXPECT_THAT(getpeername(fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                          &addrlen),
              SyscallSucceeds());

  EXPECT_EQ(addrlen, sizeof(addr));
  EXPECT_EQ(addr.nl_family, AF_NETLINK);
  // Peer is the kernel if we didn't connect elsewhere.
  EXPECT_EQ(addr.nl_pid, 0);
}

using IntSockOptTest = ::testing::TestWithParam<int>;

TEST_P(IntSockOptTest, GetSockOpt) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  int res;
  socklen_t len = sizeof(res);

  EXPECT_THAT(getsockopt(fd.get(), SOL_SOCKET, GetParam(), &res, &len),
              SyscallSucceeds());

  EXPECT_EQ(len, sizeof(res));
  EXPECT_GT(res, 0);
}

INSTANTIATE_TEST_SUITE_P(NetlinkRouteTest, IntSockOptTest,
                         ::testing::Values(SO_SNDBUF, SO_RCVBUF));

// Validates the reponses to RTM_GETLINK + NLM_F_DUMP.
void CheckGetLinkResponse(const struct nlmsghdr* hdr, int seq, int port) {
  EXPECT_THAT(hdr->nlmsg_type, AnyOf(Eq(RTM_NEWLINK), Eq(NLMSG_DONE)));

  EXPECT_TRUE((hdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI)
      << std::hex << hdr->nlmsg_flags;

  EXPECT_EQ(hdr->nlmsg_seq, seq);
  EXPECT_EQ(hdr->nlmsg_pid, port);

  if (hdr->nlmsg_type != RTM_NEWLINK) {
    return;
  }

  // RTM_NEWLINK contains at least the header and ifinfomsg.
  EXPECT_GE(hdr->nlmsg_len, NLMSG_SPACE(sizeof(struct ifinfomsg)));

  // TODO: Check ifinfomsg contents and following attrs.
}

TEST(NetlinkRouteTest, GetLinkDump) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket());
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.ifm.ifi_family = AF_UNSPEC;

  // Loopback is common among all tests, check that it's found.
  bool loopbackFound = false;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req), [&](const struct nlmsghdr* hdr) {
        CheckGetLinkResponse(hdr, kSeq, port);
        if (hdr->nlmsg_type != RTM_NEWLINK) {
          return;
        }
        ASSERT_GE(hdr->nlmsg_len, NLMSG_SPACE(sizeof(struct ifinfomsg)));
        const struct ifinfomsg* msg =
            reinterpret_cast<const struct ifinfomsg*>(NLMSG_DATA(hdr));
        std::cout << "Found interface idx=" << msg->ifi_index
                  << ", type=" << std::hex << msg->ifi_type;
        if (msg->ifi_type == ARPHRD_LOOPBACK) {
          loopbackFound = true;
          EXPECT_NE(msg->ifi_flags & IFF_LOOPBACK, 0);
        }
      }));
  EXPECT_TRUE(loopbackFound);
}

TEST(NetlinkRouteTest, MsgHdrMsgTrunc) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket());

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.ifm.ifi_family = AF_UNSPEC;

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  // No destination required; it defaults to pid 0, the kernel.

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  // Small enough to ensure that the response doesn't fit.
  constexpr size_t kBufferSize = 10;
  std::vector<char> buf(kBufferSize);
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  ASSERT_THAT(RetryEINTR(recvmsg)(fd.get(), &msg, 0),
              SyscallSucceedsWithValue(kBufferSize));
  EXPECT_EQ((msg.msg_flags & MSG_TRUNC), MSG_TRUNC);
}

TEST(NetlinkRouteTest, MsgTruncMsgHdrMsgTrunc) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket());

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.ifm.ifi_family = AF_UNSPEC;

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  // No destination required; it defaults to pid 0, the kernel.

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  // Small enough to ensure that the response doesn't fit.
  constexpr size_t kBufferSize = 10;
  std::vector<char> buf(kBufferSize);
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  int res = 0;
  ASSERT_THAT(res = RetryEINTR(recvmsg)(fd.get(), &msg, MSG_TRUNC),
              SyscallSucceeds());
  EXPECT_GT(res, kBufferSize);
  EXPECT_EQ((msg.msg_flags & MSG_TRUNC), MSG_TRUNC);
}

TEST(NetlinkRouteTest, ControlMessageIgnored) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket());
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  struct request {
    struct nlmsghdr control_hdr;
    struct nlmsghdr message_hdr;
    struct ifinfomsg ifm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};

  // This control message is ignored. We still receive a response for the
  // following RTM_GETLINK.
  req.control_hdr.nlmsg_len = sizeof(req.control_hdr);
  req.control_hdr.nlmsg_type = NLMSG_DONE;
  req.control_hdr.nlmsg_seq = kSeq;

  req.message_hdr.nlmsg_len = sizeof(req.message_hdr) + sizeof(req.ifm);
  req.message_hdr.nlmsg_type = RTM_GETLINK;
  req.message_hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.message_hdr.nlmsg_seq = kSeq;

  req.ifm.ifi_family = AF_UNSPEC;

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req), [&](const struct nlmsghdr* hdr) {
        CheckGetLinkResponse(hdr, kSeq, port);
      }));
}

TEST(NetlinkRouteTest, GetAddrDump) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket());
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  struct request {
    struct nlmsghdr hdr;
    struct rtgenmsg rgm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req;
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.rgm.rtgen_family = AF_UNSPEC;

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req), [&](const struct nlmsghdr* hdr) {
        EXPECT_THAT(hdr->nlmsg_type, AnyOf(Eq(RTM_NEWADDR), Eq(NLMSG_DONE)));

        EXPECT_TRUE((hdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI)
            << std::hex << hdr->nlmsg_flags;

        EXPECT_EQ(hdr->nlmsg_seq, kSeq);
        EXPECT_EQ(hdr->nlmsg_pid, port);

        if (hdr->nlmsg_type != RTM_NEWADDR) {
          return;
        }

        // RTM_NEWADDR contains at least the header and ifaddrmsg.
        EXPECT_GE(hdr->nlmsg_len, sizeof(*hdr) + sizeof(struct ifaddrmsg));

        // TODO: Check ifaddrmsg contents and following attrs.
      }));
}

TEST(NetlinkRouteTest, LookupAll) {
  struct ifaddrs* if_addr_list = nullptr;
  auto cleanup = Cleanup([&if_addr_list]() { freeifaddrs(if_addr_list); });

  // Not a syscall but we can use the syscall matcher as glibc sets errno.
  ASSERT_THAT(getifaddrs(&if_addr_list), SyscallSucceeds());

  int count = 0;
  for (struct ifaddrs* i = if_addr_list; i; i = i->ifa_next) {
    if (!i->ifa_addr || (i->ifa_addr->sa_family != AF_INET &&
                         i->ifa_addr->sa_family != AF_INET6)) {
      continue;
    }
    count++;
  }
  ASSERT_GT(count, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
