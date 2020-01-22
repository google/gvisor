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
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
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

// Parameters for SockOptTest. They are:
// 0: Socket option to query.
// 1: A predicate to run on the returned sockopt value. Should return true if
//    the value is considered ok.
// 2: A description of what the sockopt value is expected to be. Should complete
//    the sentence "<value> was unexpected, expected <description>"
using SockOptTest = ::testing::TestWithParam<
    std::tuple<int, std::function<bool(int)>, std::string>>;

TEST_P(SockOptTest, GetSockOpt) {
  int sockopt = std::get<0>(GetParam());
  auto verifier = std::get<1>(GetParam());
  std::string verifier_description = std::get<2>(GetParam());

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  int res;
  socklen_t len = sizeof(res);

  EXPECT_THAT(getsockopt(fd.get(), SOL_SOCKET, sockopt, &res, &len),
              SyscallSucceeds());

  EXPECT_EQ(len, sizeof(res));
  EXPECT_TRUE(verifier(res)) << absl::StrFormat(
      "getsockopt(%d, SOL_SOCKET, %d, &res, &len) => res=%d was unexpected, "
      "expected %s",
      fd.get(), sockopt, res, verifier_description);
}

std::function<bool(int)> IsPositive() {
  return [](int val) { return val > 0; };
}

std::function<bool(int)> IsEqual(int target) {
  return [target](int val) { return val == target; };
}

INSTANTIATE_TEST_SUITE_P(
    NetlinkRouteTest, SockOptTest,
    ::testing::Values(
        std::make_tuple(SO_SNDBUF, IsPositive(), "positive send buffer size"),
        std::make_tuple(SO_RCVBUF, IsPositive(),
                        "positive receive buffer size"),
        std::make_tuple(SO_TYPE, IsEqual(SOCK_RAW),
                        absl::StrFormat("SOCK_RAW (%d)", SOCK_RAW)),
        std::make_tuple(SO_DOMAIN, IsEqual(AF_NETLINK),
                        absl::StrFormat("AF_NETLINK (%d)", AF_NETLINK)),
        std::make_tuple(SO_PROTOCOL, IsEqual(NETLINK_ROUTE),
                        absl::StrFormat("NETLINK_ROUTE (%d)", NETLINK_ROUTE)),
        std::make_tuple(SO_PASSCRED, IsEqual(0), "0")));

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

  // TODO(mpratt): Check ifinfomsg contents and following attrs.
}

TEST(NetlinkRouteTest, GetLinkDump) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
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
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
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
      },
      false));
  EXPECT_TRUE(loopbackFound);
}

TEST(NetlinkRouteTest, MsgHdrMsgUnsuppType) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  // If type & 0x3 is equal to 0x2, this means a get request
  // which doesn't require CAP_SYS_ADMIN.
  req.hdr.nlmsg_type = ((__RTM_MAX + 1024) & (~0x3)) | 0x2;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.ifm.ifi_family = AF_UNSPEC;

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
        EXPECT_THAT(hdr->nlmsg_type, Eq(NLMSG_ERROR));
        EXPECT_EQ(hdr->nlmsg_seq, kSeq);
        EXPECT_GE(hdr->nlmsg_len, sizeof(*hdr) + sizeof(struct nlmsgerr));

        const struct nlmsgerr* msg =
            reinterpret_cast<const struct nlmsgerr*>(NLMSG_DATA(hdr));
        EXPECT_EQ(msg->error, -EOPNOTSUPP);
      },
      true));
}

TEST(NetlinkRouteTest, MsgHdrMsgTrunc) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

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
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

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
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
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
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
        CheckGetLinkResponse(hdr, kSeq, port);
      },
      false));
}

TEST(NetlinkRouteTest, GetAddrDump) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
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
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
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

        // TODO(mpratt): Check ifaddrmsg contents and following attrs.
      },
      false));
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

// GetRouteDump tests a RTM_GETROUTE + NLM_F_DUMP request.
TEST(NetlinkRouteTest, GetRouteDump) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  struct request {
    struct nlmsghdr hdr;
    struct rtmsg rtm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETROUTE;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.rtm.rtm_family = AF_UNSPEC;

  bool routeFound = false;
  bool dstFound = true;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
        // Validate the reponse to RTM_GETROUTE + NLM_F_DUMP.
        EXPECT_THAT(hdr->nlmsg_type, AnyOf(Eq(RTM_NEWROUTE), Eq(NLMSG_DONE)));

        EXPECT_TRUE((hdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI)
            << std::hex << hdr->nlmsg_flags;

        EXPECT_EQ(hdr->nlmsg_seq, kSeq);
        EXPECT_EQ(hdr->nlmsg_pid, port);

        // The test should not proceed if it's not a RTM_NEWROUTE message.
        if (hdr->nlmsg_type != RTM_NEWROUTE) {
          return;
        }

        // RTM_NEWROUTE contains at least the header and rtmsg.
        ASSERT_GE(hdr->nlmsg_len, NLMSG_SPACE(sizeof(struct rtmsg)));
        const struct rtmsg* msg =
            reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(hdr));
        // NOTE: rtmsg fields are char fields.
        std::cout << "Found route table=" << static_cast<int>(msg->rtm_table)
                  << ", protocol=" << static_cast<int>(msg->rtm_protocol)
                  << ", scope=" << static_cast<int>(msg->rtm_scope)
                  << ", type=" << static_cast<int>(msg->rtm_type);

        int len = RTM_PAYLOAD(hdr);
        bool rtDstFound = false;
        for (struct rtattr* attr = RTM_RTA(msg); RTA_OK(attr, len);
             attr = RTA_NEXT(attr, len)) {
          if (attr->rta_type == RTA_DST) {
            char address[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, RTA_DATA(attr), address, sizeof(address));
            std::cout << ", dst=" << address;
            rtDstFound = true;
          }
        }

        std::cout << std::endl;

        if (msg->rtm_table == RT_TABLE_MAIN) {
          routeFound = true;
          dstFound = rtDstFound && dstFound;
        }
      },
      false));
  // At least one route found in main route table.
  EXPECT_TRUE(routeFound);
  // Found RTA_DST for each route in main table.
  EXPECT_TRUE(dstFound);
}

// RecvmsgTrunc tests the recvmsg MSG_TRUNC flag with zero length output
// buffer. MSG_TRUNC with a zero length buffer should consume subsequent
// messages off the socket.
TEST(NetlinkRouteTest, RecvmsgTrunc) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

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

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  iov.iov_base = NULL;
  iov.iov_len = 0;

  int trunclen, trunclen2;

  // Note: This test assumes at least two messages are returned by the
  // RTM_GETADDR request. That means at least one RTM_NEWLINK message and one
  // NLMSG_DONE message. We cannot read all the messages without blocking
  // because we would need to read the message into a buffer and check the
  // nlmsg_type for NLMSG_DONE. However, the test depends on reading into a
  // zero-length buffer.

  // First, call recvmsg with MSG_TRUNC. This will read the full message from
  // the socket and return it's full length. Subsequent calls to recvmsg will
  // read the next messages from the socket.
  ASSERT_THAT(trunclen = RetryEINTR(recvmsg)(fd.get(), &msg, MSG_TRUNC),
              SyscallSucceeds());

  // Message should always be truncated. However, While the destination iov is
  // zero length, MSG_TRUNC returns the size of the next message so it should
  // not be zero.
  ASSERT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
  ASSERT_NE(trunclen, 0);
  // Returned length is at least the header and ifaddrmsg.
  EXPECT_GE(trunclen, sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));

  // Reset the msg_flags to make sure that the recvmsg call is setting them
  // properly.
  msg.msg_flags = 0;

  // Make a second recvvmsg call to get the next message.
  ASSERT_THAT(trunclen2 = RetryEINTR(recvmsg)(fd.get(), &msg, MSG_TRUNC),
              SyscallSucceeds());
  ASSERT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
  ASSERT_NE(trunclen2, 0);

  // Assert that the received messages are not the same.
  //
  // We are calling recvmsg with a zero length buffer so we have no way to
  // inspect the messages to make sure they are not equal in value. The best
  // we can do is to compare their lengths.
  ASSERT_NE(trunclen, trunclen2);
}

// RecvmsgTruncPeek tests recvmsg with the combination of the MSG_TRUNC and
// MSG_PEEK flags and a zero length output buffer. This is normally used to
// read the full length of the next message on the socket without consuming
// it, so a properly sized buffer can be allocated to store the message. This
// test tests that scenario.
TEST(NetlinkRouteTest, RecvmsgTruncPeek) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

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

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  int type = -1;
  do {
    int peeklen;
    int len;

    iov.iov_base = NULL;
    iov.iov_len = 0;

    // Call recvmsg with MSG_PEEK and MSG_TRUNC. This will peek at the message
    // and return it's full length.
    // See: MSG_TRUNC http://man7.org/linux/man-pages/man2/recv.2.html
    ASSERT_THAT(
        peeklen = RetryEINTR(recvmsg)(fd.get(), &msg, MSG_PEEK | MSG_TRUNC),
        SyscallSucceeds());

    // Message should always be truncated.
    ASSERT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
    ASSERT_NE(peeklen, 0);

    // Reset the message flags for the next call.
    msg.msg_flags = 0;

    // Make the actual call to recvmsg to get the actual data. We will use
    // the length returned from the peek call for the allocated buffer size..
    std::vector<char> buf(peeklen);
    iov.iov_base = buf.data();
    iov.iov_len = buf.size();
    ASSERT_THAT(len = RetryEINTR(recvmsg)(fd.get(), &msg, 0),
                SyscallSucceeds());

    // Message should not be truncated since we allocated the correct buffer
    // size.
    EXPECT_NE(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);

    // MSG_PEEK should have left data on the socket and the subsequent call
    // with should have retrieved the same data. Both calls should have
    // returned the message's full length so they should be equal.
    ASSERT_NE(len, 0);
    ASSERT_EQ(peeklen, len);

    for (struct nlmsghdr* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
         NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
      type = hdr->nlmsg_type;
    }
  } while (type != NLMSG_DONE && type != NLMSG_ERROR);
}

// No SCM_CREDENTIALS are received without SO_PASSCRED set.
TEST(NetlinkRouteTest, NoPasscredNoCreds) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  ASSERT_THAT(setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &kSockOptOff,
                         sizeof(kSockOptOff)),
              SyscallSucceeds());

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

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  iov.iov_base = NULL;
  iov.iov_len = 0;

  char control[CMSG_SPACE(sizeof(struct ucred))] = {};
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  // Note: This test assumes at least one message is returned by the
  // RTM_GETADDR request.
  ASSERT_THAT(RetryEINTR(recvmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  // No control messages.
  EXPECT_EQ(CMSG_FIRSTHDR(&msg), nullptr);
}

// SCM_CREDENTIALS are received with SO_PASSCRED set.
TEST(NetlinkRouteTest, PasscredCreds) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  ASSERT_THAT(setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());

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

  struct iovec iov = {};
  iov.iov_base = &req;
  iov.iov_len = sizeof(req);

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  iov.iov_base = NULL;
  iov.iov_len = 0;

  char control[CMSG_SPACE(sizeof(struct ucred))] = {};
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  // Note: This test assumes at least one message is returned by the
  // RTM_GETADDR request.
  ASSERT_THAT(RetryEINTR(recvmsg)(fd.get(), &msg, 0), SyscallSucceeds());

  struct ucred creds;
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(creds)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);

  memcpy(&creds, CMSG_DATA(cmsg), sizeof(creds));

  // The peer is the kernel, which is "PID" 0.
  EXPECT_EQ(creds.pid, 0);
  // The kernel identifies as root. Also allow nobody in case this test is
  // running in a userns without root mapped.
  EXPECT_THAT(creds.uid, AnyOf(Eq(0), Eq(65534)));
  EXPECT_THAT(creds.gid, AnyOf(Eq(0), Eq(65534)));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
