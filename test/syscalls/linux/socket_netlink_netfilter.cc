// Copyright 2025 The gVisor Authors.
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

#include <linux/netlink.h>

#include <cerrno>
#include <cstdint>
#include <functional>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/syscalls/linux/socket_netlink_netfilter_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Tests for NETLINK_NETFILTER sockets.

namespace gvisor {
namespace testing {

namespace {

constexpr uint32_t kSeq = 12345;

using ::testing::_;
using ::testing::Eq;

using SockOptTest = ::testing::TestWithParam<
    std::tuple<int, std::function<bool(int)>, std::string>>;

TEST_P(SockOptTest, GetSockOpt) {
  int sockopt = std::get<0>(GetParam());
  auto verifier = std::get<1>(GetParam());
  std::string verifier_description = std::get<2>(GetParam());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER));

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
    NetlinkNetfilterTest, SockOptTest,
    ::testing::Values(
        std::make_tuple(SO_SNDBUF, IsPositive(), "positive send buffer size"),
        std::make_tuple(SO_RCVBUF, IsPositive(),
                        "positive receive buffer size"),
        std::make_tuple(SO_TYPE, IsEqual(SOCK_RAW),
                        absl::StrFormat("SOCK_RAW (%d)", SOCK_RAW)),
        std::make_tuple(SO_DOMAIN, IsEqual(AF_NETLINK),
                        absl::StrFormat("AF_NETLINK (%d)", AF_NETLINK)),
        std::make_tuple(SO_PROTOCOL, IsEqual(NETLINK_NETFILTER),
                        absl::StrFormat("NETLINK_NETFILTER (%d)",
                                        NETLINK_NETFILTER)),
        std::make_tuple(SO_PASSCRED, IsEqual(0), "0")));

// Netlink sockets must be SOCK_DGRAM or SOCK_RAW.
TEST(NetlinkNetfilterTest, CanCreateSocket) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));
  EXPECT_THAT(fd.get(), SyscallSucceeds());
}

TEST(NetlinkNetfilterTest, AddAndAddTableWithDormantFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;
  const char test_table_name[] = "test_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct flagAttribute {
    struct nlattr attr;
    uint32_t flags;
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute nattr;
  };

  struct request_2 {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute nattr;
    struct flagAttribute fattr;
  };

  struct request add_tab_req = {};
  InitNetlinkHdr(&add_tab_req.hdr, sizeof(add_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq, NLM_F_REQUEST | NLM_F_ACK);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req.nattr.attr, sizeof(add_tab_req.nattr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req.nattr.name, sizeof(add_tab_req.nattr.name),
                 test_table_name);

  struct request_2 add_tab_req_2 = {};
  InitNetlinkHdr(&add_tab_req_2.hdr, sizeof(add_tab_req_2),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq + 1, NLM_F_REQUEST | NLM_F_ACK);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req_2.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req_2.nattr.attr, sizeof(add_tab_req_2.nattr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req_2.nattr.name, sizeof(add_tab_req_2.nattr.name),
                 test_table_name);
  InitNetlinkAttr(&add_tab_req_2.fattr.attr, sizeof(add_tab_req_2.fattr.flags),
                  NFTA_TABLE_FLAGS);
  add_tab_req_2.fattr.flags = NFT_TABLE_F_DORMANT;

  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(fd, kSeq, &add_tab_req, sizeof(add_tab_req)));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1, &add_tab_req_2,
                                           sizeof(add_tab_req_2)));
}

TEST(NetlinkNetfilterTest, AddAndRetrieveNewTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;
  const char test_table_name[] = "test_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute attr;
  };

  struct request add_tab_req = {};
  InitNetlinkHdr(&add_tab_req.hdr, sizeof(add_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq, NLM_F_REQUEST | NLM_F_ACK);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req.attr.attr, sizeof(add_tab_req.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req.attr.name, sizeof(add_tab_req.attr.name),
                 test_table_name);

  struct request add_tab_req_2 = {};
  bool correct_response = false;
  InitNetlinkHdr(&add_tab_req_2.hdr, sizeof(add_tab_req_2),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETTABLE),
                 kSeq + 1, NLM_F_REQUEST);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req_2.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req_2.attr.attr, sizeof(add_tab_req_2.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req_2.attr.name, sizeof(add_tab_req_2.attr.name),
                 test_table_name);

  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(fd, kSeq, &add_tab_req, sizeof(add_tab_req)));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &add_tab_req_2, sizeof(add_tab_req_2),
      [&](const struct nlmsghdr* hdr) {
        ASSERT_THAT(hdr->nlmsg_type, Eq(MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES,
                                                           NFT_MSG_GETTABLE)));
        ASSERT_GE(hdr->nlmsg_len, NLMSG_SPACE(sizeof(struct nfgenmsg)));
        const struct nfgenmsg* genmsg =
            reinterpret_cast<const struct nfgenmsg*>(NLMSG_DATA(hdr));
        EXPECT_EQ(genmsg->nfgen_family, AF_INET);
        EXPECT_EQ(genmsg->version, NFNETLINK_V0);

        const struct nfattr* nfattr = FindNfAttr(hdr, genmsg, NFTA_TABLE_NAME);
        EXPECT_NE(nullptr, nfattr) << "NFTA_TABLE_NAME not found in message.";
        if (nfattr == nullptr) {
          return;
        }

        std::string name(reinterpret_cast<const char*>(NFA_DATA(nfattr)));
        EXPECT_EQ(name, test_table_name);
        correct_response = true;
      },
      false));

  ASSERT_TRUE(correct_response);
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithExclusiveFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;
  const char test_table_name[] = "test_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute attr;
  };

  struct request add_tab_req = {};
  InitNetlinkHdr(&add_tab_req.hdr, sizeof(add_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq, NLM_F_REQUEST | NLM_F_ACK);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req.attr.attr, sizeof(add_tab_req.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req.attr.name, sizeof(add_tab_req.attr.name),
                 test_table_name);

  struct request add_tab_req_2 = {};
  InitNetlinkHdr(&add_tab_req_2.hdr, sizeof(add_tab_req_2),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq + 1, NLM_F_REQUEST | NLM_F_EXCL);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req_2.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req_2.attr.attr, sizeof(add_tab_req_2.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req_2.attr.name, sizeof(add_tab_req_2.attr.name),
                 test_table_name);

  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(fd, kSeq, &add_tab_req, sizeof(add_tab_req)));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 1, &add_tab_req_2,
                                       sizeof(add_tab_req_2)),
              PosixErrorIs(EEXIST, _));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithReplaceFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;
  const char test_table_name[] = "test_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute attr;
  };

  struct request add_tab_req = {};
  InitNetlinkHdr(&add_tab_req.hdr, sizeof(add_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq, NLM_F_REQUEST | NLM_F_ACK);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req.attr.attr, sizeof(add_tab_req.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req.attr.name, sizeof(add_tab_req.attr.name),
                 test_table_name);

  struct request add_tab_req_2 = {};
  InitNetlinkHdr(&add_tab_req_2.hdr, sizeof(add_tab_req_2),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq + 1, NLM_F_REQUEST | NLM_F_REPLACE);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&add_tab_req_2.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&add_tab_req_2.attr.attr, sizeof(add_tab_req_2.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(add_tab_req_2.attr.name, sizeof(add_tab_req_2.attr.name),
                 test_table_name);

  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(fd, kSeq, &add_tab_req, sizeof(add_tab_req)));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 1, &add_tab_req_2,
                                       sizeof(add_tab_req_2)),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithUnsupportedFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint8_t unknown_family = 255;
  uint16_t default_table_id = 0;
  const char test_table_name[] = "unsupported_family_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute attr;
  };

  struct request get_tab_req = {};
  InitNetlinkHdr(&get_tab_req.hdr, sizeof(get_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE),
                 kSeq, NLM_F_REQUEST);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&get_tab_req.msg, unknown_family, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&get_tab_req.attr.attr, sizeof(get_tab_req.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(get_tab_req.attr.name, sizeof(get_tab_req.attr.name),
                 test_table_name);

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq, &get_tab_req, sizeof(get_tab_req)),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNoSpecifiedNameTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
  };

  struct request get_tab_req = {};
  InitNetlinkHdr(&get_tab_req.hdr, sizeof(get_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETTABLE),
                 kSeq, NLM_F_REQUEST);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&get_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq, &get_tab_req, sizeof(get_tab_req)),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint16_t default_table_id = 0;
  const char test_table_name[] = "undefined_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct nameAttribute {
    struct nlattr attr;
    char name[32];
  };
  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute attr;
  };

  struct request get_tab_req = {};
  InitNetlinkHdr(&get_tab_req.hdr, sizeof(get_tab_req),
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETTABLE),
                 kSeq, NLM_F_REQUEST);
  // For both ipv4 and ipv6 tables.
  InitNetfilterGenmsg(&get_tab_req.msg, AF_INET, NFNETLINK_V0,
                      default_table_id);
  // Attribute setting
  InitNetlinkAttr(&get_tab_req.attr.attr, sizeof(get_tab_req.attr.name),
                  NFTA_TABLE_NAME);
  absl::SNPrintF(get_tab_req.attr.name, sizeof(get_tab_req.attr.name),
                 test_table_name);

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq, &get_tab_req, sizeof(get_tab_req)),
      PosixErrorIs(ENOENT, _));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
