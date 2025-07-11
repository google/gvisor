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

// netinet/in.h must be included before netfilter.h.
// clang-format off
#include <linux/netfilter/nf_tables.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
// clang-format on

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <tuple>
#include <vector>

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
  const char test_table_name[] = "test_table";
  uint32_t table_flags = NFT_TABLE_F_DORMANT;

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .U32Attr(NFTA_TABLE_FLAGS, &table_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 1, add_request_buffer_2.data(), add_request_buffer_2.size()));
}

TEST(NetlinkNetfilterTest, AddAndRetrieveNewTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_tab_add_retrieve";
  uint32_t table_flags = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER;
  uint8_t expected_udata[] = {0x01, 0x02, 0x03, 0x04};
  uint32_t expected_chain_count = 0;
  uint32_t expected_flags = table_flags;
  size_t expected_udata_size = sizeof(expected_udata);
  bool correct_response = false;

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));
  uint32_t expected_owner = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          // Include the null terminator at the end of the string.
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .U32Attr(NFTA_TABLE_FLAGS, &table_flags)
          .RawAttr(NFTA_TABLE_USERDATA, expected_udata, sizeof(expected_udata))
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          // Don't set NLM_F_ACK here, since the check will be done for every
          // nlmsg received.
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterTableAttributes(
            hdr, nullptr, test_table_name, &expected_chain_count, nullptr,
            &expected_flags, &expected_owner, expected_udata,
            &expected_udata_size, true);
        correct_response = true;
      },
      false));

  ASSERT_TRUE(correct_response);
}

TEST(NetlinkNetfilterTest, ErrGettingTableWithDifferentFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_tab_different_families";
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer_ipv4 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_IPV4)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_request_buffer_ipv6 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_IPV6)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_request_buffer_ipv4.data(),
                                           add_request_buffer_ipv4.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_request_buffer_ipv6.data(),
                                           add_request_buffer_ipv6.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 2, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithExclusiveFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "err_exclusive";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_EXCL)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_request_buffer_2.data(),
                               add_request_buffer_2.size()),
      PosixErrorIs(EEXIST, _));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithReplaceFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "err_replace";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_REPLACE)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_request_buffer_2.data(),
                               add_request_buffer_2.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithUnsupportedFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint8_t unknown_family = 255;
  const char test_table_name[] = "unsupported_family_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(unknown_family)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                       add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithUnsupportedFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint32_t unsupported_flags = 0xFFFFFFFF;
  const char test_table_name[] = "test_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .U32Attr(NFTA_TABLE_FLAGS, &unsupported_flags)
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                       add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNoSpecifiedNameTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> get_request_buffer = NlReq()
                                             .MsgType(NFT_MSG_GETTABLE)
                                             .Flags(NLM_F_REQUEST | NLM_F_ACK)
                                             .Family(NFPROTO_INET)
                                             .Seq(kSeq)
                                             .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "undefined_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveTableWithOwnerMismatch) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table";
  uint32_t table_flags = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER;
  uint8_t expected_udata[3] = {0x01, 0x02, 0x03};
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));
  FileDescriptor fd_2 =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .U32Attr(NFTA_TABLE_FLAGS, &table_flags)
          .RawAttr(NFTA_TABLE_USERDATA, expected_udata, sizeof(expected_udata))
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd_2, kSeq + 1, get_request_buffer.data(),
                               get_request_buffer.size()),
      PosixErrorIs(EPERM, _));
}

TEST(NetlinkNetfilterTest, DeleteExistingTableByName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_name_delete";
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> del_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 1, del_request_buffer.data(), del_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteTableByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  // Retrieve the actual table handle from the kernel with a GET request.
  uint64_t expected_handle = 0;
  const char test_table_name[] = "test_table_handle_delete";
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));

  // Retrieve the table handle from the kernel.
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        const nfattr* attr = FindNfAttr(hdr, nullptr, NFTA_TABLE_HANDLE);
        EXPECT_NE(attr, nullptr);
        EXPECT_EQ(attr->nfa_type, NFTA_TABLE_HANDLE);
        EXPECT_EQ(attr->nfa_len - NLA_HDRLEN, sizeof(expected_handle));
        expected_handle = *reinterpret_cast<const uint64_t*>(NFA_DATA(attr));
      },
      false));
  EXPECT_NE(expected_handle, 0);

  std::vector<char> del_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .U64Attr(NFTA_TABLE_HANDLE, &expected_handle)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 2, del_request_buffer.data(), del_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "nonexistent_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> del_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 1, del_request_buffer.data(),
                                       del_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "nonexistent_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> destroy_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DESTROYTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           destroy_request_buffer.data(),
                                           destroy_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_bridge[] = "test_table_bridge";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_bridge)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_UNSPEC)
          .Seq(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 4)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_bridge)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 1, add_request_buffer_2.data(), add_request_buffer_2.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 2,
                                           destroy_request_buffer.data(),
                                           destroy_request_buffer.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 3, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 4, get_request_buffer_2.data(),
                               get_request_buffer_2.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamilySpecifiedTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_same[] = "test_same_name_table";
  char test_table_name_different[] = "test_different_name_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer_inet =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> add_request_buffer_bridge =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> add_request_buffer_different_bridge =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_different)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_UNSPEC)
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_inet =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 4)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_bridge =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 5)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_different =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 6)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_different)
          .Build();

  bool correct_response = false;

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_request_buffer_inet.data(),
                                           add_request_buffer_inet.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_request_buffer_bridge.data(),
                                           add_request_buffer_bridge.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 2, add_request_buffer_different_bridge.data(),
      add_request_buffer_different_bridge.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 3,
                                           destroy_request_buffer.data(),
                                           destroy_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 4, get_request_buffer_inet.data(),
                               get_request_buffer_inet.size()),
      PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 5, get_request_buffer_bridge.data(),
                               get_request_buffer_bridge.size()),
      PosixErrorIs(ENOENT, _));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer_different.data(),
      get_request_buffer_different.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* table_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_TABLE_NAME);
        EXPECT_NE(table_name_attr, nullptr);
        EXPECT_EQ(table_name_attr->nfa_type, NFTA_TABLE_NAME);
        std::string name(
            reinterpret_cast<const char*>(NFA_DATA(table_name_attr)));
        EXPECT_EQ(name, test_table_name_different);
        correct_response = true;
      },
      false));

  ASSERT_TRUE(correct_response);
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedNameAndHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_bridge[] = "test_table_bridge";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_bridge)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_UNSPEC)
          .Seq(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NlReq()
          .MsgType(NFT_MSG_GETTABLE)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_BRIDGE)
          .Seq(kSeq + 4)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_bridge)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                           add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(
      fd, kSeq + 1, add_request_buffer_2.data(), add_request_buffer_2.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 2,
                                           destroy_request_buffer.data(),
                                           destroy_request_buffer.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 3, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 4, get_request_buffer_2.data(),
                               get_request_buffer_2.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_no_table_chain";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .Build();

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedNameOrHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_no_name_or_handle_chain";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithPolicySet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_reg_chain";
  const char test_chain_name[] = "test_chain";
  const uint32_t test_policy = NF_ACCEPT;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = 1 << 3;
  const uint8_t test_hook = NF_INET_PRE_ROUTING;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .U8Attr(NFTA_CHAIN_HOOK, &test_hook)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint8_t test_hook = NF_INET_PRE_ROUTING;
  // Only NFT_CHAIN_BASE, NFT_CHAIN_HW_OFFLOAD, and NFT_CHAIN_BINDING are
  // valid flags that should be set by users.
  const uint32_t test_chain_flags = 1 << 3;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .U8Attr(NFTA_CHAIN_HOOK, &test_hook)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest,
     ErrNewBaseChainWithMalformedHookDataMissingPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr().U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num).Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithMalformedHookDataMissingHookNum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr().U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority).Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidChainType) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "test_chain_type_invalid";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithUnsupportedFamilyChainTypePair) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "route";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_ARP)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_ARP)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewNATBaseChainWithInvalidPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "nat";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = -250;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewNetDevBaseChainUnsupported) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_NETDEV_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_NETDEV)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_NETDEV)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewInetBaseChainAtIngressUnsupported) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithUnsupportedChainCounters) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .RawAttr(NFTA_CHAIN_COUNTERS, nullptr, 0)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrChainWithBaseChainFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrChainWithHardwareOffloadFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_chain_flags = NFT_CHAIN_HW_OFFLOAD;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrChainWithNoNameAndChainBindingFlagNotSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const uint32_t test_chain_flags = 0;
  const uint32_t test_chain_id = 1;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .U32Attr(NFTA_CHAIN_ID, &test_chain_id)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, add_chain_request_buffer.data(),
                               add_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrUpdateChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_invalid_update";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  std::vector<char> update_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, update_chain_request_buffer.data(),
                               update_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, AddChainWithNoNameAndChainIdAttributeSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const uint32_t test_chain_flags = NFT_CHAIN_BINDING;
  const uint32_t test_chain_id = 2;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .U32Attr(NFTA_CHAIN_ID, &test_chain_id)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddChainWithName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddBaseChainWithDropPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();
  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithDumpFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_dump_fail";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, get_chain_request_buffer.data(),
                               get_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_no_table_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, get_chain_request_buffer.data(),
                               get_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoChainName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain_hook";
  const char test_chain_name[] = "test_chain_no_chain_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, get_chain_request_buffer.data(),
                               get_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, GetChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain";
  const char test_chain_name[] = "test_chain";
  uint8_t test_user_data[] = {0x01, 0x02, 0x03, 0x04};
  size_t expected_udata_size = sizeof(test_user_data);
  const uint32_t test_chain_flags = NFT_CHAIN_BINDING;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .RawAttr(NFTA_CHAIN_USERDATA, test_user_data, expected_udata_size)
          .Build();

  uint32_t expected_use = 0;
  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterChainAttributes(
            hdr, nullptr, test_table_name, test_chain_name, nullptr, nullptr,
            nullptr, &test_chain_flags, &expected_use, test_user_data,
            &expected_udata_size, true);
      },
      false));
}

TEST(NetlinkNetfilterTest, GetBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chain";
  const char test_chain_name[] = "test_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 10;
  uint8_t test_user_data[] = {0x01, 0x02, 0x03, 0x04};
  size_t expected_udata_size = sizeof(test_user_data);
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .RawAttr(NFTA_CHAIN_USERDATA, test_user_data, expected_udata_size)
          .Build();

  uint32_t expected_use = 0;
  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterChainAttributes(
            hdr, nullptr, test_table_name, test_chain_name, nullptr,
            &test_policy, test_chain_type_name, &test_chain_flags,
            &expected_use, test_user_data, &expected_udata_size, true);
      },
      false));
}

TEST(NetlinkNetfilterTest, ErrDeleteChainWithNoTableNameSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_no_table_name";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();
  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, delete_chain_request_buffer.data(),
                               delete_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_nonexistent";
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 1, delete_chain_request_buffer.data(),
                               delete_chain_request_buffer.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrDeleteChainWithChainBindingFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_binding_set";
  const uint32_t test_chain_flags = NFT_CHAIN_BINDING;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 2, delete_chain_request_buffer.data(),
                               delete_chain_request_buffer.size()),
      PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_nonexistent";
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DESTROYCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           delete_chain_request_buffer.data(),
                                           delete_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_delete_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();
  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 2,
                                           delete_chain_request_buffer.data(),
                                           delete_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteBaseChainByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  const char test_table_name[] = "test_table_chains";
  const char test_chain_name[] = "test_chain_delete_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  uint64_t chain_handle = 0;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_table_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWTABLE)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, &test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, &test_hook_priority)
          .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
          .Build();
  std::vector<char> add_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_NEWCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 1)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .U32Attr(NFTA_CHAIN_POLICY, &test_policy)
          .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                   nested_hook_data.size())
          .U32Attr(NFTA_CHAIN_FLAGS, &test_chain_flags)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_GETCHAIN)
          .Flags(NLM_F_REQUEST)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 2)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq,
                                           add_table_request_buffer.data(),
                                           add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 1,
                                           add_chain_request_buffer.data(),
                                           add_chain_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* chain_handle_attr =
            FindNfAttr(hdr, nullptr, NFTA_CHAIN_HANDLE);
        ASSERT_NE(chain_handle_attr, nullptr);
        chain_handle =
            *(reinterpret_cast<uint64_t*>(NFA_DATA(chain_handle_attr)));
      },
      false));

  ASSERT_NE(chain_handle, 0);
  std::vector<char> delete_chain_request_buffer =
      NlReq()
          .MsgType(NFT_MSG_DELCHAIN)
          .Flags(NLM_F_REQUEST | NLM_F_ACK)
          .Family(NFPROTO_INET)
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .U64Attr(NFTA_CHAIN_HANDLE, &chain_handle)
          .Build();
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(fd, kSeq + 3,
                                           delete_chain_request_buffer.data(),
                                           delete_chain_request_buffer.size()));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
