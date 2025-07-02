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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .AddAttribute(NFTA_TABLE_FLAGS, &table_flags, sizeof(table_flags))
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          // Include the null terminator at the end of the string.
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .AddAttribute(NFTA_TABLE_FLAGS, &table_flags, sizeof(table_flags))
          .AddAttribute(NFTA_TABLE_USERDATA, expected_udata,
                        sizeof(expected_udata))
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          // Don't set NLM_F_ACK here, since the check will be done for every
          // nlmsg received.
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_IPV4)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> add_request_buffer_ipv6 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_IPV6)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 2)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_EXCL)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_REPLACE)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(unknown_family)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .AddAttribute(NFTA_TABLE_FLAGS, &unsupported_flags,
                        sizeof(unsupported_flags))
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, add_request_buffer.data(),
                                       add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNoSpecifiedNameTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .AddAttribute(NFTA_TABLE_FLAGS, &table_flags, sizeof(table_flags))
          .AddAttribute(NFTA_TABLE_USERDATA, expected_udata,
                        sizeof(expected_udata))
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
  // uint16_t default_table_id = 0;
  const char test_table_name[] = "test_table_name_delete";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  struct request {
    struct nlmsghdr hdr;
    struct nfgenmsg msg;
    struct nameAttribute nattr;
  };

  std::vector<char> add_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> del_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 2)
          .AddAttribute(NFTA_TABLE_HANDLE, &expected_handle,
                        sizeof(expected_handle))
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DESTROYTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name,
                        strlen(test_table_name) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_inet,
                        strlen(test_table_name_inet) + 1)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_bridge,
                        strlen(test_table_name_bridge) + 1)
          .Build();

  std::vector<char> destroy_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_UNSPEC)
          .SetSequenceNumber(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 3)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_inet,
                        strlen(test_table_name_inet) + 1)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 4)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_bridge,
                        strlen(test_table_name_bridge) + 1)
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

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamilySpecifiedName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_same[] = "test_same_name_table";
  char test_table_name_different[] = "test_different_name_table";

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));

  std::vector<char> add_request_buffer_inet =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_same,
                        strlen(test_table_name_same) + 1)
          .Build();

  std::vector<char> add_request_buffer_bridge =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_same,
                        strlen(test_table_name_same) + 1)
          .Build();

  std::vector<char> add_request_buffer_different_bridge =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 2)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_different,
                        strlen(test_table_name_different) + 1)
          .Build();

  std::vector<char> destroy_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_UNSPEC)
          .SetSequenceNumber(kSeq + 3)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_same,
                        strlen(test_table_name_same) + 1)
          .Build();

  std::vector<char> get_request_buffer_inet =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 4)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_same,
                        strlen(test_table_name_same) + 1)
          .Build();

  std::vector<char> get_request_buffer_bridge =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 5)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_same,
                        strlen(test_table_name_same) + 1)
          .Build();

  std::vector<char> get_request_buffer_different =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 6)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_different,
                        strlen(test_table_name_different) + 1)
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
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_inet,
                        strlen(test_table_name_inet) + 1)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_NEWTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 1)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_bridge,
                        strlen(test_table_name_bridge) + 1)
          .Build();

  std::vector<char> destroy_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_DELTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_INET)
          .SetSequenceNumber(kSeq + 3)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_inet,
                        strlen(test_table_name_inet) + 1)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NetlinkRequestBuilder()
          .SetMessageType(NFT_MSG_GETTABLE)
          .SetFlags(NLM_F_REQUEST | NLM_F_ACK)
          .SetFamily(NFPROTO_BRIDGE)
          .SetSequenceNumber(kSeq + 4)
          .AddAttribute(NFTA_TABLE_NAME, test_table_name_bridge,
                        strlen(test_table_name_bridge) + 1)
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

}  // namespace

}  // namespace testing
}  // namespace gvisor
