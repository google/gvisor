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
#include <unordered_set>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "test/syscalls/linux/socket_netlink_netfilter_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Tests for NETLINK_NETFILTER sockets.
// Error test cases prefixed with "ErrUnsupported" error only because they
// are currently unsupported by gvisor.

namespace gvisor {
namespace testing {

namespace {

constexpr uint32_t kSeq = 12345;

using ::testing::_;
using ::testing::UnitTest;

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

std::string GetUniqueTestTableName() {
  return absl::StrCat("table_",
                      UnitTest::GetInstance()->current_test_info()->name());
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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  EXPECT_THAT(fd.get(), SyscallSucceeds());
}

TEST(NetlinkNetfilterTest, AddAndAddTableWithDormantFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  std::string test_table_name = GetUniqueTestTableName();
  uint32_t table_flags = NFT_TABLE_F_DORMANT;

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  // Assuming two separate transactions.
  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, table_flags)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 3, kSeq + 5, add_request_buffer_2.data(),
      add_request_buffer_2.size()));

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 6));
}

TEST(NetlinkNetfilterTest, AddAndRetrieveNewTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  uint32_t table_flags = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER;
  uint8_t expected_udata[] = {0x01, 0x02, 0x03, 0x04};
  uint32_t expected_chain_count = 0;
  uint32_t expected_flags = table_flags;
  size_t expected_udata_size = sizeof(expected_udata);
  bool correct_response = false;

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  uint32_t expected_owner = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   // Include the null terminator at the end of the string.
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, expected_flags)
                   .RawAttr(NFTA_TABLE_USERDATA, expected_udata,
                            sizeof(expected_udata))
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      // Don't set NLM_F_ACK here, since the check will be done for every
      // nlmsg received.
      NlReq("gettable req inet")
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterTableAttributes({
            .hdr = hdr,
            .test_table_name = test_table_name,
            .expected_chain_count = &expected_chain_count,
            .expected_flags = &expected_flags,
            .expected_owner = &expected_owner,
            .expected_udata = expected_udata,
            .expected_udata_size = &expected_udata_size,
            .skip_handle_check = true,
        });
        correct_response = true;
      },
      false));

  ASSERT_TRUE(correct_response);
}

TEST(NetlinkNetfilterTest, GetDumpTables) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  const char test_table_name_2[] = "test_tab_two";
  uint32_t expected_chain_count = 0;
  uint32_t expected_flags = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_2)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> get_dump_request_buffer =
      NlReq("gettable req dump inet").Seq(kSeq + 4).Build();

  std::unordered_set<std::string> expected_tables = {test_table_name,
                                                     test_table_name_2};
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_request_buffer.data(), get_dump_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        const struct nfattr* table_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_TABLE_NAME);
        ASSERT_NE(table_name_attr, nullptr);
        std::string table_name(
            reinterpret_cast<const char*>(NFA_DATA(table_name_attr)));

        if (expected_tables.count(table_name)) {
          CheckNetfilterTableAttributes({
              .hdr = hdr,
              .test_table_name = table_name.c_str(),
              .expected_chain_count = &expected_chain_count,
              .expected_flags = &expected_flags,
              .skip_handle_check = true,
          });
          expected_tables.erase(table_name);
        }
      },
      false));
  ASSERT_TRUE(expected_tables.empty());
}

TEST(NetlinkNetfilterTest, ErrGettingTableWithDifferentFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack ipv4")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newtable req ack ipv6")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq("gettable req inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 4, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithExclusiveFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  // Assuming two separate transactions.
  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newtable req excl inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_request_buffer_2.data(),
                  add_request_buffer_2.size()),
              PosixErrorIs(EEXIST, _));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithReplaceFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  // Assuming two separate transactions.
  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newtable req replace inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_request_buffer_2.data(),
                  add_request_buffer_2.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithInvalidFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint8_t invalid_family = 255;
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req")
                   .Family(invalid_family)
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 2,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithUnsupportedFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  uint32_t unsupported_flags = 0xFFFFFFFF;
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, unsupported_flags)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 2,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNoSpecifiedNameTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> get_request_buffer =
      NlReq("gettable req ack inet").Seq(kSeq).Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> get_request_buffer =
      NlReq("gettable req ack inet")
          .Seq(kSeq)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DeleteExistingTableByName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> del_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("deltable req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 3, kSeq + 5, del_request_buffer.data(),
      del_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteTableByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  // Retrieve the actual table handle from the kernel with a GET request.
  uint64_t expected_handle = 0;
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq("gettable req inet")
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));

  // Retrieve the table handle from the kernel.
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        const nfattr* attr = FindNfAttr(hdr, nullptr, NFTA_TABLE_HANDLE);
        ASSERT_NE(attr, nullptr);
        EXPECT_EQ(attr->nfa_type, NFTA_TABLE_HANDLE);
        EXPECT_EQ(attr->nfa_len - NLA_HDRLEN, sizeof(expected_handle));
        expected_handle =
            be64toh(*reinterpret_cast<const uint64_t*>(NFA_DATA(attr)));
      },
      false));
  EXPECT_NE(expected_handle, 0);

  std::vector<char> del_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("deltable req ack inet")
                   .Seq(kSeq + 5)
                   .U64Attr(NFTA_TABLE_HANDLE, expected_handle)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, del_request_buffer.data(),
      del_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> del_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("deltable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 2,
                                                     del_request_buffer.data(),
                                                     del_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> destroy_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("destroytable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, destroy_request_buffer.data(),
      destroy_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_arp[] = "test_table_arp";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
                   .Build())
          .Req(NlReq("newtable req ack arp")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_arp)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("deltable req ack unspec").Seq(kSeq + 5).Build())
          .SeqEnd(kSeq + 6)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq("gettable req inet")
          .Seq(kSeq + 7)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NlReq("gettable req arp")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_arp)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, destroy_request_buffer.data(),
      destroy_request_buffer.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 7, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 8, get_request_buffer_2.data(),
                               get_request_buffer_2.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamilySpecifiedName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  char test_table_name_same[] = "test_same_name_table";
  char test_table_name_different[] = "test_different_name_table";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
                   .Build())
          .Req(NlReq("newtable req ack arp")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
                   .Build())
          .Req(NlReq("newtable req ack arp")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_different)
                   .Build())
          .SeqEnd(kSeq + 4)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 5)
          .Req(NlReq("deltable req ack unspec")
                   .Seq(kSeq + 6)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
                   .Build())
          .SeqEnd(kSeq + 7)
          .Build();

  std::vector<char> get_request_buffer_inet =
      NlReq("gettable req inet")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_bridge =
      NlReq("gettable req arp")
          .Seq(kSeq + 9)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_different =
      NlReq("gettable req arp")
          .Seq(kSeq + 10)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_different)
          .Build();

  bool correct_response = false;

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 4, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 5, kSeq + 7, destroy_request_buffer.data(),
      destroy_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 8, get_request_buffer_inet.data(),
                               get_request_buffer_inet.size()),
      PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 9, get_request_buffer_bridge.data(),
                               get_request_buffer_bridge.size()),
      PosixErrorIs(ENOENT, _));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer_different.data(),
      get_request_buffer_different.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* table_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_TABLE_NAME);
        ASSERT_NE(table_name_attr, nullptr);
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
  char test_table_name_arp[] = "test_table_arp";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
                   .Build())
          .Req(NlReq("newtable req ack arp")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_arp)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> destroy_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("deltable req ack unspec").Seq(kSeq + 5).Build())
          .SeqEnd(kSeq + 6)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq("gettable req inet")
          .Seq(kSeq + 7)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> get_request_buffer_2 =
      NlReq("gettable req arp")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_arp)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, destroy_request_buffer.data(),
      destroy_request_buffer.size()));
  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq + 7, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 8, get_request_buffer_2.data(),
                               get_request_buffer_2.size()),
      PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  // Kept separate to make clear that the chain request is the one that
  // fails.
  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet").Seq(kSeq + 4).Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq, kSeq + 2, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedNameOrHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  // Kept separate to make clear that the chain request is the one that
  // fails.
  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithPolicySet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain";
  const uint32_t test_policy = NF_ACCEPT;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = 1 << 3;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint8_t test_hook = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  // Only NFT_CHAIN_BASE, NFT_CHAIN_HW_OFFLOAD, and NFT_CHAIN_BINDING are
  // valid flags that should be set by users.
  const uint32_t test_chain_flags = 1 << 3;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest,
     ErrNewBaseChainWithMalformedHookDataMissingPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr().U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num).Build();

  std::vector<char> add_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, add_chain_request_buffer.data(),
                  add_chain_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithMalformedHookDataMissingHookNum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr().U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority).Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidChainType) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  // TODO: b/421437663 - Fix this error test for native Linux.
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "test_chain_type_invalid";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrNewNATBaseChainWithInvalidPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  // TODO: b/421437663 - Fix this error test for native Linux.
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "nat";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = -250;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewNetDevBaseChain) {
  // TODO: b/434243967 - Remove when netdev chains are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_NETDEV_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack netdev")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack netdev")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewInetBaseChainAtIngress) {
  // TODO: b/434243967 - Remove when inet chains are supported at Ingress.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewBaseChainWithChainCounters) {
  // TODO: b/434243967 - Remove when chain counters are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_INGRESS;
  const uint32_t test_hook_priority = 10;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .RawAttr(NFTA_CHAIN_COUNTERS, nullptr, 0)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrChainWithBaseChainFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedChainWithHardwareOffloadFlagSet) {
  // TODO: b/434243967 - Remove when hardware offload chains are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const uint32_t test_chain_flags = NFT_CHAIN_HW_OFFLOAD;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, ErrChainWithNoNameAndChainBindingFlagNotSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const uint32_t test_chain_flags = 0;
  const uint32_t test_chain_id = 1;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedUpdateChain) {
  // TODO: b/434243967 - Remove when updating existing chains are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_invalid_update";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> update_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, update_chain_request_buffer.data(),
                  update_chain_request_buffer.size()),
              PosixErrorIs(ENOTSUP, _));
}

TEST(NetlinkNetfilterTest, AddChainWithNoNameAndChainIdAttributeSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  const std::string test_table_name = GetUniqueTestTableName();
  const uint32_t test_chain_flags = NFT_CHAIN_BINDING;
  const uint32_t test_chain_id = 2;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 4));
}

TEST(NetlinkNetfilterTest, AddChainWithName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddBaseChainWithDropPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_bad_policy";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, GetChainWithDumpFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain";
  const char test_chain_two_name[] = "test_chain_two";
  const uint32_t test_chain_flags = 0;
  uint32_t expected_use = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_two_name)
                   .Build())
          .SeqEnd(kSeq + 4)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req dump inet").Seq(kSeq + 5).Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 4, add_request_buffer.data(),
      add_request_buffer.size()));

  std::unordered_set<std::string> expected_chains = {test_chain_name,
                                                     test_chain_two_name};
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        const struct nfattr* chain_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_CHAIN_NAME);
        ASSERT_NE(chain_name_attr, nullptr);
        std::string chain_name(
            reinterpret_cast<const char*>(NFA_DATA(chain_name_attr)));

        if (expected_chains.count(chain_name)) {
          CheckNetfilterChainAttributes({
              .hdr = hdr,
              .expected_table_name = test_table_name,
              .expected_chain_name = chain_name.c_str(),
              .expected_use = &expected_use,
              .expected_udata = nullptr,
              .expected_udata_size = nullptr,
              .skip_handle_check = true,
          });
          expected_chains.erase(chain_name);
        }
      },
      false));

  ASSERT_TRUE(expected_chains.empty());
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_no_table_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req ack inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 4, get_chain_request_buffer.data(),
                               get_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoChainName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_no_chain_name";
  const uint32_t test_chain_flags = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req ack inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 4, get_chain_request_buffer.data(),
                               get_chain_request_buffer.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, GetChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain";
  uint8_t test_user_data[] = {0x01, 0x02, 0x03, 0x04};
  size_t expected_udata_size = sizeof(test_user_data);
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .RawAttr(NFTA_CHAIN_USERDATA, test_user_data,
                            expected_udata_size)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  uint32_t expected_use = 0;
  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterChainAttributes({
            .hdr = hdr,
            .expected_table_name = test_table_name,
            .expected_chain_name = test_chain_name,
            .expected_use = &expected_use,
            .expected_udata = test_user_data,
            .expected_udata_size = &expected_udata_size,
            .skip_handle_check = true,
        });
      },
      false));
}

TEST(NetlinkNetfilterTest, GetBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_ACCEPT;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 10;
  uint8_t test_user_data[] = {0x01, 0x02, 0x03, 0x04};
  size_t expected_udata_size = sizeof(test_user_data);
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .RawAttr(NFTA_CHAIN_USERDATA, test_user_data,
                            expected_udata_size)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  uint32_t expected_use = 0;
  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterChainAttributes({
            .hdr = hdr,
            .expected_table_name = test_table_name,
            .expected_chain_name = test_chain_name,
            .expected_policy = &test_policy,
            .expected_chain_type = test_chain_type_name,
            .expected_flags = &test_chain_flags,
            .expected_use = &expected_use,
            .expected_udata = test_user_data,
            .expected_udata_size = &expected_udata_size,
            .skip_handle_check = true,
        });
      },
      false));
}

TEST(NetlinkNetfilterTest, ErrDeleteChainWithNoTableNameSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_no_table_name";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("delchain req ack inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, delete_chain_request_buffer.data(),
                  delete_chain_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_nonexistent";
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("delchain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 3, kSeq + 5, delete_chain_request_buffer.data(),
                  delete_chain_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_nonexistent";
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_table_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("destroychain req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_table_request_buffer.data(),
      add_table_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 3, kSeq + 5, delete_chain_request_buffer.data(),
      delete_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_delete_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> delete_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("delchain req ack inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, delete_chain_request_buffer.data(),
      delete_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, DeleteBaseChainByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  const char test_chain_name[] = "test_chain_delete_base_chain";
  const char test_chain_type_name[] = "filter";
  const uint32_t test_policy = NF_DROP;
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
  const uint32_t test_chain_flags = NFT_CHAIN_BASE;
  uint64_t chain_handle = 0;
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, test_hook_priority)
          .Build();

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, test_policy)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, test_chain_type_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  std::vector<char> get_chain_request_buffer =
      NlReq("getchain req inet")
          .Seq(kSeq + 4)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_chain_request_buffer.data(), get_chain_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* chain_handle_attr =
            FindNfAttr(hdr, nullptr, NFTA_CHAIN_HANDLE);
        ASSERT_NE(chain_handle_attr, nullptr);
        chain_handle = be64toh(
            *(reinterpret_cast<uint64_t*>(NFA_DATA(chain_handle_attr))));
      },
      false));

  ASSERT_NE(chain_handle, 0);
  std::vector<char> delete_chain_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 5)
          .Req(NlReq("delchain req ack inet")
                   .Seq(kSeq + 6)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U64Attr(NFTA_CHAIN_HANDLE, chain_handle)
                   .Build())
          .SeqEnd(kSeq + 7)
          .Build();
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 5, kSeq + 7, delete_chain_request_buffer.data(),
      delete_chain_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, ErrModifyTableWithOwnerMismatchUnboundSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  uint32_t table_flags = NFT_TABLE_F_OWNER;
  uint32_t new_table_flags = NFT_TABLE_F_DORMANT;
  uint8_t expected_udata[3] = {0x01, 0x02, 0x03};
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  FileDescriptor fd_2 = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER));

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, table_flags)
                   .RawAttr(NFTA_TABLE_USERDATA, expected_udata,
                            sizeof(expected_udata))
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> add_request_buffer_2 =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, new_table_flags)
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd_2, kSeq + 3, kSeq + 5, add_request_buffer_2.data(),
                  add_request_buffer_2.size()),
              PosixErrorIs(EPERM, _));
}

TEST(NetlinkNetfilterTest, AddTableWithUnboundSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  uint32_t table_flags = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER;
  uint32_t expected_port_id = 0;
  uint8_t expected_udata[3] = {0x01, 0x02, 0x03};
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER));
  bool correct_response = false;

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .U32Attr(NFTA_TABLE_FLAGS, table_flags)
                   .RawAttr(NFTA_TABLE_USERDATA, expected_udata,
                            sizeof(expected_udata))
                   .Build())
          .SeqEnd(kSeq + 2)
          .Build();

  std::vector<char> get_request_buffer =
      NlReq("gettable req inet")
          .Seq(kSeq + 3)
          .StrAttr(NFTA_TABLE_NAME, test_table_name)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 2, add_request_buffer.data(),
      add_request_buffer.size()));

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* owner_attr =
            FindNfAttr(hdr, nullptr, NFTA_TABLE_OWNER);
        ASSERT_NE(owner_attr, nullptr);
        uint32_t owner =
            ntohl(*(reinterpret_cast<uint32_t*>(NFA_DATA(owner_attr))));
        EXPECT_NE(owner, 0);
        expected_port_id = owner;
        correct_response = true;
      },
      false));
  ASSERT_TRUE(correct_response);

  // Ensure that the port ID assigned to the table is not 0 and matches the
  // port id retrieved from getsockname() syscall.
  uint32_t assigned_port_id =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));
  ASSERT_NE(expected_port_id, 0);
  ASSERT_NE(assigned_port_id, 0);
  ASSERT_EQ(expected_port_id, assigned_port_id);
}

TEST(NetlinkNetfilterTest, ErrAddRuleWithMissingTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack inet").Seq(kSeq + 5).Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}
// here
TEST(NetlinkNetfilterTest, ErrAddRuleWithUnknownTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, "unknown_table_name")
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrAddRuleNoChainSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest,
     ErrAddRuleNoHandleOrPositionSpecifiedAndCreateReplaceFlagNotSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrAddRuleNoHandleOrPositionSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrAddRuleInvalidPositionSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint64_t invalid_position = 10;
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .U64Attr(NFTA_RULE_POSITION, invalid_position)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, ErrAddRuleInvalidHandleSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint64_t invalid_handle = 10;
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .U64Attr(NFTA_RULE_HANDLE, invalid_handle)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(ENOENT, _));
}

TEST(NetlinkNetfilterTest, AddEmptyRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t expected_udata[] = {0, 1, 2, 3, 4};
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, expected_udata,
                            sizeof(expected_udata))
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, ErrRuleExpressionWrongType) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2, 3, 4};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();
  struct nlattr* attr = reinterpret_cast<struct nlattr*>(list_expr_data.data());
  attr->nla_type = NFTA_LIST_UNSPEC;

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrRuleTooManyExpressions) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  // TODO: b/421437663 - Fix this error test for native Linux.
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2, 3, 4};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr::BuildWithMaxAttrs();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrImmRuleNoDestinationRegisterSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_data = {0, 1, 2};
  std::vector<char> immediate_data =
      NlNestedAttr()
          .RawAttr(NFTA_DATA_VALUE, rule_data.data(), rule_data.size())
          .Build();
  std::vector<char> immediate_attrs =
      NlNestedAttr()
          .RawAttr(NFTA_IMMEDIATE_DATA, immediate_data.data(),
                   immediate_data.size())
          .Build();
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, "immediate")
          .RawAttr(NFTA_EXPR_DATA, immediate_attrs.data(),
                   immediate_attrs.size())
          .Build();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrImmRuleNoDataSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  uint32_t dreg = NFT_REG_VERDICT;
  std::vector<char> rule_data = {0, 1, 2};
  std::vector<char> immediate_attrs =
      NlNestedAttr().U32Attr(NFTA_IMMEDIATE_DREG, dreg).Build();
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, "immediate")
          .RawAttr(NFTA_EXPR_DATA, immediate_attrs.data(),
                   immediate_attrs.size())
          .Build();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrValueDataWithVerdictRegister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data =
      NlImmExpr().Dreg(NFT_REG_VERDICT).VerdictCode(NF_ACCEPT).ValueBuild();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrVerdictDataWithNonVerdictRegister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data =
      NlImmExpr().Dreg(NFT_REG_1).VerdictCode(NF_ACCEPT).VerdictBuild();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrExpressionDataMalformed) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  uint32_t dreg = NFT_REG_1;
  std::vector<char> rule_data = {0, 1, 2};
  std::vector<char> immediate_data =
      NlNestedAttr().RawAttr(20, rule_data.data(), rule_data.size()).Build();
  std::vector<char> immediate_attrs =
      NlNestedAttr()
          .U32Attr(NFTA_IMMEDIATE_DREG, dreg)
          .RawAttr(NFTA_IMMEDIATE_DATA, immediate_data.data(),
                   immediate_data.size())
          .Build();
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, "immediate")
          .RawAttr(NFTA_EXPR_DATA, immediate_attrs.data(),
                   immediate_attrs.size())
          .Build();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest, ErrImmInvalidDreg) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  uint32_t dreg = 1000;
  std::vector<char> rule_data = {0, 1, 2};
  std::vector<char> immediate_data =
      NlNestedAttr()
          .RawAttr(NFTA_DATA_VALUE, rule_data.data(), rule_data.size())
          .Build();
  std::vector<char> immediate_attrs =
      NlNestedAttr()
          .U32Attr(NFTA_IMMEDIATE_DREG, dreg)
          .RawAttr(NFTA_IMMEDIATE_DATA, immediate_data.data(),
                   immediate_data.size())
          .Build();
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, "immediate")
          .RawAttr(NFTA_EXPR_DATA, immediate_attrs.data(),
                   immediate_attrs.size())
          .Build();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                  add_rule_request_buffer.size()),
              PosixErrorIs(ERANGE, _));
}

TEST(NetlinkNetfilterTest, AddAcceptAllRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddDropAllRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultDropAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddRuleWithImmDataValue) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2, 3, 4};
  uint32_t dreg = NFT_REG_1;
  std::vector<char> rule_data = {0, 1, 2};
  std::vector<char> rule_expr_data =
      NlImmExpr().Dreg(dreg).Value(rule_data).ValueBuild();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddRuleToEndOfRuleList) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  std::vector<char> add_rule_request_buffer_2 =
      NlBatchReq()
          .SeqStart(kSeq + 9)
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 10)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 11)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 9, kSeq + 11, add_rule_request_buffer_2.data(),
      add_rule_request_buffer_2.size()));
}

TEST(NetlinkNetfilterTest, AddDropRuleBeforeAcceptRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::string table_name = GetUniqueTestTableName();
  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_accept_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  // TODO - b/421437663: Change to use GET_RULE to retrieve the rule handle
  // dynamically.
  uint64_t rule_handle = 2;
  std::vector<char> rule_expr_drop = NlImmExpr::DefaultDropAll();
  std::vector<char> list_expr_data_2 = NlListAttr().Add(rule_expr_drop).Build();
  std::vector<char> add_rule_drop_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 9)
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 10)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .U64Attr(NFTA_RULE_POSITION, rule_handle)
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data_2.data(),
                            list_expr_data_2.size())
                   .Build())
          .SeqEnd(kSeq + 11)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = table_name, .seq = kSeq});
  AddDefaultBaseChain({.fd = fd, .table_name = table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_accept_request_buffer.data(),
      add_rule_accept_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 9, kSeq + 11, add_rule_drop_request_buffer.data(),
      add_rule_drop_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, AddDropRuleAfterAcceptRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::string table_name = GetUniqueTestTableName();
  uint8_t udata[] = {0, 1, 2};
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_rule_accept_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  // TODO - b/421437663: Change to use GET_RULE to retrieve the rule handle
  // dynamically.
  uint64_t rule_handle = 2;
  std::vector<char> rule_expr_drop = NlImmExpr::DefaultDropAll();
  std::vector<char> list_expr_data_2 = NlListAttr().Add(rule_expr_drop).Build();
  std::vector<char> add_rule_drop_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 9)
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 10)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .U64Attr(NFTA_RULE_POSITION, rule_handle)
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data_2.data(),
                            list_expr_data_2.size())
                   .Build())
          .SeqEnd(kSeq + 11)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = table_name, .seq = kSeq});
  AddDefaultBaseChain({.fd = fd, .table_name = table_name, .seq = kSeq + 3});
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_accept_request_buffer.data(),
      add_rule_accept_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 9, kSeq + 11, add_rule_drop_request_buffer.data(),
      add_rule_drop_request_buffer.size()));
}

TEST(NetlinkNetfilterTest, GetRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::string table_name = GetUniqueTestTableName();
  uint8_t udata[] = {0, 1, 2};
  size_t expected_udata_size = sizeof(udata);
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();
  // Rule handle is two because the atomic counter that assigns the handles
  // for chains and rules are the same.
  uint64_t rule_handle = 2;

  AddDefaultTable({.fd = fd, .table_name = table_name, .seq = kSeq});
  AddDefaultBaseChain({.fd = fd, .table_name = table_name, .seq = kSeq + 3});
  std::vector<char> add_rule_accept_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  std::vector<char> get_rule_request_buffer =
      NlReq("getrule req inet")
          .Seq(kSeq + 9)
          .StrAttr(NFTA_RULE_TABLE, table_name)
          .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
          .U64Attr(NFTA_RULE_HANDLE, rule_handle)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 8, add_rule_accept_request_buffer.data(),
      add_rule_accept_request_buffer.size()));

  bool correct_response = false;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_rule_request_buffer.data(), get_rule_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        CheckNetfilterRuleAttributes({
            .hdr = hdr,
            .expected_table_name = table_name,
            .expected_chain_name = GetDefaultChainName(),
            .expected_handle = &rule_handle,
            .expected_udata = udata,
            .expected_udata_size = &expected_udata_size,
        });
        correct_response = true;
      },
      false));
  EXPECT_TRUE(correct_response);
}

TEST(NetlinkNetfilterTest, GetRuleDump) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  size_t expected_udata_size = sizeof(udata);
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});
  AddDefaultBaseChain(
      {.fd = fd, .table_name = test_table_name, .seq = kSeq + 3});
  // Add two rules.
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  std::vector<char> get_dump_rule_request_buffer =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 10)
          .StrAttr(NFTA_RULE_TABLE, test_table_name)
          .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 6, kSeq + 9, add_rule_request_buffer.data(),
      add_rule_request_buffer.size()));

  int rules_found = 0;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_rule_request_buffer.data(),
      get_dump_rule_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        CheckNetfilterRuleAttributes({
            .hdr = hdr,
            .expected_table_name = test_table_name,
            .expected_chain_name = GetDefaultChainName(),
            .expected_udata = udata,
            .expected_udata_size = &expected_udata_size,
            .skip_handle_check = true,
        });
        rules_found++;
      },
      false));
  EXPECT_EQ(rules_found, 2);
}

TEST(NetlinkNetfilterTest, GetRuleDumpTableSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  size_t expected_udata_size = sizeof(udata);
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_request =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newtable req ack ipv6")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, GetDefaultChainName())
                   .Build())
          .Req(NlReq("newchain req ack ipv6")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, GetDefaultChainName())
                   .Build())
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .Req(NlReq("newrule req ack create ipv6")
                   .Seq(kSeq + 6)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, GetDefaultChainName())
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 7)
          .Build();

  std::vector<char> get_dump_request_inet =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_RULE_TABLE, test_table_name)
          .Build();

  std::vector<char> get_dump_request_ipv6 =
      NlReq("getrule req dump ipv6")
          .Seq(kSeq + 9)
          .StrAttr(NFTA_RULE_TABLE, test_table_name)
          .Build();

  int rules_found = 0;
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 7, add_request.data(), add_request.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_request_inet.data(), get_dump_request_inet.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        CheckNetfilterRuleAttributes(
            {.hdr = hdr,
             .expected_table_name = test_table_name,
             .expected_chain_name = GetDefaultChainName(),
             .expected_udata = udata,
             .expected_udata_size = &expected_udata_size,
             .skip_handle_check = true});
        rules_found++;
      },
      false));
  EXPECT_EQ(rules_found, 1);

  rules_found = 0;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_request_ipv6.data(), get_dump_request_ipv6.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        CheckNetfilterRuleAttributes(
            {.hdr = hdr,
             .expected_table_name = test_table_name,
             .expected_chain_name = GetDefaultChainName(),
             .expected_udata = udata,
             .expected_udata_size = &expected_udata_size,
             .skip_handle_check = true});
        rules_found++;
      },
      false));
  EXPECT_EQ(rules_found, 1);
}

TEST(NetlinkNetfilterTest, GetRuleDumpTableChainSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::string test_table_name = GetUniqueTestTableName();
  const char* test_chain_name_one = "test_chain_1";
  const char* test_chain_name_two = "test_chain_2";

  uint8_t udata[] = {0, 1, 2};
  size_t expected_udata_size = sizeof(udata);
  std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> add_request =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name_one)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name_two)
                   .Build())
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, test_chain_name_one)
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .Req(NlReq("newrule req ack create append inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, test_chain_name_one)
                   .RawAttr(NFTA_RULE_USERDATA, udata, sizeof(udata))
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  std::vector<char> get_dump_request_inet =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 7)
          .StrAttr(NFTA_RULE_TABLE, test_table_name)
          .StrAttr(NFTA_RULE_CHAIN, test_chain_name_one)
          .Build();

  std::vector<char> get_dump_request_inet_two =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_RULE_TABLE, test_table_name)
          .StrAttr(NFTA_RULE_CHAIN, test_chain_name_two)
          .Build();

  int rules_found = 0;
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 6, add_request.data(), add_request.size()));
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_request_inet.data(), get_dump_request_inet.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        CheckNetfilterRuleAttributes(
            {.hdr = hdr,
             .expected_table_name = test_table_name,
             .expected_chain_name = test_chain_name_one,
             .expected_udata = udata,
             .expected_udata_size = &expected_udata_size,
             .skip_handle_check = true});
        rules_found++;
      },
      false));
  EXPECT_EQ(rules_found, 2);

  rules_found = 0;
  // We expect no rules to be found as they were registered to a different
  // chain.
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_dump_request_inet_two.data(), get_dump_request_inet_two.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        rules_found++;
      },
      false));
  EXPECT_EQ(rules_found, 0);
}

TEST(NetlinkNetfilterTest, GetGenerationID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> get_gen_request =
      NlReq("getgen req inet").Seq(kSeq).Build();

  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_gen_request.data(), get_gen_request.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* gen_id_attr =
            FindNfAttr(hdr, nullptr, NFTA_GEN_ID);
        ASSERT_NE(gen_id_attr, nullptr);
        // Although the generation ID is initialized to 1, this number gets
        // incremented on successful NETFILTER nftables batch requests.
        // Thus, we simply check that is is greater than 1 here.
        uint32_t gen_id =
            ntohl(*(reinterpret_cast<uint32_t*>(NFA_DATA(gen_id_attr))));
        EXPECT_GE(gen_id, 1);
      },
      false));
}

struct RuleWithExprTestParams {
  std::string test_name;
  std::string expr_name;
  NlNestedAttr expr_attrs;
  int expected_error_no;
};

class AddRuleWithExprTest
    : public ::testing::TestWithParam<RuleWithExprTestParams> {};

TEST_P(AddRuleWithExprTest, AddRuleWithExpr) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!IsRunningOnGvisor());
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));
  std::vector<char> expr_data = NlNestedAttr(GetParam().expr_attrs).Build();
  ASSERT_FALSE(GetParam().expr_name.empty());
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, GetParam().expr_name)
          .RawAttr(NFTA_EXPR_DATA, expr_data.data(), expr_data.size())
          .Build();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();
  const std::string table_name =
      absl::StrCat("table_", GetParam().expr_name, "_", GetParam().test_name);
  const std::string chain_name = "test_chain";
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, chain_name)
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd, .table_name = table_name, .seq = kSeq});
  AddDefaultBaseChain({.fd = fd,
                       .table_name = table_name,
                       .chain_name = chain_name,
                       .seq = kSeq + 3});

  if (GetParam().expected_error_no != 0) {
    ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                    fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
                    add_rule_request_buffer.size()),
                PosixErrorIs(GetParam().expected_error_no, _));
  } else {
    ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
        fd, kSeq + 6, kSeq + 8, add_rule_request_buffer.data(),
        add_rule_request_buffer.size()));
  }
}

std::vector<RuleWithExprTestParams> GetPayloadRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "LoadValid",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_DREG, NFT_REG_1)},
      RuleWithExprTestParams{
          .test_name = "SetValid",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG32_00)},
      RuleWithExprTestParams{
          .test_name = "SetWithCsumValid",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_1)
                  .U32Attr(NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_INET)
                  .U32Attr(NFTA_PAYLOAD_CSUM_OFFSET, 1)},
      RuleWithExprTestParams{
          .test_name = "LoadWithInvalidRegister",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  // Verdict register is not supported for payload load.
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_VERDICT),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "LoadWithInvalidOffset",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, UINT32_MAX)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_VERDICT),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "LoadWithInvalidLen",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, NFT_REG_SIZE + 1)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_VERDICT),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "SetWithInvalidBase",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, /* NFT_PAYLOAD_INNER_HEADER */ 3)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_DREG, NFT_REG_1),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "SetWithInvalidRegister",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, 4)
                  .U32Attr(NFTA_PAYLOAD_DREG, NFT_REG_VERDICT),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "SetWithInvalidLen",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, NFT_REG_SIZE + 1)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_VERDICT),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "WithSregAndDregSet",
          .expr_name = "payload",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                  .U32Attr(NFTA_PAYLOAD_OFFSET, 1)
                  .U32Attr(NFTA_PAYLOAD_LEN, NFT_REG_SIZE + 1)
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG_1)
                  .U32Attr(NFTA_PAYLOAD_DREG, NFT_REG_2),
          .expected_error_no = EINVAL},
  };
}

INSTANTIATE_TEST_SUITE_P(
    PayloadRuleTest, AddRuleWithExprTest,
    /*param_generator=*/::testing::ValuesIn(GetPayloadRuleTestParams()),
    /*param_name_generator=*/
    [](const ::testing::TestParamInfo<RuleWithExprTestParams>& info) {
      return info.param.test_name;
    });

std::vector<RuleWithExprTestParams> GetMetaRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "GetValid",
          .expr_name = "meta",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_META_DREG, NFT_REG_1)
                            .U32Attr(NFTA_META_KEY, NFT_META_PKTTYPE)},
      RuleWithExprTestParams{
          .test_name = "SetValid",
          .expr_name = "meta",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_META_DREG, NFT_REG_1)
                            .U32Attr(NFTA_META_KEY, NFT_META_PKTTYPE)},
      RuleWithExprTestParams{
          .test_name = "WithSregAndDregSet",
          .expr_name = "meta",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_META_DREG, NFT_REG_1)
                            .U32Attr(NFTA_META_KEY, NFT_META_PKTTYPE)
                            .U32Attr(NFTA_META_SREG, NFT_REG_2),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "WithInvalidKey",
          .expr_name = "meta",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_META_DREG, NFT_REG_1)
                            .U32Attr(NFTA_META_KEY, 256),
          .expected_error_no = EINVAL},
  };
}

INSTANTIATE_TEST_SUITE_P(
    MetaRuleTest, AddRuleWithExprTest,
    /*param_generator=*/::testing::ValuesIn(GetMetaRuleTestParams()),
    /*param_name_generator=*/
    [](const ::testing::TestParamInfo<RuleWithExprTestParams>& info) {
      return info.param.test_name;
    });

}  // namespace

}  // namespace testing
}  // namespace gvisor
