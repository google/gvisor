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
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/xt_addrtype.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_tcpudp.h>
// clang-format on

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
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
using ::testing::TestParamInfo;
using ::testing::UnitTest;
using ::testing::UnorderedElementsAreArray;
using ::testing::ValuesIn;

using SockOptTest = ::testing::TestWithParam<
    std::tuple<int, std::function<bool(int)>, std::string>>;

// Environment to create a new network namespace.
// Enables isolated nftables modification.
class NetnsEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0) {
      return;
    }
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));
  }
};
// Load the environment to create a new network namespace.
::testing::Environment* const netns_env =
    ::testing::AddGlobalTestEnvironment(new NetnsEnvironment);

PosixErrorOr<bool> HaveCaps() {
  if (!IsRunningOnGvisor()) {
    ASSIGN_OR_RETURN_ERRNO(KernelVersion version, GetKernelVersion());
    if (version.major < 6) {
      return false;
    }
  }
  return HaveCapability(CAP_NET_RAW);
}

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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  EXPECT_THAT(fd.get(), SyscallSucceeds());
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddAndAddTableWithDormantFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddAndRetrieveNewTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetDumpTables) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetSets) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::string test_table_name = GetUniqueTestTableName();
  const char test_set_name_1[] = "test_set_one";
  const char test_set_name_2[] = "test_set_two";

  // Creates the parent table to hold our test sets.
  AddDefaultTable({.fd = fd, .table_name = test_table_name, .seq = kSeq});

  // Assemble Netlink structures to create multiple sets via NFT_MSG_NEWSET.
  //   [NLM_F_DEFAULT_BATCH]
  //     ├── [NFT_MSG_NEWSET]
  //     │     ├── NFTA_SET_TABLE = "test_table"
  //     │     ├── NFTA_SET_NAME  = "test_set_one"
  //     │     └── NFTA_SET_KEY_LEN = 4
  //     │
  //     └── [NFT_MSG_NEWSET]
  //           ├── NFTA_SET_TABLE = "test_table"
  //           ├── NFTA_SET_NAME  = "test_set_two"
  //           └── NFTA_SET_KEY_LEN = 4

  std::vector<char> add_sets_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 3)
          .Req(NlReq()
                   .MsgType(NFT_MSG_NEWSET)
                   .Flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
                   .Family(NFPROTO_INET)
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_SET_TABLE, test_table_name)
                   .StrAttr(NFTA_SET_NAME, test_set_name_1)
                   .U32Attr(NFTA_SET_KEY_LEN, 4)
                   .U32Attr(NFTA_SET_ID, 1)
                   .U32Attr(NFTA_SET_FLAGS, NFT_SET_MAP)
                   .U32Attr(NFTA_SET_DATA_LEN, 4)
                   .U32Attr(NFTA_SET_DATA_TYPE, 0)
                   .Build())
          .Req(NlReq()
                   .MsgType(NFT_MSG_NEWSET)
                   .Flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
                   .Family(NFPROTO_INET)
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_SET_TABLE, test_table_name)
                   .StrAttr(NFTA_SET_NAME, test_set_name_2)
                   .U32Attr(NFTA_SET_KEY_LEN, 4)
                   .U32Attr(NFTA_SET_ID, 2)
                   .U32Attr(NFTA_SET_FLAGS, NFT_SET_MAP)
                   .U32Attr(NFTA_SET_DATA_LEN, 4)
                   .U32Attr(NFTA_SET_DATA_TYPE, 0)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 3, kSeq + 6, add_sets_request_buffer.data(),
      add_sets_request_buffer.size()));

  // Setup the global dump request: NFT_MSG_GETSET with NLM_F_DUMP flag set.
  std::vector<char> get_request_buffer = NlReq()
                                             .MsgType(NFT_MSG_GETSET)
                                             .Flags(NLM_F_REQUEST | NLM_F_DUMP)
                                             .Family(NFPROTO_INET)
                                             .Seq(kSeq + 7)
                                             .Build();

  absl::flat_hash_set<std::string> expected_sets = {test_set_name_1,
                                                    test_set_name_2};

  // Perform the dump iteratively and extract NLM_F_MULTI sequenced packets.
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer.data(), get_request_buffer.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }

        // Entire response must properly utilize chunk streaming flags.
        EXPECT_TRUE(hdr->nlmsg_flags & NLM_F_MULTI);

        const struct nfattr* set_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_SET_NAME);
        if (set_name_attr) {
          std::string set_name(
              reinterpret_cast<const char*>(NFA_DATA(set_name_attr)));
          expected_sets.erase(set_name);
        }
      },
      false));

  // Verify we saw exactly the requested sets successfully dumped out.
  ASSERT_TRUE(expected_sets.empty());
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

class NetlinkNetfilterSetElementsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    constexpr uint32_t kKeyLen = 4;
    constexpr uint32_t kDataLen = 4;

    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
    fd_ = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
    test_table_name_ = GetUniqueTestTableName();

    // Creates the parent table to hold our test set.
    AddDefaultTable({.fd = fd_, .table_name = test_table_name_, .seq = kSeq});

    // Create set.
    std::vector<char> add_set_request_buffer =
        NlBatchReq()
            .SeqStart(kSeq + 3)
            .Req(NlReq()
                     .MsgType(NFT_MSG_NEWSET)
                     .Flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
                     .Family(NFPROTO_INET)
                     .Seq(kSeq + 4)
                     .StrAttr(NFTA_SET_TABLE, test_table_name_)
                     .StrAttr(NFTA_SET_NAME, test_set_name_)
                     .U32Attr(NFTA_SET_KEY_LEN, kKeyLen)
                     .U32Attr(NFTA_SET_ID, 1)
                     .U32Attr(NFTA_SET_FLAGS, NFT_SET_MAP)
                     .U32Attr(NFTA_SET_DATA_LEN, kDataLen)
                     .U32Attr(NFTA_SET_DATA_TYPE, 0)
                     .Build())
            .SeqEnd(kSeq + 5)
            .Build();

    ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
        fd_, kSeq + 3, kSeq + 5, add_set_request_buffer.data(),
        add_set_request_buffer.size()));

    // Add 2 elements.
    elem1_desc_ = {.key = {192, 168, 1, 1}, .data = {10, 0, 0, 1}, .flags = 0};
    elem2_desc_ = {.key = {}, .data = {10, 0, 0, 1}, .flags = kCatchallFlag};

    std::vector<char> elem1 = BuildNetlinkElement(elem1_desc_);
    std::vector<char> elem2 = BuildNetlinkElement(elem2_desc_);

    std::vector<char> elements = NlListAttr().Add(elem1).Add(elem2).Build();

    // Assemble array Netlink structures to create set elements natively.
    //   [NLM_F_DEFAULT_BATCH]
    //     └── [NFT_MSG_NEWSETELEM]
    //           ├── NFTA_SET_ELEM_LIST_TABLE = "test_table"
    //           ├── NFTA_SET_ELEM_LIST_SET   = "test_set_one"
    //           └── NFTA_SET_ELEM_LIST_ELEMENTS (Nested Array)
    //                 ├── NFTA_LIST_ELEM
    //                 │     └── NFTA_SET_ELEM_KEY
    //                 │           └── NFTA_DATA_VALUE
    //                 └── NFTA_LIST_ELEM
    //                       └── NFTA_SET_ELEM_FLAGS (CATCHALL)
    std::vector<char> add_elements_buffer =
        NlBatchReq()
            .SeqStart(kSeq + 6)
            .Req(NlReq()
                     .MsgType(NFT_MSG_NEWSETELEM)
                     .Flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
                     .Family(NFPROTO_INET)
                     .Seq(kSeq + 7)
                     .StrAttr(NFTA_SET_ELEM_LIST_TABLE, test_table_name_)
                     .StrAttr(NFTA_SET_ELEM_LIST_SET, test_set_name_)
                     .RawAttr(NFTA_SET_ELEM_LIST_ELEMENTS, elements.data(),
                              elements.size())
                     .Build())
            .SeqEnd(kSeq + 8)
            .Build();

    ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
        fd_, kSeq + 6, kSeq + 8, add_elements_buffer.data(),
        add_elements_buffer.size()));
  }

  std::vector<char> BuildDeleteElementsReq(
      const std::vector<ElementDescriptor>& elems, uint32_t seq,
      bool delete_all = false) {
    NlReq req = NlReq()
                    .MsgType(NFT_MSG_DELSETELEM)
                    .Flags(NLM_F_REQUEST | NLM_F_ACK)
                    .Family(NFPROTO_INET)
                    .Seq(seq + 1)
                    .StrAttr(NFTA_SET_ELEM_LIST_TABLE, test_table_name_)
                    .StrAttr(NFTA_SET_ELEM_LIST_SET, test_set_name_);

    if (!delete_all) {
      NlListAttr list_attr;
      for (const auto& elem : elems) {
        list_attr.Add(BuildNetlinkElement(elem));
      }
      std::vector<char> elem_list = list_attr.Build();
      req.RawAttr(NFTA_SET_ELEM_LIST_ELEMENTS, elem_list.data(),
                  elem_list.size());
    }

    return NlBatchReq().SeqStart(seq).Req(req.Build()).SeqEnd(seq + 2).Build();
  }

  const uint32_t kCatchallFlag = 0x2;
  const char* test_set_name_ = "test_set_one";
  FileDescriptor fd_;
  std::string test_table_name_;
  ElementDescriptor elem1_desc_;
  ElementDescriptor elem2_desc_;
};

TEST_F(NetlinkNetfilterSetElementsTest, GetSetElements) {
  std::vector<ElementDescriptor> elements = ASSERT_NO_ERRNO_AND_VALUE(
      GetSetElements(fd_, test_table_name_, test_set_name_, kSeq + 9));
  EXPECT_THAT(elements,
              UnorderedElementsAreArray(
                  std::vector<ElementDescriptor>{elem1_desc_, elem2_desc_}));
}

TEST_F(NetlinkNetfilterSetElementsTest, DeleteNonExistentSetElement) {
  // Delete a non-existent element.
  ElementDescriptor elem = {.key = {192, 168, 1, 2}};
  std::vector<char> delete_req = BuildDeleteElementsReq({elem}, kSeq + 10);

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd_, kSeq + 10, kSeq + 12, delete_req.data(), delete_req.size()),
      PosixErrorIs(ENOENT, _));

  // Verify both of the elements are still there.
  std::vector<ElementDescriptor> elements = ASSERT_NO_ERRNO_AND_VALUE(
      GetSetElements(fd_, test_table_name_, test_set_name_, kSeq + 13));
  EXPECT_THAT(elements,
              UnorderedElementsAreArray(
                  std::vector<ElementDescriptor>{elem1_desc_, elem2_desc_}));
}

TEST_F(NetlinkNetfilterSetElementsTest, DeleteSetElement) {
  // Delete elem1 (keyed).
  ElementDescriptor elem_desc = {.key = elem1_desc_.key};
  std::vector<char> delete_req = BuildDeleteElementsReq({elem_desc}, kSeq + 10);

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 10, kSeq + 12, delete_req.data(), delete_req.size()));

  // Verify that elem2 is still there.
  std::vector<ElementDescriptor> elements = ASSERT_NO_ERRNO_AND_VALUE(
      GetSetElements(fd_, test_table_name_, test_set_name_, kSeq + 13));
  EXPECT_THAT(elements, UnorderedElementsAreArray(
                            std::vector<ElementDescriptor>{elem2_desc_}));
}

TEST_F(NetlinkNetfilterSetElementsTest, DeleteCatchallSetElement) {
  // Delete elem2 (catchall).
  ElementDescriptor elem_desc = {.flags = kCatchallFlag};
  std::vector<char> delete_req = BuildDeleteElementsReq({elem_desc}, kSeq + 10);

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 10, kSeq + 12, delete_req.data(), delete_req.size()));

  // Verify that only elem1 exists.
  std::vector<ElementDescriptor> elements = ASSERT_NO_ERRNO_AND_VALUE(
      GetSetElements(fd_, test_table_name_, test_set_name_, kSeq + 13));
  EXPECT_THAT(elements, UnorderedElementsAreArray(
                            std::vector<ElementDescriptor>{elem1_desc_}));
}

TEST_F(NetlinkNetfilterSetElementsTest, DeleteAllSetElements) {
  // Remove all elements.
  std::vector<char> delete_req =
      BuildDeleteElementsReq({}, kSeq + 10, /*delete_all=*/true);

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 10, kSeq + 12, delete_req.data(), delete_req.size()));
  // Verify elements are deleted.
  std::vector<ElementDescriptor> elements = ASSERT_NO_ERRNO_AND_VALUE(
      GetSetElements(fd_, test_table_name_, test_set_name_, kSeq + 13));
  EXPECT_TRUE(elements.empty());
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd_));
}

TEST(NetlinkNetfilterTest, ErrGettingTableWithDifferentFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithExclusiveFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddExistingTableWithReplaceFlag) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithInvalidFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddTableWithUnsupportedFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNoSpecifiedNameTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> get_request_buffer =
      NlReq("gettable req ack inet").Seq(kSeq).Build();

  ASSERT_THAT(NetlinkRequestAckOrError(fd, kSeq, get_request_buffer.data(),
                                       get_request_buffer.size()),
              PosixErrorIs(EINVAL, _));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrRetrieveNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteExistingTableByName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteTableByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  if (!IsRunningOnGvisor()) {
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 6 || (version.major == 6 && version.minor < 5));
  }
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_ipv4[] = "test_table_ipv4";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
                   .Build())
          .Req(NlReq("newtable req ack ipv4")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
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
      NlReq("gettable req ipv4")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedFamilySpecifiedName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
          .Req(NlReq("newtable req ack ipv4")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
                   .Build())
          .Req(NlReq("newtable req ack ipv4")
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
      NlReq("gettable req ipv4")
          .Seq(kSeq + 9)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_same)
          .Build();

  std::vector<char> get_request_buffer_different =
      NlReq("gettable req ipv4")
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesUnspecifiedNameAndHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_ipv4[] = "test_table_ipv4";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
                   .Build())
          .Req(NlReq("newtable req ack ipv4")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
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
      NlReq("gettable req ipv4")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteAllTablesInetFamily) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  char test_table_name_inet[] = "test_table_inet";
  char test_table_name_ipv4[] = "test_table_ipv4";

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
                   .Build())
          .Req(NlReq("newtable req ack ipv4")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  // Delete all tables in inet family only.
  std::vector<char> destroy_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("deltable req ack inet").Seq(kSeq + 5).Build())
          .SeqEnd(kSeq + 6)
          .Build();

  std::vector<char> get_request_buffer_inet =
      NlReq("gettable req inet")
          .Seq(kSeq + 7)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_inet)
          .Build();

  std::vector<char> get_request_buffer_ipv4 =
      NlReq("gettable req ipv4")
          .Seq(kSeq + 8)
          .StrAttr(NFTA_TABLE_NAME, test_table_name_ipv4)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));
  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, destroy_request_buffer.data(),
      destroy_request_buffer.size()));

  // Inet table should be gone.
  ASSERT_THAT(
      NetlinkRequestAckOrError(fd, kSeq + 7, get_request_buffer_inet.data(),
                               get_request_buffer_inet.size()),
      PosixErrorIs(ENOENT, _));
  // IPv4 table should still exist.
  bool ipv4_table_exists = false;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, get_request_buffer_ipv4.data(), get_request_buffer_ipv4.size(),
      [&](const struct nlmsghdr* hdr) {
        const struct nfattr* table_name_attr =
            FindNfAttr(hdr, nullptr, NFTA_TABLE_NAME);
        ASSERT_NE(table_name_attr, nullptr);
        EXPECT_EQ(table_name_attr->nfa_type, NFTA_TABLE_NAME);
        std::string name(
            reinterpret_cast<const char*>(NFA_DATA(table_name_attr)));
        EXPECT_EQ(name, test_table_name_ipv4);
        ipv4_table_exists = true;
      },
      false));
  ASSERT_TRUE(ipv4_table_exists);
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithNoSpecifiedNameOrHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewChainWithPolicySet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest,
     ErrNewBaseChainWithMalformedHookDataMissingPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithMalformedHookDataMissingHookNum) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewBaseChainWithInvalidChainType) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrNewNATBaseChainWithInvalidPriority) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewNetDevBaseChain) {
  // TODO: b/434243967 - Remove when netdev chains are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewInetBaseChainAtIngress) {
  // TODO: b/434243967 - Remove when inet chains are supported at Ingress.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedNewBaseChainWithChainCounters) {
  // TODO: b/434243967 - Remove when chain counters are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrChainWithBaseChainFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrUnsupportedChainWithHardwareOffloadFlagSet) {
  // TODO: b/434243967 - Remove when hardware offload chains are supported.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrChainWithNoNameAndChainBindingFlagNotSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

class NetlinkNetfilterChainUpdateTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
    fd_ = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
    test_table_name_ = GetUniqueTestTableName();
    AddDefaultTable({.fd = fd_, .table_name = test_table_name_, .seq = kSeq});
  }

  void TearDown() override {
    if (fd_.get() >= 0 && !test_table_name_.empty()) {
      // Clean up table and ruleset automatically regardless of test outcome.
      EXPECT_NO_ERRNO(DestroyNetfilterTable(fd_, test_table_name_, kSeq + 100));
      EXPECT_NO_ERRNO(NetfilterFlushRuleset(fd_));
    }
  }

  // Helper methods inside the fixture for concise chain creation and checks:
  void AddBaseChain(absl::string_view chain_name, uint32_t seq,
                    uint32_t hook_priority = 0,
                    uint32_t flags = NFT_CHAIN_BASE) {
    AddDefaultBaseChain({.fd = fd_,
                         .table_name = test_table_name_,
                         .chain_name = std::string(chain_name),
                         .seq = seq,
                         .chain_type = "filter",
                         .hook_num = NF_INET_PRE_ROUTING,
                         .hook_priority = hook_priority,
                         .flags = flags,
                         .family_name = "inet"});
  }

  void AddRegularChain(absl::string_view chain_name, uint32_t seq,
                       uint32_t flags = 0, uint32_t chain_id = 0) {
    AddDefaultRegularChain({.fd = fd_,
                            .table_name = test_table_name_,
                            .chain_name = std::string(chain_name),
                            .seq = seq,
                            .flags = flags,
                            .chain_id = chain_id,
                            .family_name = "inet"});
  }

  uint64_t GetHandle(absl::string_view chain_name, uint32_t seq) {
    auto res = GetChainHandle(fd_, test_table_name_, chain_name, seq);
    EXPECT_NO_ERRNO(res);
    return res.ok() ? res.ValueOrDie() : 0;
  }

  void VerifyPolicy(absl::string_view chain_name, uint32_t expected_policy,
                    uint32_t seq) {
    VerifyChainPolicy(fd_, test_table_name_, chain_name, expected_policy, seq);
  }

  FileDescriptor fd_;
  std::string test_table_name_;
};

TEST_F(NetlinkNetfilterChainUpdateTest, UpdateBaseChainPolicy) {
  const char test_chain_name[] = "test_base_chain_policy";

  AddBaseChain(test_chain_name, kSeq + 3, /*hook_priority=*/10);

  // 1. Update policy to NF_DROP.
  std::vector<char> update_drop =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, NF_DROP)
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 6, kSeq + 8, update_drop.data(), update_drop.size()));

  VerifyPolicy(test_chain_name, NF_DROP, kSeq + 9);

  // 2. Update policy back to NF_ACCEPT.
  std::vector<char> update_accept =
      NlBatchReq()
          .SeqStart(kSeq + 10)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 11)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, NF_ACCEPT)
                   .Build())
          .SeqEnd(kSeq + 12)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 10, kSeq + 12, update_accept.data(), update_accept.size()));

  VerifyPolicy(test_chain_name, NF_ACCEPT, kSeq + 13);
}

TEST_F(NetlinkNetfilterChainUpdateTest, UpdateChainRename) {
  const char test_chain_orig[] = "chain_orig";
  const char test_chain_renamed[] = "chain_renamed";

  AddRegularChain(test_chain_orig, kSeq + 3);

  uint64_t chain_handle = GetHandle(test_chain_orig, kSeq + 6);

  // Rename chain using NFTA_CHAIN_HANDLE and NFTA_CHAIN_NAME.
  std::vector<char> rename_req =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
                   .U64Attr(NFTA_CHAIN_HANDLE, chain_handle)
                   .StrAttr(NFTA_CHAIN_NAME, test_chain_renamed)
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 7, kSeq + 9, rename_req.data(), rename_req.size()));

  // Verify chain_renamed exists
  uint64_t chain_renamed_handle = GetHandle(test_chain_renamed, kSeq + 10);
  EXPECT_EQ(chain_handle, chain_renamed_handle);

  // Verify chain_orig no longer exists.
  std::vector<char> get_chain_orig_req =
      NlReq("getchain req inet")
          .Seq(kSeq + 12)
          .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
          .StrAttr(NFTA_CHAIN_NAME, test_chain_orig)
          .Build();

  ASSERT_THAT(
      NetlinkRequestAckOrError(fd_, kSeq + 12, get_chain_orig_req.data(),
                               get_chain_orig_req.size()),
      PosixErrorIs(ENOENT, _));
}

TEST_F(NetlinkNetfilterChainUpdateTest, UpdateChainPreservesOtherChains) {
  const char chain_a[] = "chain_a";
  const char chain_b[] = "chain_b";
  const char chain_c_orig[] = "chain_c_orig";
  const char chain_c_renamed[] = "chain_c_renamed";

  AddBaseChain(chain_a, kSeq + 3, /*hook_priority=*/10);
  AddBaseChain(chain_b, kSeq + 6, /*hook_priority=*/20);
  AddRegularChain(chain_c_orig, kSeq + 9);

  // 1. Update chain_a policy to NF_DROP.
  std::vector<char> update_a_req =
      NlBatchReq()
          .SeqStart(kSeq + 12)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 13)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
                   .StrAttr(NFTA_CHAIN_NAME, chain_a)
                   .U32Attr(NFTA_CHAIN_POLICY, NF_DROP)
                   .Build())
          .SeqEnd(kSeq + 14)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 12, kSeq + 14, update_a_req.data(), update_a_req.size()));

  uint64_t chain_c_handle = GetHandle(chain_c_orig, kSeq + 15);

  // 2. Rename chain_c_orig to chain_c_renamed.
  std::vector<char> rename_c_req =
      NlBatchReq()
          .SeqStart(kSeq + 18)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 19)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name_)
                   .U64Attr(NFTA_CHAIN_HANDLE, chain_c_handle)
                   .StrAttr(NFTA_CHAIN_NAME, chain_c_renamed)
                   .Build())
          .SeqEnd(kSeq + 20)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 18, kSeq + 20, rename_c_req.data(), rename_c_req.size()));

  // Verify that modifying chain_a did not affect chain_b.
  VerifyPolicy(chain_b, NF_ACCEPT, kSeq + 21);

  // Verify chain_a policy is NF_DROP.
  VerifyPolicy(chain_a, NF_DROP, kSeq + 22);
}

struct ChainUpdateErrorParam {
  std::string test_name;
  bool is_base_chain;
  std::function<std::vector<char>(const std::string& table_name,
                                  const std::string& chain_name, uint32_t seq,
                                  uint64_t chain_handle)>
      build_update_req;
  int expected_error;
  bool gvisor_only = false;
};

class NetlinkNetfilterChainUpdateErrorTest
    : public NetlinkNetfilterChainUpdateTest,
      public ::testing::WithParamInterface<ChainUpdateErrorParam> {};

TEST_P(NetlinkNetfilterChainUpdateErrorTest, InvalidChainUpdates) {
  const ChainUpdateErrorParam& param = GetParam();
  if (param.gvisor_only) {
    SKIP_IF(!IsRunningOnGvisor());
  }

  const std::string chain_name = "test_err_chain";
  if (param.is_base_chain) {
    AddBaseChain(chain_name, kSeq + 3);
  } else {
    AddRegularChain(
        chain_name, kSeq + 3,
        param.test_name == "UpdateBindingChain" ? NFT_CHAIN_BINDING : 0,
        param.test_name == "UpdateBindingChain" ? 10 : 0);
  }

  uint64_t chain_handle = 0;
  if (param.test_name == "DuplicateRename") {
    AddRegularChain("chain_dup_2", kSeq + 6);
    chain_handle = GetHandle(chain_name, kSeq + 9);
  }

  std::vector<char> update_req = param.build_update_req(
      test_table_name_, chain_name, kSeq + 12, chain_handle);

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd_, kSeq + 12, kSeq + 14, update_req.data(), update_req.size()),
      PosixErrorIs(param.expected_error, _));
}

INSTANTIATE_TEST_SUITE_P(
    ChainUpdateErrors, NetlinkNetfilterChainUpdateErrorTest,
    ::testing::Values(
        ChainUpdateErrorParam{
            .test_name = "RegularChainPolicyNotSupported",
            .is_base_chain = false,
            .build_update_req =
                [](const std::string& table, const std::string& chain,
                   uint32_t seq, uint64_t handle) {
                  return NlBatchReq()
                      .SeqStart(seq)
                      .Req(NlReq("newchain req ack inet")
                               .Seq(seq + 1)
                               .StrAttr(NFTA_CHAIN_TABLE, table)
                               .StrAttr(NFTA_CHAIN_NAME, chain)
                               .U32Attr(NFTA_CHAIN_POLICY, NF_DROP)
                               .Build())
                      .SeqEnd(seq + 2)
                      .Build();
                },
            .expected_error = ENOTSUP,
        },
        ChainUpdateErrorParam{
            .test_name = "DuplicateRename",
            .is_base_chain = false,
            .build_update_req =
                [](const std::string& table, const std::string& chain,
                   uint32_t seq, uint64_t handle) {
                  return NlBatchReq()
                      .SeqStart(seq)
                      .Req(NlReq("newchain req ack inet")
                               .Seq(seq + 1)
                               .StrAttr(NFTA_CHAIN_TABLE, table)
                               .U64Attr(NFTA_CHAIN_HANDLE, handle)
                               .StrAttr(NFTA_CHAIN_NAME, "chain_dup_2")
                               .Build())
                      .SeqEnd(seq + 2)
                      .Build();
                },
            .expected_error = EEXIST,
        },
        ChainUpdateErrorParam{
            .test_name = "RegularChainWithHook",
            .is_base_chain = false,
            .build_update_req =
                [](const std::string& table, const std::string& chain,
                   uint32_t seq, uint64_t handle) {
                  std::vector<char> nested_hook_data =
                      NlNestedAttr()
                          .U32Attr(NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING)
                          .U32Attr(NFTA_HOOK_PRIORITY, 0)
                          .Build();
                  return NlBatchReq()
                      .SeqStart(seq)
                      .Req(NlReq("newchain req ack inet")
                               .Seq(seq + 1)
                               .StrAttr(NFTA_CHAIN_TABLE, table)
                               .StrAttr(NFTA_CHAIN_NAME, chain)
                               .RawAttr(NFTA_CHAIN_HOOK,
                                        nested_hook_data.data(),
                                        nested_hook_data.size())
                               .Build())
                      .SeqEnd(seq + 2)
                      .Build();
                },
            .expected_error = EEXIST,
        },
        ChainUpdateErrorParam{
            .test_name = "ChainUpdateExclusiveExists",
            .is_base_chain = false,
            .build_update_req =
                [](const std::string& table, const std::string& chain,
                   uint32_t seq, uint64_t handle) {
                  return NlBatchReq()
                      .SeqStart(seq)
                      .Req(NlReq("newchain req ack create excl inet")
                               .Seq(seq + 1)
                               .StrAttr(NFTA_CHAIN_TABLE, table)
                               .StrAttr(NFTA_CHAIN_NAME, chain)
                               .Build())
                      .SeqEnd(seq + 2)
                      .Build();
                },
            .expected_error = EEXIST,
        },
        ChainUpdateErrorParam{
            .test_name = "ChainUpdateFlagsNotSupported",
            .is_base_chain = false,
            .build_update_req =
                [](const std::string& table, const std::string& chain,
                   uint32_t seq, uint64_t handle) {
                  return NlBatchReq()
                      .SeqStart(seq)
                      .Req(NlReq("newchain req ack inet")
                               .Seq(seq + 1)
                               .StrAttr(NFTA_CHAIN_TABLE, table)
                               .StrAttr(NFTA_CHAIN_NAME, chain)
                               .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_HW_OFFLOAD)
                               .Build())
                      .SeqEnd(seq + 2)
                      .Build();
                },
            .expected_error = EOPNOTSUPP,
        }),
    [](const ::testing::TestParamInfo<ChainUpdateErrorParam>& info) {
      return info.param.test_name;
    });

struct AnonymousChainTestParam {
  std::string test_name;
  std::optional<uint32_t> flags;
  std::optional<uint32_t> id;
  std::optional<std::string> name;
  int expected_error;
};

class NetlinkNetfilterChainTest
    : public ::testing::TestWithParam<AnonymousChainTestParam> {
 protected:
  FileDescriptor fd_;
  std::string test_table_name_;
};

// AnonymousChain tests error cases when adding anonymous chains.
// An anonymous chain is a chain with the NFT_CHAIN_BINDING flag set.
TEST_P(NetlinkNetfilterChainTest, AnonymousChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  fd_ = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  test_table_name_ = GetUniqueTestTableName();
  const AnonymousChainTestParam& param = GetParam();

  auto new_chain_req = NlReq("newchain req ack inet")
                           .Seq(kSeq + 2)
                           .StrAttr(NFTA_CHAIN_TABLE, test_table_name_);
  if (param.flags.has_value()) {
    new_chain_req.U32Attr(NFTA_CHAIN_FLAGS, param.flags.value());
  }
  if (param.id.has_value()) {
    new_chain_req.U32Attr(NFTA_CHAIN_ID, param.id.value());
  }
  if (param.name.has_value()) {
    new_chain_req.StrAttr(NFTA_CHAIN_NAME, param.name.value());
  }

  std::vector<char> add_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name_)
                   .Build())
          .Req(new_chain_req.Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd_, kSeq, kSeq + 3,
                                                     add_request_buffer.data(),
                                                     add_request_buffer.size()),
              PosixErrorIs(param.expected_error, _));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd_));
}

INSTANTIATE_TEST_SUITE_P(
    AddChainErrorcases, NetlinkNetfilterChainTest,
    ::testing::Values(
        AnonymousChainTestParam{.test_name = "AddUnboundBindingChain",
                                .flags = NFT_CHAIN_BINDING,
                                .id = 2,
                                .name = std::nullopt,
                                .expected_error = EINVAL},
        AnonymousChainTestParam{.test_name = "AddNamedBindingChain",
                                .flags = NFT_CHAIN_BINDING,
                                .id = std::nullopt,
                                .name = "binding_chain",
                                .expected_error = EINVAL},
        AnonymousChainTestParam{.test_name = "AddUnnamedRegularChain",
                                .flags = std::nullopt,
                                .id = std::nullopt,
                                .name = std::nullopt,
                                .expected_error = EINVAL}),
    [](const ::testing::TestParamInfo<AnonymousChainTestParam>& info) {
      return info.param.test_name;
    });

// ErrUpdateChainByID tests that updating a chain by ID without a name fails.
TEST(NetlinkNetfilterTest, ErrUpdateChainByID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  std::string test_table_name = GetUniqueTestTableName();

  const uint32_t test_chain_id = 99;
  const std::string test_chain_name = "test_chain";

  std::vector<char> request_buffer =
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
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .SeqEnd(kSeq + 4)
          .Build();

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd, kSeq, kSeq + 4, request_buffer.data(), request_buffer.size()),
      PosixErrorIs(EINVAL, _));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

// ErrDeleteChainByID tests that deleting a chain by ID without a name fails.
TEST(NetlinkNetfilterTest, ErrDeleteChainByID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  std::string test_table_name = GetUniqueTestTableName();

  const uint32_t test_chain_id = 99;
  const std::string test_chain_name = "test_chain";

  std::vector<char> request_buffer =
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
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .Req(NlReq("delchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .SeqEnd(kSeq + 4)
          .Build();

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd, kSeq, kSeq + 4, request_buffer.data(), request_buffer.size()),
      PosixErrorIs(EINVAL, _));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

// AddRuleWithAnonymousChainJump tests creating an anonymous binding chain
// and adding a rule that jumps to it in the same batch.
TEST(NetlinkNetfilterTest, AddRuleWithAnonymousChainJump) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  std::string test_table_name = GetUniqueTestTableName();

  const uint32_t test_chain_id = 99;
  const std::string test_base_chain_name = "test_base_chain";

  std::vector<char> rule_expr_data = NlImmExpr()
                                         .Dreg(NFT_REG_VERDICT)
                                         .VerdictCode(NFT_JUMP)
                                         .VerdictChainId(test_chain_id)
                                         .VerdictBuild();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

  std::vector<char> request_buffer =
      NlBatchReq()
          .SeqStart(kSeq)
          .Req(NlReq("newtable req ack inet")
                   .Seq(kSeq + 1)
                   .StrAttr(NFTA_TABLE_NAME, test_table_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 2)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, test_base_chain_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_BINDING)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, test_base_chain_name)
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 5, request_buffer.data(), request_buffer.size()));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddChainWithName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddBaseChainWithDropPolicy) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetChainWithDumpFlagSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrGetChainWithNoChainName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrDeleteChainWithNoTableNameSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrDeleteNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DestroyNonexistentChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  if (!IsRunningOnGvisor()) {
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 6 || (version.major == 6 && version.minor < 5));
  }
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteBaseChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, DeleteBaseChainByHandle) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrModifyTableWithOwnerMismatchUnboundSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddTableWithUnboundSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddRuleWithMissingTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}
// here
TEST(NetlinkNetfilterTest, ErrAddRuleWithUnknownTableName) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddRuleNoChainSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

class NetlinkNetfilterDeletionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
    fd_ = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
    test_table_name_ = GetUniqueTestTableName();

    std::vector<char> rule_expr_data = NlImmExpr::DefaultAcceptAll();
    std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

    // Create table, 2 chains with rules in both.
    std::vector<char> add_request =
        NlBatchReq()
            .SeqStart(kSeq)
            .Req(NlReq("newtable req ack inet")
                     .Seq(kSeq + 1)
                     .StrAttr(NFTA_TABLE_NAME, test_table_name_)
                     .Build())
            .Req(NlReq("newchain req ack inet")
                     .Seq(kSeq + 2)
                     .StrAttr(NFTA_TABLE_NAME, test_table_name_)
                     .StrAttr(NFTA_CHAIN_NAME, chain_1_)
                     .Build())
            .Req(NlReq("newchain req ack inet")
                     .Seq(kSeq + 3)
                     .StrAttr(NFTA_TABLE_NAME, test_table_name_)
                     .StrAttr(NFTA_CHAIN_NAME, chain_2_)
                     .Build())
            .Req(NlReq("newrule req ack create inet")
                     .Seq(kSeq + 4)
                     .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                     .StrAttr(NFTA_RULE_CHAIN, chain_1_)
                     .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                              list_expr_data.size())
                     .Build())
            .Req(NlReq("newrule req ack create inet")
                     .Seq(kSeq + 5)
                     .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                     .StrAttr(NFTA_RULE_CHAIN, chain_2_)
                     .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                              list_expr_data.size())
                     .Build())
            .SeqEnd(kSeq + 6)
            .Build();

    ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
        fd_, kSeq, kSeq + 6, add_request.data(), add_request.size()));
  }

  FileDescriptor fd_;
  std::string test_table_name_;
  const std::string chain_1_ = "test_chain_1";
  const std::string chain_2_ = "test_chain_2";
};

TEST_F(NetlinkNetfilterDeletionTest, FlushChainRules) {
  // Flush chain rules (Delete rule without handle).
  std::vector<char> flush_request =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("delrule req ack inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                   .StrAttr(NFTA_RULE_CHAIN, chain_1_)
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 7, kSeq + 9, flush_request.data(), flush_request.size()));

  struct Expectation {
    std::string chain;
    int want_rules_count;
  } expectations[] = {{chain_1_, 0}, {chain_2_, 1}};

  uint32_t seq = kSeq + 10;
  for (const auto& exp : expectations) {
    std::vector<char> get_dump_request =
        NlReq("getrule req dump inet")
            .Seq(seq++)
            .StrAttr(NFTA_RULE_TABLE, test_table_name_)
            .StrAttr(NFTA_RULE_CHAIN, exp.chain)
            .Build();

    int rules_in_chain = 0;
    ASSERT_NO_ERRNO(NetlinkRequestResponse(
        fd_, get_dump_request.data(), get_dump_request.size(),
        [&](const struct nlmsghdr* hdr) {
          if (hdr->nlmsg_type == NLMSG_DONE) {
            return;
          }
          rules_in_chain++;
        },
        false));
    EXPECT_EQ(rules_in_chain, exp.want_rules_count) << "Chain: " << exp.chain;
  }
}

TEST_F(NetlinkNetfilterDeletionTest, FlushTableRules) {
  // Flush table rules (Delete rule without chain and handle).
  std::vector<char> flush_request =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("delrule req ack inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  // Verify rules are gone.
  std::vector<char> get_dump_request =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 10)
          .StrAttr(NFTA_RULE_TABLE, test_table_name_)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 7, kSeq + 9, flush_request.data(), flush_request.size()));

  int rules_in_table = 0;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd_, get_dump_request.data(), get_dump_request.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }
        rules_in_table++;
      },
      false));
  EXPECT_EQ(rules_in_table, 0);
}

TEST_F(NetlinkNetfilterDeletionTest, DeleteRuleByHandle) {
  // 1. Get the handle of the rule in chain_1_ and verify it has exactly 1 rule.
  std::vector<char> get_dump_request =
      NlReq("getrule req dump inet")
          .Seq(kSeq + 7)
          .StrAttr(NFTA_RULE_TABLE, test_table_name_)
          .StrAttr(NFTA_RULE_CHAIN, chain_1_)
          .Build();

  uint64_t rule_handle = 0;
  int rules_in_chain_before = 0;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd_, get_dump_request.data(), get_dump_request.size(),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
          return;
        }
        rules_in_chain_before++;
        const struct nfattr* handle_attr =
            FindNfAttr(hdr, nullptr, NFTA_RULE_HANDLE);
        if (handle_attr != nullptr) {
          EXPECT_EQ(handle_attr->nfa_len - NLA_HDRLEN, sizeof(uint64_t));
          uint64_t aligned_value;
          memcpy(&aligned_value, NFA_DATA(handle_attr), sizeof(uint64_t));
          rule_handle = be64toh(aligned_value);
        }
      },
      false));

  EXPECT_EQ(rules_in_chain_before, 1);
  ASSERT_NE(rule_handle, 0);

  // 2. Delete the rule by handle.
  std::vector<char> delete_request =
      NlBatchReq()
          .SeqStart(kSeq + 8)
          .Req(NlReq("delrule req ack inet")
                   .Seq(kSeq + 9)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                   .StrAttr(NFTA_RULE_CHAIN, chain_1_)
                   .U64Attr(NFTA_RULE_HANDLE, rule_handle)
                   .Build())
          .SeqEnd(kSeq + 10)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd_, kSeq + 8, kSeq + 10, delete_request.data(), delete_request.size()));

  // 3. Verify chain_1_ has 0 rules and chain_2_ still has 1 rule.
  struct Expectation {
    std::string chain;
    int want_rules_count;
  } expectations[] = {{chain_1_, 0}, {chain_2_, 1}};

  uint32_t seq = kSeq + 11;
  for (const auto& exp : expectations) {
    std::vector<char> get_dump_request_verify =
        NlReq("getrule req dump inet")
            .Seq(seq++)
            .StrAttr(NFTA_RULE_TABLE, test_table_name_)
            .StrAttr(NFTA_RULE_CHAIN, exp.chain)
            .Build();

    int rules_in_chain = 0;
    ASSERT_NO_ERRNO(NetlinkRequestResponse(
        fd_, get_dump_request_verify.data(), get_dump_request_verify.size(),
        [&](const struct nlmsghdr* hdr) {
          if (hdr->nlmsg_type == NLMSG_DONE) {
            return;
          }
          rules_in_chain++;
        },
        false));
    EXPECT_EQ(rules_in_chain, exp.want_rules_count) << "Chain: " << exp.chain;
  }
}

TEST_F(NetlinkNetfilterDeletionTest, ErrFlushChainRulesUnknownTable) {
  std::vector<char> flush_request =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("delrule req ack inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_RULE_TABLE, "unknown_table")
                   .StrAttr(NFTA_RULE_CHAIN, "valid_chain")
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd_, kSeq + 7, kSeq + 9, flush_request.data(), flush_request.size()),
      PosixErrorIs(ENOENT, _));
}

TEST_F(NetlinkNetfilterDeletionTest, ErrFlushChainRulesUnknownChain) {
  std::vector<char> flush_request =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("delrule req ack inet")
                   .Seq(kSeq + 8)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name_)
                   .StrAttr(NFTA_RULE_CHAIN, "unknown_chain")
                   .Build())
          .SeqEnd(kSeq + 9)
          .Build();

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd_, kSeq + 7, kSeq + 9, flush_request.data(), flush_request.size()),
      PosixErrorIs(ENOENT, _));
}

TEST_F(NetlinkNetfilterDeletionTest, ErrFlushRulesMissingTable) {
  std::vector<char> flush_request =
      NlBatchReq()
          .SeqStart(kSeq + 7)
          .Req(NlReq("delrule req ack inet").Seq(kSeq + 8).Build())
          .SeqEnd(kSeq + 9)
          .Build();

  ASSERT_THAT(
      NetlinkNetfilterBatchRequestAckOrError(
          fd_, kSeq + 7, kSeq + 9, flush_request.data(), flush_request.size()),
      PosixErrorIs(EINVAL, _));
}

TEST(NetlinkNetfilterTest,
     ErrAddRuleNoHandleOrPositionSpecifiedAndCreateReplaceFlagNotSet) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddRuleNoHandleOrPositionSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddRuleInvalidPositionSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrAddRuleInvalidHandleSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddEmptyRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrRuleExpressionWrongType) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrRuleTooManyExpressions) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrImmRuleNoDestinationRegisterSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrImmRuleNoDataSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrValueDataWithVerdictRegister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrVerdictDataWithNonVerdictRegister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrExpressionDataMalformed) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrImmInvalidDreg) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddAcceptAllRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddDropAllRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddRuleWithImmDataValue) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddRuleToEndOfRuleList) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddDropRuleBeforeAcceptRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, AddDropRuleAfterAcceptRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetRuleDump) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  std::string test_table_name = GetUniqueTestTableName();
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  uint8_t udata[] = {0, 1, 2};
  size_t expected_udata_size = sizeof(udata);
  // Add two expressions.
  std::vector<char> imm_expr_accept_all_data = NlImmExpr::DefaultAcceptAll();
  std::vector<char> imm_expr_drop_all_data = NlImmExpr::DefaultDropAll();
  std::vector<char> list_expr_data = NlListAttr()
                                         .Add(imm_expr_accept_all_data)
                                         .Add(imm_expr_drop_all_data)
                                         .Build();

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

  std::vector<ParsedRule> rules = ASSERT_NO_ERRNO_AND_VALUE(GetRules(
      fd, NFPROTO_INET, test_table_name, GetDefaultChainName(), kSeq + 10));
  EXPECT_EQ(rules.size(), 2);
  for (const auto& rule : rules) {
    EXPECT_EQ(rule.table_name, test_table_name);
    EXPECT_EQ(rule.chain_name, GetDefaultChainName());
    EXPECT_EQ(rule.userdata,
              std::vector<uint8_t>(udata, udata + expected_udata_size));
    EXPECT_THAT(rule.ExpressionNames(),
                ::testing::ElementsAre("immediate", "immediate"));
  }
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetRuleDumpTableSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 7, add_request.data(), add_request.size()));

  std::vector<ParsedRule> inet_rules = ASSERT_NO_ERRNO_AND_VALUE(
      GetRules(fd, NFPROTO_INET, test_table_name, "", kSeq + 8));
  ASSERT_EQ(inet_rules.size(), 1);
  EXPECT_EQ(inet_rules[0].table_name, test_table_name);
  EXPECT_EQ(inet_rules[0].chain_name, GetDefaultChainName());
  EXPECT_EQ(inet_rules[0].userdata,
            std::vector<uint8_t>(udata, udata + expected_udata_size));

  std::vector<ParsedRule> ipv6_rules = ASSERT_NO_ERRNO_AND_VALUE(
      GetRules(fd, NFPROTO_IPV6, test_table_name, "", kSeq + 9));
  ASSERT_EQ(ipv6_rules.size(), 1);
  EXPECT_EQ(ipv6_rules[0].table_name, test_table_name);
  EXPECT_EQ(ipv6_rules[0].chain_name, GetDefaultChainName());
  EXPECT_EQ(ipv6_rules[0].userdata,
            std::vector<uint8_t>(udata, udata + expected_udata_size));

  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetRuleDumpTableChainSpecified) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 6, add_request.data(), add_request.size()));

  std::vector<ParsedRule> chain_one_rules = ASSERT_NO_ERRNO_AND_VALUE(GetRules(
      fd, NFPROTO_INET, test_table_name, test_chain_name_one, kSeq + 7));
  ASSERT_EQ(chain_one_rules.size(), 2);
  for (const auto& rule : chain_one_rules) {
    EXPECT_EQ(rule.table_name, test_table_name);
    EXPECT_EQ(rule.chain_name, test_chain_name_one);
    EXPECT_EQ(rule.userdata,
              std::vector<uint8_t>(udata, udata + expected_udata_size));
  }

  std::vector<ParsedRule> chain_two_rules = ASSERT_NO_ERRNO_AND_VALUE(GetRules(
      fd, NFPROTO_INET, test_table_name, test_chain_name_two, kSeq + 8));
  EXPECT_EQ(chain_two_rules.size(), 0);

  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, GetGenerationID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

struct RuleWithExprTestParams {
  std::string test_name;
  std::string expr_name;
  NlNestedAttr expr_attrs;
  int expected_error_no;
  // List of registers to initialize to zero before accessing in a rule.
  std::vector<uint32_t> regs_to_init = {};
  std::string chain_type;
  uint32_t hook_num;
  std::string family_name = "inet";
};

class AddRuleWithExprTest
    : public ::testing::TestWithParam<RuleWithExprTestParams> {};

TEST_P(AddRuleWithExprTest, AddRuleWithExpr) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_NETFILTER));
  std::vector<char> expr_data = NlNestedAttr(GetParam().expr_attrs).Build();
  ASSERT_FALSE(GetParam().expr_name.empty());
  std::vector<char> rule_expr_data =
      NlNestedAttr()
          .StrAttr(NFTA_EXPR_NAME, GetParam().expr_name)
          .RawAttr(NFTA_EXPR_DATA, expr_data.data(), expr_data.size())
          .Build();
  NlListAttr list_attr;
  // Initialize the registers to zero.
  // Linux throws error if a Nftable opcode tries to read from an uninitialized
  // register.
  // TODO: b/486197011 - Support uninitialized register verification in gvisor.
  for (uint32_t reg : GetParam().regs_to_init) {
    std::vector<char> zero_data;
    if (reg >= NFT_REG_1 && reg <= NFT_REG_4) {
      zero_data = std::vector<char>(16, 0);
    } else {
      zero_data = std::vector<char>(4, 0);
    }
    std::vector<char> imm_expr =
        NlImmExpr().Dreg(reg).Value(zero_data).ValueBuild();
    list_attr.Add(imm_expr);
  }
  list_attr.Add(rule_expr_data);
  std::vector<char> list_expr_data = list_attr.Build();
  const std::string table_name =
      absl::StrCat("table_", GetParam().expr_name, "_", GetParam().test_name);
  const std::string chain_name = "test_chain";
  std::vector<char> add_rule_request_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq(absl::StrCat("newrule req ack create ",
                                  GetParam().family_name))
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_RULE_TABLE, table_name)
                   .StrAttr(NFTA_RULE_CHAIN, chain_name)
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  AddDefaultTable({.fd = fd,
                   .table_name = table_name,
                   .seq = kSeq,
                   .family_name = GetParam().family_name});
  std::string test_chain_type = GetParam().chain_type;
  if (test_chain_type.empty() &&
      (GetParam().expr_name == "nat" || GetParam().expr_name == "masq")) {
    test_chain_type = "nat";
  }

  AddDefaultBaseChain({.fd = fd,
                       .table_name = table_name,
                       .chain_name = chain_name,
                       .seq = kSeq + 3,
                       .chain_type = test_chain_type,
                       .hook_num = GetParam().hook_num,
                       .family_name = GetParam().family_name});
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
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
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
                  .U32Attr(NFTA_PAYLOAD_SREG, NFT_REG32_00),
          .regs_to_init = {NFT_REG32_00}},
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
                  .U32Attr(NFTA_PAYLOAD_CSUM_OFFSET, 1),
          .regs_to_init = {NFT_REG_1}},
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
          .expected_error_no = ERANGE},
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
    /*param_generator=*/ValuesIn(GetPayloadRuleTestParams()),
    /*param_name_generator=*/
    [](const TestParamInfo<RuleWithExprTestParams>& info) {
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
          .expected_error_no = ERANGE},
  };
}

INSTANTIATE_TEST_SUITE_P(MetaRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetMetaRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });

std::vector<RuleWithExprTestParams> GetCmpRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "Valid",
          .expr_name = "cmp",
          .expr_attrs =
              []() {
                std::vector<char> data_value =
                    NlNestedAttr().U32Attr(NFTA_DATA_VALUE, 1).Build();
                return NlNestedAttr()
                    .U32Attr(NFTA_CMP_SREG, NFT_REG_1)
                    .U32Attr(NFTA_CMP_OP, NFT_CMP_EQ)
                    .RawAttr(NFTA_CMP_DATA, data_value.data(),
                             data_value.size());
              }(),
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "InvalidCmpOp",
          .expr_name = "cmp",
          .expr_attrs = []() -> NlNestedAttr {
            std::vector<char> data_value =
                NlNestedAttr().U32Attr(NFTA_DATA_VALUE, 1).Build();
            return NlNestedAttr()
                .U32Attr(NFTA_CMP_SREG, NFT_REG_1)
                // Invalid comparison operator as only 6 operators are
                // supported.
                .U32Attr(NFTA_CMP_OP, 100)
                .RawAttr(NFTA_CMP_DATA, data_value.data(), data_value.size());
          }(),
          .expected_error_no = EINVAL},
  };
}

INSTANTIATE_TEST_SUITE_P(CmpRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetCmpRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });

std::vector<RuleWithExprTestParams> GetCounterRuleTestParams() {
  return {
      RuleWithExprTestParams{.test_name = "ValidWithDefaultValues",
                             .expr_name = "counter",
                             .expr_attrs = NlNestedAttr()
                                               .U64Attr(NFTA_COUNTER_PACKETS, 0)
                                               .U64Attr(NFTA_COUNTER_BYTES, 0)},
      RuleWithExprTestParams{.test_name = "ValidWithNoDefaultValues",
                             .expr_name = "counter",
                             .expr_attrs = NlNestedAttr()},
  };
}

INSTANTIATE_TEST_SUITE_P(
    CounterRuleTest, AddRuleWithExprTest,
    /*param_generator=*/::testing::ValuesIn(GetCounterRuleTestParams()),
    /*param_name_generator=*/
    [](const ::testing::TestParamInfo<RuleWithExprTestParams>& info) {
      return info.param.test_name;
    });

std::vector<RuleWithExprTestParams> GetNATRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "SNATAddrPortIPv4",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_SNAT)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1)
                            .U32Attr(NFTA_NAT_REG_PROTO_MIN, NFT_REG_2),
          .regs_to_init = {NFT_REG_1, NFT_REG_2},
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "DNATAddrPortIPv4",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_DNAT)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1)
                            .U32Attr(NFTA_NAT_REG_PROTO_MIN, NFT_REG_2),
          .regs_to_init = {NFT_REG_1, NFT_REG_2},
          .hook_num = NF_INET_PRE_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "SNATAddrProtoMinMaxIPv4",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_SNAT)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1)
                            .U32Attr(NFTA_NAT_REG_ADDR_MAX, NFT_REG_4)
                            .U32Attr(NFTA_NAT_REG_PROTO_MIN, NFT_REG32_00)
                            .U32Attr(NFTA_NAT_REG_PROTO_MAX, NFT_REG32_15),
          .regs_to_init = {NFT_REG_1, NFT_REG_4, NFT_REG32_00, NFT_REG32_15},
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "DNATAddrProtoMinMaxIPv6",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_DNAT)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET6)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1)
                            .U32Attr(NFTA_NAT_REG_ADDR_MAX, NFT_REG_2)
                            .U32Attr(NFTA_NAT_REG_PROTO_MIN, NFT_REG_3)
                            .U32Attr(NFTA_NAT_REG_PROTO_MAX, NFT_REG_4),
          .regs_to_init = {NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4},
          .hook_num = NF_INET_PRE_ROUTING,
          .family_name = "ipv6"},
      RuleWithExprTestParams{
          .test_name = "NoNATType",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1},
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "NoNATFamily",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_SNAT)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1},
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "NoAddrOrProto",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_NAT_TYPE, NFT_NAT_SNAT)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET),
          .expected_error_no = EINVAL,
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
      RuleWithExprTestParams{
          .test_name = "InvalidNATType",
          .expr_name = "nat",
          .expr_attrs = NlNestedAttr()
                            // NAT type should be either 0 or 1.
                            .U32Attr(NFTA_NAT_TYPE, 2)
                            .U32Attr(NFTA_NAT_FAMILY, AF_INET)
                            .U32Attr(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1),
          .expected_error_no = EOPNOTSUPP,
          .regs_to_init = {NFT_REG_1},
          .hook_num = NF_INET_POST_ROUTING,
          .family_name = "ipv4"},
  };
}

INSTANTIATE_TEST_SUITE_P(NATRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetNATRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });

std::vector<RuleWithExprTestParams> GetMasqRuleTestParams() {
  return {
      RuleWithExprTestParams{.test_name = "MasqNoAttrs",
                             .expr_name = "masq",
                             .expr_attrs = NlNestedAttr(),
                             .expected_error_no = 0,
                             .chain_type = "nat",
                             .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{
          .test_name = "MasqWithFlags",
          .expr_name = "masq",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_MASQ_FLAGS, 1),
          .expected_error_no = 0,
          .chain_type = "nat",
          .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{.test_name = "MasqWithProtoMin",
                             .expr_name = "masq",
                             .expr_attrs = NlNestedAttr().U32Attr(
                                 NFTA_MASQ_REG_PROTO_MIN, NFT_REG32_00),
                             .expected_error_no = 0,
                             .regs_to_init = {NFT_REG32_00},
                             .chain_type = "nat",
                             .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{
          .test_name = "MasqWithProtoMinMax",
          .expr_name = "masq",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_MASQ_REG_PROTO_MIN, NFT_REG32_00)
                            .U32Attr(NFTA_MASQ_REG_PROTO_MAX, NFT_REG32_15),
          .expected_error_no = 0,
          .regs_to_init = {NFT_REG32_00, NFT_REG32_15},
          .chain_type = "nat",
          .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{
          .test_name = "MasqInvalidFlags",
          .expr_name = "masq",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_MASQ_FLAGS, 0xffffffff),
          .expected_error_no = EINVAL,
          .chain_type = "nat",
          .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{
          .test_name = "MasqInvalidReg",
          .expr_name = "masq",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_MASQ_REG_PROTO_MIN, 256),
          .expected_error_no = ERANGE,
          .chain_type = "nat",
          .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{
          .test_name = "MasqRegNumberNotExist",
          .expr_name = "masq",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_MASQ_REG_PROTO_MIN, 5),
          .expected_error_no = ERANGE,
          .chain_type = "nat",
          .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{.test_name = "MasqWrongChainType",
                             .expr_name = "masq",
                             .expr_attrs = NlNestedAttr(),
                             .expected_error_no = EOPNOTSUPP,
                             .chain_type = "filter",
                             .hook_num = NF_INET_POST_ROUTING},
      RuleWithExprTestParams{.test_name = "MasqWrongHook",
                             .expr_name = "masq",
                             .expr_attrs = NlNestedAttr(),
                             .expected_error_no = EOPNOTSUPP,
                             .chain_type = "nat",
                             .hook_num = NF_INET_PRE_ROUTING},
  };
}

INSTANTIATE_TEST_SUITE_P(MasqRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetMasqRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });

std::vector<RuleWithExprTestParams> GetLookupRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "SetNotFound",
          .expr_name = "lookup",
          .expr_attrs = NlNestedAttr()
                            .StrAttr(NFTA_LOOKUP_SET, "bad_set")
                            .U32Attr(NFTA_LOOKUP_SREG, NFT_REG_1),
          .expected_error_no = ENOENT},
      RuleWithExprTestParams{
          .test_name = "MissingSet",
          .expr_name = "lookup",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_LOOKUP_SREG, NFT_REG_1),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "MissingSreg",
          .expr_name = "lookup",
          .expr_attrs = NlNestedAttr().StrAttr(NFTA_LOOKUP_SET, "bad_set"),
          .expected_error_no = EINVAL},
  };
}

INSTANTIATE_TEST_SUITE_P(
    LookupRuleTest, AddRuleWithExprTest,
    /*param_generator=*/ValuesIn(GetLookupRuleTestParams()),
    /*param_name_generator=*/
    [](const TestParamInfo<RuleWithExprTestParams>& info) {
      return info.param.test_name;
    });

std::vector<RuleWithExprTestParams> GetFibRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "MissingDreg",
          .expr_name = "fib",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIF)
                            .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "MissingResult",
          .expr_name = "fib",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                            .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "MissingFlags",
          .expr_name = "fib",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                            .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIF),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "BothSaddrDaddr",
          .expr_name = "fib",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                  .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIF)
                  .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "BothOifIif",
          .expr_name = "fib",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                  .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIF)
                  .U32Attr(NFTA_FIB_FLAGS,
                           NFTA_FIB_F_SADDR | NFTA_FIB_F_IIF | NFTA_FIB_F_OIF),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "InvalidResult",
          .expr_name = "fib",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                            .U32Attr(NFTA_FIB_RESULT, 999)
                            .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "ValidOIF",
          .expr_name = "fib",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                            .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIF)
                            .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR),
          .expected_error_no = 0},
      RuleWithExprTestParams{
          .test_name = "ValidOIFNAME",
          .expr_name = "fib",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                  .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIFNAME)
                  .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR | NFTA_FIB_F_IIF),
          .expected_error_no = 0},
      RuleWithExprTestParams{
          .test_name = "ValidADDRTYPE",
          .expr_name = "fib",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_FIB_DREG, NFT_REG_1)
                  .U32Attr(NFTA_FIB_RESULT, NFT_FIB_RESULT_ADDRTYPE)
                  .U32Attr(NFTA_FIB_FLAGS, NFTA_FIB_F_SADDR | NFTA_FIB_F_IIF),
          .expected_error_no = 0},
  };
}

INSTANTIATE_TEST_SUITE_P(FibRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetFibRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });

std::vector<RuleWithExprTestParams> GetBitwiseRuleTestParams() {
  uint8_t mask_val[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t xor_val[4] = {0x11, 0x22, 0x33, 0x44};
  uint8_t data_val[4] = {0x02, 0x00, 0x00, 0x00};

  std::vector<char> mask_nested =
      NlNestedAttr().RawAttr(NFTA_DATA_VALUE, mask_val, 4).Build();
  std::vector<char> xor_nested =
      NlNestedAttr().RawAttr(NFTA_DATA_VALUE, xor_val, 4).Build();
  std::vector<char> data_nested =
      NlNestedAttr().RawAttr(NFTA_DATA_VALUE, data_val, 4).Build();

  uint8_t short_mask_val[2] = {0xaa, 0xbb};
  std::vector<char> short_mask_nested =
      NlNestedAttr().RawAttr(NFTA_DATA_VALUE, short_mask_val, 2).Build();

  return {
      RuleWithExprTestParams{
          .test_name = "ValidBool",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_BOOL)
                            .RawAttr(NFTA_BITWISE_MASK, mask_nested.data(),
                                     mask_nested.size())
                            .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                                     xor_nested.size()),
          .expected_error_no = 0,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "ValidLshift",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_LSHIFT)
                            .RawAttr(NFTA_BITWISE_DATA, data_nested.data(),
                                     data_nested.size()),
          .expected_error_no = 0,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "LenMismatchMaskBool",
          .expr_name = "bitwise",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                  .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                  .U32Attr(NFTA_BITWISE_LEN, 4)
                  .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_BOOL)
                  .RawAttr(NFTA_BITWISE_MASK, short_mask_nested.data(),
                           short_mask_nested.size())
                  .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                           xor_nested.size()),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "LenMismatchDataShift",
          .expr_name = "bitwise",
          .expr_attrs =
              NlNestedAttr()
                  .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                  .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                  .U32Attr(NFTA_BITWISE_LEN, 4)
                  .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_LSHIFT)
                  .RawAttr(NFTA_BITWISE_DATA, short_mask_nested.data(),
                           short_mask_nested.size()),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "VerdictRegSreg",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_VERDICT)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_BOOL)
                            .RawAttr(NFTA_BITWISE_MASK, mask_nested.data(),
                                     mask_nested.size())
                            .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                                     xor_nested.size()),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "MissingSreg",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .RawAttr(NFTA_BITWISE_MASK, mask_nested.data(),
                                     mask_nested.size())
                            .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                                     xor_nested.size()),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "MissingMaskBool",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_BOOL)
                            .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                                     xor_nested.size()),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "HasDataBool",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_BOOL)
                            .RawAttr(NFTA_BITWISE_MASK, mask_nested.data(),
                                     mask_nested.size())
                            .RawAttr(NFTA_BITWISE_XOR, xor_nested.data(),
                                     xor_nested.size())
                            .RawAttr(NFTA_BITWISE_DATA, data_nested.data(),
                                     data_nested.size()),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "MissingDataShift",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_LSHIFT),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
      RuleWithExprTestParams{
          .test_name = "BothMaskAndShift",
          .expr_name = "bitwise",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_BITWISE_SREG, NFT_REG_1)
                            .U32Attr(NFTA_BITWISE_DREG, NFT_REG_2)
                            .U32Attr(NFTA_BITWISE_LEN, 4)
                            .U32Attr(NFTA_BITWISE_OP, NFT_BITWISE_LSHIFT)
                            .RawAttr(NFTA_BITWISE_DATA, data_nested.data(),
                                     data_nested.size())
                            .RawAttr(NFTA_BITWISE_MASK, mask_nested.data(),
                                     mask_nested.size()),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_1}},
  };
}

INSTANTIATE_TEST_SUITE_P(
    BitwiseRuleTest, AddRuleWithExprTest,
    /*param_generator=*/ValuesIn(GetBitwiseRuleTestParams()),
    /*param_name_generator=*/
    [](const TestParamInfo<RuleWithExprTestParams>& info) {
      return info.param.test_name;
    });

std::vector<RuleWithExprTestParams> GetCTRuleTestParams() {
  return {
      RuleWithExprTestParams{
          .test_name = "ValidGetState",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                            .U32Attr(NFTA_CT_KEY, NFT_CT_STATE),
          .expected_error_no = 0},
      RuleWithExprTestParams{.test_name = "ValidGetSrcWithDirection",
                             .expr_name = "ct",
                             .expr_attrs = NlNestedAttr()
                                               .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                                               .U32Attr(NFTA_CT_KEY, NFT_CT_SRC)
                                               .U8Attr(NFTA_CT_DIRECTION, 0),
                             .expected_error_no = 0},
      RuleWithExprTestParams{
          .test_name = "MissingDregAndSreg",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_CT_KEY, NFT_CT_STATE),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "BothDregAndSreg",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                            .U32Attr(NFTA_CT_SREG, NFT_REG_2)
                            .U32Attr(NFTA_CT_KEY, NFT_CT_STATE),
          .expected_error_no = EINVAL,
          .regs_to_init = {NFT_REG_2}},
      RuleWithExprTestParams{
          .test_name = "MissingKey",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr().U32Attr(NFTA_CT_DREG, NFT_REG_1),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "DirectionNotAllowed",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                            .U32Attr(NFTA_CT_KEY, NFT_CT_STATE)
                            .U8Attr(NFTA_CT_DIRECTION, 0),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{
          .test_name = "DirectionRequiredMissing",
          .expr_name = "ct",
          .expr_attrs = NlNestedAttr()
                            .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                            .U32Attr(NFTA_CT_KEY, NFT_CT_SRC),
          .expected_error_no = EINVAL},
      RuleWithExprTestParams{.test_name = "InvalidDirection",
                             .expr_name = "ct",
                             .expr_attrs = NlNestedAttr()
                                               .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                                               .U32Attr(NFTA_CT_KEY, NFT_CT_SRC)
                                               .U8Attr(NFTA_CT_DIRECTION, 2),
                             .expected_error_no = EINVAL},
      RuleWithExprTestParams{.test_name = "InvalidKeyTooLarge",
                             .expr_name = "ct",
                             .expr_attrs = NlNestedAttr()
                                               .U32Attr(NFTA_CT_DREG, NFT_REG_1)
                                               .U32Attr(NFTA_CT_KEY, 256),
                             .expected_error_no = ERANGE},
  };
}

INSTANTIATE_TEST_SUITE_P(CTRuleTest, AddRuleWithExprTest,
                         /*param_generator=*/ValuesIn(GetCTRuleTestParams()),
                         /*param_name_generator=*/
                         [](const TestParamInfo<RuleWithExprTestParams>& info) {
                           return info.param.test_name;
                         });
}  // namespace

// Restored non-parameterized complex tests
TEST(NetlinkNetfilterTest, ErrUpdateBaseChainHookMismatch) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  std::string test_table_name = GetUniqueTestTableName();
  const char base_chain_name[] = "base_chain_hook";
  const char reg_chain_name[] = "reg_chain_hook";
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
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
                   .StrAttr(NFTA_CHAIN_NAME, base_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, NF_ACCEPT)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, "filter")
                   .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, reg_chain_name)
                   .Build())
          .SeqEnd(kSeq + 4)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 4, add_request_buffer.data(),
      add_request_buffer.size()));

  // 1. Attempt to update base chain with mismatched hook priority
  // (1 instead of 0).
  std::vector<char> mismatched_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, test_hook_num)
          .U32Attr(NFTA_HOOK_PRIORITY, 1)
          .Build();

  std::vector<char> update_mismatched_base_req =
      NlBatchReq()
          .SeqStart(kSeq + 5)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 6)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, base_chain_name)
                   .RawAttr(NFTA_CHAIN_HOOK, mismatched_hook_data.data(),
                            mismatched_hook_data.size())
                   .Build())
          .SeqEnd(kSeq + 7)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 5, kSeq + 7, update_mismatched_base_req.data(),
                  update_mismatched_base_req.size()),
              PosixErrorIs(EOPNOTSUPP, _));

  // 2. Attempt to add NFTA_CHAIN_HOOK to non-base chain.
  std::vector<char> update_reg_with_hook_req =
      NlBatchReq()
          .SeqStart(kSeq + 8)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 9)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, reg_chain_name)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .Build())
          .SeqEnd(kSeq + 10)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                  fd, kSeq + 8, kSeq + 10, update_reg_with_hook_req.data(),
                  update_reg_with_hook_req.size()),
              PosixErrorIs(EEXIST, _));

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 11));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, ErrUpdateBindingChain) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  std::string test_table_name = GetUniqueTestTableName();
  const uint32_t test_chain_flags = NFT_CHAIN_BINDING;
  const uint32_t test_chain_id = 10;
  const std::string test_base_chain_name = "test_base_chain";
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  std::vector<char> rule_expr_data = NlImmExpr()
                                         .Dreg(NFT_REG_VERDICT)
                                         .VerdictCode(NFT_JUMP)
                                         .VerdictChainId(test_chain_id)
                                         .VerdictBuild();
  std::vector<char> list_expr_data = NlListAttr().Add(rule_expr_data).Build();

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
                   .StrAttr(NFTA_CHAIN_NAME, test_base_chain_name)
                   .Build())
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 3)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .Build())
          .Req(NlReq("newrule req ack create inet")
                   .Seq(kSeq + 4)
                   .StrAttr(NFTA_RULE_TABLE, test_table_name)
                   .StrAttr(NFTA_RULE_CHAIN, test_base_chain_name)
                   .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                            list_expr_data.size())
                   .Build())
          .SeqEnd(kSeq + 5)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 5, add_request_buffer.data(),
      add_request_buffer.size()));

  // Attempt to update bound chain.
  std::vector<char> update_req_buffer =
      NlBatchReq()
          .SeqStart(kSeq + 6)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 7)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .U32Attr(NFTA_CHAIN_ID, test_chain_id)
                   .U32Attr(NFTA_CHAIN_FLAGS, test_chain_flags)
                   .Build())
          .SeqEnd(kSeq + 8)
          .Build();

  ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(fd, kSeq + 6, kSeq + 8,
                                                     update_req_buffer.data(),
                                                     update_req_buffer.size()),
              PosixErrorIs(EINVAL, _));

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 9));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

TEST(NetlinkNetfilterTest, UpdateChainWithCounters) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  SKIP_IF(!IsRunningOnGvisor());
  std::string test_table_name = GetUniqueTestTableName();
  const char base_chain_name[] = "chain_counters_test";
  const uint32_t test_hook_num = NF_INET_PRE_ROUTING;
  const uint32_t test_hook_priority = 0;
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
                   .StrAttr(NFTA_CHAIN_NAME, base_chain_name)
                   .U32Attr(NFTA_CHAIN_POLICY, NF_ACCEPT)
                   .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                            nested_hook_data.size())
                   .StrAttr(NFTA_CHAIN_TYPE, "filter")
                   .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE)
                   .Build())
          .SeqEnd(kSeq + 3)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 3, add_request_buffer.data(),
      add_request_buffer.size()));

  // Update base chain passing NFTA_CHAIN_COUNTERS
  std::vector<char> update_counter_req =
      NlBatchReq()
          .SeqStart(kSeq + 4)
          .Req(NlReq("newchain req ack inet")
                   .Seq(kSeq + 5)
                   .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                   .StrAttr(NFTA_CHAIN_NAME, base_chain_name)
                   .RawAttr(NFTA_CHAIN_COUNTERS, nullptr, 0)
                   .Build())
          .SeqEnd(kSeq + 6)
          .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq + 4, kSeq + 6, update_counter_req.data(),
      update_counter_req.size()));

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 7));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

struct CompatMatchOptions {
  std::optional<std::string> name;
  std::optional<uint32_t> rev;
  std::optional<std::vector<char>> info_data;
};

static std::vector<char> BuildRawCompatMatchExpr(
    const CompatMatchOptions& opts) {
  NlNestedAttr match_attr;
  if (opts.name.has_value()) {
    match_attr.StrAttr(NFTA_MATCH_NAME, opts.name.value());
  }
  if (opts.rev.has_value()) {
    match_attr.U32Attr(NFTA_MATCH_REV, opts.rev.value());
  }
  if (opts.info_data.has_value() && !opts.info_data->empty()) {
    match_attr.RawAttr(NFTA_MATCH_INFO, opts.info_data->data(),
                       opts.info_data->size());
  }
  std::vector<char> match_bytes = match_attr.Build();

  return NlNestedAttr()
      .StrAttr(NFTA_EXPR_NAME, "match")
      .RawAttr(NFTA_EXPR_DATA, match_bytes.data(), match_bytes.size())
      .Build();
}

static std::vector<char> BuildCompatMatchExpr(const CompatMatchOptions& opts) {
  return NlListAttr().Add(BuildRawCompatMatchExpr(opts)).Build();
}

template <typename T>
static std::vector<char> StructToBytes(const T& val) {
  const char* p = reinterpret_cast<const char*>(&val);
  return std::vector<char>(p, p + sizeof(T));
}

struct CompatTargetOptions {
  std::optional<std::string> name;
  std::optional<uint32_t> rev;
  std::optional<std::vector<char>> info_data;
};

static std::vector<char> BuildRawCompatTargetExpr(
    const CompatTargetOptions& opts) {
  NlNestedAttr target_attr;
  if (opts.name.has_value()) {
    target_attr.StrAttr(NFTA_TARGET_NAME, opts.name.value());
  }
  if (opts.rev.has_value()) {
    target_attr.U32Attr(NFTA_TARGET_REV, opts.rev.value());
  }
  if (opts.info_data.has_value() && !opts.info_data->empty()) {
    target_attr.RawAttr(NFTA_TARGET_INFO, opts.info_data->data(),
                        opts.info_data->size());
  }
  std::vector<char> target_bytes = target_attr.Build();

  return NlNestedAttr()
      .StrAttr(NFTA_EXPR_NAME, "target")
      .RawAttr(NFTA_EXPR_DATA, target_bytes.data(), target_bytes.size())
      .Build();
}

static std::vector<char> BuildCompatTargetExpr(
    const CompatTargetOptions& opts) {
  return NlListAttr().Add(BuildRawCompatTargetExpr(opts)).Build();
}

// Parameters defining a single nft_compat test case.
struct CompatTestParam {
  std::string test_name;
  uint16_t family = NFPROTO_IPV4;
  std::string table_name;
  std::string chain_name = "compat_test_chain";
  bool is_base_chain = true;
  uint32_t hook = NF_INET_PRE_ROUTING;
  std::string chain_type = "filter";
  uint32_t compat_proto = 0;
  std::optional<CompatMatchOptions> match_opts;
  std::optional<CompatTargetOptions> target_opts;
  bool gvisor_only = false;
  int expected_error = 0;
};

// Parameterized test fixture for nftables compatibility layer (nft_compat)
// extensions, verifying matches (e.g. addrtype, conntrack) and targets (e.g.
// SNAT, DNAT, MASQUERADE) across families, revisions, and hook constraints.
class NetlinkNetfilterCompatTest
    : public ::testing::TestWithParam<CompatTestParam> {};

// Tests creating a rule containing an nft_compat match or target in a batch
// transaction.
TEST_P(NetlinkNetfilterCompatTest, AddCompatRule) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  const CompatTestParam& param = GetParam();
  if (param.gvisor_only) {
    SKIP_IF(!IsRunningOnGvisor());
  }

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());
  std::string test_table_name =
      param.table_name.empty() ? GetUniqueTestTableName() : param.table_name;

  std::vector<char> list_expr_data;
  if (param.match_opts.has_value()) {
    list_expr_data = BuildCompatMatchExpr(param.match_opts.value());
  } else if (param.target_opts.has_value()) {
    list_expr_data = BuildCompatTargetExpr(param.target_opts.value());
  }

  NlReq table_req = NlReq("newtable req ack")
                        .Seq(kSeq + 1)
                        .Family(param.family)
                        .StrAttr(NFTA_TABLE_NAME, test_table_name);

  NlReq chain_req = NlReq("newchain req ack")
                        .Seq(kSeq + 2)
                        .Family(param.family)
                        .StrAttr(NFTA_CHAIN_TABLE, test_table_name)
                        .StrAttr(NFTA_CHAIN_NAME, param.chain_name);

  if (param.is_base_chain) {
    std::vector<char> nested_hook_data =
        NlNestedAttr()
            .U32Attr(NFTA_HOOK_HOOKNUM, param.hook)
            .U32Attr(NFTA_HOOK_PRIORITY, 0)
            .Build();
    chain_req.U32Attr(NFTA_CHAIN_POLICY, NF_ACCEPT)
        .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                 nested_hook_data.size())
        .StrAttr(NFTA_CHAIN_TYPE, param.chain_type)
        .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);
  }

  NlReq rule_req = NlReq("newrule req ack create")
                       .Seq(kSeq + 3)
                       .Family(param.family)
                       .StrAttr(NFTA_RULE_TABLE, test_table_name)
                       .StrAttr(NFTA_RULE_CHAIN, param.chain_name)
                       .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                                list_expr_data.size());

  if (param.compat_proto != 0) {
    std::vector<char> nested_compat_data =
        NlNestedAttr()
            .U32Attr(NFTA_RULE_COMPAT_PROTO, param.compat_proto)
            .U32Attr(NFTA_RULE_COMPAT_FLAGS, 0)
            .Build();
    rule_req.RawAttr(NFTA_RULE_COMPAT, nested_compat_data.data(),
                     nested_compat_data.size());
  }

  std::vector<char> batch_req = NlBatchReq()
                                    .SeqStart(kSeq)
                                    .Req(table_req.Build())
                                    .Req(chain_req.Build())
                                    .Req(rule_req.Build())
                                    .SeqEnd(kSeq + 4)
                                    .Build();

  if (param.expected_error == 0) {
    ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
        fd, kSeq, kSeq + 4, batch_req.data(), batch_req.size()));
  } else {
    ASSERT_THAT(NetlinkNetfilterBatchRequestAckOrError(
                    fd, kSeq, kSeq + 4, batch_req.data(), batch_req.size()),
                PosixErrorIs(param.expected_error, _));
  }

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, test_table_name, kSeq + 5));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

INSTANTIATE_TEST_SUITE_P(
    CompatAddrtypeTests, NetlinkNetfilterCompatTest,
    ::testing::Values(
        // Rev 0 tests with struct xt_addrtype_info
        CompatTestParam{
            .test_name = "Rev0_SourceMatch",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{
                        .source = XT_ADDRTYPE_LOCAL,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev0_DestMatchInverted",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{
                        .dest = XT_ADDRTYPE_UNICAST,
                        .invert_dest = 1,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev0_SourceAndDestMatch",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{
                        .source = XT_ADDRTYPE_LOCAL,
                        .dest = XT_ADDRTYPE_MULTICAST,
                        .invert_source = 1,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev0_RegularChain",
            .is_base_chain = false,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{
                        .source = XT_ADDRTYPE_LOCAL,
                    }),
                },
        },
        // Rev 1 tests with struct xt_addrtype_info_v1
        CompatTestParam{
            .test_name = "Rev1_SourceMatch",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_InvertFlags",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .dest = XT_ADDRTYPE_UNICAST,
                        .flags = XT_ADDRTYPE_INVERT_SOURCE |
                                 XT_ADDRTYPE_INVERT_DEST,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceIn_ValidHook",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_IN,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceOut_ValidHook",
            .hook = NF_INET_POST_ROUTING,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .dest = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_OUT,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceIn_RegularChain",
            .is_base_chain = false,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_IN,
                    }),
                },
        },
        // Error cases
        CompatTestParam{
            .test_name = "Rev0_SizeTooSmall",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                    .info_data = std::vector<char>(sizeof(xt_addrtype_info) - 1,
                                                   0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev1_SizeTooSmall",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data =
                        std::vector<char>(sizeof(xt_addrtype_info_v1) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "UnsupportedRevision",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 2,
                    .info_data = StructToBytes(xt_addrtype_info_v1{}),
                },
            .expected_error = ENOENT,
        },
        CompatTestParam{
            .test_name = "Rev1_BothIfaceInAndOut",
            .hook = NF_INET_FORWARD,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .dest = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_IN |
                                 XT_ADDRTYPE_LIMIT_IFACE_OUT,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceOut_InvalidPrerouting",
            .hook = NF_INET_PRE_ROUTING,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .dest = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_OUT,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceOut_InvalidInput",
            .hook = NF_INET_LOCAL_IN,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .dest = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_OUT,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceIn_InvalidPostrouting",
            .hook = NF_INET_POST_ROUTING,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_IN,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev1_LimitIfaceIn_InvalidOutput",
            .hook = NF_INET_LOCAL_OUT,
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 1,
                    .info_data = StructToBytes(xt_addrtype_info_v1{
                        .source = XT_ADDRTYPE_LOCAL,
                        .flags = XT_ADDRTYPE_LIMIT_IFACE_IN,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "MissingMatchName",
            .match_opts =
                CompatMatchOptions{
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{}),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "MissingMatchRev",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .info_data = StructToBytes(xt_addrtype_info{}),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "MissingMatchInfo",
            .match_opts =
                CompatMatchOptions{
                    .name = "addrtype",
                    .rev = 0,
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "UnknownMatchName",
            .match_opts =
                CompatMatchOptions{
                    .name = "unknown_match",
                    .rev = 0,
                    .info_data = StructToBytes(xt_addrtype_info{}),
                },
            .expected_error = ENOENT,
        }),
    [](const ::testing::TestParamInfo<CompatTestParam>& info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(
    CompatConntrackTests, NetlinkNetfilterCompatTest,
    ::testing::Values(
        CompatTestParam{
            .test_name = "Rev1_StateMatch",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 1,
                    .info_data = StructToBytes(xt_conntrack_mtinfo1{
                        .match_flags = XT_CONNTRACK_STATE,
                        .state_mask = XT_CONNTRACK_STATE_INVALID,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_DirectionMatch",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 1,
                    .info_data = StructToBytes(xt_conntrack_mtinfo1{
                        .match_flags = XT_CONNTRACK_DIRECTION,
                        .invert_flags = XT_CONNTRACK_DIRECTION,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev2_StateMatch",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 2,
                    .info_data = StructToBytes(xt_conntrack_mtinfo2{
                        .match_flags = XT_CONNTRACK_STATE,
                        .state_mask = XT_CONNTRACK_STATE_INVALID,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev3_StateMatch",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 3,
                    .info_data = StructToBytes(xt_conntrack_mtinfo3{
                        .match_flags = XT_CONNTRACK_STATE,
                        .state_mask = XT_CONNTRACK_STATE_INVALID,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "Rev1_SizeTooSmall",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 1,
                    .info_data =
                        std::vector<char>(sizeof(xt_conntrack_mtinfo1) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev2_SizeTooSmall",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 2,
                    .info_data =
                        std::vector<char>(sizeof(xt_conntrack_mtinfo2) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "Rev3_SizeTooSmall",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 3,
                    .info_data =
                        std::vector<char>(sizeof(xt_conntrack_mtinfo3) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "UnsupportedRevision",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 4,
                    .info_data = StructToBytes(xt_conntrack_mtinfo3{}),
                },
            .expected_error = ENOENT,
        },
        CompatTestParam{
            .test_name = "UnsupportedFlags",
            .family = NFPROTO_INET,
            .match_opts =
                CompatMatchOptions{
                    .name = "conntrack",
                    .rev = 1,
                    .info_data = StructToBytes(xt_conntrack_mtinfo1{
                        .match_flags = XT_CONNTRACK_ORIGSRC,
                    }),
                },
            .gvisor_only = true,
            .expected_error = ENOTSUP,
        }),
    [](const ::testing::TestParamInfo<CompatTestParam>& info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(
    CompatMasqTests, NetlinkNetfilterCompatTest,
    ::testing::Values(
        CompatTestParam{
            .test_name = "IPv4_NoFlags",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{.flags = 0}},
                    }),
                },
        },
        CompatTestParam{
            .test_name = "IPv4_WithPortRange",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{
                            .flags = NF_NAT_RANGE_PROTO_SPECIFIED,
                            .min = {.all = htons(1024)},
                            .max = {.all = htons(2048)},
                        }},
                    }),
                },
        },
        CompatTestParam{
            .test_name = "IPv6_NoFlags",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = 0,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "IPv6_WithPortRange",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_PROTO_SPECIFIED,
                        .min_proto = {.all = htons(1024)},
                        .max_proto = {.all = htons(2048)},
                    }),
                },
        },
        CompatTestParam{
            .test_name = "IPv4_SizeTooSmall",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = std::vector<char>(
                        sizeof(nf_nat_ipv4_multi_range_compat) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "IPv6_SizeTooSmall",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = std::vector<char>(sizeof(nf_nat_range) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "InvalidTable",
            .family = NFPROTO_IPV4,
            .table_name = "filter_table",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "UnsupportedRevision",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                    }),
                },
            .expected_error = ENOENT,
        },
        CompatTestParam{
            .test_name = "InvalidRangeSize",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 2,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "InvalidHookPrerouting",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "NonNatChainType",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "filter",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "MapIPsNotSupported",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{.flags = NF_NAT_RANGE_MAP_IPS}},
                    }),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "ValidPortRangeZero",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "MASQUERADE",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{
                            .flags = NF_NAT_RANGE_PROTO_SPECIFIED,
                            .min = {.all = htons(0)},
                            .max = {.all = htons(100)},
                        }},
                    }),
                },
        }),
    [](const ::testing::TestParamInfo<CompatTestParam>& info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(
    CompatNATTests, NetlinkNetfilterCompatTest,
    ::testing::Values(
        // Rev 0 tests (IPv4 only)
        CompatTestParam{
            .test_name = "SNAT_Rev0_Valid",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{.flags = NF_NAT_RANGE_MAP_IPS}},
                    }),
                },
        },
        CompatTestParam{
            .test_name = "DNAT_Rev0_Valid",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "DNAT",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                        .range = {{.flags = NF_NAT_RANGE_MAP_IPS}},
                    }),
                },
        },
        // Rev 1 tests
        CompatTestParam{
            .test_name = "SNAT_Rev1_IPv4_Valid",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_MAP_IPS,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "DNAT_Rev1_IPv6_Valid",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "DNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_MAP_IPS,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "SNAT_Rev1_IPv6_Valid",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_MAP_IPS,
                    }),
                },
        },
        CompatTestParam{
            .test_name = "SNAT_Rev1_WithPorts",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_PROTO_SPECIFIED,
                        .min_proto = {.all = htons(1024)},
                        .max_proto = {.all = htons(2048)},
                    }),
                },
        },
        // Rev 2 tests: Validate support for NAT revision 2 (nf_nat_range2).
        // Standard 44-byte struct payload (from UAPI
        // <linux/netfilter/nf_nat.h>).
        CompatTestParam{
            .test_name = "SNAT_Rev2_Valid",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 2,
                    .info_data = StructToBytes(nf_nat_range2{
                        .flags = NF_NAT_RANGE_MAP_IPS,
                    }),
                },
        },
        // 48-byte XT_ALIGN-padded payload produced by userspace iptables-nft.
        CompatTestParam{
            .test_name = "SNAT_Rev2_Valid_Padded48",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 2,
                    .info_data =
                        []() {
                          std::vector<char> buf(48, 0);
                          *reinterpret_cast<uint32_t*>(buf.data()) =
                              NF_NAT_RANGE_MAP_IPS;
                          return buf;
                        }(),
                },
        },
        // IPv6 NAT revision 2 support.
        CompatTestParam{
            .test_name = "SNAT_Rev2_IPv6_Valid",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 2,
                    .info_data = StructToBytes(nf_nat_range2{
                        .flags = NF_NAT_RANGE_MAP_IPS,
                    }),
                },
        },
        // Error cases
        // Rev 0 does not support IPv6 (IPv4-only multi_range).
        CompatTestParam{
            .test_name = "Rev0_IPv6NotSupported",
            .family = NFPROTO_IPV6,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 0,
                    .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                        .rangesize = 1,
                    }),
                },
            .expected_error = ENOENT,
        },
        // Buffer truncated below sizeof(nf_nat_ipv4_multi_range_compat).
        CompatTestParam{
            .test_name = "Rev0_SizeTooSmall",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 0,
                    .info_data = std::vector<char>(
                        sizeof(nf_nat_ipv4_multi_range_compat) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        // Buffer truncated below sizeof(nf_nat_range).
        CompatTestParam{
            .test_name = "Rev1_SizeTooSmall",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = std::vector<char>(sizeof(nf_nat_range) - 1, 0),
                },
            .expected_error = EINVAL,
        },
        // Buffer truncated below sizeof(nf_nat_range2) (43 bytes).
        CompatTestParam{
            .test_name = "Rev2_SizeTooSmall",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 2,
                    .info_data = std::vector<char>(sizeof(nf_nat_range2) - 1,
                                                   0),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "UnsupportedRevision",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 3,
                    .info_data = StructToBytes(nf_nat_range2{}),
                },
            .expected_error = ENOENT,
        },
        CompatTestParam{
            .test_name = "SNAT_InvalidHookPrerouting",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{}),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "DNAT_InvalidHookPostrouting",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "DNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{}),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "NonNatChainType",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "filter",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{}),
                },
            .expected_error = EINVAL,
        },
        CompatTestParam{
            .test_name = "ValidPortRangeZero",
            .family = NFPROTO_IPV4,
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .target_opts =
                CompatTargetOptions{
                    .name = "SNAT",
                    .rev = 1,
                    .info_data = StructToBytes(nf_nat_range{
                        .flags = NF_NAT_RANGE_PROTO_SPECIFIED,
                        .min_proto = {.all = htons(0)},
                        .max_proto = {.all = htons(100)},
                    }),
                },
        }),
    [](const ::testing::TestParamInfo<CompatTestParam>& info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(
    CompatNoopMatchTests, NetlinkNetfilterCompatTest,
    ::testing::Values(
        CompatTestParam{
            .test_name = "TCPMatch",
            .compat_proto = IPPROTO_TCP,
            .match_opts =
                CompatMatchOptions{
                    .name = "tcp",
                    .rev = 0,
                    .info_data = StructToBytes(xt_tcp{}),
                },
        },
        CompatTestParam{
            .test_name = "UDPMatch",
            .compat_proto = IPPROTO_UDP,
            .match_opts =
                CompatMatchOptions{
                    .name = "udp",
                    .rev = 0,
                    .info_data = StructToBytes(xt_udp{}),
                },
        }),
    [](const ::testing::TestParamInfo<CompatTestParam>& info) {
      return info.param.test_name;
    });

struct CompatRuleDumpTestParam {
  std::string test_name;
  uint16_t family = NFPROTO_IPV4;
  std::string table_name = "nat";
  std::string chain_name = "compat_dump_chain";
  uint32_t hook = NF_INET_POST_ROUTING;
  std::string chain_type = "nat";
  uint32_t compat_proto = 0;
  std::vector<CompatMatchOptions> matches;
  std::vector<CompatTargetOptions> targets;
  std::vector<std::string> expected_expr_names;
};

class NetlinkNetfilterCompatDumpTest
    : public ::testing::TestWithParam<CompatRuleDumpTestParam> {};

TEST_P(NetlinkNetfilterCompatDumpTest, RuleDump) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCaps()));
  const CompatRuleDumpTestParam& param = GetParam();

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NetfilterBoundSocket());

  NlListAttr expr_list;
  for (const auto& match_opt : param.matches) {
    expr_list.Add(BuildRawCompatMatchExpr(match_opt));
  }
  for (const auto& target_opt : param.targets) {
    expr_list.Add(BuildRawCompatTargetExpr(target_opt));
  }
  std::vector<char> list_expr_data = expr_list.Build();

  std::vector<char> nested_hook_data =
      NlNestedAttr()
          .U32Attr(NFTA_HOOK_HOOKNUM, param.hook)
          .U32Attr(NFTA_HOOK_PRIORITY, 0)
          .Build();

  NlReq table_req = NlReq("newtable req ack")
                        .Seq(kSeq + 1)
                        .Family(param.family)
                        .StrAttr(NFTA_TABLE_NAME, param.table_name);

  NlReq chain_req = NlReq("newchain req ack")
                        .Seq(kSeq + 2)
                        .Family(param.family)
                        .StrAttr(NFTA_CHAIN_TABLE, param.table_name)
                        .StrAttr(NFTA_CHAIN_NAME, param.chain_name)
                        .U32Attr(NFTA_CHAIN_POLICY, NF_ACCEPT)
                        .RawAttr(NFTA_CHAIN_HOOK, nested_hook_data.data(),
                                 nested_hook_data.size())
                        .StrAttr(NFTA_CHAIN_TYPE, param.chain_type)
                        .U32Attr(NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);

  NlReq rule_req = NlReq("newrule req ack create")
                       .Seq(kSeq + 3)
                       .Family(param.family)
                       .StrAttr(NFTA_RULE_TABLE, param.table_name)
                       .StrAttr(NFTA_RULE_CHAIN, param.chain_name)
                       .RawAttr(NFTA_RULE_EXPRESSIONS, list_expr_data.data(),
                                list_expr_data.size());

  if (param.compat_proto != 0) {
    std::vector<char> nested_compat_data =
        NlNestedAttr()
            .U32Attr(NFTA_RULE_COMPAT_PROTO, param.compat_proto)
            .U32Attr(NFTA_RULE_COMPAT_FLAGS, 0)
            .Build();
    rule_req.RawAttr(NFTA_RULE_COMPAT, nested_compat_data.data(),
                     nested_compat_data.size());
  }

  std::vector<char> batch_req = NlBatchReq()
                                    .SeqStart(kSeq)
                                    .Req(table_req.Build())
                                    .Req(chain_req.Build())
                                    .Req(rule_req.Build())
                                    .SeqEnd(kSeq + 4)
                                    .Build();

  ASSERT_NO_ERRNO(NetlinkNetfilterBatchRequestAckOrError(
      fd, kSeq, kSeq + 4, batch_req.data(), batch_req.size()));

  std::vector<ParsedRule> rules = ASSERT_NO_ERRNO_AND_VALUE(
      GetRules(fd, param.family, param.table_name, param.chain_name, kSeq + 5));
  ASSERT_EQ(rules.size(), 1);
  EXPECT_THAT(rules[0].ExpressionNames(),
              ::testing::ElementsAreArray(param.expected_expr_names));

  ASSERT_NO_ERRNO(DestroyNetfilterTable(fd, param.table_name, kSeq + 6));
  ASSERT_NO_ERRNO(NetfilterFlushRuleset(fd));
}

INSTANTIATE_TEST_SUITE_P(
    CompatRuleDumpTests, NetlinkNetfilterCompatDumpTest,
    ::testing::Values(
        CompatRuleDumpTestParam{
            .test_name = "NoopTCPMatch",
            .table_name = "filter",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "filter",
            .compat_proto = IPPROTO_TCP,
            .matches = {CompatMatchOptions{
                .name = "tcp",
                .rev = 0,
                .info_data = StructToBytes(xt_tcp{}),
            }},
            .expected_expr_names = {"match"},
        },
        CompatRuleDumpTestParam{
            .test_name = "AddrtypeMatch",
            .table_name = "filter",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "filter",
            .matches = {CompatMatchOptions{
                .name = "addrtype",
                .rev = 1,
                .info_data = StructToBytes(xt_addrtype_info_v1{
                    .source = XT_ADDRTYPE_LOCAL,
                    .flags = XT_ADDRTYPE_INVERT_SOURCE,
                }),
            }},
            .expected_expr_names = {"match"},
        },
        CompatRuleDumpTestParam{
            .test_name = "ConntrackMatch",
            .table_name = "filter",
            .hook = NF_INET_PRE_ROUTING,
            .chain_type = "filter",
            .matches = {CompatMatchOptions{
                .name = "conntrack",
                .rev = 1,
                .info_data = StructToBytes(xt_conntrack_mtinfo1{
                    .match_flags = XT_CONNTRACK_STATE,
                    .state_mask = XT_CONNTRACK_STATE_INVALID,
                }),
            }},
            .expected_expr_names = {"match"},
        },
        CompatRuleDumpTestParam{
            .test_name = "MatchAndTarget",
            .table_name = "nat",
            .hook = NF_INET_POST_ROUTING,
            .chain_type = "nat",
            .matches = {CompatMatchOptions{
                .name = "conntrack",
                .rev = 1,
                .info_data = StructToBytes(xt_conntrack_mtinfo1{
                    .match_flags = XT_CONNTRACK_STATE,
                    .state_mask = XT_CONNTRACK_STATE_INVALID,
                }),
            }},
            .targets = {CompatTargetOptions{
                .name = "MASQUERADE",
                .rev = 0,
                .info_data = StructToBytes(nf_nat_ipv4_multi_range_compat{
                    .rangesize = 1,
                }),
            }},
            .expected_expr_names = {"match", "target"},
        },
        CompatRuleDumpTestParam{
            .test_name = "SNATTarget",
            .targets = {CompatTargetOptions{
                .name = "SNAT",
                .rev = 1,
                .info_data = StructToBytes(nf_nat_range{
                    .flags = NF_NAT_RANGE_MAP_IPS,
                }),
            }},
            .expected_expr_names = {"target"},
        }),
    [](const ::testing::TestParamInfo<CompatRuleDumpTestParam>& info) {
      return info.param.test_name;
    });

}  // namespace testing
}  // namespace gvisor
