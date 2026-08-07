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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_

#include <linux/capability.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_compat.h>

// clang-format off
#include <netinet/in.h>
#include <linux/netfilter.h>
// clang-format on
#include <linux/netlink.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

#ifndef NFTA_TABLE_OWNER
#define NFTA_TABLE_OWNER (NFTA_TABLE_USERDATA + 1)
#endif

#ifndef NFT_TABLE_F_OWNER
#define NFT_TABLE_F_OWNER (2)
#endif

#ifndef NFT_MSG_DESTROYTABLE
#define NFT_MSG_DESTROYTABLE (26)
#endif

#ifndef NFT_MSG_DESTROYCHAIN
#define NFT_MSG_DESTROYCHAIN (27)
#endif

#define TABLE_NAME_SIZE 32
#define VALID_USERDATA_SIZE 128

struct ElementDescriptor {
  std::vector<uint8_t> key;
  std::vector<uint8_t> data;
  uint32_t flags = 0;

  bool operator==(const ElementDescriptor& other) const {
    return key == other.key && data == other.data && flags == other.flags;
  }
};

struct NfTableCheckOptions {
  const struct nlmsghdr* hdr;
  std::string test_table_name;
  uint32_t* expected_chain_count;
  uint64_t* expected_handle;
  uint32_t* expected_flags;
  uint32_t* expected_owner;
  uint8_t* expected_udata;
  size_t* expected_udata_size;
  bool skip_handle_check;
};

struct NfChainCheckOptions {
  const struct nlmsghdr* hdr;
  std::string expected_table_name;
  std::string expected_chain_name;
  uint64_t* expected_handle;
  const uint32_t* expected_policy;
  std::string expected_chain_type;
  const uint32_t* expected_flags;
  uint32_t* expected_use;
  uint8_t* expected_udata;
  size_t* expected_udata_size;
  bool skip_handle_check;
};

struct NfRuleCheckOptions {
  const struct nlmsghdr* hdr;
  std::string expected_table_name;
  std::string expected_chain_name;
  uint64_t* expected_handle;
  uint8_t* expected_udata;
  size_t* expected_udata_size;
  bool skip_handle_check;
  std::vector<std::vector<char>> expected_rule_exprs_data;
};

struct AddDefaultTableOptions {
  const FileDescriptor& fd;
  std::string table_name;
  uint32_t seq;
  std::string family_name = "inet";
};

struct AddDefaultBaseChainOptions {
  const FileDescriptor& fd;
  std::string table_name;
  std::string chain_name;
  uint32_t seq;
  std::string chain_type;
  uint32_t hook_num;
  uint32_t hook_priority = 0;
  uint32_t flags = NFT_CHAIN_BASE;
  std::string family_name = "inet";
};

struct AddDefaultRegularChainOptions {
  const FileDescriptor& fd;
  std::string table_name;
  std::string chain_name;
  uint32_t seq;
  uint32_t flags = 0;
  uint32_t chain_id = 0;
  std::string family_name = "inet";
};

// Returns default table name for tests.
const std::string& GetDefaultTableName();

// Returns default chain name for tests.
const std::string& GetDefaultChainName();

// Like NetlinkBoundSocket, but with extra configuration for netfilter tests..
PosixErrorOr<FileDescriptor> NetfilterBoundSocket();

void InitNetfilterGenmsg(struct nfgenmsg* genmsg, uint8_t family,
                         uint8_t version, uint16_t res_id);

// Check the attributes of a netfilter table.
void CheckNetfilterTableAttributes(const NfTableCheckOptions& options);

// Check the attributes of a netfilter chain.
void CheckNetfilterChainAttributes(const NfChainCheckOptions& options);

// Check the attributes of a netfilter rule.
void CheckNetfilterRuleAttributes(const struct NfRuleCheckOptions& options);

// Helper function to add a default table.
void AddDefaultTable(const AddDefaultTableOptions& options);

// Helper function to add a default base chain.
void AddDefaultBaseChain(const AddDefaultBaseChainOptions& options);

// Helper function to add a default regular chain.
void AddDefaultRegularChain(const AddDefaultRegularChainOptions& options);

// Helper function to get chain handle.
PosixErrorOr<uint64_t> GetChainHandle(const FileDescriptor& fd,
                                      absl::string_view table_name,
                                      absl::string_view chain_name,
                                      uint32_t seq);

// Helper function to verify chain policy.
void VerifyChainPolicy(const FileDescriptor& fd, absl::string_view table_name,
                       absl::string_view chain_name, uint32_t expected_policy,
                       uint32_t seq);

// Reads string from an nfattr.
std::string GetNfAttrString(const struct nfattr* attr);

// Reads raw bytes from an nfattr safely. Supported types: char, uint8_t.
template <typename T = char>
std::vector<T> GetNfAttrBytes(const struct nfattr* attr);

// Helper function to get set elements.
PosixErrorOr<std::vector<ElementDescriptor>> GetSetElements(
    const FileDescriptor& fd, absl::string_view table_name,
    absl::string_view set_name, uint32_t seq);

// Represents a parsed expression (e.g. payload, cmp, counter, target) within a
// rule.
struct ParsedRuleExpr {
  std::string name;        // Expression type name (e.g. "target", "cmp").
  std::vector<char> data;  // Nested expression-specific attribute payload.
};

// Represents a parsed nftables rule from an NFT_MSG_NEWRULE netlink message.
struct ParsedRule {
  uint16_t family = 0;
  std::string table_name;
  std::string chain_name;
  uint64_t handle = 0;
  std::vector<uint8_t> userdata;
  std::vector<ParsedRuleExpr> expressions;

  // Returns the names of all expressions in this rule in evaluation order.
  std::vector<std::string> ExpressionNames() const {
    std::vector<std::string> names;
    names.reserve(expressions.size());
    for (const auto& expr : expressions) {
      names.push_back(expr.name);
    }
    return names;
  }
};

// Parses a single rule from an NFT_MSG_NEWRULE netlink message.
PosixErrorOr<ParsedRule> ParseRule(const struct nlmsghdr* hdr);

// Helper function to get rules via an NFT_MSG_GETRULE dump request.
PosixErrorOr<std::vector<ParsedRule>> GetRules(
    const FileDescriptor& fd, uint16_t family = NFPROTO_UNSPEC,
    absl::string_view table_name = "", absl::string_view chain_name = "",
    uint32_t seq = 12345);

// Helper function to build a netlink set element attribute from a descriptor.
std::vector<char> BuildNetlinkElement(const ElementDescriptor& desc);

// Helper function to generate a batch netfilter request.
PosixError NetlinkNetfilterBatchRequestAckOrError(const FileDescriptor& fd,
                                                  uint32_t seq_start,
                                                  uint32_t seq_end,
                                                  void* request, size_t len);

// Helper function to delete a table.
PosixError DestroyNetfilterTable(FileDescriptor& fd,
                                 absl::string_view table_name, int seq_num);

// Helper function to flush all rules.
PosixError NetfilterFlushRuleset(const FileDescriptor& fd);

// Helper function to drain leftover messages from a netlink socket.
void DrainNetlinkSocket(const FileDescriptor& fd);

// Helper function to send a dump request and process each streamed message.
// `on_item` is called for each dumped message; returning an error halts the
// dump.
PosixError NetlinkDumpRequest(
    const FileDescriptor& fd, void* req, size_t req_len, uint32_t seq,
    const std::function<PosixError(const struct nlmsghdr* hdr)>& on_item);

class NlBatchReq {
 public:
  // Default constructor.
  NlBatchReq() = default;

  NlBatchReq& SeqStart(uint32_t seq);

  NlBatchReq& SeqEnd(uint32_t seq);

  NlBatchReq& Req(std::vector<char> req);

  std::vector<char> Build();

 private:
  uint32_t seq_start_ = 0;
  uint32_t seq_end_ = 0;
  std::vector<char> reqs_buffer_;
};

class NlReq {
 public:
  // Default constructor.
  NlReq() = default;
  // Constructor that parses a string into a NlReq object with the header
  // filled in.
  explicit NlReq(const std::string& s);

  NlReq& MsgType(uint8_t msg_type);
  NlReq& Flags(uint16_t flags);
  NlReq& Seq(uint32_t seq);
  NlReq& Family(uint8_t family);

  // Method to add an attribute to the message. payload_size must be the size of
  // the payload in bytes.
  NlReq& RawAttr(uint16_t attr_type, const void* payload, size_t payload_size);

  // Method to add a string attribute to the message.
  // The payload is expected to be a null-terminated string.
  NlReq& StrAttr(uint16_t attr_type, const std::string& payload);

  // Method to add a uint8_t attribute to the message.
  NlReq& U8Attr(uint16_t attr_type, uint8_t payload);

  // Method to add a uint16_t attribute to the message.
  NlReq& U16Attr(uint16_t attr_type, uint16_t payload);

  // Method to add a uint32_t attribute to the message.
  NlReq& U32Attr(uint16_t attr_type, uint32_t payload);

  // Method to add a uint64_t attribute to the message.
  NlReq& U64Attr(uint16_t attr_type, uint64_t payload);

  std::vector<char> Build();

  std::vector<char> BuildBatched();

 private:
  bool MsgTypeToken(const std::string& token);
  bool FlagsToken(const std::string& token);
  bool FamilyToken(const std::string& token);

  uint8_t msg_type_ = 0;
  uint16_t flags_ = 0;
  uint32_t seq_ = 0;
  uint8_t family_ = 0;
  bool msg_type_set_ = false;
  bool family_set_ = false;
  std::map<uint16_t, std::vector<char>> attributes_ = {};
  std::vector<char> msg_buffer_;
};

class NlNestedAttr {
 public:
  NlNestedAttr() = default;

  // Method to add an attribute to the message. If there is a default
  // size for the attribute type, it will be used.
  // Otherwise, assumes the payload is of at least size payload_size.
  NlNestedAttr& RawAttr(uint16_t attr_type, const void* payload,
                        size_t payload_size);

  // Method to add a string attribute to the message.
  // The payload is expected to be a null-terminated string.
  NlNestedAttr& StrAttr(uint16_t attr_type, const std::string& payload);

  // Method to add a uint8_t attribute to the message.
  NlNestedAttr& U8Attr(uint16_t attr_type, uint8_t payload);

  // Method to add a uint16_t attribute to the message.
  NlNestedAttr& U16Attr(uint16_t attr_type, uint16_t payload);

  // Method to add a uint32_t attribute to the message.
  NlNestedAttr& U32Attr(uint16_t attr_type, uint32_t payload);

  // Method to add a uint64_t attribute to the message.
  NlNestedAttr& U64Attr(uint16_t attr_type, uint64_t payload);

  std::vector<char> Build();

 private:
  std::map<uint16_t, std::vector<char>> attributes_ = {};
  std::vector<char> msg_buffer_;
};

const int kMaxExprs = 128;
class NlListAttr {
 public:
  NlListAttr() = default;

  // Method to add an attribute to the payload of this list attribute..
  NlListAttr& Add(const std::vector<char>& attr);

  std::vector<char> Build();

  static std::vector<char> BuildWithMaxAttrs();

 private:
  std::vector<char> msg_buffer_;
  std::vector<std::vector<char>> nested_attrs_;
};

// A builder for immediate expressions.
class NlImmExpr {
 public:
  NlImmExpr() = default;

  // Sets the destination register.
  NlImmExpr& Dreg(uint32_t dreg);

  // Sets the verdict code to place in the register for the immediate data.
  NlImmExpr& VerdictCode(uint32_t verdict_code);

  // Sets the verdict chain ID for jump/goto.
  NlImmExpr& VerdictChainId(uint32_t chain_id);

  // Sets the raw value to place in the register for the immediate data.
  NlImmExpr& Value(const std::vector<char>& value);

  // Builds the immediate expression to contain a verdict code.
  std::vector<char> VerdictBuild();

  // Builds the immediate expression to contain a raw value that is not a
  // verdict code.
  std::vector<char> ValueBuild();

  static std::vector<char> DefaultAcceptAll();

  static std::vector<char> DefaultDropAll();

 private:
  uint32_t dreg_ = 0;
  std::vector<char> value_;
  uint32_t verdict_code_ = 0;
  bool has_verdict_code_ = false;
  std::optional<uint32_t> verdict_chain_id_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_
