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

#include <map>
#include <string>
#include <utility>
#include <vector>
#ifndef NFTA_TABLE_OWNER
#define NFTA_TABLE_OWNER NFTA_TABLE_USERDATA + 1
#endif

#ifndef NFT_TABLE_F_OWNER
#define NFT_TABLE_F_OWNER 2
#endif

#ifndef NFT_MSG_DESTROYTABLE
#define NFT_MSG_DESTROYTABLE 26
#endif

#ifndef NFT_MSG_DESTROYCHAIN
#define NFT_MSG_DESTROYCHAIN 27
#endif

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

namespace gvisor {
namespace testing {

#define TABLE_NAME_SIZE 32
#define VALID_USERDATA_SIZE 128

void InitNetfilterGenmsg(struct nfgenmsg* genmsg, uint8_t family,
                         uint8_t version, uint16_t res_id);

void CheckNetfilterTableAttributes(
    const struct nlmsghdr* hdr, const struct nfgenmsg* genmsg,
    const char* test_table_name, uint32_t* expected_chain_count,
    uint64_t* expected_handle, uint32_t* expected_flags,
    uint32_t* expected_owner, uint8_t* expected_udata,
    size_t* expected_udata_size, bool skip_handle_check);

void CheckNetfilterChainAttributes(
    const struct nlmsghdr* hdr, const struct nfgenmsg* genmsg,
    const char* expected_table_name, const char* expected_chain_name,
    uint64_t* expected_handle, const uint32_t* expected_policy,
    const char* expected_chain_type, const uint32_t* expected_flags,
    uint32_t* expected_use, uint8_t* expected_udata,
    size_t* expected_udata_size, bool skip_handle_check);

class NlReq {
 public:
  // Default constructor.
  NlReq() = default;
  // Constructor that parses a string into a NlReq object with the header
  // filled in.
  explicit NlReq(const std::string& s);

  NlReq& MsgType(uint8_t message_type);
  NlReq& Flags(uint16_t flags);
  NlReq& Seq(uint32_t seq);
  NlReq& Family(uint8_t family);

  bool MsgTypeToken(const std::string& token);
  bool FlagsToken(const std::string& token);
  bool FamilyToken(const std::string& token);

  // Method to add an attribute to the message. payload_size must be the size of
  // the payload in bytes.
  NlReq& RawAttr(uint16_t attr_type, const void* payload, size_t payload_size);

  // Method to add a string attribute to the message.
  // The payload is expected to be a null-terminated string.
  NlReq& StrAttr(uint16_t attr_type, const char* payload);

  // Method to add a uint8_t attribute to the message.
  NlReq& U8Attr(uint16_t attr_type, const uint8_t* payload);

  // Method to add a uint16_t attribute to the message.
  NlReq& U16Attr(uint16_t attr_type, const uint16_t* payload);

  // Method to add a uint32_t attribute to the message.
  NlReq& U32Attr(uint16_t attr_type, const uint32_t* payload);

  // Method to add a uint64_t attribute to the message.
  NlReq& U64Attr(uint16_t attr_type, const uint64_t* payload);

  std::vector<char> Build();

 private:
  uint8_t message_type_ = 0;
  uint16_t flags_ = 0;
  uint32_t seq_ = 0;
  uint8_t family_ = 0;
  std::map<uint16_t, std::pair<const char*, size_t>> attributes_ = {};
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
  NlNestedAttr& StrAttr(uint16_t attr_type, const char* payload);

  // Method to add a uint8_t attribute to the message.
  NlNestedAttr& U8Attr(uint16_t attr_type, const uint8_t* payload);

  // Method to add a uint16_t attribute to the message.
  NlNestedAttr& U16Attr(uint16_t attr_type, const uint16_t* payload);

  // Method to add a uint32_t attribute to the message.
  NlNestedAttr& U32Attr(uint16_t attr_type, const uint32_t* payload);

  // Method to add a uint64_t attribute to the message.
  NlNestedAttr& U64Attr(uint16_t attr_type, const uint64_t* payload);

  std::vector<char> Build();

 private:
  uint8_t message_type_ = 0;
  uint16_t flags_ = 0;
  uint32_t seq_ = 0;
  uint8_t family_ = 0;
  std::map<uint16_t, std::pair<const char*, size_t>> attributes_ = {};
  std::vector<char> msg_buffer_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_SOCKET_NETLINK_NETFILTER_UTIL_H_
