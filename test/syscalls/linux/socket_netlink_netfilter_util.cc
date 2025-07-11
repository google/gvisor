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

#include "test/syscalls/linux/socket_netlink_netfilter_util.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"

namespace gvisor {
namespace testing {

NetlinkRequestBuilder& NetlinkRequestBuilder::SetMessageType(
    uint8_t message_type) {
  message_type_ = message_type;
  return *this;
}

NetlinkRequestBuilder& NetlinkRequestBuilder::SetFlags(uint16_t flags) {
  flags_ = flags;
  return *this;
}

NetlinkRequestBuilder& NetlinkRequestBuilder::SetSequenceNumber(uint32_t seq) {
  seq_ = seq;
  return *this;
}

NetlinkRequestBuilder& NetlinkRequestBuilder::SetFamily(uint8_t family) {
  family_ = family;
  return *this;
}

// Method to add an attribute to the message. payload_size must be the size of
// the payload in bytes.
NetlinkRequestBuilder& NetlinkRequestBuilder::AddAttribute(
    uint16_t attr_type, const void* payload, size_t payload_size) {
  // Store a pointer to the payload and the size to construct it later.
  attributes_[attr_type] = {reinterpret_cast<const char*>(payload),
                            payload_size};
  return *this;
}

std::vector<char> NetlinkRequestBuilder::Build() {
  size_t aligned_hdr_size = NLMSG_ALIGN(sizeof(nlmsghdr));
  size_t aligned_genmsg_size = NLMSG_ALIGN(sizeof(nfgenmsg));
  size_t total_attr_size = 0;

  for (const auto& [attr_type, attr_data] : attributes_) {
    const auto& [_, payload_size] = attr_data;
    total_attr_size += NLA_ALIGN(NLA_HDRLEN + payload_size);
  }

  size_t total_message_len =
      NLMSG_ALIGN(aligned_hdr_size + aligned_genmsg_size + total_attr_size);

  msg_buffer_.resize(total_message_len);
  std::memset(msg_buffer_.data(), 0, total_message_len);

  struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(msg_buffer_.data());
  InitNetlinkHdr(nlh, (uint32_t)total_message_len,
                 MakeNetlinkMsgType(NFNL_SUBSYS_NFTABLES, message_type_), seq_,
                 flags_);

  struct nfgenmsg* nfg = reinterpret_cast<struct nfgenmsg*>(NLMSG_DATA(nlh));
  InitNetfilterGenmsg(nfg, family_, NFNETLINK_V0, 0);

  char* payload =
      (char*)msg_buffer_.data() + aligned_hdr_size + aligned_genmsg_size;

  for (const auto& [attr_type, attr_data] : attributes_) {
    const auto& [payload_data, payload_size] = attr_data;
    struct nlattr* attr = reinterpret_cast<struct nlattr*>(payload);
    InitNetlinkAttr(attr, payload_size, attr_type);
    std::memcpy((char*)attr + NLA_HDRLEN, payload_data, payload_size);
    // Move over to the next attribute.
    payload += NLA_ALIGN(NLA_HDRLEN + payload_size);
  }
  return msg_buffer_;
}

NetlinkNestedAttributeBuilder& NetlinkNestedAttributeBuilder::AddAttribute(
    uint16_t attr_type, const void* payload, size_t payload_size) {
  // Store a pointer to the payload and the size to construct it later.
  attributes_[attr_type] = {reinterpret_cast<const char*>(payload),
                            payload_size};
  return *this;
}

std::vector<char> NetlinkNestedAttributeBuilder::Build() {
  size_t total_attr_size = 0;

  for (const auto& [attr_type, attr_data] : attributes_) {
    const auto& [_, payload_size] = attr_data;
    total_attr_size += NLA_ALIGN(NLA_HDRLEN + payload_size);
  }

  msg_buffer_.resize(total_attr_size);
  std::memset(msg_buffer_.data(), 0, total_attr_size);

  char* payload = (char*)msg_buffer_.data();

  for (const auto& [attr_type, attr_data] : attributes_) {
    const auto& [payload_data, payload_size] = attr_data;
    struct nlattr* attr = reinterpret_cast<struct nlattr*>(payload);
    InitNetlinkAttr(attr, payload_size, attr_type);
    std::memcpy((char*)attr + NLA_HDRLEN, payload_data, payload_size);
    // Move over to the next attribute.
    payload += NLA_ALIGN(NLA_HDRLEN + payload_size);
  }
  return msg_buffer_;
}

// Helper function to initialize a nfgenmsg header.
void InitNetfilterGenmsg(struct nfgenmsg* genmsg, uint8_t family,
                         uint8_t version, uint16_t res_id) {
  genmsg->nfgen_family = family;
  genmsg->version = version;
  genmsg->res_id = res_id;
}

// Helper function to check the netfilter table attributes.
void CheckNetfilterTableAttributes(
    const struct nlmsghdr* hdr, const struct nfgenmsg* genmsg,
    const char* test_table_name, uint32_t* expected_chain_count,
    uint64_t* expected_handle, uint32_t* expected_flags,
    uint32_t* expected_owner, uint8_t* expected_udata,
    size_t* expected_udata_size, bool skip_handle_check) {
  // Check for the NFTA_TABLE_NAME attribute.
  const struct nfattr* table_name_attr =
      FindNfAttr(hdr, genmsg, NFTA_TABLE_NAME);
  if (table_name_attr != nullptr && test_table_name != nullptr) {
    std::string name(reinterpret_cast<const char*>(NFA_DATA(table_name_attr)));
    EXPECT_EQ(name, test_table_name);
  } else {
    EXPECT_EQ(table_name_attr, nullptr);
    EXPECT_EQ(test_table_name, nullptr);
  }

  // Check for the NFTA_TABLE_USE attribute.
  const struct nfattr* table_use_attr = FindNfAttr(hdr, genmsg, NFTA_TABLE_USE);
  if (table_use_attr != nullptr && expected_chain_count != nullptr) {
    uint32_t count = *(reinterpret_cast<uint32_t*>(NFA_DATA(table_use_attr)));
    EXPECT_EQ(count, *expected_chain_count);
  } else {
    EXPECT_EQ(table_use_attr, nullptr);
    EXPECT_EQ(expected_chain_count, nullptr);
  }

  if (!skip_handle_check) {
    // Check for the NFTA_TABLE_HANDLE attribute.
    const struct nfattr* handle_attr =
        FindNfAttr(hdr, genmsg, NFTA_TABLE_HANDLE);
    if (handle_attr != nullptr && expected_handle != nullptr) {
      uint64_t handle = *(reinterpret_cast<uint64_t*>(NFA_DATA(handle_attr)));
      EXPECT_EQ(handle, *expected_handle);
    } else {
      EXPECT_EQ(handle_attr, nullptr);
      EXPECT_EQ(expected_handle, nullptr);
    }
  }

  // Check for the NFTA_TABLE_FLAGS attribute.
  const struct nfattr* flags_attr = FindNfAttr(hdr, genmsg, NFTA_TABLE_FLAGS);
  if (flags_attr != nullptr && expected_flags != nullptr) {
    uint32_t flags = *(reinterpret_cast<uint32_t*>(NFA_DATA(flags_attr)));
    EXPECT_EQ(flags, *expected_flags);
  } else {
    EXPECT_EQ(flags_attr, nullptr);
    EXPECT_EQ(expected_flags, nullptr);
  }

  // Check for the NFTA_TABLE_OWNER attribute.
  const struct nfattr* owner_attr = FindNfAttr(hdr, genmsg, NFTA_TABLE_OWNER);
  if (owner_attr != nullptr) {
    uint32_t owner = *(reinterpret_cast<uint32_t*>(NFA_DATA(owner_attr)));
    EXPECT_EQ(owner, *expected_owner);
  } else {
    EXPECT_EQ(owner_attr, nullptr);
    EXPECT_EQ(expected_owner, nullptr);
  }

  // Check for the NFTA_TABLE_USERDATA attribute.
  const struct nfattr* user_data_attr =
      FindNfAttr(hdr, genmsg, NFTA_TABLE_USERDATA);

  if (user_data_attr != nullptr && expected_udata_size != nullptr) {
    uint8_t user_data[VALID_USERDATA_SIZE] = {};
    EXPECT_EQ(user_data_attr->nfa_len - NLA_HDRLEN, *expected_udata_size);
    std::memcpy(user_data, NFA_DATA(user_data_attr), *expected_udata_size);
    EXPECT_EQ(memcmp(user_data, expected_udata, *expected_udata_size), 0);
  } else {
    EXPECT_EQ(user_data_attr, nullptr);
    EXPECT_EQ(expected_udata_size, nullptr);
  }
}

}  // namespace testing
}  // namespace gvisor
