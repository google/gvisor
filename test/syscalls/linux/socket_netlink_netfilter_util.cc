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
#include <string>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"

namespace gvisor {
namespace testing {

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
