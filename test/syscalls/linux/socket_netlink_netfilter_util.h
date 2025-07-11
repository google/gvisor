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

struct nameAttribute {
  struct nlattr attr;
  char name[TABLE_NAME_SIZE];
};
struct flagAttribute {
  struct nlattr attr;
  uint32_t flags;
};
struct userDataAttribute {
  struct nlattr attr;
  uint8_t userdata[VALID_USERDATA_SIZE];
};
struct deleteAttribute {
  struct nlattr attr;
  uint32_t handle;
};

void InitNetfilterGenmsg(struct nfgenmsg* genmsg, uint8_t family,
                         uint8_t version, uint16_t res_id);

void CheckNetfilterTableAttributes(
    const struct nlmsghdr* hdr, const struct nfgenmsg* genmsg,
    const char* test_table_name, uint32_t* expected_chain_count,
    uint64_t* expected_handle, uint32_t* expected_flags,
    uint32_t* expected_owner, uint8_t* expected_udata,
    size_t* expected_udata_size, bool skip_handle_check);

class NetlinkRequestBuilder {
 public:
  NetlinkRequestBuilder() = default;

  NetlinkRequestBuilder& SetMessageType(uint8_t message_type);
  NetlinkRequestBuilder& SetFlags(uint16_t flags);
  NetlinkRequestBuilder& SetSequenceNumber(uint32_t seq);
  NetlinkRequestBuilder& SetFamily(uint8_t family);

  // Method to add an attribute to the message. If there is a default
  // size for the attribute type, it will be used.
  // Otherwise, assumes the payload is of at least size payload_size.
  NetlinkRequestBuilder& AddAttribute(uint16_t attr_type, const void* payload,
                                      size_t payload_size);

  std::vector<char> Build();

 private:
  uint8_t message_type_ = 0;
  uint16_t flags_ = 0;
  uint32_t seq_ = 0;
  uint8_t family_ = 0;
  std::map<uint16_t, std::pair<const char*, size_t>> attributes_ = {};
  std::vector<char> msg_buffer_;
};

class NetlinkNestedAttributeBuilder {
 public:
  NetlinkNestedAttributeBuilder() = default;

  // Method to add an attribute to the message. If there is a default
  // size for the attribute type, it will be used.
  // Otherwise, assumes the payload is of at least size payload_size.
  NetlinkNestedAttributeBuilder& AddAttribute(uint16_t attr_type,
                                              const void* payload,
                                              size_t payload_size);

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
