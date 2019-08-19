// Copyright 2019 The gVisor Authors.
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

#include "test/syscalls/linux/iptables.h"

#include <arpa/inet.h>
#include <linux/capability.h>
#include <linux/netfilter/x_tables.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kNatTablename[] = "nat";
constexpr char kErrorTarget[] = "ERROR";
constexpr size_t kEmptyStandardEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_standard_target);
constexpr size_t kEmptyErrorEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_error_target);

TEST(IPTablesBasic, CreateSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, FailSockoptNonRaw) {
  // Even if the user has CAP_NET_RAW, they shouldn't be able to use the
  // iptables sockopts with a non-raw socket.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  EXPECT_THAT(getsockopt(sock, IPPROTO_IP, SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOPROTOOPT));

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

// Fixture for iptables tests.
class IPTablesTest : public ::testing::Test {
 protected:
  // Creates a socket to be used in tests.
  void SetUp() override;

  // Closes the socket created by SetUp().
  void TearDown() override;

  // The socket via which to manipulate iptables.
  int s_;
};

void IPTablesTest::SetUp() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  ASSERT_THAT(s_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), SyscallSucceeds());
}

void IPTablesTest::TearDown() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  EXPECT_THAT(close(s_), SyscallSucceeds());
}

// This tests the initial state of a machine with empty iptables. We don't have
// a guarantee that the iptables are empty when running in native, but we can
// test that gVisor has the same initial state that a newly-booted Linux machine
// would have.
TEST_F(IPTablesTest, InitialState) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  //
  // Get info via sockopt.
  //
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, IPPROTO_IP, SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // The nat table supports PREROUTING, and OUTPUT.
  unsigned int valid_hooks = (1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_LOCAL_OUT) |
                             (1 << NF_IP_POST_ROUTING) | (1 << NF_IP_LOCAL_IN);

  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Each chain consists of an empty entry with a standard target..
  EXPECT_EQ(info.hook_entry[NF_IP_PRE_ROUTING], 0);
  EXPECT_EQ(info.hook_entry[NF_IP_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.hook_entry[NF_IP_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.hook_entry[NF_IP_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // The underflow points are the same as the entry points.
  EXPECT_EQ(info.underflow[NF_IP_PRE_ROUTING], 0);
  EXPECT_EQ(info.underflow[NF_IP_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.underflow[NF_IP_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.underflow[NF_IP_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // One entry for each chain, plus an error entry at the end.
  EXPECT_EQ(info.num_entries, 5);

  EXPECT_EQ(info.size, 4 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kNatTablename), 0);

  //
  // Use info to get entries.
  //
  socklen_t entries_size = sizeof(struct ipt_get_entries) + info.size;
  struct ipt_get_entries* entries =
      static_cast<struct ipt_get_entries*>(malloc(entries_size));
  snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  entries->size = info.size;
  ASSERT_THAT(
      getsockopt(s_, IPPROTO_IP, SO_GET_ENTRIES, entries, &entries_size),
      SyscallSucceeds());

  // Verify the name and size.
  ASSERT_EQ(info.size, entries->size);
  ASSERT_EQ(strcmp(entries->name, kNatTablename), 0);

  // Verify that the entrytable is 4 entries with accept targets and no matches
  // followed by a single error target.
  size_t entry_offset = 0;
  while (entry_offset < entries->size) {
    struct ipt_entry* entry = reinterpret_cast<struct ipt_entry*>(
        reinterpret_cast<char*>(entries->entrytable) + entry_offset);

    // ip should be zeroes.
    struct ipt_ip zeroed = {};
    EXPECT_EQ(memcmp(static_cast<void*>(&zeroed),
                     static_cast<void*>(&entry->ip), sizeof(zeroed)),
              0);

    // target_offset should be zero.
    EXPECT_EQ(entry->target_offset, sizeof(ipt_entry));

    if (entry_offset < kEmptyStandardEntrySize * 4) {
      // The first 4 entries are standard targets
      struct ipt_standard_target* target =
          reinterpret_cast<struct ipt_standard_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyStandardEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, ""), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      // This is what's returned for an accept verdict. I don't know why.
      EXPECT_EQ(target->verdict, -NF_ACCEPT - 1);
    } else {
      // The last entry is an error target
      struct ipt_error_target* target =
          reinterpret_cast<struct ipt_error_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyErrorEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, kErrorTarget), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      EXPECT_EQ(strcmp(target->errorname, kErrorTarget), 0);
    }

    entry_offset += entry->next_offset;
  }

  free(entries);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
