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
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/iptables_util.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kNatTablename[] = "nat";
constexpr char kRawTablename[] = "raw";
constexpr char kErrorTarget[] = "ERROR";
constexpr size_t kEmptyStandardEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_standard_target);
constexpr size_t kEmptyErrorEntrySize =
    sizeof(struct ipt_entry) + sizeof(struct ipt_error_target);

using ::testing::AnyOf;

TEST(IPTablesBasic, CreateSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, GetInfoShortBuffer) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info) - 1;
  ASSERT_THAT(
      getsockopt(sock.get(), SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
      SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, GetEntriesShortBuffer) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct ipt_get_entries entries = {};
  socklen_t entries_size = sizeof(struct ipt_get_entries) - 1;
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  ASSERT_THAT(getsockopt(sock.get(), SOL_IP, IPT_SO_GET_ENTRIES, &entries,
                         &entries_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, OriginalDstErrors) {
  const FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  // An unconnected socket has no tracked connection to look up.
  struct sockaddr_in addr = {};
  socklen_t addr_len = sizeof(addr);
  int ret = getsockopt(sock.get(), SOL_IP, SO_ORIGINAL_DST, &addr, &addr_len);
  // Linux fails with ENOPROTOOPT if nf_conntrack is not loaded.
  SKIP_IF(ret == -1 && errno == ENOPROTOOPT &&
          GvisorPlatform() == Platform::kNative);
  EXPECT_THAT(ret, SyscallFailsWithErrno(ENOENT));
}

TEST(IPTablesBasic, GetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "REDIRECT");
  rev.revision = 0;

  // Revision 0 exists.
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  // Revisions > 0 don't exist.
  rev.revision = 1;
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallFailsWithErrno(EPROTONOSUPPORT));

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, GetRevisionMatchMark) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "mark");
  rev.revision = 1;

  // Revision 1 exists for mark.
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_MATCH, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 1);

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

// Linux returns ENOENT when asked about a table that isn't registered. Tools
// such as syzkaller rely on this to skip unsupported tables (e.g. "security").
TEST_F(IPTablesTest, GetInfoNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", "nonexistent");
  socklen_t info_size = sizeof(info);
  EXPECT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOENT));

  info_size = sizeof(info) + 1;
  EXPECT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(IPTablesTest, GetEntriesNonexistentTable) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct ipt_get_entries entries = {};
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", "nonexistent");
  socklen_t entries_size = sizeof(entries);
  EXPECT_THAT(
      getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(ENOENT));

  entries.size = 1;
  EXPECT_THAT(
      getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(EINVAL));
}

// This tests the initial state of a machine with empty iptables. We don't
// have a guarantee that the iptables are empty when running in native, but we
// can test that gVisor has the same initial state that a newly-booted Linux
// machine would have.
TEST_F(IPTablesTest, InitialState) {
  SKIP_IF(GvisorPlatform() == Platform::kNative);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  //
  // Get info via sockopt.
  //
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
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
      getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, entries, &entries_size),
      SyscallSucceeds());

  // Verify the name and size.
  ASSERT_EQ(info.size, entries->size);
  ASSERT_EQ(strcmp(entries->name, kNatTablename), 0);

  // Verify that the entrytable is 4 entries with accept targets and no
  // matches followed by a single error target.
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

// Regression test for a bug where gVisor's hard-coded maxOptLen of 8KB
// silently rejected setsockopt(IPT_SO_SET_REPLACE) payloads larger than 8192
// bytes with EINVAL. Real-world workloads such as Istio service mesh generate
// nat table rulesets that commonly exceed 8KB (Istio 1.28+ produces ~13KB).
// The limit has been raised to 32KB; Linux itself uses INT_MAX.
TEST_F(IPTablesTest, LargeReplacePayload) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Get current nat table metadata.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // Read current entries.
  socklen_t orig_sz = sizeof(struct ipt_get_entries) + info.size;
  std::unique_ptr<char[]> orig_buf(new char[orig_sz]());
  struct ipt_get_entries* orig =
      reinterpret_cast<struct ipt_get_entries*>(orig_buf.get());
  snprintf(orig->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  orig->size = info.size;
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_ENTRIES, orig, &orig_sz),
              SyscallSucceeds());

  // Compute extra entries needed to push the total setsockopt payload past 8KB.
  const size_t kMinPayload = 9 * 1024;
  size_t extra = 0;
  if (sizeof(struct ipt_replace) + info.size < kMinPayload) {
    extra = (kMinPayload - sizeof(struct ipt_replace) - info.size +
             kEmptyStandardEntrySize - 1) /
            kEmptyStandardEntrySize;
  }
  const size_t shift = extra * kEmptyStandardEntrySize;
  const size_t new_entries_size = info.size + shift;
  const unsigned int new_num_entries = info.num_entries + extra;
  const size_t buf_sz = sizeof(struct ipt_replace) + new_entries_size;

  ASSERT_GT(buf_sz, 8192u);

  // Build ipt_replace buffer.
  std::unique_ptr<char[]> buf(new char[buf_sz]());
  struct ipt_replace* repl = reinterpret_cast<struct ipt_replace*>(buf.get());

  snprintf(repl->name, sizeof(repl->name), "%s", kNatTablename);
  repl->valid_hooks = info.valid_hooks;
  repl->num_entries = new_num_entries;
  repl->size = new_entries_size;
  // Linux returns counters from the table being replaced.
  repl->num_counters = info.num_entries;

  std::unique_ptr<struct xt_counters[]> ctrs(
      new struct xt_counters[info.num_entries]());
  repl->counters = ctrs.get();

  // Insert extra entries at the start of the PREROUTING chain. All valid
  // hook/underflow offsets shift forward by `shift` bytes to account for the
  // new entries. The PREROUTING hook_entry stays at 0 because the new entries
  // ARE the beginning of the chain.
  for (int h = 0; h < NF_IP_NUMHOOKS; h++) {
    if (info.valid_hooks & (1 << h)) {
      repl->hook_entry[h] = info.hook_entry[h] + shift;
      repl->underflow[h] = info.underflow[h] + shift;
    }
  }
  repl->hook_entry[NF_IP_PRE_ROUTING] = 0;

  // Fill extra entries: unconditional ACCEPT rules.
  char* dst = reinterpret_cast<char*>(repl->entries);
  for (size_t i = 0; i < extra; i++) {
    struct ipt_entry* e =
        reinterpret_cast<struct ipt_entry*>(dst + i * kEmptyStandardEntrySize);
    memset(e, 0, kEmptyStandardEntrySize);
    e->target_offset = sizeof(struct ipt_entry);
    e->next_offset = kEmptyStandardEntrySize;
    struct ipt_standard_target* t =
        reinterpret_cast<struct ipt_standard_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    t->verdict = -NF_ACCEPT - 1;
  }

  // Copy original entries after the extra ones.
  memcpy(dst + shift, reinterpret_cast<char*>(orig->entrytable), info.size);

  ASSERT_THAT(setsockopt(s_, SOL_IP, IPT_SO_SET_REPLACE, repl, buf_sz),
              SyscallSucceeds());

  // Restore original table to avoid side effects on other tests.
  size_t restore_sz = sizeof(struct ipt_replace) + info.size;
  std::unique_ptr<char[]> restore_buf(new char[restore_sz]());
  struct ipt_replace* restore =
      reinterpret_cast<struct ipt_replace*>(restore_buf.get());
  snprintf(restore->name, sizeof(restore->name), "%s", kNatTablename);
  restore->valid_hooks = info.valid_hooks;
  restore->num_entries = info.num_entries;
  restore->size = info.size;
  restore->num_counters = new_num_entries;
  std::unique_ptr<struct xt_counters[]> rctrs(
      new struct xt_counters[new_num_entries]());
  restore->counters = rctrs.get();
  memcpy(restore->hook_entry, info.hook_entry, sizeof(info.hook_entry));
  memcpy(restore->underflow, info.underflow, sizeof(info.underflow));
  memcpy(restore->entries, orig->entrytable, info.size);
  EXPECT_THAT(setsockopt(s_, SOL_IP, IPT_SO_SET_REPLACE, restore, restore_sz),
              SyscallSucceeds());
}

// Tests the initial state of the raw table. The raw table has PREROUTING and
// OUTPUT hooks (no INPUT, FORWARD, or POSTROUTING).
TEST_F(IPTablesTest, RawTableInitialState) {
  SKIP_IF(GvisorPlatform() == Platform::kNative);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kRawTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(getsockopt(s_, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallSucceeds());

  // The raw table supports PREROUTING and OUTPUT only.
  unsigned int valid_hooks = (1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_LOCAL_OUT);
  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Two chain entries (PREROUTING, OUTPUT) plus one error entry.
  EXPECT_EQ(info.num_entries, 3);
  EXPECT_EQ(info.size, 2 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kRawTablename), 0);
}

// Tests that the CT target revision 0 is recognized.
TEST(IPTablesBasic, CTTargetGetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "CT");
  rev.revision = 0;

  // CT revision 0 should exist.
  EXPECT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  EXPECT_THAT(close(sock), SyscallSucceeds());
}

struct SockOptArgs {
  int sock;
  int optname;
  std::shared_ptr<char[]> optval;
  socklen_t optlen;
};

struct RequiresCapNetAdminTestParams {
  std::string test_name;
  std::function<absl::StatusOr<SockOptArgs>(int sock)> generate_sockopt_args;
};

using SockOptTestParams = std::tuple<SocketKind, RequiresCapNetAdminTestParams>;

const auto kSocketKinds = ::testing::Values(
    SimpleSocket(AF_INET, SOCK_RAW, IPPROTO_RAW),
    SimpleSocket(AF_INET, SOCK_DGRAM, 0), SimpleSocket(AF_INET, SOCK_STREAM, 0),
    // SOL_IP is also available on non-raw IPv6 sockets.
    SimpleSocket(AF_INET6, SOCK_DGRAM, 0),
    SimpleSocket(AF_INET6, SOCK_STREAM, 0));

std::string SockOptTestName(
    const ::testing::TestParamInfo<SockOptTestParams>& info) {
  const auto& [kind, params] = info.param;
  std::string name = params.test_name;
  name += kind.domain == AF_INET ? "IPv4" : "IPv6";
  if (kind.type == SOCK_RAW) {
    return name + "Raw";
  }
  if (kind.type == SOCK_DGRAM) {
    return name + "Datagram";
  }
  return name + "Stream";
}

class GetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<SockOptTestParams> {};

TEST_P(GetSockOptRequiresCapNetAdminTest, Validate) {
  const auto& [kind, params] = GetParam();
  SKIP_IF(kind.type == SOCK_RAW &&
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(kind.domain, kind.type, kind.protocol));
  // Linux fails with ENOENT if the kernel lacks the queried table or target
  // so skip natively in that case.
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  SKIP_IF(absl::IsNotFound(args_or_status.status()) &&
          GvisorPlatform() == Platform::kNative);
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& getsockopt_args = *args_or_status;

  // Copy the optval to a new buffer before the current process' getsockopt
  // call.
  std::unique_ptr<char[]> child_optval =
      std::make_unique<char[]>(getsockopt_args.optlen);
  std::memcpy(child_optval.get(), getsockopt_args.optval.get(),
              getsockopt_args.optlen);

  // Validate that the socket creator can successfully getsockopt.
  int ret = getsockopt(getsockopt_args.sock, SOL_IP, getsockopt_args.optname,
                       getsockopt_args.optval.get(), &getsockopt_args.optlen);
  SKIP_IF(ret == -1 && errno == ENOENT &&
          GvisorPlatform() == Platform::kNative);
  ASSERT_THAT(ret, SyscallSucceeds());

  // Validate that another process from a different user namespace cannot
  // getsockopt and fails with EPERM.
  EXPECT_THAT(
      InForkedProcess([sock_fd = sock.get(), optname = getsockopt_args.optname,
                       optval = child_optval.get(),
                       optlen = &getsockopt_args.optlen]() -> void {
        // unshare to remove the child's permissions in the parent's
        // user and network namespaces.
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET));
        // getsockopt is async signal safe, so it's okay to call it here.
        TEST_CHECK_ERRNO(getsockopt(sock_fd, SOL_IP, optname, optval, optlen),
                         EPERM);
        if (optname == IPT_SO_GET_INFO) {
          socklen_t invalid_len = 0;
          TEST_CHECK_ERRNO(
              getsockopt(sock_fd, SOL_IP, optname, optval, &invalid_len),
              EPERM);
          invalid_len = *optlen + 1;
          TEST_CHECK_ERRNO(
              getsockopt(sock_fd, SOL_IP, optname, optval, &invalid_len),
              EPERM);
        }
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    GetSockOpt, GetSockOptRequiresCapNetAdminTest,
    ::testing::Combine(
        kSocketKinds,
        ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
            {{.test_name = "GetInfo",
              .generate_sockopt_args =
                  [](int sock) {
                    SockOptArgs args;
                    args.sock = sock;
                    std::unique_ptr<char[]> info_buffer =
                        std::make_unique<char[]>(sizeof(ipt_getinfo));
                    ipt_getinfo* info =
                        reinterpret_cast<ipt_getinfo*>(info_buffer.get());
                    snprintf(info->name, XT_TABLE_MAXNAMELEN, "%s",
                             kNatTablename);
                    args.optname = IPT_SO_GET_INFO;
                    args.optval = std::move(info_buffer);
                    args.optlen = sizeof(ipt_getinfo);
                    return args;
                  }},
             {.test_name = "GetEntries",
              .generate_sockopt_args =
                  [](int sock) -> absl::StatusOr<SockOptArgs> {
                socklen_t get_info_optlen = sizeof(ipt_getinfo);
                ipt_getinfo get_info;
                snprintf(get_info.name, XT_TABLE_MAXNAMELEN, "%s",
                         kNatTablename);
                if (getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, &get_info,
                               &get_info_optlen) != 0) {
                  return absl::ErrnoToStatus(errno, "IPT_SO_GET_INFO");
                }
                socklen_t get_entries_optlen =
                    sizeof(ipt_get_entries) + get_info.size;
                std::unique_ptr<char[]> entries_buffer =
                    std::make_unique<char[]>(get_entries_optlen);
                ipt_get_entries* entries =
                    reinterpret_cast<ipt_get_entries*>(entries_buffer.get());
                snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s",
                         kNatTablename);
                entries->size = get_info.size;
                SockOptArgs get_entries_args = {
                    .sock = sock,
                    .optname = IPT_SO_GET_ENTRIES,
                    .optval = std::move(entries_buffer),
                    .optlen = get_entries_optlen,
                };
                return get_entries_args;
              }},
             {.test_name = "GetRevisionTarget",
              .generate_sockopt_args =
                  [](int sock) {
                    std::unique_ptr<char[]> rev_buffer =
                        std::make_unique<char[]>(sizeof(xt_get_revision));
                    xt_get_revision* rev =
                        reinterpret_cast<xt_get_revision*>(rev_buffer.get());
                    snprintf(rev->name, sizeof(rev->name), "REDIRECT");
                    rev->revision = 0;
                    return SockOptArgs{
                        .sock = sock,
                        .optname = IPT_SO_GET_REVISION_TARGET,
                        .optval = std::move(rev_buffer),
                        .optlen = sizeof(xt_get_revision),
                    };
                  }},
             {.test_name = "GetRevisionMatch",
              .generate_sockopt_args =
                  [](int sock) {
                    std::unique_ptr<char[]> rev_buffer =
                        std::make_unique<char[]>(sizeof(xt_get_revision));
                    xt_get_revision* rev =
                        reinterpret_cast<xt_get_revision*>(rev_buffer.get());
                    snprintf(rev->name, sizeof(rev->name), "tcp");
                    rev->revision = 0;
                    return SockOptArgs{
                        .sock = sock,
                        .optname = IPT_SO_GET_REVISION_MATCH,
                        .optval = std::move(rev_buffer),
                        .optlen = sizeof(xt_get_revision),
                    };
                  }}})),
    SockOptTestName);

class SetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<SockOptTestParams> {};

TEST_P(SetSockOptRequiresCapNetAdminTest, Validate) {
  const auto& [kind, params] = GetParam();
  SKIP_IF(kind.type == SOCK_RAW &&
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(kind.domain, kind.type, kind.protocol));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& setsockopt_args = *args_or_status;

  // The socket creator passes the permission check, but the replacement
  // lacks table entries and is invalid.
  ASSERT_THAT(setsockopt(setsockopt_args.sock, /*level=*/SOL_IP,
                         setsockopt_args.optname, setsockopt_args.optval.get(),
                         setsockopt_args.optlen),
              SyscallFailsWithErrno(EINVAL));

  // Validate that another process from a different user namespace cannot
  // setsockopt and fails with EPERM.
  EXPECT_THAT(
      // Not using a copy of optval since the setsockopt accepts a const pointer
      // and so it shouldn't have modified the optval in the previous call.
      InForkedProcess([sock_fd = sock.get(), optname = setsockopt_args.optname,
                       optval = setsockopt_args.optval.get(),
                       optlen = &setsockopt_args.optlen]() {
        // unshare to remove the child's permissions in the parent's
        // user and network namespaces.
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET));
        // setsockopt is async signal safe, so it's okay to call it here.
        TEST_CHECK_ERRNO(
            setsockopt(sock_fd, /*level=*/SOL_IP, optname, optval, *optlen),
            EPERM);
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    SetSockOpt, SetSockOptRequiresCapNetAdminTest,
    ::testing::Combine(
        kSocketKinds,
        ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
            {{.test_name = "SetReplace",
              .generate_sockopt_args =
                  [](int sock) {
                    SockOptArgs args;
                    args.sock = sock;
                    std::unique_ptr<char[]> replace_buffer =
                        std::make_unique<char[]>(sizeof(ipt_replace));
                    ipt_replace* replace =
                        reinterpret_cast<ipt_replace*>(replace_buffer.get());
                    snprintf(replace->name, sizeof(replace->name), "%s",
                             kNatTablename);
                    args.optname = IPT_SO_SET_REPLACE;
                    args.optval = std::move(replace_buffer);
                    args.optlen = sizeof(ipt_replace);
                    return args;
                  }}})),
    SockOptTestName);

// Creates an iptables replace payload for the "filter" table where a built-in
// hook entry point (LOCAL_IN) points directly to a user-defined chain header
// (an XT_ERROR_TARGET whose errorname is a custom chain name, "my_chain").
std::vector<char> MakeUserChainTargetReplacePayload() {
  return MakeUserChainTargetReplacePayload4();
}

TEST(IPTablesBasic, UserChainTargetCrash) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
  std::vector<char> replace = MakeUserChainTargetReplacePayload();
  EXPECT_THAT(
      setsockopt(sock.get(), SOL_IP, IPT_SO_SET_REPLACE, replace.data(),
                 replace.size()),
      AnyOf(SyscallFailsWithErrno(EINVAL), SyscallFailsWithErrno(ENOPROTOOPT)));
}

constexpr char kTunName[] = "tun0";
constexpr int kPollTimeoutMs = 5000;
const in_addr_t kTunAddr = htonl(0x0a000001);   // 10.0.0.1
const in_addr_t kPeerAddr = htonl(0x0a000002);  // 10.0.0.2
const in_addr_t kSNATAddr = htonl(0x0a000003);  // 10.0.0.3
const in_addr_t kVIPAddr = htonl(0x0a000064);   // 10.0.0.100
constexpr uint16_t kLocalPort = 8000;
constexpr uint16_t kPeerPort = 9000;
constexpr uint16_t kSNATPort = 7000;
constexpr uint16_t kVIPPort = 80;

constexpr size_t kNATTargetSize =
    XT_ALIGN(sizeof(struct xt_entry_target) +
             sizeof(struct nf_nat_ipv4_multi_range_compat));
constexpr size_t kNATEntrySize = sizeof(struct ipt_entry) + kNATTargetSize;

// A single SNAT or DNAT rule (revision 0 target) for the nat table.
struct NATRule {
  unsigned int hook;
  const char* target;
  uint8_t protocol;
  in_addr_t src;  // INADDR_ANY matches any source.
  in_addr_t dst;  // INADDR_ANY matches any destination.
  in_addr_t to_addr;
  uint16_t to_port;
};

// Replaces the nat table with one that holds only rule, in its hook's chain,
// and ACCEPT policies.
PosixError ReplaceNATTable(const NATRule& rule) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor sock, Socket(AF_INET, SOCK_DGRAM, 0));
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  if (getsockopt(sock.get(), SOL_IP, IPT_SO_GET_INFO, &info, &info_size) != 0) {
    return PosixError(errno, "IPT_SO_GET_INFO");
  }

  constexpr unsigned int kHooks[] = {NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN,
                                     NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING};
  const size_t entries_size = kNATEntrySize +
                              std::size(kHooks) * kEmptyStandardEntrySize +
                              kEmptyErrorEntrySize;
  std::vector<char> buf(sizeof(struct ipt_replace) + entries_size);
  struct ipt_replace* repl = reinterpret_cast<struct ipt_replace*>(buf.data());
  snprintf(repl->name, sizeof(repl->name), "%s", kNatTablename);
  repl->valid_hooks = info.valid_hooks;
  repl->num_entries = std::size(kHooks) + 2;
  repl->size = entries_size;
  repl->num_counters = info.num_entries;
  std::vector<struct xt_counters> counters(info.num_entries);
  repl->counters = counters.data();

  char* entries = reinterpret_cast<char*>(repl->entries);
  size_t offset = 0;
  for (unsigned int hook : kHooks) {
    repl->hook_entry[hook] = offset;
    if (hook == rule.hook) {
      struct ipt_entry* e =
          reinterpret_cast<struct ipt_entry*>(entries + offset);
      e->ip.src.s_addr = rule.src;
      e->ip.smsk.s_addr = rule.src == INADDR_ANY ? 0 : 0xffffffff;
      e->ip.dst.s_addr = rule.dst;
      e->ip.dmsk.s_addr = rule.dst == INADDR_ANY ? 0 : 0xffffffff;
      e->ip.proto = rule.protocol;
      e->target_offset = sizeof(struct ipt_entry);
      e->next_offset = kNATEntrySize;
      struct xt_entry_target* t =
          reinterpret_cast<struct xt_entry_target*>(e->elems);
      t->u.user.target_size = kNATTargetSize;
      snprintf(t->u.user.name, sizeof(t->u.user.name), "%s", rule.target);
      struct nf_nat_ipv4_multi_range_compat* range =
          reinterpret_cast<struct nf_nat_ipv4_multi_range_compat*>(t->data);
      range->rangesize = 1;
      range->range[0].flags =
          NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
      range->range[0].min_ip = rule.to_addr;
      range->range[0].max_ip = rule.to_addr;
      range->range[0].min.all = htons(rule.to_port);
      range->range[0].max.all = htons(rule.to_port);
      offset += kNATEntrySize;
    }
    repl->underflow[hook] = offset;
    struct ipt_entry* e = reinterpret_cast<struct ipt_entry*>(entries + offset);
    e->target_offset = sizeof(struct ipt_entry);
    e->next_offset = kEmptyStandardEntrySize;
    struct ipt_standard_target* t =
        reinterpret_cast<struct ipt_standard_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    t->verdict = -NF_ACCEPT - 1;
    offset += kEmptyStandardEntrySize;
  }
  struct ipt_entry* e = reinterpret_cast<struct ipt_entry*>(entries + offset);
  e->target_offset = sizeof(struct ipt_entry);
  e->next_offset = kEmptyErrorEntrySize;
  struct ipt_error_target* t =
      reinterpret_cast<struct ipt_error_target*>(e->elems);
  t->target.u.user.target_size = sizeof(*t);
  snprintf(t->target.u.user.name, sizeof(t->target.u.user.name), "%s",
           kErrorTarget);
  snprintf(t->errorname, sizeof(t->errorname), "%s", kErrorTarget);

  if (setsockopt(sock.get(), SOL_IP, IPT_SO_SET_REPLACE, buf.data(),
                 buf.size()) != 0) {
    return PosixError(errno, "IPT_SO_SET_REPLACE");
  }
  return NoError();
}

// Returns the TCP or UDP checksum of l4 (header and payload) inside ip.
uint16_t L4Checksum(const struct iphdr& ip, const char* l4, size_t len) {
  uint32_t sum = 0;
  auto add = [&sum](const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i + 1 < n; i += 2) {
      sum += (p[i] << 8) | p[i + 1];
    }
    if (n % 2) {
      sum += p[n - 1] << 8;
    }
  };
  add(&ip.saddr, sizeof(ip.saddr));
  add(&ip.daddr, sizeof(ip.daddr));
  const uint16_t proto_len[] = {htons(ip.protocol), htons(len)};
  add(proto_len, sizeof(proto_len));
  add(l4, len);
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  const uint16_t csum = htons(~sum & 0xffff);
  return csum == 0 ? 0xffff : csum;
}

// Returns an IPv4 packet carrying l4, with valid IP and transport checksums.
// checksum_offset is the offset of the checksum field in l4.
std::vector<char> IPv4Packet(uint8_t protocol, in_addr_t src, in_addr_t dst,
                             std::vector<char> l4, size_t checksum_offset,
                             bool zero_checksum = false) {
  struct iphdr ip = {};
  ip.ihl = sizeof(ip) / 4;
  ip.version = 4;
  ip.tot_len = htons(sizeof(ip) + l4.size());
  ip.ttl = 64;
  ip.protocol = protocol;
  ip.saddr = src;
  ip.daddr = dst;
  ip.check = IPChecksum(ip);
  if (!zero_checksum) {
    const uint16_t csum = L4Checksum(ip, l4.data(), l4.size());
    memcpy(l4.data() + checksum_offset, &csum, sizeof(csum));
  }
  std::vector<char> pkt(sizeof(ip) + l4.size());
  memcpy(pkt.data(), &ip, sizeof(ip));
  memcpy(pkt.data() + sizeof(ip), l4.data(), l4.size());
  return pkt;
}

std::vector<char> UDPPacket(in_addr_t src, uint16_t sport, in_addr_t dst,
                            uint16_t dport, absl::string_view payload,
                            bool zero_checksum = false) {
  struct udphdr udp = {};
  udp.source = htons(sport);
  udp.dest = htons(dport);
  udp.len = htons(sizeof(udp) + payload.size());
  std::vector<char> l4(sizeof(udp) + payload.size());
  memcpy(l4.data(), &udp, sizeof(udp));
  memcpy(l4.data() + sizeof(udp), payload.data(), payload.size());
  return IPv4Packet(IPPROTO_UDP, src, dst, std::move(l4),
                    offsetof(struct udphdr, check), zero_checksum);
}

std::vector<char> TCPPacket(in_addr_t src, uint16_t sport, in_addr_t dst,
                            uint16_t dport, uint32_t seq, uint32_t ack,
                            bool syn) {
  struct tcphdr tcp = {};
  tcp.source = htons(sport);
  tcp.dest = htons(dport);
  tcp.seq = htonl(seq);
  tcp.ack_seq = htonl(ack);
  tcp.doff = sizeof(tcp) / 4;
  tcp.syn = syn;
  tcp.ack = !syn;
  tcp.window = htons(65535);
  std::vector<char> l4(sizeof(tcp));
  memcpy(l4.data(), &tcp, sizeof(tcp));
  return IPv4Packet(IPPROTO_TCP, src, dst, std::move(l4),
                    offsetof(struct tcphdr, check));
}

// Reads packets from the TUN device until an IPv4 packet with the given
// transport protocol and destination arrives, and returns it. Other packets,
// such as IPv6 router solicitations, are skipped.
PosixErrorOr<std::vector<char>> ReadIPv4Packet(int tun, uint8_t protocol,
                                               in_addr_t dst) {
  for (;;) {
    struct pollfd pfd = {.fd = tun, .events = POLLIN};
    int n = poll(&pfd, 1, kPollTimeoutMs);
    if (n < 0) {
      return PosixError(errno, "poll");
    }
    if (n == 0) {
      return PosixError(ETIMEDOUT, "no matching packet on the TUN device");
    }
    std::vector<char> buf(1500);
    ssize_t len = read(tun, buf.data(), buf.size());
    if (len < 0) {
      return PosixError(errno, "read");
    }
    buf.resize(len);
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(buf.data());
    if (static_cast<size_t>(len) >= sizeof(*ip) && ip->version == 4 &&
        ip->protocol == protocol && ip->daddr == dst) {
      return buf;
    }
  }
}

// Waits up to kPollTimeoutMs for a datagram on sock and returns its payload,
// storing the sender in peer.
PosixErrorOr<std::string> RecvFrom(int sock, struct sockaddr_in* peer) {
  struct pollfd pfd = {.fd = sock, .events = POLLIN};
  int n = poll(&pfd, 1, kPollTimeoutMs);
  if (n < 0) {
    return PosixError(errno, "poll");
  }
  if (n == 0) {
    return PosixError(ETIMEDOUT, "no datagram received");
  }
  char buf[64];
  socklen_t peer_len = sizeof(*peer);
  ssize_t len = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, AsSockAddr(peer),
                         &peer_len);
  if (len < 0) {
    return PosixError(errno, "recvfrom");
  }
  return std::string(buf, len);
}

// Runs each test in a new network namespace whose only device besides
// loopback is a TUN device (IFF_NO_PI) at 10.0.0.1/24. Linux and gVisor both
// verify the transport checksum of packets written to a TUN device, so these
// tests check that NAT keeps that checksum valid.
class IPTablesNATTunTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

    orig_netns_ = ASSERT_NO_ERRNO_AND_VALUE(
        Open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC));
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());

    // Linux fails with ENOENT if iptable_nat isn't available.
    FileDescriptor sock =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
    struct ipt_getinfo info = {};
    snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
    socklen_t info_size = sizeof(info);
    int ret =
        getsockopt(sock.get(), SOL_IP, IPT_SO_GET_INFO, &info, &info_size);
    SKIP_IF(ret == -1 && errno == ENOENT &&
            GvisorPlatform() == Platform::kNative);
    ASSERT_THAT(ret, SyscallSucceeds());

    tun_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/net/tun", O_RDWR));
    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", kTunName);
    ASSERT_THAT(ioctl(tun_.get(), TUNSETIFF, &ifr), SyscallSucceeds());

    const int index = if_nametoindex(kTunName);
    ASSERT_NE(index, 0);
    FileDescriptor nlsk =
        ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
    const struct in_addr addr = {.s_addr = kTunAddr};
    ASSERT_NO_ERRNO(LinkAddLocalAddr(nlsk, index, AF_INET, /*prefixlen=*/24,
                                     &addr, sizeof(addr)));
    // gVisor creates TUN devices up.
    if (!IsRunningOnGvisor()) {
      ASSERT_NO_ERRNO(LinkChangeFlags(index, IFF_UP, IFF_UP));
    }
  }

  void TearDown() override {
    if (orig_netns_.get() >= 0) {
      EXPECT_THAT(setns(orig_netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

  // Checks that a UDP datagram from 10.0.0.2 is delivered with the source
  // rewritten by a nat INPUT SNAT rule.
  void TestInputSNATUDP(bool zero_checksum) {
    ASSERT_NO_ERRNO(ReplaceNATTable({.hook = NF_INET_LOCAL_IN,
                                     .target = "SNAT",
                                     .protocol = IPPROTO_UDP,
                                     .src = kPeerAddr,
                                     .dst = INADDR_ANY,
                                     .to_addr = kSNATAddr,
                                     .to_port = kSNATPort}));
    FileDescriptor sock =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = htons(kLocalPort),
                                .sin_addr = {.s_addr = kTunAddr}};
    ASSERT_THAT(bind(sock.get(), AsSockAddr(&local), sizeof(local)),
                SyscallSucceeds());

    constexpr absl::string_view kPayload = "hello";
    std::vector<char> pkt = UDPPacket(kPeerAddr, kPeerPort, kTunAddr,
                                      kLocalPort, kPayload, zero_checksum);
    ASSERT_THAT(write(tun_.get(), pkt.data(), pkt.size()),
                SyscallSucceedsWithValue(pkt.size()));

    struct sockaddr_in peer = {};
    EXPECT_THAT(RecvFrom(sock.get(), &peer),
                IsPosixErrorOkAndHolds(std::string(kPayload)));
    EXPECT_EQ(peer.sin_addr.s_addr, kSNATAddr);
    EXPECT_EQ(ntohs(peer.sin_port), kSNATPort);
  }

  // Don't do cooperative save/restore because netstack state is not restored.
  // TODO(gvisor.dev/issue/4595): enable cooperative save tests.
  const DisableSave ds_;
  FileDescriptor orig_netns_;
  FileDescriptor tun_;
};

TEST_F(IPTablesNATTunTest, InputSNATUDP) {
  TestInputSNATUDP(/*zero_checksum=*/false);
}

// A zero IPv4 UDP checksum means "no checksum" and must stay zero after NAT.
TEST_F(IPTablesNATTunTest, InputSNATUDPZeroChecksum) {
  TestInputSNATUDP(/*zero_checksum=*/true);
}

// Checks that a TCP handshake from 10.0.0.2 completes through a nat INPUT
// SNAT rule: the SYN-ACK is un-SNATed back to 10.0.0.2 and the accepted
// connection's peer is the SNAT address.
TEST_F(IPTablesNATTunTest, InputSNATTCP) {
  ASSERT_NO_ERRNO(ReplaceNATTable({.hook = NF_INET_LOCAL_IN,
                                   .target = "SNAT",
                                   .protocol = IPPROTO_TCP,
                                   .src = kPeerAddr,
                                   .dst = INADDR_ANY,
                                   .to_addr = kSNATAddr,
                                   .to_port = kSNATPort}));
  FileDescriptor listener = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
  struct sockaddr_in local = {.sin_family = AF_INET,
                              .sin_port = htons(kLocalPort),
                              .sin_addr = {.s_addr = kTunAddr}};
  ASSERT_THAT(bind(listener.get(), AsSockAddr(&local), sizeof(local)),
              SyscallSucceeds());
  ASSERT_THAT(listen(listener.get(), 1), SyscallSucceeds());

  constexpr uint32_t kISN = 1000;
  std::vector<char> syn = TCPPacket(kPeerAddr, kPeerPort, kTunAddr, kLocalPort,
                                    kISN, 0, /*syn=*/true);
  ASSERT_THAT(write(tun_.get(), syn.data(), syn.size()),
              SyscallSucceedsWithValue(syn.size()));

  std::vector<char> synack = ASSERT_NO_ERRNO_AND_VALUE(
      ReadIPv4Packet(tun_.get(), IPPROTO_TCP, kPeerAddr));
  const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(synack.data());
  ASSERT_GE(synack.size(), ip->ihl * 4 + sizeof(struct tcphdr));
  const struct tcphdr* tcp =
      reinterpret_cast<const struct tcphdr*>(synack.data() + ip->ihl * 4);
  EXPECT_EQ(ip->saddr, kTunAddr);
  EXPECT_EQ(ntohs(tcp->source), kLocalPort);
  EXPECT_EQ(ntohs(tcp->dest), kPeerPort);
  ASSERT_TRUE(tcp->syn && tcp->ack);
  ASSERT_EQ(ntohl(tcp->ack_seq), kISN + 1);

  std::vector<char> ack =
      TCPPacket(kPeerAddr, kPeerPort, kTunAddr, kLocalPort, kISN + 1,
                ntohl(tcp->seq) + 1, /*syn=*/false);
  ASSERT_THAT(write(tun_.get(), ack.data(), ack.size()),
              SyscallSucceedsWithValue(ack.size()));

  struct pollfd pfd = {.fd = listener.get(), .events = POLLIN};
  ASSERT_THAT(poll(&pfd, 1, kPollTimeoutMs), SyscallSucceedsWithValue(1));
  struct sockaddr_in peer = {};
  socklen_t peer_len = sizeof(peer);
  FileDescriptor conn = ASSERT_NO_ERRNO_AND_VALUE(
      Accept(listener.get(), AsSockAddr(&peer), &peer_len));
  EXPECT_EQ(peer.sin_addr.s_addr, kSNATAddr);
  EXPECT_EQ(ntohs(peer.sin_port), kSNATPort);
}

// Checks that the reply to a datagram DNATed by a nat OUTPUT rule is
// delivered with its source rewritten back to the original destination.
TEST_F(IPTablesNATTunTest, OutputDNATUDPReply) {
  ASSERT_NO_ERRNO(ReplaceNATTable({.hook = NF_INET_LOCAL_OUT,
                                   .target = "DNAT",
                                   .protocol = IPPROTO_UDP,
                                   .src = INADDR_ANY,
                                   .dst = kVIPAddr,
                                   .to_addr = kPeerAddr,
                                   .to_port = kPeerPort}));
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  struct sockaddr_in vip = {.sin_family = AF_INET,
                            .sin_port = htons(kVIPPort),
                            .sin_addr = {.s_addr = kVIPAddr}};
  constexpr absl::string_view kRequest = "request";
  ASSERT_THAT(sendto(sock.get(), kRequest.data(), kRequest.size(), 0,
                     AsSockAddr(&vip), sizeof(vip)),
              SyscallSucceedsWithValue(kRequest.size()));

  std::vector<char> out = ASSERT_NO_ERRNO_AND_VALUE(
      ReadIPv4Packet(tun_.get(), IPPROTO_UDP, kPeerAddr));
  const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(out.data());
  ASSERT_EQ(out.size(), ip->ihl * 4 + sizeof(struct udphdr) + kRequest.size());
  const struct udphdr* udp =
      reinterpret_cast<const struct udphdr*>(out.data() + ip->ihl * 4);
  EXPECT_EQ(ntohs(udp->dest), kPeerPort);

  constexpr absl::string_view kReply = "reply";
  std::vector<char> reply =
      UDPPacket(kPeerAddr, kPeerPort, ip->saddr, ntohs(udp->source), kReply);
  ASSERT_THAT(write(tun_.get(), reply.data(), reply.size()),
              SyscallSucceedsWithValue(reply.size()));

  struct sockaddr_in peer = {};
  EXPECT_THAT(RecvFrom(sock.get(), &peer),
              IsPosixErrorOkAndHolds(std::string(kReply)));
  EXPECT_EQ(peer.sin_addr.s_addr, kVIPAddr);
  EXPECT_EQ(ntohs(peer.sin_port), kVIPPort);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
