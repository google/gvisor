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

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
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

using ::testing::AnyOf;

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
  EXPECT_THAT(getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOPROTOOPT));

  ASSERT_THAT(close(sock), SyscallSucceeds());
}

TEST(IPTablesBasic, GetInfoErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info) - 1;
  ASSERT_THAT(getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, GetEntriesErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_get_entries entries = {};
  socklen_t entries_size = sizeof(struct ipt_get_entries) - 1;
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  ASSERT_THAT(
      getsockopt(sock, SOL_IP, IPT_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(EINVAL));
}

TEST(IPTablesBasic, OriginalDstErrors) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET, SOCK_STREAM, 0), SyscallSucceeds());

  // Sockets not affected by NAT should fail to find an original destination.
  struct sockaddr_in addr = {};
  socklen_t addr_len = sizeof(addr);
  EXPECT_THAT(getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, &addr, &addr_len),
              SyscallFailsWithErrno(ENOTCONN));
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

// This tests the initial state of a machine with empty iptables. We don't
// have a guarantee that the iptables are empty when running in native, but we
// can test that gVisor has the same initial state that a newly-booted Linux
// machine would have.
TEST_F(IPTablesTest, InitialState) {
  SKIP_IF(!IsRunningOnGvisor());
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

class GetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {};

TEST_P(GetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*family=*/AF_INET, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& getsockopt_args = *args_or_status;

  // Copy the optval to a new buffer before the current process' getsockopt
  // call.
  std::unique_ptr<char[]> child_optval =
      std::make_unique<char[]>(getsockopt_args.optlen);
  std::memcpy(child_optval.get(), getsockopt_args.optval.get(),
              getsockopt_args.optlen);

  // Validate that the socket creator can successfully getsockopt.
  ASSERT_THAT(getsockopt(getsockopt_args.sock, SOL_IP, getsockopt_args.optname,
                         getsockopt_args.optval.get(), &getsockopt_args.optlen),
              SyscallSucceeds());

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
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    GetSockOpt, GetSockOptRequiresCapNetAdminTest,
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
                snprintf(info->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
                args.optname = IPT_SO_GET_INFO;
                args.optval = std::move(info_buffer);
                args.optlen = sizeof(ipt_getinfo);
                return args;
              }},
         {.test_name = "GetEntries",
          .generate_sockopt_args = [](int sock) -> absl::StatusOr<SockOptArgs> {
            socklen_t get_info_optlen = sizeof(ipt_getinfo);
            ipt_getinfo get_info;
            snprintf(get_info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            EXPECT_THAT(getsockopt(sock, /*level=*/SOL_IP, IPT_SO_GET_INFO,
                                   &get_info, &get_info_optlen),
                        SyscallSucceeds());
            socklen_t get_entries_optlen =
                sizeof(ipt_get_entries) + get_info.size;
            std::unique_ptr<char[]> entries_buffer =
                std::make_unique<char[]>(get_entries_optlen);
            ipt_get_entries* entries =
                reinterpret_cast<ipt_get_entries*>(entries_buffer.get());
            snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
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
              }}}),
    [](const ::testing::TestParamInfo<
        GetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });

class SetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {};

TEST_P(SetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*family=*/AF_INET, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& setsockopt_args = *args_or_status;

  // Validate that the socket creator either succeeds or fails with EINVAL,
  // but not with EPERM.
  ASSERT_THAT(setsockopt(setsockopt_args.sock, /*level=*/SOL_IP,
                         setsockopt_args.optname, setsockopt_args.optval.get(),
                         setsockopt_args.optlen),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EINVAL)));

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
              }}}),
    [](const ::testing::TestParamInfo<
        SetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });
}  // namespace

}  // namespace testing
}  // namespace gvisor
