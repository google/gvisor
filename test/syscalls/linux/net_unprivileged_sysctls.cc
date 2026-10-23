// Copyright 2026 The gVisor Authors.
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

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <sched.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <functional>
#include <string>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr char kPortStart[] = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
constexpr char kPingRange[] = "/proc/sys/net/ipv4/ping_group_range";
constexpr char kLocalRange[] = "/proc/sys/net/ipv4/ip_local_port_range";

// Returns 0, or the errno of writing val to path. Async-signal-safe.
int WriteSysctl(const char* path, const char* val) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    return errno;
  }
  int ret = 0;
  if (write(fd, val, strlen(val)) < 0) {
    ret = errno;
  }
  close(fd);
  return ret;
}

// Returns whether the contents of path equal want. Async-signal-safe.
bool SysctlIs(const char* path, const char* want) {
  char buf[64] = {};
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return false;
  }
  int n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  return n >= 0 && strcmp(buf, want) == 0;
}

// Returns 0, or the errno of binding a new socket to port on the wildcard
// address. Async-signal-safe.
int Bind(int family, int type, int protocol, uint16_t port) {
  int fd = socket(family, type, protocol);
  if (fd < 0) {
    return errno;
  }
  struct sockaddr_storage addr = {};
  socklen_t len;
  if (family == AF_INET) {
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&addr);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    sin->sin_port = htons(port);
    len = sizeof(*sin);
  } else {
    auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = in6addr_any;
    sin6->sin6_port = htons(port);
    len = sizeof(*sin6);
  }
  int ret = 0;
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), len) < 0) {
    ret = errno;
  }
  close(fd);
  return ret;
}

int IcmpProtocol(int family) {
  return family == AF_INET ? static_cast<int>(IPPROTO_ICMP)
                           : static_cast<int>(IPPROTO_ICMPV6);
}

// Returns 0, or the errno of creating an ICMP or ICMPv6 datagram socket.
// Async-signal-safe.
int PingSocket(int family) {
  int fd = socket(family, SOCK_DGRAM, IcmpProtocol(family));
  if (fd < 0) {
    return errno;
  }
  close(fd);
  return 0;
}

// The tests change per network namespace sysctls. Natively they run in a fresh
// network namespace so the host's values are untouched. Tests that use Run run
// under gVisor in the test's own network namespace, because
// ip_local_port_range only reaches the root network namespace
// (gvisor.dev/issue/1833), and the values are restored afterwards.
class UnprivilegedNetSysctlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Writing the sysctls requires root; unshare(CLONE_NEWNET) requires
    // CAP_SYS_ADMIN.
    SKIP_IF(geteuid() != 0);
    SKIP_IF(!IsRunningOnGvisor() &&
            !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_BIND_SERVICE)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    ipv6_ = fd >= 0;
    if (fd >= 0) {
      close(fd);
    }

    if (IsRunningOnGvisor()) {
      port_start_ = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kPortStart));
      local_range_ = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kLocalRange));
      ping_range_ = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kPingRange));
      restore_ = true;
    }
  }

  void TearDown() override {
    if (!restore_) {
      return;
    }
    // A start of 0 is valid with any local port range.
    EXPECT_NO_ERRNO(SetContents(kPortStart, "0"));
    EXPECT_NO_ERRNO(SetContents(kLocalRange, local_range_));
    EXPECT_NO_ERRNO(SetContents(kPortStart, port_start_));
    EXPECT_NO_ERRNO(SetContents(kPingRange, ping_range_));
  }

  // Runs fn in a child process, in a fresh network namespace natively.
  void Run(const std::function<void()>& fn) {
    const bool native = !IsRunningOnGvisor();
    EXPECT_THAT(InForkedProcess([&] {
                  if (native) {
                    TEST_CHECK_SUCCESS(unshare(CLONE_NEWNET));
                  }
                  fn();
                }),
                IsPosixErrorOkAndHolds(0));
  }

  // Runs fn in a child process in a fresh network namespace.
  void RunInNewNetns(const std::function<void()>& fn) {
    // A restore gives child network namespaces new network stacks.
    const DisableSave ds;
    EXPECT_THAT(InForkedProcess([&] {
                  TEST_CHECK_SUCCESS(unshare(CLONE_NEWNET));
                  fn();
                }),
                IsPosixErrorOkAndHolds(0));
  }

  bool ipv6_ = false;

 private:
  bool restore_ = false;
  std::string port_start_;
  std::string local_range_;
  std::string ping_range_;
};

// A fresh network namespace starts with Linux's defaults.
TEST_F(UnprivilegedNetSysctlTest, Defaults) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewNetns([] {
    TEST_CHECK(SysctlIs(kPortStart, "1024\n"));
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));
  });
}

TEST_F(UnprivilegedNetSysctlTest, BindBelowStartNeedsCapability) {
  const bool ipv6 = ipv6_;
  Run([ipv6] {
    TEST_CHECK(WriteSysctl(kPortStart, "1024") == 0);
    TEST_CHECK(SysctlIs(kPortStart, "1024\n"));
    // Ping sockets bind without the capability check, so allow them for
    // root's group.
    TEST_CHECK(WriteSysctl(kPingRange, "0 0") == 0);

    const int families[] = {AF_INET, AF_INET6};
    for (int family : families) {
      if (family == AF_INET6 && !ipv6) {
        continue;
      }
      TEST_CHECK(Bind(family, SOCK_STREAM, 0, 80) == 0);
      TEST_CHECK(Bind(family, SOCK_DGRAM, 0, 80) == 0);
    }

    TEST_CHECK_NO_ERRNO(SetCapability(CAP_NET_BIND_SERVICE, false));
    for (int family : families) {
      if (family == AF_INET6 && !ipv6) {
        continue;
      }
      TEST_CHECK(Bind(family, SOCK_STREAM, 0, 80) == EACCES);
      TEST_CHECK(Bind(family, SOCK_DGRAM, 0, 80) == EACCES);
      TEST_CHECK(Bind(family, SOCK_STREAM, 0, 1023) == EACCES);
      TEST_CHECK(Bind(family, SOCK_STREAM, 0, 1024) == 0);
      TEST_CHECK(Bind(family, SOCK_DGRAM, 0, 1024) == 0);
      // Port 0 picks an ephemeral port.
      TEST_CHECK(Bind(family, SOCK_STREAM, 0, 0) == 0);
      TEST_CHECK(Bind(family, SOCK_DGRAM, 0, 0) == 0);
      TEST_CHECK(Bind(family, SOCK_DGRAM, IcmpProtocol(family), 80) == 0);
    }

    // Moving the start takes effect for later binds.
    TEST_CHECK(WriteSysctl(kPortStart, "81") == 0);
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 80) == EACCES);
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 81) == 0);
    TEST_CHECK(WriteSysctl(kPortStart, "0") == 0);
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 80) == 0);
    TEST_CHECK(Bind(AF_INET, SOCK_DGRAM, 0, 80) == 0);
    if (ipv6) {
      TEST_CHECK(Bind(AF_INET6, SOCK_STREAM, 0, 80) == 0);
      TEST_CHECK(Bind(AF_INET6, SOCK_DGRAM, 0, 80) == 0);
    }
  });
}

TEST_F(UnprivilegedNetSysctlTest, PortStartValidation) {
  Run([] {
    TEST_CHECK(WriteSysctl(kLocalRange, "32768 60999") == 0);
    TEST_CHECK(WriteSysctl(kPortStart, "65536") == EINVAL);
    TEST_CHECK(WriteSysctl(kPortStart, "-1") == EINVAL);
    TEST_CHECK(WriteSysctl(kPortStart, "1024") == 0);

    // The start may not exceed the low end of the local port range.
    TEST_CHECK(WriteSysctl(kPortStart, "32769") == EINVAL);
    TEST_CHECK(SysctlIs(kPortStart, "1024\n"));
    TEST_CHECK(WriteSysctl(kPortStart, "32768") == 0);
    TEST_CHECK(SysctlIs(kPortStart, "32768\n"));

    // In turn, the local port range may not start below it.
    TEST_CHECK(WriteSysctl(kLocalRange, "32767 60999") == EINVAL);
    TEST_CHECK(WriteSysctl(kLocalRange, "32768 60999") == 0);
    TEST_CHECK(WriteSysctl(kPortStart, "1024") == 0);
    TEST_CHECK(WriteSysctl(kLocalRange, "32767 60999") == 0);
    TEST_CHECK(WriteSysctl(kLocalRange, "32768 60999") == 0);
  });
}

TEST_F(UnprivilegedNetSysctlTest, PingGroupRange) {
  const bool ipv6 = ipv6_;
  Run([ipv6] {
    constexpr gid_t kSupplementary = 4242;
    const gid_t groups[] = {kSupplementary};
    TEST_CHECK_SUCCESS(setgroups(1, groups));
    TEST_CHECK(getegid() == 0);

    // An empty range refuses everyone, root included.
    TEST_CHECK(WriteSysctl(kPingRange, "1 0") == 0);
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));
    TEST_CHECK(PingSocket(AF_INET) == EACCES);
    if (ipv6) {
      TEST_CHECK(PingSocket(AF_INET6) == EACCES);
    }

    // The effective GID is in range.
    TEST_CHECK(WriteSysctl(kPingRange, "0 0") == 0);
    TEST_CHECK(SysctlIs(kPingRange, "0\t0\n"));
    TEST_CHECK(PingSocket(AF_INET) == 0);
    if (ipv6) {
      TEST_CHECK(PingSocket(AF_INET6) == 0);
    }

    // A supplementary GID is in range.
    TEST_CHECK(WriteSysctl(kPingRange, "4000 4242") == 0);
    TEST_CHECK(PingSocket(AF_INET) == 0);
    if (ipv6) {
      TEST_CHECK(PingSocket(AF_INET6) == 0);
    }

    // Neither is in range.
    TEST_CHECK(WriteSysctl(kPingRange, "4243 5000") == 0);
    TEST_CHECK(PingSocket(AF_INET) == EACCES);
    if (ipv6) {
      TEST_CHECK(PingSocket(AF_INET6) == EACCES);
    }

    // Writing one value changes only the low end.
    TEST_CHECK(WriteSysctl(kPingRange, "4242") == 0);
    TEST_CHECK(SysctlIs(kPingRange, "4242\t5000\n"));
    TEST_CHECK(PingSocket(AF_INET) == 0);

    // high < low is stored as the empty range "1 0".
    TEST_CHECK(WriteSysctl(kPingRange, "5 3") == 0);
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));

    // Values must be valid GIDs.
    TEST_CHECK(WriteSysctl(kPingRange, "0 4294967295") == EINVAL);
    TEST_CHECK(WriteSysctl(kPingRange, "-1 0") == EINVAL);
    TEST_CHECK(WriteSysctl(kPingRange, "0 x") == EINVAL);
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));
    TEST_CHECK(WriteSysctl(kPingRange, "0 4294967294") == 0);
    TEST_CHECK(SysctlIs(kPingRange, "0\t4294967294\n"));
  });
}

// Each network namespace has its own values. A task sets and reads its own
// namespace's, a file keeps referring to the namespace it was opened in, and
// bind(2) and socket(2) use the values of the socket's namespace.
TEST_F(UnprivilegedNetSysctlTest, PerNetworkNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  RunInNewNetns([] {
    TEST_CHECK(WriteSysctl(kPortStart, "81") == 0);
    TEST_CHECK(WriteSysctl(kPingRange, "1 0") == 0);
    int parent_ns = open("/proc/self/ns/net", O_RDONLY);
    TEST_PCHECK(parent_ns >= 0);
    int parent_start = open(kPortStart, O_WRONLY);
    TEST_PCHECK(parent_start >= 0);

    TEST_CHECK_SUCCESS(unshare(CLONE_NEWNET));
    TEST_CHECK(SysctlIs(kPortStart, "1024\n"));
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));
    TEST_CHECK(WriteSysctl(kPortStart, "0") == 0);
    TEST_CHECK(WriteSysctl(kPingRange, "0 0") == 0);
    TEST_CHECK(SysctlIs(kPortStart, "0\n"));
    TEST_CHECK(SysctlIs(kPingRange, "0\t0\n"));

    // The file opened before unshare(2) still writes the parent's value.
    TEST_PCHECK(write(parent_start, "82", 2) == 2);
    close(parent_start);
    TEST_CHECK(SysctlIs(kPortStart, "0\n"));

    TEST_CHECK_NO_ERRNO(SetCapability(CAP_NET_BIND_SERVICE, false));
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 80) == 0);
    TEST_CHECK(PingSocket(AF_INET) == 0);

    TEST_CHECK_SUCCESS(setns(parent_ns, CLONE_NEWNET));
    close(parent_ns);
    TEST_CHECK(SysctlIs(kPortStart, "82\n"));
    TEST_CHECK(SysctlIs(kPingRange, "1\t0\n"));
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 81) == EACCES);
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 82) == 0);
    TEST_CHECK(PingSocket(AF_INET) == EACCES);
  });
}

// CAP_NET_BIND_SERVICE counts only in the user namespace that owns the
// socket's network namespace, not in the task's own user namespace.
TEST_F(UnprivilegedNetSysctlTest, BindCapabilityInNetnsOwner) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  RunInNewNetns([] {
    TEST_CHECK(WriteSysctl(kPortStart, "1024") == 0);

    // The new user namespace grants every capability, but only in itself.
    TEST_CHECK_SUCCESS(unshare(CLONE_NEWUSER));
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 80) == EACCES);
    TEST_CHECK(Bind(AF_INET, SOCK_DGRAM, 0, 80) == EACCES);
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 1024) == 0);

    // A network namespace it owns honors them.
    TEST_CHECK_SUCCESS(unshare(CLONE_NEWNET));
    TEST_CHECK(SysctlIs(kPortStart, "1024\n"));
    TEST_CHECK(Bind(AF_INET, SOCK_STREAM, 0, 80) == 0);
    TEST_CHECK(Bind(AF_INET, SOCK_DGRAM, 0, 80) == 0);
  });
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
