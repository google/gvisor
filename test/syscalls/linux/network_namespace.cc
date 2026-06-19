// Copyright 2020 The gVisor Authors.
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

#include <fcntl.h>
#include <sys/mount.h>
#include <unistd.h>

#include <cerrno>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(NetworkNamespaceTest, LoopbackExists) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  ScopedThread t([&] {
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));

    // TODO(gvisor.dev/issue/1833): Update this to test that only "lo" exists.
    ASSERT_NE(ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()), 0);
  });
}

// Like Linux, a newly created network namespace starts with its loopback
// interface administratively DOWN. The application is responsible for bringing
// it up, after which it reports IFF_UP.
TEST(NetworkNamespaceTest, LoopbackStartsDown) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  ScopedThread t([&] {
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));

    Link lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
    EXPECT_EQ(lo.flags & IFF_UP, 0u)
        << "loopback should start down in a new network namespace";

    // The application can bring it up, just like on Linux.
    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
    EXPECT_NE(lo.flags & IFF_UP, 0u)
        << "loopback should be up after bringing it up";
  });
}

// Like Linux, the loopback interface of a new network namespace starts with no
// addresses; the kernel assigns 127.0.0.1/8 and ::1/128 when it is brought up.
TEST(NetworkNamespaceTest, LoopbackAddressesAddedOnUp) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  ScopedThread t([&] {
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));

    struct sockaddr_in addr4 = {};
    addr4.sin_family = AF_INET;
    addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct sockaddr_in6 addr6 = {};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;

    // Before the loopback interface is brought up it has no addresses, so
    // binding to a loopback address fails.
    {
      FileDescriptor s4 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s4.get(), AsSockAddr(&addr4), sizeof(addr4)),
                  SyscallFailsWithErrno(EADDRNOTAVAIL));
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallFailsWithErrno(EADDRNOTAVAIL));
    }

    Link lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    // Bringing it up assigns the default loopback addresses, just like Linux, so
    // binding to them now succeeds.
    {
      FileDescriptor s4 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s4.get(), AsSockAddr(&addr4), sizeof(addr4)),
                  SyscallSucceeds());
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallSucceeds());
    }

    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, 0, IFF_UP));

    // Linux removes IPv6 local addresses when an interface goes down, so ::1 is
    // no longer bindable. IPv4 loopback addresses remain assigned.
    {
      FileDescriptor s4 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s4.get(), AsSockAddr(&addr4), sizeof(addr4)),
                  SyscallSucceeds());
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallFailsWithErrno(EADDRNOTAVAIL));
    }

    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    // Bringing loopback up again recreates ::1.
    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallSucceeds());
    }
  });
}

// Like Linux, IPv6 addresses are flushed when an interface goes down. When
// net/ipv6/conf/all/keep_addr_on_down is enabled, permanent global addresses
// instead survive a down/up cycle.
TEST(NetworkNamespaceTest, IPv6KeepAddrOnDown) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  ScopedThread t([&] {
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));

    FileDescriptor nlsk =
        ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

    Link lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    // A permanent global IPv6 address (2001:db8::1) assigned to loopback. It is
    // neither link-local nor loopback, so keep_addr_on_down applies to it.
    struct in6_addr global = {};
    global.s6_addr[0] = 0x20;
    global.s6_addr[1] = 0x01;
    global.s6_addr[2] = 0x0d;
    global.s6_addr[3] = 0xb8;
    global.s6_addr[15] = 0x01;

    struct sockaddr_in6 addr6 = {};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = global;

    // keep_addr_on_down defaults to off: bringing the interface down flushes
    // the global address, and bringing it back up does not restore it.
    ASSERT_NO_ERRNO(LinkAddLocalAddr(nlsk, lo.index, AF_INET6,
                                     /*prefixlen=*/128, &global,
                                     sizeof(global)));
    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallSucceeds());
    }

    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, 0, IFF_UP));
    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallFailsWithErrno(EADDRNOTAVAIL));
    }

    // Enable keep_addr_on_down and re-assign the global address.
    {
      const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
          Open("/proc/sys/net/ipv6/conf/all/keep_addr_on_down", O_WRONLY));
      constexpr char kEnable[] = "1";
      ASSERT_THAT(write(fd.get(), kEnable, sizeof(kEnable) - 1),
                  SyscallSucceedsWithValue(sizeof(kEnable) - 1));
    }

    ASSERT_NO_ERRNO(LinkAddLocalAddr(nlsk, lo.index, AF_INET6,
                                     /*prefixlen=*/128, &global,
                                     sizeof(global)));

    struct sockaddr_in6 loaddr6 = {};
    loaddr6.sin6_family = AF_INET6;
    loaddr6.sin6_addr = in6addr_loopback;

    // Like Linux, keep_addr_on_down does not apply to IPv6 loopback or
    // link-local addresses: ::1 is still removed when the interface goes down.
    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, 0, IFF_UP));
    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&loaddr6), sizeof(loaddr6)),
                  SyscallFailsWithErrno(EADDRNOTAVAIL));
    }

    ASSERT_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));

    // Bringing the interface back up recreates ::1, and the permanent global
    // address survived the down/up cycle because keep_addr_on_down is enabled.
    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&loaddr6), sizeof(loaddr6)),
                  SyscallSucceeds());
    }
    {
      FileDescriptor s6 =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, 0));
      EXPECT_THAT(bind(s6.get(), AsSockAddr(&addr6), sizeof(addr6)),
                  SyscallSucceeds());
    }
  });
}

TEST(NetworkNamespaceTest, Setns) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct stat st;
  uint64_t netns1, netns2, netns3;
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));

  ASSERT_THAT(stat("/proc/thread-self/ns/net", &st), SyscallSucceeds());
  netns1 = st.st_ino;

  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/net", &st), SyscallSucceeds());
  netns2 = st.st_ino;
  EXPECT_NE(netns1, netns2);

  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWNET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/net", &st), SyscallSucceeds());
  netns3 = st.st_ino;
  EXPECT_EQ(netns1, netns3);

  ASSERT_NE(ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()), 0);
}

TEST(NetworkNamespaceTest, BindMount) {
  // TODO(b/267210840): Fix this tests for hostinet.
  SKIP_IF(IsRunningWithHostinet());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(
      mount("/proc/self/ns/net", file.path().c_str(), NULL, MS_BIND, NULL),
      SyscallSucceedsWithValue(0));

  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDONLY));
  ASSERT_THAT(umount2(file.path().c_str(), MNT_DETACH),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWNET), SyscallSucceedsWithValue(0));

  ASSERT_NE(ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()), 0);
}

TEST(NetworkNamespaceTest, CloneNewNetWithCloneNewUserDoesNotNeedCapSysAdmin) {
  AutoCapability cap(CAP_SYS_ADMIN, false);
  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallFailsWithErrno(EPERM));

  // Fork to avoid changing the user namespace of the original test process.
  ASSERT_THAT(
      InForkedProcess([&] {
        // Fails with EPERM because we don't have CAP_SYS_ADMIN.
        TEST_CHECK_ERRNO(syscall(SYS_unshare, CLONE_NEWNET), EPERM);
        // Succeeds because we also requested a new user namespace.
        TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET));
        _exit(0);
      }),
      IsPosixErrorOkAndHolds(0));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
