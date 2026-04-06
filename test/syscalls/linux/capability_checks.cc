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

// Tests for missing capability checks that were added to match Linux behavior.

#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_main.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

// Test that SO_BINDTODEVICE requires CAP_NET_RAW.
// Linux enforces this in net/core/sock.c:sock_setsockopt().
TEST(SoBindToDeviceCapTest, RequiresCapNetRaw) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int fd;
  ASSERT_THAT(fd = socket(AF_INET, SOCK_STREAM, 0), SyscallSucceeds());
  FileDescriptor sock(fd);

  // With CAP_NET_RAW: should succeed (or ENODEV if "lo" is not found).
  const std::string dev = "lo";
  int ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev.c_str(),
                       dev.size() + 1);
  // Accept either success or ENODEV (device not found in some configs).
  if (ret != 0) {
    EXPECT_EQ(errno, ENODEV);
  }

  // Drop CAP_NET_RAW: should fail with EPERM.
  AutoCapability cap(CAP_NET_RAW, false);
  EXPECT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev.c_str(),
                         dev.size() + 1),
              SyscallFailsWithErrno(EPERM));
}

// Test that mknod(S_IFCHR) requires CAP_MKNOD.
// Linux enforces this in fs/namei.c:vfs_mknod().
TEST(MknodCapTest, CharDevRequiresCapMknod) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_MKNOD)));

  auto path = NewTempAbsPath();

  // With CAP_MKNOD: should succeed.
  ASSERT_THAT(mknod(path.c_str(), S_IFCHR | 0666, makedev(1, 3)),
              SyscallSucceeds());
  ASSERT_THAT(unlink(path.c_str()), SyscallSucceeds());

  // Drop CAP_MKNOD: should fail with EPERM.
  AutoCapability cap(CAP_MKNOD, false);
  EXPECT_THAT(mknod(path.c_str(), S_IFCHR | 0666, makedev(1, 3)),
              SyscallFailsWithErrno(EPERM));
}

// Test that mknod(S_IFBLK) requires CAP_MKNOD.
TEST(MknodCapTest, BlockDevRequiresCapMknod) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_MKNOD)));

  auto path = NewTempAbsPath();

  // With CAP_MKNOD: should succeed.
  ASSERT_THAT(mknod(path.c_str(), S_IFBLK | 0666, makedev(7, 0)),
              SyscallSucceeds());
  ASSERT_THAT(unlink(path.c_str()), SyscallSucceeds());

  // Drop CAP_MKNOD: should fail with EPERM.
  AutoCapability cap(CAP_MKNOD, false);
  EXPECT_THAT(mknod(path.c_str(), S_IFBLK | 0666, makedev(7, 0)),
              SyscallFailsWithErrno(EPERM));
}

// Test that mknod(S_IFIFO) does NOT require CAP_MKNOD.
TEST(MknodCapTest, FifoDoesNotRequireCapMknod) {
  auto path = NewTempAbsPath();
  AutoCapability cap(CAP_MKNOD, false);
  EXPECT_THAT(mknod(path.c_str(), S_IFIFO | 0666, 0), SyscallSucceeds());
  EXPECT_THAT(unlink(path.c_str()), SyscallSucceeds());
}

// Test that writing to /proc/sys/net/ipv4/tcp_sack requires CAP_NET_ADMIN.
// Linux enforces this in net/sysctl_net.c:net_ctl_permissions().
TEST(ProcSysCapTest, TcpSackRequiresCapNetAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Read current value first.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc/sys/net/ipv4/tcp_sack", O_RDWR));
  char buf;
  ASSERT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  // With CAP_NET_ADMIN: write should succeed.
  char val = buf;
  EXPECT_THAT(PwriteFd(fd.get(), &val, sizeof(val), 0),
              SyscallSucceedsWithValue(sizeof(val)));

  // Drop CAP_NET_ADMIN: write should fail with EPERM.
  AutoCapability cap(CAP_NET_ADMIN, false);
  EXPECT_THAT(PwriteFd(fd.get(), &val, sizeof(val), 0),
              SyscallFailsWithErrno(EPERM));
}

// Test that writing to /proc/sys/net/ipv4/ip_local_port_range requires
// CAP_NET_ADMIN.
TEST(ProcSysCapTest, IpLocalPortRangeRequiresCapNetAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc/sys/net/ipv4/ip_local_port_range", O_RDWR));

  // Read current value.
  char buf[64] = {};
  int n = read(fd.get(), buf, sizeof(buf) - 1);
  ASSERT_GT(n, 0);

  // With CAP_NET_ADMIN: write should succeed.
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(fd.get(), buf, n), SyscallSucceedsWithValue(n));

  // Drop CAP_NET_ADMIN: write should fail with EPERM.
  AutoCapability cap(CAP_NET_ADMIN, false);
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(fd.get(), buf, n), SyscallFailsWithErrno(EPERM));
}

// Test that writing to /proc/sys/fs/nr_open requires CAP_SYS_ADMIN.
// Linux enforces this in the root sysctl table via sysctl_perm().
TEST(ProcSysCapTest, NrOpenRequiresCapSysAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc/sys/fs/nr_open", O_RDWR));

  // Read current value.
  char buf[32] = {};
  int n = read(fd.get(), buf, sizeof(buf) - 1);
  ASSERT_GT(n, 0);

  // With CAP_SYS_ADMIN: write should succeed.
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(fd.get(), buf, n), SyscallSucceedsWithValue(n));

  // Drop CAP_SYS_ADMIN: write should fail with EPERM.
  AutoCapability cap(CAP_SYS_ADMIN, false);
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(fd.get(), buf, n), SyscallFailsWithErrno(EPERM));
}

// Test that sched_setaffinity on another task requires UID match or
// CAP_SYS_NICE. Linux enforces this in
// kernel/sched/core.c:check_same_owner().
TEST(SchedSetaffinityCapTest, OtherTaskRequiresCapSysNice) {
  // We need another thread to target. Use the init process (pid 1).
  // This test only makes sense if pid 1 exists and we are not pid 1.
  SKIP_IF(getpid() == 1);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);

  // With CAP_SYS_NICE: should succeed (or ESRCH if pid 1 is not visible).
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Drop CAP_SYS_NICE: should fail with EPERM.
  AutoCapability cap(CAP_SYS_NICE, false);
  // Target pid 1 which is owned by root. If we are not root, the UID check
  // also fails, so EPERM is expected.
  EXPECT_THAT(sched_setaffinity(1, sizeof(mask), &mask),
              SyscallFailsWithErrno(EPERM));
}

// Test that setpriority on another task requires UID match or CAP_SYS_NICE.
// Linux enforces this in kernel/sys.c:set_one_prio().
TEST(SetpriorityCapTest, OtherTaskRequiresCapSysNice) {
  SKIP_IF(getpid() == 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));

  // Drop CAP_SYS_NICE: should fail with EPERM.
  AutoCapability cap(CAP_SYS_NICE, false);
  EXPECT_THAT(setpriority(PRIO_PROCESS, 1, 0),
              SyscallFailsWithErrno(EPERM));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
