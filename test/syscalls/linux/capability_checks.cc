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
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
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
  if (IsRunningOnGvisor()) {
    GTEST_SKIP() << "runsc does not permit creating character device nodes";
  }
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
  if (IsRunningOnGvisor()) {
    GTEST_SKIP() << "runsc does not permit creating block device nodes";
  }
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

// Test that sched_setaffinity on another task owned by a different UID
// requires CAP_SYS_NICE. Linux enforces this in
// kernel/sched/core.c:check_same_owner().
//
// We cannot target PID 1 because in gvisor the test process and PID 1
// typically share UID 0. The UID match would bypass the capability check,
// making the test always pass. Instead, we fork a child that changes its
// UID to nobody (65534), then the parent (still root but without
// CAP_SYS_NICE) attempts sched_setaffinity on the child.
TEST(SchedSetaffinityCapTest, OtherUidRequiresCapSysNice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));
  // Need CAP_SETUID to change the child's UID.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // Two pipes for synchronization:
  // - child_ready: child signals parent after changing UID
  // - parent_done: parent signals child to exit after testing
  int child_ready[2];
  int parent_done[2];
  ASSERT_THAT(pipe(child_ready), SyscallSucceeds());
  ASSERT_THAT(pipe(parent_done), SyscallSucceeds());

  pid_t child = fork();
  ASSERT_THAT(child, SyscallSucceeds());

  if (child == 0) {
    close(child_ready[0]);
    close(parent_done[1]);
    // Change to nobody UID.
    if (setresuid(65534, 65534, 65534) != 0) {
      _exit(1);
    }
    // Signal parent that we're ready.
    char ready = 'r';
    write(child_ready[1], &ready, 1);
    close(child_ready[1]);
    // Wait until parent is done.
    char buf;
    read(parent_done[0], &buf, 1);
    close(parent_done[0]);
    _exit(0);
  }

  close(child_ready[1]);
  close(parent_done[0]);

  // Wait for the child to change UID.
  char ready;
  ASSERT_THAT(read(child_ready[0], &ready, 1),
              SyscallSucceedsWithValue(1));
  close(child_ready[0]);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);

  // With CAP_SYS_NICE: should succeed on a different-UID process.
  EXPECT_THAT(sched_setaffinity(child, sizeof(mask), &mask),
              SyscallSucceeds());

  // Drop CAP_SYS_NICE: should fail with EPERM (different UID, no cap).
  AutoCapability cap(CAP_SYS_NICE, false);
  EXPECT_THAT(sched_setaffinity(child, sizeof(mask), &mask),
              SyscallFailsWithErrno(EPERM));

  // Clean up child.
  close(parent_done[1]);
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceeds());
}

// Test that setpriority on another task owned by a different UID requires
// CAP_SYS_NICE. Linux enforces this in kernel/sys.c:set_one_prio().
//
// Same approach as above: fork a child with a different UID.
TEST(SetpriorityCapTest, OtherUidRequiresCapSysNice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_NICE)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  int child_ready[2];
  int parent_done[2];
  ASSERT_THAT(pipe(child_ready), SyscallSucceeds());
  ASSERT_THAT(pipe(parent_done), SyscallSucceeds());

  pid_t child = fork();
  ASSERT_THAT(child, SyscallSucceeds());

  if (child == 0) {
    close(child_ready[0]);
    close(parent_done[1]);
    if (setresuid(65534, 65534, 65534) != 0) {
      _exit(1);
    }
    char ready = 'r';
    write(child_ready[1], &ready, 1);
    close(child_ready[1]);
    char buf;
    read(parent_done[0], &buf, 1);
    close(parent_done[0]);
    _exit(0);
  }

  close(child_ready[1]);
  close(parent_done[0]);

  char ready;
  ASSERT_THAT(read(child_ready[0], &ready, 1),
              SyscallSucceedsWithValue(1));
  close(child_ready[0]);

  // With CAP_SYS_NICE: should succeed.
  EXPECT_THAT(setpriority(PRIO_PROCESS, child, 0), SyscallSucceeds());

  // Drop CAP_SYS_NICE: should fail with EPERM.
  AutoCapability cap(CAP_SYS_NICE, false);
  EXPECT_THAT(setpriority(PRIO_PROCESS, child, 0),
              SyscallFailsWithErrno(EPERM));

  close(parent_done[1]);
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceeds());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
