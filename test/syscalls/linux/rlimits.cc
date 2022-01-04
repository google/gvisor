// Copyright 2018 The gVisor Authors.
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
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>

#include "test/util/capability_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(RlimitTest, SetRlimitHigher) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));

  struct rlimit rl = {};
  EXPECT_THAT(getrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  // Lower the rlimit first, as it may be equal to /proc/sys/fs/nr_open, in
  // which case even users with CAP_SYS_RESOURCE can't raise it.
  rl.rlim_cur--;
  rl.rlim_max--;
  ASSERT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  rl.rlim_max++;
  EXPECT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());
}

TEST(RlimitTest, UnprivilegedSetRlimit) {
  // Drop privileges if necessary.
  AutoCapability cap(CAP_SYS_RESOURCE, false);

  struct rlimit rl = {};
  rl.rlim_cur = 1000;
  rl.rlim_max = 20000;
  EXPECT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  struct rlimit rl2 = {};
  EXPECT_THAT(getrlimit(RLIMIT_NOFILE, &rl2), SyscallSucceeds());
  EXPECT_EQ(rl.rlim_cur, rl2.rlim_cur);
  EXPECT_EQ(rl.rlim_max, rl2.rlim_max);

  rl.rlim_max = 100000;
  EXPECT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallFailsWithErrno(EPERM));
}

TEST(RlimitTest, SetSoftRlimitAboveHard) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));

  struct rlimit rl = {};
  EXPECT_THAT(getrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  rl.rlim_cur = rl.rlim_max + 1;
  EXPECT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallFailsWithErrno(EINVAL));
}

TEST(RlimitTest, RlimitNProc) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // The native test can be run in a user namespace without a mapping for
  // kNobody or there can be other processes that are running from the kNobody
  // user.
  SKIP_IF(!IsRunningOnGvisor());

  // Run the test in a sub-thread to avoid changing UID of the current thread.
  ScopedThread([&] {
    constexpr int kNobody = 65534;
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());

    struct rlimit rl = {};
    EXPECT_THAT(getrlimit(RLIMIT_NPROC, &rl), SyscallSucceeds());

    constexpr int kNProc = 10;
    rl.rlim_cur = kNProc;
    EXPECT_THAT(setrlimit(RLIMIT_NPROC, &rl), SyscallSucceeds());

    constexpr int kIterations = 2;
    // Run test actions a few times to check that processes are not leaked.
    for (int iter = 0; iter < kIterations; iter++) {
      pid_t pids[kNProc];
      for (int i = 0; i < kNProc; i++) {
        pid_t pid = fork();
        if (pid == 0) {
          while (1) {
            sleep(1);
          }
          _exit(1);
        }
        EXPECT_THAT(pid, SyscallSucceeds());
        pids[i] = pid;
      }
      auto cleanup = Cleanup([pids] {
        for (int i = 0; i < kNProc; i++) {
          if (pids[i] < 0) {
            continue;
          }
          EXPECT_THAT(kill(pids[i], SIGKILL), SyscallSucceeds());
          EXPECT_THAT(waitpid(pids[i], nullptr, 0), SyscallSucceeds());
        }
      });
      pid_t pid = fork();
      if (pid == 0) {
        _exit(1);
      }
      EXPECT_THAT(pid, SyscallFailsWithErrno(EAGAIN));
    }
  }).Join();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
