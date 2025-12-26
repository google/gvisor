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
#include <linux/if_ether.h>
#include <linux/mempolicy.h>
#include <linux/prctl.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(UnshareTest, AllowsZeroFlags) {
  ASSERT_THAT(unshare(0), SyscallSucceeds());
}

TEST(UnshareTest, ThreadFlagFailsIfMultithreaded) {
  absl::Mutex mu;
  bool finished = false;
  ScopedThread t([&] {
    mu.Lock();
    mu.Await(absl::Condition(&finished));
    mu.Unlock();
  });
  ASSERT_THAT(unshare(CLONE_THREAD), SyscallFailsWithErrno(EINVAL));
  mu.Lock();
  finished = true;
  mu.Unlock();
}

struct UnshareCapTestParam {
  const char* name;
  int capability;
  int want_errno;
  int (*operation)();
};

class UnshareCapTest : public ::testing::TestWithParam<UnshareCapTestParam> {};

TEST_P(UnshareCapTest, CaplessSyscallFailsDespiteUnshareNewUser) {
  const auto& param = GetParam();
  AutoCapability cap(param.capability, false);
  int (*syscall_ut)() = param.operation;
  int want_errno = param.want_errno;

  EXPECT_THAT(InForkedProcess([&] {
                TEST_CHECK_ERRNO(syscall_ut(), want_errno);
                // Caps gained by unshare() shouldn't be a way to beat the
                // capability requirements in the init user namespace.
                TEST_CHECK_SUCCESS(syscall(SYS_unshare, CLONE_NEWUSER));
                TEST_CHECK_ERRNO(syscall_ut(), want_errno);
                _exit(0);
              }),
              IsPosixErrorOkAndHolds(0));
}

// Note: The lambda bodies should be async-signal-safe.
INSTANTIATE_TEST_SUITE_P(
    UnshareCapTest, UnshareCapTest,
    ::testing::Values(
        UnshareCapTestParam{
            "PR_SET_MM", CAP_SYS_RESOURCE, EPERM,
            []() -> int { return syscall(SYS_prctl, PR_SET_MM, 0, 0, 0, 0); }},
        UnshareCapTestParam{
            "PivotRoot", CAP_SYS_ADMIN, EPERM,
            []() -> int { return syscall(SYS_pivot_root, ".", "."); }},
        UnshareCapTestParam{"MbindMoveAll", CAP_SYS_NICE, EPERM,
                            []() -> int {
                              return syscall(SYS_mbind, 0, 0, 0, nullptr, 0,
                                             MPOL_MF_MOVE_ALL);
                            }}),
    [](const ::testing::TestParamInfo<UnshareCapTestParam>& info) {
      return info.param.name;
    });

}  // namespace

}  // namespace testing
}  // namespace gvisor
