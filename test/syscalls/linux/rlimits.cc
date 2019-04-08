// Copyright 2018 Google LLC
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

#include <sys/resource.h>
#include <sys/time.h>

#include "test/util/capability_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(RlimitTest, SetRlimitHigher) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE)));
  SKIP_IF(!IsRunningOnGvisor());

  struct rlimit rl = {};
  EXPECT_THAT(getrlimit(RLIMIT_NOFILE, &rl), SyscallSucceeds());

  // TODO: Even with CAP_SYS_RESOURCE, gVisor does not allow
  // setting a higher rlimit.
  rl.rlim_max++;
  EXPECT_THAT(setrlimit(RLIMIT_NOFILE, &rl), SyscallFailsWithErrno(EPERM));
}

TEST(RlimitTest, UnprivilegedSetRlimit) {
  // Drop privileges if necessary.
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_RESOURCE))) {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_RESOURCE, false));
  }

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

}  // namespace

}  // namespace testing
}  // namespace gvisor
