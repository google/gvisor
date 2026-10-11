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
#include <linux/capability.h>
#include <unistd.h>

#include <cstdint>
#include <limits>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr char kMaxKeysPath[] = "/proc/sys/kernel/keys/maxkeys";

TEST(ProcSysKernelKeysMax, Exists) {
  const std::string maxkeys =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kMaxKeysPath));
  int32_t value;
  ASSERT_TRUE(absl::SimpleAtoi(maxkeys, &value));
  EXPECT_GT(value, 0);
  if (IsRunningOnGvisor()) {
    // Each sandbox initializes its own limit; Linux's host policy may differ.
    EXPECT_EQ(value, 200);
  }
}

// Returns true if the caller can write to /proc/sys/kernel/keys/maxkeys. On
// Linux, sysctl file permissions ignore capabilities and only allow the global
// root user to write to this file (see test_perm() in fs/proc/proc_sysctl.c).
PosixErrorOr<bool> CanSetMaxKeys() {
  ASSIGN_OR_RETURN_ERRNO(bool have_sys_admin, HaveCapability(CAP_SYS_ADMIN));
  ASSIGN_OR_RETURN_ERRNO(bool in_init_userns, InInitialUserNamespace());
  return have_sys_admin && in_init_userns && geteuid() == 0;
}

TEST(ProcSysKernelKeysMax, InvalidMaxKeysValue) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanSetMaxKeys()));
  const std::string before =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kMaxKeysPath));
  auto cleanup = Cleanup([before] {
    EXPECT_NO_ERRNO(SetContents(kMaxKeysPath, before));
    EXPECT_THAT(GetContents(kMaxKeysPath), IsPosixErrorOkAndHolds(before));
  });
  ASSERT_THAT(SetContents(kMaxKeysPath, "-1"), PosixErrorIs(EINVAL));
  EXPECT_THAT(GetContents(kMaxKeysPath), IsPosixErrorOkAndHolds(before));
}

TEST(ProcSysKernelKeysMax, SetMaxKeys) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanSetMaxKeys()));
  const std::string before =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kMaxKeysPath));
  int32_t value;
  ASSERT_TRUE(absl::SimpleAtoi(before, &value));
  ASSERT_GT(value, 0);
  auto cleanup = Cleanup([before] {
    EXPECT_NO_ERRNO(SetContents(kMaxKeysPath, before));
    EXPECT_THAT(GetContents(kMaxKeysPath), IsPosixErrorOkAndHolds(before));
  });
  // Change the limit even when the host already uses a nondefault policy.
  const int32_t updated =
      value == std::numeric_limits<int32_t>::max() ? value - 1 : value + 1;
  ASSERT_NO_ERRNO(SetContents(kMaxKeysPath, absl::StrCat(updated)));
  const std::string maxkeys =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents(kMaxKeysPath));
  int32_t actual;
  ASSERT_TRUE(absl::SimpleAtoi(maxkeys, &actual));
  EXPECT_EQ(actual, updated);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
