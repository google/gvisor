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
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

struct KeyQuotaFile {
  const char* name;
  uint32_t linux_default;
};

class ProcSysKernelKeysQuotaTest
    : public ::testing::TestWithParam<KeyQuotaFile> {
 protected:
  std::string Path() const {
    return absl::StrCat("/proc/sys/kernel/keys/", GetParam().name);
  }
};

TEST_P(ProcSysKernelKeysQuotaTest, Exists) {
  const std::string contents = ASSERT_NO_ERRNO_AND_VALUE(GetContents(Path()));
  uint32_t value;
  ASSERT_TRUE(absl::SimpleAtoi(contents, &value)) << contents;
  EXPECT_GT(value, 0);
  EXPECT_LE(value, std::numeric_limits<int32_t>::max());
  if (IsRunningOnGvisor()) {
    // Linux's host policy may differ.
    EXPECT_EQ(value, GetParam().linux_default);
  }
}

// Returns true if the caller can write to the key quota files. On Linux,
// sysctl file permissions ignore capabilities and only allow the global root
// user to write to these files (see test_perm() in fs/proc/proc_sysctl.c).
PosixErrorOr<bool> CanSetKeyQuotas() {
  ASSIGN_OR_RETURN_ERRNO(bool in_init_userns, InInitialUserNamespace());
  return in_init_userns && geteuid() == 0;
}

// The quotas accept values from 1 to INT_MAX (see key_sysctls in
// security/keys/sysctl.c).
TEST_P(ProcSysKernelKeysQuotaTest, InvalidValue) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanSetKeyQuotas()));
  const std::string before = ASSERT_NO_ERRNO_AND_VALUE(GetContents(Path()));
  const Cleanup cleanup([this, before] {
    EXPECT_NO_ERRNO(SetContents(Path(), before));
    EXPECT_THAT(GetContents(Path()), IsPosixErrorOkAndHolds(before));
  });
  for (const char* value : {"0", "-1", "2147483648", "4294967296"}) {
    SCOPED_TRACE(value);
    ASSERT_THAT(SetContents(Path(), value), PosixErrorIs(EINVAL));
    EXPECT_THAT(GetContents(Path()), IsPosixErrorOkAndHolds(before));
  }
}

TEST_P(ProcSysKernelKeysQuotaTest, SetValue) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanSetKeyQuotas()));
  const std::string before = ASSERT_NO_ERRNO_AND_VALUE(GetContents(Path()));
  uint32_t value;
  ASSERT_TRUE(absl::SimpleAtoi(before, &value)) << before;
  const Cleanup cleanup([this, before] {
    EXPECT_NO_ERRNO(SetContents(Path(), before));
    EXPECT_THAT(GetContents(Path()), IsPosixErrorOkAndHolds(before));
  });
  // Raising the limit keeps the host usable even when it is not Linux.
  const uint32_t updated = value == std::numeric_limits<int32_t>::max()
                               ? value - 1
                               : std::numeric_limits<int32_t>::max();
  ASSERT_NO_ERRNO(SetContents(Path(), absl::StrCat(updated)));
  // Checkpoint and restore with the new value set.
  MaybeSave();
  EXPECT_THAT(GetContents(Path()),
              IsPosixErrorOkAndHolds(absl::StrCat(updated, "\n")));
}

// Writing the files needs no capability, only the global root user.
TEST_P(ProcSysKernelKeysQuotaTest, WriteWithoutCapSysAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanSetKeyQuotas()));
  const std::string before = ASSERT_NO_ERRNO_AND_VALUE(GetContents(Path()));
  AutoCapability no_sys_admin(CAP_SYS_ADMIN, false);
  EXPECT_NO_ERRNO(SetContents(Path(), before));
}

INSTANTIATE_TEST_SUITE_P(
    , ProcSysKernelKeysQuotaTest,
    ::testing::Values(KeyQuotaFile{"maxkeys", 200},
                      KeyQuotaFile{"maxbytes", 20000},
                      KeyQuotaFile{"root_maxkeys", 1000000},
                      KeyQuotaFile{"root_maxbytes", 25000000}),
    [](const ::testing::TestParamInfo<KeyQuotaFile>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace testing
}  // namespace gvisor
