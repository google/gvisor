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

#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

// glibc does not provide a prototype for arch_prctl() so declare it here.
extern "C" int arch_prctl(int code, uintptr_t addr);

namespace gvisor {
namespace testing {

namespace {

TEST(ArchPrctlTest, GetSetFS) {
  uintptr_t orig;
  const uintptr_t kNonCanonicalFsbase = 0x4141414142424242;

  // Get the original FS.base and then set it to the same value (this is
  // intentional because FS.base is the TLS pointer so we cannot change it
  // arbitrarily).
  ASSERT_THAT(arch_prctl(ARCH_GET_FS, reinterpret_cast<uintptr_t>(&orig)),
              SyscallSucceeds());
  ASSERT_THAT(arch_prctl(ARCH_SET_FS, orig), SyscallSucceeds());

  // Trying to set FS.base to a non-canonical value should return an error.
  ASSERT_THAT(arch_prctl(ARCH_SET_FS, kNonCanonicalFsbase),
              SyscallFailsWithErrno(EPERM));
}

// Tests that /proc/cpuinfo advertised to the workload has FSGSBASE disabled
// under Systrap, so workloads do not execute WRGSBASE directly.
TEST(ArchPrctlTest, FSGSBaseDisabledInCpuInfo) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);
  std::string cpuinfo;
  ASSERT_NO_ERRNO(GetContents("/proc/cpuinfo", &cpuinfo));
  EXPECT_THAT(cpuinfo,
              ::testing::Not(::testing::ContainsRegex(R"(\bfsgsbase\b)")))
      << "gVisor must not advertise fsgsbase in /proc/cpuinfo under systrap";
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
