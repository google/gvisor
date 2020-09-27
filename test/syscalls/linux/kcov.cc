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

#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// For this test to work properly, it must be run with coverage enabled. On
// native Linux, this involves compiling the kernel with kcov enabled. For
// gVisor, we need to enable the Go coverage tool, e.g.
// bazel test --collect_coverage_data --instrumentation_filter=//pkg/... <test>.
TEST(KcovTest, Kcov) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  constexpr int kSize = 4096;
  constexpr int KCOV_INIT_TRACE = 0x80086301;
  constexpr int KCOV_ENABLE = 0x6364;
  constexpr int KCOV_DISABLE = 0x6365;

  int fd;
  ASSERT_THAT(fd = open("/sys/kernel/debug/kcov", O_RDWR),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));

  // Kcov not available.
  SKIP_IF(errno == ENOENT);

  ASSERT_THAT(ioctl(fd, KCOV_INIT_TRACE, kSize), SyscallSucceeds());
  uint64_t* area = (uint64_t*)mmap(nullptr, kSize * sizeof(uint64_t),
                                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  ASSERT_TRUE(area != MAP_FAILED);
  ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallSucceeds());

  for (int i = 0; i < 10; i++) {
    // Make some syscalls to generate coverage data.
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallFailsWithErrno(EINVAL));
  }

  uint64_t num_pcs = *(uint64_t*)(area);
  EXPECT_GT(num_pcs, 0);
  for (uint64_t i = 1; i <= num_pcs; i++) {
    // Verify that PCs are in the standard kernel range.
    EXPECT_GT(area[i], 0xffffffff7fffffffL);
  }

  ASSERT_THAT(ioctl(fd, KCOV_DISABLE, 0), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
