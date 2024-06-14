// Copyright 2024 The gVisor Authors.
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

// mmap tests that often take longer than 900s to run and thus may be skipped
// by test automation.

#include <stddef.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Tests that when using one entry per page table leaf page at a time, page
// table pages that become empty do not accumulate.
TEST(MmapEternalTest, PageTableLeak) {
  // Skip this test on platforms where app page tables are managed as for
  // ordinary processes by the host kernel, both because there's relatively
  // little value in exercising this behavior (separately from
  // Platform::kNative) and because MM can be slow enough on such platforms to
  // cause the test to time out.
  SKIP_IF(GvisorPlatform() == Platform::kPtrace ||
          GvisorPlatform() == Platform::kSystrap);

  // Guess how much virtual address space we need.
  constexpr size_t kMemoryLimitBytes = 12L << 30;
  const size_t kMemoryLimitPages = kMemoryLimitBytes / kPageSize;
  const size_t kEntriesPerPageTablePage = kPageSize / sizeof(void*);
  const size_t kMemoryPerPageTableLeafPage =
      kPageSize * kEntriesPerPageTablePage;
  const size_t kMemorySizeBytes =
      kMemoryLimitPages * kMemoryPerPageTableLeafPage;

  // Reserve virtual address space.
  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kMemorySizeBytes, PROT_NONE, MAP_PRIVATE));

  // Map and unmap one page at a time. This uses a subprocess since the
  // existence of our reservation VMA interferes with page table freeing;
  // forking ensures that there are no other threads in the subprocess,
  // allowing us to safely unmap the reservation.
  const DisableSave ds;
  const auto rest = [&] {
    char* ptr = static_cast<char*>(m.ptr());
    char const* const end = static_cast<char*>(m.endptr());
    m.reset();
    while (ptr < end) {
      TEST_PCHECK(
          MmapSafe(ptr, kPageSize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1,
                   0) == ptr);
      TEST_PCHECK(MunmapSafe(ptr, kPageSize) == 0);
      ptr += kMemoryPerPageTableLeafPage;
    }
  };

  // The test passes if this does not result in an OOM kill (of the subprocess
  // or the sandbox).
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
