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

#include <sys/mman.h>

#include <map>

#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::absl::StrFormat;

// AnonUsageFromMeminfo scrapes the current anonymous memory usage from
// /proc/meminfo and returns it in bytes.
PosixErrorOr<uint64_t> AnonUsageFromMeminfo() {
  ASSIGN_OR_RETURN_ERRNO(auto meminfo, GetContents("/proc/meminfo"));
  std::vector<std::string> lines(absl::StrSplit(meminfo, '\n'));

  // Try to find AnonPages line, the format is AnonPages:\\s+(\\d+) kB\n.
  for (const auto& line : lines) {
    if (!absl::StartsWith(line, "AnonPages:")) {
      continue;
    }

    std::vector<std::string> parts(
        absl::StrSplit(line, ' ', absl::SkipEmpty()));
    if (parts.size() == 3) {
      // The size is the second field, let's try to parse it as a number.
      ASSIGN_OR_RETURN_ERRNO(auto anon_kb, Atoi<uint64_t>(parts[1]));
      return anon_kb * 1024;
    }

    return PosixError(EINVAL, "AnonPages field in /proc/meminfo was malformed");
  }

  return PosixError(EINVAL, "AnonPages field not found in /proc/meminfo");
}

TEST(MemoryAccounting, AnonAccountingPreservedOnSaveRestore) {
  // This test isn't meaningful on Linux. /proc/meminfo reports system-wide
  // memory usage, which can change arbitrarily in Linux from other activity on
  // the machine. In gvisor, this test is the only thing running on the
  // "machine", so values in /proc/meminfo accurately reflect the memory used by
  // the test.
  SKIP_IF(!IsRunningOnGvisor());

  uint64_t anon_initial = ASSERT_NO_ERRNO_AND_VALUE(AnonUsageFromMeminfo());

  // Cause some anonymous memory usage.
  uint64_t map_bytes = Megabytes(512);
  char* mem =
      static_cast<char*>(mmap(nullptr, map_bytes, PROT_READ | PROT_WRITE,
                              MAP_POPULATE | MAP_ANON | MAP_PRIVATE, -1, 0));
  ASSERT_NE(mem, MAP_FAILED)
      << "Map failed, errno: " << errno << " (" << strerror(errno) << ").";

  // Write something to each page to prevent them from being decommited on
  // S/R. Zero pages are dropped on save.
  for (uint64_t i = 0; i < map_bytes; i += kPageSize) {
    mem[i] = 'a';
  }

  uint64_t anon_after_alloc = ASSERT_NO_ERRNO_AND_VALUE(AnonUsageFromMeminfo());
  EXPECT_THAT(anon_after_alloc,
              EquivalentWithin(anon_initial + map_bytes, 0.03));

  // We have many implicit S/R cycles from scraping /proc/meminfo throughout the
  // test, but throw an explicit S/R in here as well.
  MaybeSave();

  // Usage should remain the same across S/R.
  uint64_t anon_after_sr = ASSERT_NO_ERRNO_AND_VALUE(AnonUsageFromMeminfo());
  EXPECT_THAT(anon_after_sr, EquivalentWithin(anon_after_alloc, 0.03));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
