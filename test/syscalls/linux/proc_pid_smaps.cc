// Copyright 2019 The gVisor Authors.
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

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/proc_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Contains;
using ::testing::ElementsAreArray;
using ::testing::IsSupersetOf;
using ::testing::Not;
using ::testing::Optional;

namespace gvisor {
namespace testing {

namespace {
TEST(ProcPidSmapsTest, SharedAnon) {
  // Map with MAP_POPULATE so we get some RSS.
  Mapping const m = ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(
      2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE));
  auto const entries = ASSERT_NO_ERRNO_AND_VALUE(ReadProcSelfSmaps());
  auto const entry =
      ASSERT_NO_ERRNO_AND_VALUE(FindUniqueSmapsEntry(entries, m.addr()));

  EXPECT_EQ(entry.size_kb, m.len() / 1024);
  // It's possible that populated pages have been swapped out, so RSS might be
  // less than size.
  EXPECT_LE(entry.rss_kb, entry.size_kb);

  if (entry.pss_kb) {
    // PSS should be exactly equal to RSS since no other address spaces should
    // be sharing our new mapping.
    EXPECT_EQ(entry.pss_kb.value(), entry.rss_kb);
  }

  // "Shared" and "private" in smaps refers to whether or not *physical pages*
  // are shared; thus all pages in our MAP_SHARED mapping should nevertheless
  // be private.
  EXPECT_EQ(entry.shared_clean_kb, 0);
  EXPECT_EQ(entry.shared_dirty_kb, 0);
  EXPECT_EQ(entry.private_clean_kb + entry.private_dirty_kb, entry.rss_kb)
      << "Private_Clean = " << entry.private_clean_kb
      << " kB, Private_Dirty = " << entry.private_dirty_kb << " kB";

  // Shared anonymous mappings are implemented as a shmem file, so their pages
  // are not PageAnon.
  if (entry.anonymous_kb) {
    EXPECT_EQ(entry.anonymous_kb.value(), 0);
  }

  if (entry.vm_flags) {
    EXPECT_THAT(entry.vm_flags.value(),
                IsSupersetOf({"rd", "wr", "sh", "mr", "mw", "me", "ms"}));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("ex")));
  }
}

TEST(ProcPidSmapsTest, PrivateAnon) {
  // Map with MAP_POPULATE so we get some RSS.
  Mapping const m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(2 * kPageSize, PROT_WRITE, MAP_PRIVATE | MAP_POPULATE));
  auto const entries = ASSERT_NO_ERRNO_AND_VALUE(ReadProcSelfSmaps());
  auto const entry =
      ASSERT_NO_ERRNO_AND_VALUE(FindUniqueSmapsEntry(entries, m.addr()));

  // It's possible that our mapping was merged with another vma, so the smaps
  // entry might be bigger than our original mapping.
  EXPECT_GE(entry.size_kb, m.len() / 1024);
  EXPECT_LE(entry.rss_kb, entry.size_kb);
  if (entry.pss_kb) {
    EXPECT_LE(entry.pss_kb.value(), entry.rss_kb);
  }

  if (entry.anonymous_kb) {
    EXPECT_EQ(entry.anonymous_kb.value(), entry.rss_kb);
  }

  if (entry.vm_flags) {
    EXPECT_THAT(entry.vm_flags.value(), IsSupersetOf({"wr", "mr", "mw", "me"}));
    // We passed PROT_WRITE to mmap. On at least x86, the mapping is in
    // practice readable because there is no way to configure the MMU to make
    // pages writable but not readable. However, VmFlags should reflect the
    // flags set on the VMA, so "rd" (VM_READ) should not appear in VmFlags.
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("rd")));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("ex")));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("sh")));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("ms")));
  }
}

TEST(ProcPidSmapsTest, SharedReadOnlyFile) {
  size_t const kFileSize = kPageSize;

  auto const temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(truncate(temp_file.path().c_str(), kFileSize), SyscallSucceeds());
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_RDONLY));

  auto const m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kFileSize, PROT_READ, MAP_SHARED | MAP_POPULATE, fd.get(), 0));
  auto const entries = ASSERT_NO_ERRNO_AND_VALUE(ReadProcSelfSmaps());
  auto const entry =
      ASSERT_NO_ERRNO_AND_VALUE(FindUniqueSmapsEntry(entries, m.addr()));

  // Most of the same logic as the SharedAnon case applies.
  EXPECT_EQ(entry.size_kb, kFileSize / 1024);
  EXPECT_LE(entry.rss_kb, entry.size_kb);
  if (entry.pss_kb) {
    EXPECT_EQ(entry.pss_kb.value(), entry.rss_kb);
  }
  EXPECT_EQ(entry.shared_clean_kb, 0);
  EXPECT_EQ(entry.shared_dirty_kb, 0);
  EXPECT_EQ(entry.private_clean_kb + entry.private_dirty_kb, entry.rss_kb)
      << "Private_Clean = " << entry.private_clean_kb
      << " kB, Private_Dirty = " << entry.private_dirty_kb << " kB";
  if (entry.anonymous_kb) {
    EXPECT_EQ(entry.anonymous_kb.value(), 0);
  }

  if (entry.vm_flags) {
    EXPECT_THAT(entry.vm_flags.value(), IsSupersetOf({"rd", "mr", "me", "ms"}));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("wr")));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("ex")));
    // Because the mapped file was opened O_RDONLY, the VMA is !VM_MAYWRITE and
    // also !VM_SHARED.
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("sh")));
    EXPECT_THAT(entry.vm_flags.value(), Not(Contains("mw")));
  }
}

// Tests that gVisor's /proc/[pid]/smaps provides all of the fields we expect it
// to, which as of this writing is all fields provided by Linux 4.4.
TEST(ProcPidSmapsTest, GvisorFields) {
  SKIP_IF(!IsRunningOnGvisor());
  auto const entries = ASSERT_NO_ERRNO_AND_VALUE(ReadProcSelfSmaps());
  for (auto const& entry : entries) {
    EXPECT_TRUE(entry.pss_kb);
    EXPECT_TRUE(entry.referenced_kb);
    EXPECT_TRUE(entry.anonymous_kb);
    EXPECT_TRUE(entry.anon_huge_pages_kb);
    EXPECT_TRUE(entry.shared_hugetlb_kb);
    EXPECT_TRUE(entry.private_hugetlb_kb);
    EXPECT_TRUE(entry.swap_kb);
    EXPECT_TRUE(entry.swap_pss_kb);
    EXPECT_THAT(entry.kernel_page_size_kb, Optional(kPageSize / 1024));
    EXPECT_THAT(entry.mmu_page_size_kb, Optional(kPageSize / 1024));
    EXPECT_TRUE(entry.locked_kb);
    EXPECT_TRUE(entry.vm_flags);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
