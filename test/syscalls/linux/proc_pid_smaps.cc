// Copyright 2019 Google LLC
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
#include "absl/types/optional.h"
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

struct ProcPidSmapsEntry {
  ProcMapsEntry maps_entry;

  // These fields should always exist, as they were included in e070ad49f311
  // "[PATCH] add /proc/pid/smaps".
  size_t size_kb;
  size_t rss_kb;
  size_t shared_clean_kb;
  size_t shared_dirty_kb;
  size_t private_clean_kb;
  size_t private_dirty_kb;

  // These fields were added later and may not be present.
  absl::optional<size_t> pss_kb;
  absl::optional<size_t> referenced_kb;
  absl::optional<size_t> anonymous_kb;
  absl::optional<size_t> anon_huge_pages_kb;
  absl::optional<size_t> shared_hugetlb_kb;
  absl::optional<size_t> private_hugetlb_kb;
  absl::optional<size_t> swap_kb;
  absl::optional<size_t> swap_pss_kb;
  absl::optional<size_t> kernel_page_size_kb;
  absl::optional<size_t> mmu_page_size_kb;
  absl::optional<size_t> locked_kb;

  // Caution: "Note that there is no guarantee that every flag and associated
  // mnemonic will be present in all further kernel releases. Things get
  // changed, the flags may be vanished or the reverse -- new added." - Linux
  // Documentation/filesystems/proc.txt, on VmFlags. Avoid checking for any
  // flags that are not extremely well-established.
  absl::optional<std::vector<std::string>> vm_flags;
};

// Given the value part of a /proc/[pid]/smaps field containing a value in kB
// (for example, "    4 kB", returns the value in kB (in this example, 4).
PosixErrorOr<size_t> SmapsValueKb(absl::string_view value) {
  // TODO: let us use RE2 or <regex>
  std::pair<absl::string_view, absl::string_view> parts =
      absl::StrSplit(value, ' ', absl::SkipEmpty());
  if (parts.second != "kB") {
    return PosixError(EINVAL,
                      absl::StrCat("invalid smaps field value: ", value));
  }
  ASSIGN_OR_RETURN_ERRNO(auto val_kb, Atoi<size_t>(parts.first));
  return val_kb;
}

PosixErrorOr<std::vector<ProcPidSmapsEntry>> ParseProcPidSmaps(
    absl::string_view contents) {
  std::vector<ProcPidSmapsEntry> entries;
  absl::optional<ProcPidSmapsEntry> entry;
  bool have_size_kb = false;
  bool have_rss_kb = false;
  bool have_shared_clean_kb = false;
  bool have_shared_dirty_kb = false;
  bool have_private_clean_kb = false;
  bool have_private_dirty_kb = false;

  auto const finish_entry = [&] {
    if (entry) {
      if (!have_size_kb) {
        return PosixError(EINVAL, "smaps entry is missing Size");
      }
      if (!have_rss_kb) {
        return PosixError(EINVAL, "smaps entry is missing Rss");
      }
      if (!have_shared_clean_kb) {
        return PosixError(EINVAL, "smaps entry is missing Shared_Clean");
      }
      if (!have_shared_dirty_kb) {
        return PosixError(EINVAL, "smaps entry is missing Shared_Dirty");
      }
      if (!have_private_clean_kb) {
        return PosixError(EINVAL, "smaps entry is missing Private_Clean");
      }
      if (!have_private_dirty_kb) {
        return PosixError(EINVAL, "smaps entry is missing Private_Dirty");
      }
      // std::move(entry.value()) instead of std::move(entry).value(), because
      // otherwise tools may report a "use-after-move" warning, which is
      // spurious because entry.emplace() below resets entry to a new
      // ProcPidSmapsEntry.
      entries.emplace_back(std::move(entry.value()));
    }
    entry.emplace();
    have_size_kb = false;
    have_rss_kb = false;
    have_shared_clean_kb = false;
    have_shared_dirty_kb = false;
    have_private_clean_kb = false;
    have_private_dirty_kb = false;
    return NoError();
  };

  // Holds key/value pairs from smaps field lines. Declared here so it can be
  // captured by reference by the following lambdas.
  std::vector<absl::string_view> key_value;

  auto const on_required_field_kb = [&](size_t* field, bool* have_field) {
    if (*have_field) {
      return PosixError(
          EINVAL,
          absl::StrFormat("smaps entry has duplicate %s line", key_value[0]));
    }
    ASSIGN_OR_RETURN_ERRNO(*field, SmapsValueKb(key_value[1]));
    *have_field = true;
    return NoError();
  };

  auto const on_optional_field_kb = [&](absl::optional<size_t>* field) {
    if (*field) {
      return PosixError(
          EINVAL,
          absl::StrFormat("smaps entry has duplicate %s line", key_value[0]));
    }
    ASSIGN_OR_RETURN_ERRNO(*field, SmapsValueKb(key_value[1]));
    return NoError();
  };

  absl::flat_hash_set<std::string> unknown_fields;
  auto const on_unknown_field = [&] {
    absl::string_view key = key_value[0];
    // Don't mention unknown fields more than once.
    if (unknown_fields.count(key)) {
      return;
    }
    unknown_fields.insert(std::string(key));
    std::cerr << "skipping unknown smaps field " << key;
  };

  auto lines = absl::StrSplit(contents, '\n', absl::SkipEmpty());
  for (absl::string_view l : lines) {
    // Is this line a valid /proc/[pid]/maps entry?
    auto maybe_maps_entry = ParseProcMapsLine(l);
    if (maybe_maps_entry.ok()) {
      // This marks the beginning of a new /proc/[pid]/smaps entry.
      RETURN_IF_ERRNO(finish_entry());
      entry->maps_entry = std::move(maybe_maps_entry).ValueOrDie();
      continue;
    }
    // Otherwise it's a field in an existing /proc/[pid]/smaps entry of the form
    // "key:value" (where value in practice will be preceded by a variable
    // amount of whitespace).
    if (!entry) {
      std::cerr << "smaps line not considered a maps line: "
                << maybe_maps_entry.error_message();
      return PosixError(
          EINVAL,
          absl::StrCat("smaps field line without preceding maps line: ", l));
    }
    key_value = absl::StrSplit(l, absl::MaxSplits(':', 1));
    if (key_value.size() != 2) {
      return PosixError(EINVAL, absl::StrCat("invalid smaps field line: ", l));
    }
    absl::string_view const key = key_value[0];
    if (key == "Size") {
      RETURN_IF_ERRNO(on_required_field_kb(&entry->size_kb, &have_size_kb));
    } else if (key == "Rss") {
      RETURN_IF_ERRNO(on_required_field_kb(&entry->rss_kb, &have_rss_kb));
    } else if (key == "Shared_Clean") {
      RETURN_IF_ERRNO(
          on_required_field_kb(&entry->shared_clean_kb, &have_shared_clean_kb));
    } else if (key == "Shared_Dirty") {
      RETURN_IF_ERRNO(
          on_required_field_kb(&entry->shared_dirty_kb, &have_shared_dirty_kb));
    } else if (key == "Private_Clean") {
      RETURN_IF_ERRNO(on_required_field_kb(&entry->private_clean_kb,
                                           &have_private_clean_kb));
    } else if (key == "Private_Dirty") {
      RETURN_IF_ERRNO(on_required_field_kb(&entry->private_dirty_kb,
                                           &have_private_dirty_kb));
    } else if (key == "Pss") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->pss_kb));
    } else if (key == "Referenced") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->referenced_kb));
    } else if (key == "Anonymous") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->anonymous_kb));
    } else if (key == "AnonHugePages") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->anon_huge_pages_kb));
    } else if (key == "Shared_Hugetlb") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->shared_hugetlb_kb));
    } else if (key == "Private_Hugetlb") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->private_hugetlb_kb));
    } else if (key == "Swap") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->swap_kb));
    } else if (key == "SwapPss") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->swap_pss_kb));
    } else if (key == "KernelPageSize") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->kernel_page_size_kb));
    } else if (key == "MMUPageSize") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->mmu_page_size_kb));
    } else if (key == "Locked") {
      RETURN_IF_ERRNO(on_optional_field_kb(&entry->locked_kb));
    } else if (key == "VmFlags") {
      if (entry->vm_flags) {
        return PosixError(EINVAL, "duplicate VmFlags line");
      }
      entry->vm_flags = absl::StrSplit(key_value[1], ' ', absl::SkipEmpty());
    } else {
      on_unknown_field();
    }
  }
  RETURN_IF_ERRNO(finish_entry());
  return entries;
};

TEST(ParseProcPidSmapsTest, Correctness) {
  auto entries = ASSERT_NO_ERRNO_AND_VALUE(
      ParseProcPidSmaps("0-10000 rw-s 00000000 00:00 0 "
                        "                   /dev/zero (deleted)\n"
                        "Size:                  0 kB\n"
                        "Rss:                   1 kB\n"
                        "Pss:                   2 kB\n"
                        "Shared_Clean:          3 kB\n"
                        "Shared_Dirty:          4 kB\n"
                        "Private_Clean:         5 kB\n"
                        "Private_Dirty:         6 kB\n"
                        "Referenced:            7 kB\n"
                        "Anonymous:             8 kB\n"
                        "AnonHugePages:         9 kB\n"
                        "Shared_Hugetlb:       10 kB\n"
                        "Private_Hugetlb:      11 kB\n"
                        "Swap:                 12 kB\n"
                        "SwapPss:              13 kB\n"
                        "KernelPageSize:       14 kB\n"
                        "MMUPageSize:          15 kB\n"
                        "Locked:               16 kB\n"
                        "FutureUnknownKey:     17 kB\n"
                        "VmFlags: rd wr sh mr mw me ms lo ?? sd \n"));
  ASSERT_EQ(entries.size(), 1);
  auto& entry = entries[0];
  EXPECT_EQ(entry.maps_entry.filename, "/dev/zero (deleted)");
  EXPECT_EQ(entry.size_kb, 0);
  EXPECT_EQ(entry.rss_kb, 1);
  EXPECT_THAT(entry.pss_kb, Optional(2));
  EXPECT_EQ(entry.shared_clean_kb, 3);
  EXPECT_EQ(entry.shared_dirty_kb, 4);
  EXPECT_EQ(entry.private_clean_kb, 5);
  EXPECT_EQ(entry.private_dirty_kb, 6);
  EXPECT_THAT(entry.referenced_kb, Optional(7));
  EXPECT_THAT(entry.anonymous_kb, Optional(8));
  EXPECT_THAT(entry.anon_huge_pages_kb, Optional(9));
  EXPECT_THAT(entry.shared_hugetlb_kb, Optional(10));
  EXPECT_THAT(entry.private_hugetlb_kb, Optional(11));
  EXPECT_THAT(entry.swap_kb, Optional(12));
  EXPECT_THAT(entry.swap_pss_kb, Optional(13));
  EXPECT_THAT(entry.kernel_page_size_kb, Optional(14));
  EXPECT_THAT(entry.mmu_page_size_kb, Optional(15));
  EXPECT_THAT(entry.locked_kb, Optional(16));
  EXPECT_THAT(entry.vm_flags,
              Optional(ElementsAreArray({"rd", "wr", "sh", "mr", "mw", "me",
                                         "ms", "lo", "??", "sd"})));
}

// Returns the unique entry in entries containing the given address.
PosixErrorOr<ProcPidSmapsEntry> FindUniqueSmapsEntry(
    std::vector<ProcPidSmapsEntry> const& entries, uintptr_t addr) {
  auto const pred = [&](ProcPidSmapsEntry const& entry) {
    return entry.maps_entry.start <= addr && addr < entry.maps_entry.end;
  };
  auto const it = std::find_if(entries.begin(), entries.end(), pred);
  if (it == entries.end()) {
    return PosixError(EINVAL,
                      absl::StrFormat("no entry contains address %#x", addr));
  }
  auto const it2 = std::find_if(it + 1, entries.end(), pred);
  if (it2 != entries.end()) {
    return PosixError(
        EINVAL,
        absl::StrFormat("overlapping entries [%#x-%#x) and [%#x-%#x) both "
                        "contain address %#x",
                        it->maps_entry.start, it->maps_entry.end,
                        it2->maps_entry.start, it2->maps_entry.end, addr));
  }
  return *it;
}

PosixErrorOr<std::vector<ProcPidSmapsEntry>> ReadProcSelfSmaps() {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents("/proc/self/smaps"));
  return ParseProcPidSmaps(contents);
}

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
