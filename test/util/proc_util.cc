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

#include "test/util/proc_util.h"

#include <sys/prctl.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Parses a single line from /proc/<xxx>/maps.
PosixErrorOr<ProcMapsEntry> ParseProcMapsLine(absl::string_view line) {
  ProcMapsEntry map_entry = {};

  // Limit splitting to 6 parts so that if there is a file path and it contains
  // spaces, the file path is not split.
  std::vector<std::string> parts =
      absl::StrSplit(line, absl::MaxSplits(' ', 5), absl::SkipEmpty());

  // parts.size() should be 6 if there is a file name specified, and 5
  // otherwise.
  if (parts.size() < 5) {
    return PosixError(EINVAL, absl::StrCat("Invalid line: ", line));
  }

  // Address range in the form X-X where X are hex values without leading 0x.
  std::vector<std::string> addresses = absl::StrSplit(parts[0], '-');
  if (addresses.size() != 2) {
    return PosixError(EINVAL,
                      absl::StrCat("Invalid address range: ", parts[0]));
  }
  ASSIGN_OR_RETURN_ERRNO(map_entry.start, AtoiBase(addresses[0], 16));
  ASSIGN_OR_RETURN_ERRNO(map_entry.end, AtoiBase(addresses[1], 16));

  // Permissions are four bytes of the form rwxp or - if permission not set.
  if (parts[1].size() != 4) {
    return PosixError(EINVAL,
                      absl::StrCat("Invalid permission field: ", parts[1]));
  }

  map_entry.readable = parts[1][0] == 'r';
  map_entry.writable = parts[1][1] == 'w';
  map_entry.executable = parts[1][2] == 'x';
  map_entry.priv = parts[1][3] == 'p';

  ASSIGN_OR_RETURN_ERRNO(map_entry.offset, AtoiBase(parts[2], 16));

  std::vector<std::string> device = absl::StrSplit(parts[3], ':');
  if (device.size() != 2) {
    return PosixError(EINVAL, absl::StrCat("Invalid device: ", parts[3]));
  }
  ASSIGN_OR_RETURN_ERRNO(map_entry.major, AtoiBase(device[0], 16));
  ASSIGN_OR_RETURN_ERRNO(map_entry.minor, AtoiBase(device[1], 16));

  ASSIGN_OR_RETURN_ERRNO(map_entry.inode, Atoi<int64_t>(parts[4]));
  if (parts.size() == 6) {
    // A filename is present. However, absl::StrSplit retained the whitespace
    // between the inode number and the filename.
    map_entry.filename =
        std::string(absl::StripLeadingAsciiWhitespace(parts[5]));
  }

  return map_entry;
}

PosixErrorOr<std::vector<ProcMapsEntry>> ParseProcMaps(
    absl::string_view contents) {
  std::vector<ProcMapsEntry> entries;
  auto lines = absl::StrSplit(contents, '\n', absl::SkipEmpty());
  for (const auto& l : lines) {
    std::cout << "line: " << l << std::endl;
    ASSIGN_OR_RETURN_ERRNO(auto entry, ParseProcMapsLine(l));
    entries.push_back(entry);
  }
  return entries;
}

PosixErrorOr<bool> IsVsyscallEnabled() {
  ASSIGN_OR_RETURN_ERRNO(auto contents, GetContents("/proc/self/maps"));
  ASSIGN_OR_RETURN_ERRNO(auto maps, ParseProcMaps(contents));
  return std::any_of(maps.begin(), maps.end(), [](const ProcMapsEntry& e) {
    return e.filename == "[vsyscall]";
  });
}

// Given the value part of a /proc/[pid]/smaps field containing a value in kB
// (for example, "    4 kB", returns the value in kB (in this example, 4).
PosixErrorOr<size_t> SmapsValueKb(absl::string_view value) {
  // TODO(jamieliu): let us use RE2 or <regex>
  std::pair<absl::string_view, absl::string_view> parts =
      absl::StrSplit(value, ' ', absl::SkipEmpty());
  if (parts.second != "kB") {
    return PosixError(EINVAL,
                      absl::StrCat("invalid smaps field value: ", value));
  }
  ASSIGN_OR_RETURN_ERRNO(auto val_kb, Atoi<size_t>(parts.first));
  return val_kb;
}

PosixErrorOr<std::vector<ProcSmapsEntry>> ParseProcSmaps(
    absl::string_view contents) {
  std::vector<ProcSmapsEntry> entries;
  absl::optional<ProcSmapsEntry> entry;
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
      // ProcSmapsEntry.
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
    std::cerr << "skipping unknown smaps field " << key << std::endl;
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
                << maybe_maps_entry.error().message() << std::endl;
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
}

PosixErrorOr<ProcSmapsEntry> FindUniqueSmapsEntry(
    std::vector<ProcSmapsEntry> const& entries, uintptr_t addr) {
  auto const pred = [&](ProcSmapsEntry const& entry) {
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

PosixErrorOr<std::vector<ProcSmapsEntry>> ReadProcSelfSmaps() {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents("/proc/self/smaps"));
  return ParseProcSmaps(contents);
}

PosixErrorOr<std::vector<ProcSmapsEntry>> ReadProcSmaps(pid_t pid) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents,
                         GetContents(absl::StrCat("/proc/", pid, "/smaps")));
  return ParseProcSmaps(contents);
}

bool EntryHasNH(const ProcSmapsEntry& e) {
  if (e.vm_flags) {
    auto flags = e.vm_flags.value();
    return std::find(flags.begin(), flags.end(), "nh") != flags.end();
  }
  return false;
}

bool StackTHPDisabled(std::vector<ProcSmapsEntry> maps) {
  return std::any_of(maps.begin(), maps.end(), [](const ProcSmapsEntry& e) {
    return e.maps_entry.filename == "[stack]" && EntryHasNH(e);
  });
}

bool IsTHPDisabled() {
  auto maps = ReadProcSelfSmaps();
  return StackTHPDisabled(maps.ValueOrDie());
}

}  // namespace testing
}  // namespace gvisor
