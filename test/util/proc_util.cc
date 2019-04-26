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

#include "test/util/proc_util.h"

#include <algorithm>
#include <iostream>
#include <vector>

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
    map_entry.filename = std::string(absl::StripLeadingAsciiWhitespace(parts[5]));
  }

  return map_entry;
}

PosixErrorOr<std::vector<ProcMapsEntry>> ParseProcMaps(
    absl::string_view contents) {
  std::vector<ProcMapsEntry> entries;
  auto lines = absl::StrSplit(contents, '\n', absl::SkipEmpty());
  for (const auto& l : lines) {
    std::cout << "line: " << l;
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

}  // namespace testing
}  // namespace gvisor
