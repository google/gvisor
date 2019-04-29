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

#ifndef GVISOR_TEST_UTIL_PROC_UTIL_H_
#define GVISOR_TEST_UTIL_PROC_UTIL_H_

#include <ostream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// ProcMapsEntry contains the data from a single line in /proc/<xxx>/maps.
struct ProcMapsEntry {
  uint64_t start;
  uint64_t end;
  bool readable;
  bool writable;
  bool executable;
  bool priv;
  uint64_t offset;
  int major;
  int minor;
  int64_t inode;
  std::string filename;
};

// Parses a ProcMaps line or returns an error.
PosixErrorOr<ProcMapsEntry> ParseProcMapsLine(absl::string_view line);
PosixErrorOr<std::vector<ProcMapsEntry>> ParseProcMaps(
    absl::string_view contents);

// Returns true if vsyscall (emmulation or not) is enabled.
PosixErrorOr<bool> IsVsyscallEnabled();

// Printer for ProcMapsEntry.
inline std::ostream& operator<<(std::ostream& os, const ProcMapsEntry& entry) {
  std::string str =
      absl::StrCat(absl::Hex(entry.start, absl::PadSpec::kZeroPad8), "-",
                   absl::Hex(entry.end, absl::PadSpec::kZeroPad8), " ");

  absl::StrAppend(&str, entry.readable ? "r" : "-");
  absl::StrAppend(&str, entry.writable ? "w" : "-");
  absl::StrAppend(&str, entry.executable ? "x" : "-");
  absl::StrAppend(&str, entry.priv ? "p" : "s");

  absl::StrAppend(&str, " ", absl::Hex(entry.offset, absl::PadSpec::kZeroPad8),
                  " ", absl::Hex(entry.major, absl::PadSpec::kZeroPad2), ":",
                  absl::Hex(entry.minor, absl::PadSpec::kZeroPad2), " ",
                  entry.inode);
  if (absl::string_view(entry.filename) != "") {
    // Pad to column 74
    int pad = 73 - str.length();
    if (pad > 0) {
      absl::StrAppend(&str, std::string(pad, ' '));
    }
    absl::StrAppend(&str, entry.filename);
  }
  os << str;
  return os;
}

// Printer for std::vector<ProcMapsEntry>.
inline std::ostream& operator<<(std::ostream& os,
                                const std::vector<ProcMapsEntry>& vec) {
  for (unsigned int i = 0; i < vec.size(); i++) {
    os << vec[i];
    if (i != vec.size() - 1) {
      os << "\n";
    }
  }
  return os;
}

// GMock printer for std::vector<ProcMapsEntry>.
inline void PrintTo(const std::vector<ProcMapsEntry>& vec, std::ostream* os) {
  *os << vec;
}

// Checks that /proc/pid/maps contains all of the passed mappings.
//
// The major, minor, and inode fields are ignored.
MATCHER_P(ContainsMappings, mappings,
          "contains mappings:\n" + ::testing::PrintToString(mappings)) {
  auto contents_or = GetContents(absl::StrCat("/proc/", arg, "/maps"));
  if (!contents_or.ok()) {
    *result_listener << "Unable to read mappings: "
                     << contents_or.error().ToString();
    return false;
  }

  auto maps_or = ParseProcMaps(contents_or.ValueOrDie());
  if (!maps_or.ok()) {
    *result_listener << "Unable to parse mappings: "
                     << maps_or.error().ToString();
    return false;
  }

  auto maps = std::move(maps_or).ValueOrDie();

  // Does maps contain all elements in mappings? The comparator ignores
  // the major, minor, and inode fields.
  bool all_present = true;
  std::for_each(mappings.begin(), mappings.end(), [&](const ProcMapsEntry& e1) {
    auto it =
        std::find_if(maps.begin(), maps.end(), [&e1](const ProcMapsEntry& e2) {
          return e1.start == e2.start && e1.end == e2.end &&
                 e1.readable == e2.readable && e1.writable == e2.writable &&
                 e1.executable == e2.executable && e1.priv == e2.priv &&
                 e1.offset == e2.offset && e1.filename == e2.filename;
        });
    if (it == maps.end()) {
      // It wasn't found.
      if (all_present) {
        // We will output the message once and then a line for each mapping
        // that wasn't found.
        all_present = false;
        *result_listener << "Got mappings:\n"
                         << maps << "\nThat were missing:\n";
      }
      *result_listener << e1 << "\n";
    }
  });

  return all_present;
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_PROC_UTIL_H_
