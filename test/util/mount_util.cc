// Copyright 2021 The gVisor Authors.
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

#include "test/util/mount_util.h"

#include <sys/syscall.h>
#include <unistd.h>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"

namespace gvisor {
namespace testing {

PosixErrorOr<std::vector<ProcMountsEntry>> ProcSelfMountsEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/self/mounts", &content));

  std::vector<ProcMountsEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');
  std::cerr << "<contents of /proc/self/mounts>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/self/mounts.
    //
    // Example entries:
    //
    // sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
    // proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
    //  ^     ^    ^                ^                  ^ ^
    //  0     1    2                3                  4 5

    ProcMountsEntry entry;
    std::vector<std::string> fields =
        absl::StrSplit(line, absl::ByChar(' '), absl::SkipEmpty());
    if (fields.size() != 6) {
      return PosixError(EINVAL,
                        absl::StrFormat("Not enough tokens, got %d, line: %s",
                                        fields.size(), line));
    }

    entry.spec = fields[0];
    entry.mount_point = fields[1];
    entry.fstype = fields[2];
    entry.mount_opts = fields[3];
    ASSIGN_OR_RETURN_ERRNO(entry.dump, Atoi<uint32_t>(fields[4]));
    ASSIGN_OR_RETURN_ERRNO(entry.fsck, Atoi<uint32_t>(fields[5]));

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/self/mounts>" << std::endl;

  return entries;
}

PosixErrorOr<std::vector<ProcMountInfoEntry>> ProcSelfMountInfoEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/self/mountinfo", &content));

  std::vector<ProcMountInfoEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');
  std::cerr << "<contents of /proc/self/mountinfo>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/self/mountinfo.
    //
    // Example entries:
    //
    // 22 28 0:20 / /sys rw,relatime shared:7 - sysfs sysfs rw
    // 23 28 0:21 / /proc rw,relatime shared:14 - proc proc rw
    // ^  ^    ^  ^   ^        ^         ^      ^  ^    ^   ^
    // 0  1    2  3   4        5         6      7  8    9   10

    ProcMountInfoEntry entry;
    std::vector<std::string> fields =
        absl::StrSplit(line, absl::ByChar(' '), absl::SkipEmpty());
    if (fields.size() < 10 || fields.size() > 11) {
      return PosixError(
          EINVAL,
          absl::StrFormat("Unexpected number of tokens, got %d, line: %s",
                          fields.size(), line));
    }

    ASSIGN_OR_RETURN_ERRNO(entry.id, Atoi<uint64_t>(fields[0]));
    ASSIGN_OR_RETURN_ERRNO(entry.parent_id, Atoi<uint64_t>(fields[1]));

    std::vector<std::string> devs =
        absl::StrSplit(fields[2], absl::ByChar(':'));
    if (devs.size() != 2) {
      return PosixError(
          EINVAL,
          absl::StrFormat(
              "Failed to parse dev number field %s: too many tokens, got %d",
              fields[2], devs.size()));
    }
    ASSIGN_OR_RETURN_ERRNO(entry.major, Atoi<dev_t>(devs[0]));
    ASSIGN_OR_RETURN_ERRNO(entry.minor, Atoi<dev_t>(devs[1]));

    entry.root = fields[3];
    entry.mount_point = fields[4];
    entry.mount_opts = fields[5];

    // The optional field (fields[6]) may or may not be present. We know based
    // on the total number of tokens.
    int off = -1;
    if (fields.size() == 11) {
      entry.optional = fields[6];
      off = 0;
    }
    // Field 7 is the optional field terminator char '-'.
    entry.fstype = fields[8 + off];
    entry.mount_source = fields[9 + off];
    entry.super_opts = fields[10 + off];

    entries.push_back(entry);
  }
  std::cerr << "<end of /proc/self/mountinfo>" << std::endl;

  return entries;
}

absl::flat_hash_map<std::string, std::string> ParseMountOptions(
    std::string mopts) {
  absl::flat_hash_map<std::string, std::string> entries;
  const std::vector<std::string> tokens =
      absl::StrSplit(mopts, absl::ByChar(','), absl::SkipEmpty());
  for (const auto& token : tokens) {
    std::vector<std::string> kv =
        absl::StrSplit(token, absl::MaxSplits('=', 1));
    if (kv.size() == 2) {
      entries[kv[0]] = kv[1];
    } else if (kv.size() == 1) {
      entries[kv[0]] = "";
    } else {
      TEST_CHECK_MSG(
          false,
          absl::StrFormat(
              "Invalid mount option token '%s', was split into %d subtokens",
              token, kv.size())
              .c_str());
    }
  }
  return entries;
}

}  // namespace testing
}  // namespace gvisor
