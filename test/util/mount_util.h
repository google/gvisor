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

#ifndef GVISOR_TEST_UTIL_MOUNT_UTIL_H_
#define GVISOR_TEST_UTIL_MOUNT_UTIL_H_

#include <errno.h>
#include <sys/mount.h>

#include <functional>
#include <string>

#include "gmock/gmock.h"
#include "absl/container/flat_hash_map.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Mount mounts the filesystem, and unmounts when the returned reference is
// destroyed.
inline PosixErrorOr<Cleanup> Mount(const std::string& source,
                                   const std::string& target,
                                   const std::string& fstype,
                                   uint64_t mountflags, const std::string& data,
                                   uint64_t umountflags) {
  if (mount(source.c_str(), target.c_str(), fstype.c_str(), mountflags,
            data.c_str()) == -1) {
    return PosixError(errno, "mount failed");
  }
  return Cleanup([target, umountflags]() {
    EXPECT_THAT(umount2(target.c_str(), umountflags), SyscallSucceeds());
  });
}

struct ProcMountsEntry {
  std::string spec;
  std::string mount_point;
  std::string fstype;
  std::string mount_opts;
  uint32_t dump;
  uint32_t fsck;
};

// ProcSelfMountsEntries returns a parsed representation of /proc/self/mounts.
PosixErrorOr<std::vector<ProcMountsEntry>> ProcSelfMountsEntries();

// ProcSelfMountsEntries returns a parsed representation of mounts from the
// provided content.
PosixErrorOr<std::vector<ProcMountsEntry>> ProcSelfMountsEntriesFrom(
    const std::string& content);

struct ProcMountInfoEntry {
  uint64_t id;
  uint64_t parent_id;
  dev_t major;
  dev_t minor;
  std::string root;
  std::string mount_point;
  std::string mount_opts;
  std::string optional;
  std::string fstype;
  std::string mount_source;
  std::string super_opts;
};

// ProcSelfMountInfoEntries returns a parsed representation of
// /proc/self/mountinfo.
PosixErrorOr<std::vector<ProcMountInfoEntry>> ProcSelfMountInfoEntries();

// ProcSelfMountInfoEntriesFrom returns a parsed representation of
// mountinfo from the provided content.
PosixErrorOr<std::vector<ProcMountInfoEntry>> ProcSelfMountInfoEntriesFrom(
    const std::string&);

// Interprets the input string mopts as a comma separated list of mount
// options. A mount option can either be just a value, or a key=value pair. For
// example, the string "rw,relatime,fd=7" will be parsed into a map like { "rw":
// "", "relatime": "", "fd": "7" }.
absl::flat_hash_map<std::string, std::string> ParseMountOptions(
    std::string mopts);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_MOUNT_UTIL_H_
