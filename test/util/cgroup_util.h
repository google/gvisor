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

#ifndef GVISOR_TEST_UTIL_CGROUP_UTIL_H_
#define GVISOR_TEST_UTIL_CGROUP_UTIL_H_

#include <unistd.h>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"

namespace gvisor {
namespace testing {

// Cgroup represents a cgroup directory on a mounted cgroupfs.
class Cgroup {
 public:
  static Cgroup RootCgroup(absl::string_view path) {
    return Cgroup(path, path);
  }

  uint64_t id() const { return id_; }

  // Deletes the current cgroup represented by this object.
  PosixError Delete();

  const std::string& Path() const { return cgroup_path_; }

  // Returns the canonical path for this cgroup, which is the absolute path
  // starting at the hierarchy root.
  const std::string CanonicalPath() const {
    std::string relpath =
        GetRelativePath(mountpoint_, cgroup_path_).ValueOrDie();
    if (relpath == ".") {
      return "/";
    }
    return "/" + relpath;
  }

  // Creates a child cgroup under this cgroup with the given name.
  PosixErrorOr<Cgroup> CreateChild(std::string_view name) const;

  std::string Relpath(absl::string_view leaf) const {
    return JoinPath(cgroup_path_, leaf);
  }

  // Returns the contents of a cgroup control file with the given name.
  PosixErrorOr<std::string> ReadControlFile(absl::string_view name) const;

  // Reads the contents of a cgroup control with the given name, and attempts
  // to parse it as an integer.
  PosixErrorOr<int64_t> ReadIntegerControlFile(absl::string_view name) const;

  // Writes a string to a cgroup control file.
  PosixError WriteControlFile(absl::string_view name,
                              const std::string& value) const;

  // Writes an integer value to a cgroup control file.
  PosixError WriteIntegerControlFile(absl::string_view name,
                                     int64_t value) const;

  // Waits for a control file's value to change.
  PosixError PollControlFileForChange(absl::string_view name,
                                      absl::Duration timeout) const;

  // Waits for a control file's value to change after calling body.
  PosixError PollControlFileForChangeAfter(absl::string_view name,
                                           absl::Duration timeout,
                                           std::function<void()> body) const;

  // Returns the thread ids of the leaders of thread groups managed by this
  // cgroup.
  PosixErrorOr<absl::flat_hash_set<pid_t>> Procs() const;

  PosixErrorOr<absl::flat_hash_set<pid_t>> Tasks() const;

  // ContainsCallingProcess checks whether the calling process is part of the
  // cgroup.
  PosixError ContainsCallingProcess() const;

  // ContainsCallingThread checks whether the calling thread is part of the
  // cgroup.
  PosixError ContainsCallingThread() const;

  // Moves process with the specified pid to this cgroup.
  PosixError Enter(pid_t pid) const;

  // Moves thread with the specified pid to this cgroup.
  PosixError EnterThread(pid_t pid) const;

 private:
  Cgroup(std::string_view path, std::string_view mountpoint);

  PosixErrorOr<absl::flat_hash_set<pid_t>> ParsePIDList(
      absl::string_view data) const;

  static int64_t next_id_;
  int64_t id_;
  const std::string cgroup_path_;
  const std::string mountpoint_;
};

// Mounter is a utility for creating cgroupfs mounts. It automatically manages
// the lifetime of created mounts.
class Mounter {
 public:
  Mounter(TempPath root) : root_(std::move(root)) {}

  PosixErrorOr<Cgroup> MountCgroupfs(std::string mopts);

  PosixError Unmount(const Cgroup& c);

  void release(const Cgroup& c);

 private:
  // The destruction order of these members avoids errors during cleanup. We
  // first unmount (by executing the mounts_ cleanups), then delete the
  // mountpoint subdirs, then delete the root.
  TempPath root_;
  absl::flat_hash_map<int64_t, TempPath> mountpoints_;
  absl::flat_hash_map<int64_t, Cleanup> mounts_;
};

// Represents a line from /proc/cgroups.
struct CgroupsEntry {
  std::string subsys_name;
  uint32_t hierarchy;
  uint64_t num_cgroups;
  bool enabled;
};

// Returns a parsed representation of /proc/cgroups.
PosixErrorOr<absl::flat_hash_map<std::string, CgroupsEntry>>
ProcCgroupsEntries();

// Represents a line from /proc/<pid>/cgroup.
struct PIDCgroupEntry {
  uint32_t hierarchy;
  std::string controllers;
  std::string path;
};

// Returns a parsed representation of /proc/<pid>/cgroup.
PosixErrorOr<absl::flat_hash_map<std::string, PIDCgroupEntry>>
ProcPIDCgroupEntries(pid_t pid);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_CGROUP_UTIL_H_
