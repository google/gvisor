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

#include "test/util/cgroup_util.h"

#include <sys/syscall.h>
#include <unistd.h>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"

namespace gvisor {
namespace testing {

Cgroup::Cgroup(absl::string_view path, absl::string_view mountpoint)
    : cgroup_path_(path), mountpoint_(mountpoint) {
  id_ = ++Cgroup::next_id_;
  std::cerr << absl::StreamFormat("[cg#%d] <= %s", id_, cgroup_path_)
            << std::endl;
}

PosixError Cgroup::Delete() { return Rmdir(cgroup_path_); }

PosixErrorOr<Cgroup> Cgroup::CreateChild(absl::string_view name) const {
  std::string path = JoinPath(Path(), name);
  RETURN_IF_ERRNO(Mkdir(path));
  return Cgroup(path, mountpoint_);
}

PosixErrorOr<std::string> Cgroup::ReadControlFile(
    absl::string_view name) const {
  std::string buf;
  RETURN_IF_ERRNO(GetContents(Relpath(name), &buf));

  const std::string alias_path = absl::StrFormat("[cg#%d]/%s", id_, name);
  std::cerr << absl::StreamFormat("<contents of %s>", alias_path) << std::endl;
  std::cerr << buf;
  std::cerr << absl::StreamFormat("<end of %s>", alias_path) << std::endl;

  return buf;
}

PosixErrorOr<int64_t> Cgroup::ReadIntegerControlFile(
    absl::string_view name) const {
  ASSIGN_OR_RETURN_ERRNO(const std::string buf, ReadControlFile(name));
  ASSIGN_OR_RETURN_ERRNO(const int64_t val, Atoi<int64_t>(buf));
  return val;
}

PosixError Cgroup::WriteControlFile(absl::string_view name,
                                    const std::string& value) const {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, Open(Relpath(name), O_WRONLY));
  RETURN_ERROR_IF_SYSCALL_FAIL(WriteFd(fd.get(), value.c_str(), value.size()));
  const std::string alias_path = absl::StrFormat("[cg#%d]/%s", id_, name);
  std::cerr << absl::StreamFormat("echo '%s' > %s", value, alias_path)
            << std::endl;
  return NoError();
}

PosixError Cgroup::WriteIntegerControlFile(absl::string_view name,
                                           int64_t value) const {
  return WriteControlFile(name, absl::StrCat(value));
}

PosixErrorOr<absl::flat_hash_set<pid_t>> Cgroup::Procs() const {
  ASSIGN_OR_RETURN_ERRNO(std::string buf, ReadControlFile("cgroup.procs"));
  return ParsePIDList(buf);
}

PosixErrorOr<absl::flat_hash_set<pid_t>> Cgroup::Tasks() const {
  ASSIGN_OR_RETURN_ERRNO(std::string buf, ReadControlFile("tasks"));
  return ParsePIDList(buf);
}

PosixError Cgroup::PollControlFileForChange(absl::string_view name,
                                            absl::Duration timeout) const {
  return PollControlFileForChangeAfter(name, timeout, []() {});
}

PosixError Cgroup::PollControlFileForChangeAfter(
    absl::string_view name, absl::Duration timeout,
    std::function<void()> body) const {
  const absl::Duration poll_interval = absl::Milliseconds(10);
  const absl::Time deadline = absl::Now() + timeout;
  const std::string alias_path = absl::StrFormat("[cg#%d]/%s", id_, name);

  ASSIGN_OR_RETURN_ERRNO(const int64_t initial_value,
                         ReadIntegerControlFile(name));

  body();

  // The loop below iterates quickly and results in too many save-restore
  // cycles. This can prevent tasks from being scheduled and incurring the
  // resource usage this function is often waiting for, resulting in timeouts.
  const DisableSave ds;

  while (true) {
    ASSIGN_OR_RETURN_ERRNO(const int64_t current_value,
                           ReadIntegerControlFile(name));
    if (current_value != initial_value) {
      std::cerr << absl::StreamFormat(
                       "Control file '%s' changed from '%d' to '%d'",
                       alias_path, initial_value, current_value)
                << std::endl;
      return NoError();
    }
    if (absl::Now() >= deadline) {
      return PosixError(ETIME, absl::StrCat(alias_path, " didn't change in ",
                                            absl::FormatDuration(timeout)));
    }
    std::cerr << absl::StreamFormat(
                     "Waiting for control file '%s' to change from '%d'...",
                     alias_path, initial_value)
              << std::endl;
    absl::SleepFor(poll_interval);
  }
}

PosixError Cgroup::ContainsCallingProcess() const {
  ASSIGN_OR_RETURN_ERRNO(const absl::flat_hash_set<pid_t> procs, Procs());
  ASSIGN_OR_RETURN_ERRNO(const absl::flat_hash_set<pid_t> tasks, Tasks());
  const pid_t pid = getpid();
  const pid_t tid = syscall(SYS_gettid);
  if (!procs.contains(pid)) {
    return PosixError(
        ENOENT, absl::StrFormat("Cgroup doesn't contain process %d", pid));
  }
  if (!tasks.contains(tid)) {
    return PosixError(ENOENT,
                      absl::StrFormat("Cgroup doesn't contain task %d", tid));
  }
  return NoError();
}

PosixError Cgroup::ContainsCallingThread() const {
  ASSIGN_OR_RETURN_ERRNO(const absl::flat_hash_set<pid_t> tasks, Tasks());
  const pid_t tid = syscall(SYS_gettid);
  if (!tasks.contains(tid)) {
    return PosixError(ENOENT,
                      absl::StrFormat("Cgroup doesn't contain task %d", tid));
  }
  return NoError();
}

PosixError Cgroup::Enter(pid_t pid) const {
  return WriteIntegerControlFile("cgroup.procs", static_cast<int64_t>(pid));
}

PosixError Cgroup::EnterThread(pid_t pid) const {
  return WriteIntegerControlFile("tasks", static_cast<int64_t>(pid));
}

PosixErrorOr<absl::flat_hash_set<pid_t>> Cgroup::ParsePIDList(
    absl::string_view data) const {
  absl::flat_hash_set<pid_t> res;
  std::vector<absl::string_view> lines = absl::StrSplit(data, '\n');
  for (const absl::string_view& line : lines) {
    if (line.empty()) {
      continue;
    }
    ASSIGN_OR_RETURN_ERRNO(const int32_t pid, Atoi<int32_t>(line));
    res.insert(static_cast<pid_t>(pid));
  }
  return res;
}

int64_t Cgroup::next_id_ = 0;

PosixErrorOr<Cgroup> Mounter::MountCgroupfs(std::string mopts) {
  ASSIGN_OR_RETURN_ERRNO(TempPath mountpoint,
                         TempPath::CreateDirIn(root_.path()));
  ASSIGN_OR_RETURN_ERRNO(
      Cleanup mount, Mount("none", mountpoint.path(), "cgroup", 0, mopts, 0));
  const std::string mountpath = mountpoint.path();
  std::cerr << absl::StreamFormat(
                   "Mount(\"none\", \"%s\", \"cgroup\", 0, \"%s\", 0) => OK",
                   mountpath, mopts)
            << std::endl;
  Cgroup cg = Cgroup::RootCgroup(mountpath);
  mountpoints_[cg.id()] = std::move(mountpoint);
  mounts_[cg.id()] = std::move(mount);
  return cg;
}

PosixError Mounter::Unmount(const Cgroup& c) {
  auto mount = mounts_.find(c.id());
  auto mountpoint = mountpoints_.find(c.id());

  if (mount == mounts_.end() || mountpoint == mountpoints_.end()) {
    return PosixError(
        ESRCH, absl::StrFormat("No mount found for cgroupfs containing cg#%d",
                               c.id()));
  }

  std::cerr << absl::StreamFormat("Unmount([cg#%d])", c.id()) << std::endl;

  // Simply delete the entries, their destructors will unmount and delete the
  // mountpoint. Note the order is important to avoid errors: mount then
  // mountpoint.
  mounts_.erase(mount);
  mountpoints_.erase(mountpoint);

  return NoError();
}

void Mounter::release(const Cgroup& c) {
  auto mp = mountpoints_.find(c.id());
  if (mp != mountpoints_.end()) {
    mp->second.release();
    mountpoints_.erase(mp);
  }

  auto m = mounts_.find(c.id());
  if (m != mounts_.end()) {
    m->second.Release();
    mounts_.erase(m);
  }
}

constexpr char kProcCgroupsHeader[] =
    "#subsys_name\thierarchy\tnum_cgroups\tenabled";

PosixErrorOr<absl::flat_hash_map<std::string, CgroupsEntry>>
ProcCgroupsEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/cgroups", &content));

  bool found_header = false;
  absl::flat_hash_map<std::string, CgroupsEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');
  std::cerr << "<contents of /proc/cgroups>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (!found_header) {
      EXPECT_EQ(line, kProcCgroupsHeader);
      found_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/cgroups.
    //
    // Example entries, fields are tab separated in the real file:
    //
    // #subsys_name    hierarchy       num_cgroups     enabled
    // cpuset  12      35      1
    // cpu     3       222     1
    //   ^     ^       ^       ^
    //   0     1       2       3

    CgroupsEntry entry;
    std::vector<std::string> fields =
        StrSplit(line, absl::ByAnyChar(": \t"), absl::SkipEmpty());

    entry.subsys_name = fields[0];
    ASSIGN_OR_RETURN_ERRNO(entry.hierarchy, Atoi<uint32_t>(fields[1]));
    ASSIGN_OR_RETURN_ERRNO(entry.num_cgroups, Atoi<uint64_t>(fields[2]));
    ASSIGN_OR_RETURN_ERRNO(const int enabled, Atoi<int>(fields[3]));
    entry.enabled = enabled != 0;

    entries[entry.subsys_name] = entry;
  }
  std::cerr << "<end of /proc/cgroups>" << std::endl;

  return entries;
}

PosixErrorOr<absl::flat_hash_map<std::string, PIDCgroupEntry>>
ProcPIDCgroupEntries(pid_t pid) {
  const std::string path = absl::StrFormat("/proc/%d/cgroup", pid);
  std::string content;
  RETURN_IF_ERRNO(GetContents(path, &content));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');

  std::cerr << absl::StreamFormat("<contents of %s>", path) << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/<pid>/cgroup.
    //
    // Example entries:
    //
    // 2:cpu:/path/to/cgroup
    // 1:memory:/

    PIDCgroupEntry entry;
    std::vector<std::string> fields =
        absl::StrSplit(line, absl::ByChar(':'), absl::SkipEmpty());

    ASSIGN_OR_RETURN_ERRNO(entry.hierarchy, Atoi<uint32_t>(fields[0]));
    entry.controllers = fields[1];
    entry.path = fields[2];

    entries[entry.controllers] = entry;
  }
  std::cerr << absl::StreamFormat("<end of %s>", path) << std::endl;

  return entries;
}

}  // namespace testing
}  // namespace gvisor
