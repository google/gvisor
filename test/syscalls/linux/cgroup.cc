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

// All tests in this file rely on being about to mount and unmount cgroupfs,
// which isn't expected to work, or be safe on a general linux system.

#include <sys/mount.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "test/util/capability_util.h"
#include "test/util/cgroup_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;
using ::testing::Gt;

std::vector<std::string> known_controllers = {"cpu", "cpuset", "cpuacct",
                                              "memory"};

bool CgroupsAvailable() {
  return IsRunningOnGvisor() && !IsRunningWithVFS1() &&
         TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN));
}

TEST(Cgroup, MountSucceeds) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  EXPECT_NO_ERRNO(c.ContainsCallingProcess());
}

TEST(Cgroup, SeparateMounts) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));

  for (const auto& ctl : known_controllers) {
    Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(ctl));
    EXPECT_NO_ERRNO(c.ContainsCallingProcess());
  }
}

TEST(Cgroup, AllControllersImplicit) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));

  absl::flat_hash_map<std::string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  for (const auto& ctl : known_controllers) {
    EXPECT_TRUE(cgroups_entries.contains(ctl))
        << absl::StreamFormat("ctl=%s", ctl);
  }
  EXPECT_EQ(cgroups_entries.size(), known_controllers.size());
}

TEST(Cgroup, AllControllersExplicit) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("all"));

  absl::flat_hash_map<std::string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  for (const auto& ctl : known_controllers) {
    EXPECT_TRUE(cgroups_entries.contains(ctl))
        << absl::StreamFormat("ctl=%s", ctl);
  }
  EXPECT_EQ(cgroups_entries.size(), known_controllers.size());
}

TEST(Cgroup, ProcsAndTasks) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  absl::flat_hash_set<pid_t> pids = ASSERT_NO_ERRNO_AND_VALUE(c.Procs());
  absl::flat_hash_set<pid_t> tids = ASSERT_NO_ERRNO_AND_VALUE(c.Tasks());

  EXPECT_GE(tids.size(), pids.size()) << "Found more processes than threads";

  // Pids should be a strict subset of tids.
  for (auto it = pids.begin(); it != pids.end(); ++it) {
    EXPECT_TRUE(tids.contains(*it))
        << absl::StreamFormat("Have pid %d, but no such tid", *it);
  }
}

TEST(Cgroup, ControllersMustBeInUniqueHierarchy) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  // Hierarchy #1: all controllers.
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  // Hierarchy #2: memory.
  //
  // This should conflict since memory is already in hierarchy #1, and the two
  // hierarchies have different sets of controllers, so this mount can't be a
  // view into hierarchy #1.
  EXPECT_THAT(m.MountCgroupfs("memory"), PosixErrorIs(EBUSY, _))
      << "Memory controller mounted on two hierarchies";
  EXPECT_THAT(m.MountCgroupfs("cpu"), PosixErrorIs(EBUSY, _))
      << "CPU controller mounted on two hierarchies";
}

TEST(Cgroup, UnmountFreesControllers) {
  SKIP_IF(!CgroupsAvailable());
  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  // All controllers are now attached to all's hierarchy. Attempting new mount
  // with any individual controller should fail.
  EXPECT_THAT(m.MountCgroupfs("memory"), PosixErrorIs(EBUSY, _))
      << "Memory controller mounted on two hierarchies";

  // Unmount the "all" hierarchy. This should enable any controller to be
  // mounted on a new hierarchy again.
  ASSERT_NO_ERRNO(m.Unmount(all));
  EXPECT_NO_ERRNO(m.MountCgroupfs("memory"));
  EXPECT_NO_ERRNO(m.MountCgroupfs("cpu"));
}

TEST(Cgroup, OnlyContainsControllerSpecificFiles) {
  SKIP_IF(!CgroupsAvailable());
  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup mem = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  EXPECT_THAT(Exists(mem.Relpath("memory.usage_in_bytes")),
              IsPosixErrorOkAndHolds(true));
  // CPU files shouldn't exist in memory cgroups.
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_period_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_quota_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.shares")), IsPosixErrorOkAndHolds(false));

  Cgroup cpu = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.cfs_period_us")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.cfs_quota_us")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.shares")), IsPosixErrorOkAndHolds(true));
  // Memory files shouldn't exist in cpu cgroups.
  EXPECT_THAT(Exists(cpu.Relpath("memory.usage_in_bytes")),
              IsPosixErrorOkAndHolds(false));
}

TEST(Cgroup, InvalidController) {
  SKIP_IF(!CgroupsAvailable());

  TempPath mountpoint = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string mopts = "this-controller-is-invalid";
  EXPECT_THAT(
      mount("none", mountpoint.path().c_str(), "cgroup", 0, mopts.c_str()),
      SyscallFailsWithErrno(EINVAL));
}

TEST(Cgroup, MoptAllMustBeExclusive) {
  SKIP_IF(!CgroupsAvailable());

  TempPath mountpoint = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string mopts = "all,cpu";
  EXPECT_THAT(
      mount("none", mountpoint.path().c_str(), "cgroup", 0, mopts.c_str()),
      SyscallFailsWithErrno(EINVAL));
}

TEST(MemoryCgroup, MemoryUsageInBytes) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  EXPECT_THAT(c.ReadIntegerControlFile("memory.usage_in_bytes"),
              IsPosixErrorOkAndHolds(Gt(0)));
}

TEST(CPUCgroup, ControlFilesHaveDefaultValues) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.cfs_quota_us"),
              IsPosixErrorOkAndHolds(-1));
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.cfs_period_us"),
              IsPosixErrorOkAndHolds(100000));
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.shares"),
              IsPosixErrorOkAndHolds(1024));
}

TEST(ProcCgroups, Empty) {
  SKIP_IF(!CgroupsAvailable());

  absl::flat_hash_map<std::string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  // No cgroups mounted yet, we should have no entries.
  EXPECT_TRUE(entries.empty());
}

TEST(ProcCgroups, ProcCgroupsEntries) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));

  Cgroup mem = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  absl::flat_hash_map<std::string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 1);
  ASSERT_TRUE(entries.contains("memory"));
  CgroupsEntry mem_e = entries["memory"];
  EXPECT_EQ(mem_e.subsys_name, "memory");
  EXPECT_GE(mem_e.hierarchy, 1);
  // Expect a single root cgroup.
  EXPECT_EQ(mem_e.num_cgroups, 1);
  // Cgroups are currently always enabled when mounted.
  EXPECT_TRUE(mem_e.enabled);

  // Add a second cgroup, and check for new entry.

  Cgroup cpu = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 2);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  ASSERT_TRUE(entries.contains("cpu"));
  CgroupsEntry cpu_e = entries["cpu"];
  EXPECT_EQ(cpu_e.subsys_name, "cpu");
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.num_cgroups, 1);
  EXPECT_TRUE(cpu_e.enabled);

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcCgroups, UnmountRemovesEntries) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu,memory"));
  absl::flat_hash_map<std::string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 2);

  ASSERT_NO_ERRNO(m.Unmount(cg));

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_TRUE(entries.empty());
}

TEST(ProcPIDCgroup, Empty) {
  SKIP_IF(!CgroupsAvailable());

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_TRUE(entries.empty());
}

TEST(ProcPIDCgroup, Entries) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_EQ(entries.size(), 1);
  PIDCgroupEntry mem_e = entries["memory"];
  EXPECT_GE(mem_e.hierarchy, 1);
  EXPECT_EQ(mem_e.controllers, "memory");
  EXPECT_EQ(mem_e.path, "/");

  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_EQ(entries.size(), 2);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  PIDCgroupEntry cpu_e = entries["cpu"];
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.controllers, "cpu");
  EXPECT_EQ(cpu_e.path, "/");

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcPIDCgroup, UnmountRemovesEntries) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_GT(entries.size(), 0);

  ASSERT_NO_ERRNO(m.Unmount(all));

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_TRUE(entries.empty());
}

TEST(ProcCgroup, PIDCgroupMatchesCgroups) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));

  absl::flat_hash_map<std::string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  absl::flat_hash_map<std::string, PIDCgroupEntry> pid_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));

  CgroupsEntry cgroup_mem = cgroups_entries["memory"];
  PIDCgroupEntry pid_mem = pid_entries["memory"];

  EXPECT_EQ(cgroup_mem.hierarchy, pid_mem.hierarchy);

  CgroupsEntry cgroup_cpu = cgroups_entries["cpu"];
  PIDCgroupEntry pid_cpu = pid_entries["cpu"];

  EXPECT_EQ(cgroup_cpu.hierarchy, pid_cpu.hierarchy);
  EXPECT_NE(cgroup_mem.hierarchy, cgroup_cpu.hierarchy);
  EXPECT_NE(pid_mem.hierarchy, pid_cpu.hierarchy);
}

TEST(ProcCgroup, MultiControllerHierarchy) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory,cpu"));

  absl::flat_hash_map<std::string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());

  CgroupsEntry mem_e = cgroups_entries["memory"];
  CgroupsEntry cpu_e = cgroups_entries["cpu"];

  // Both controllers should have the same hierarchy ID.
  EXPECT_EQ(mem_e.hierarchy, cpu_e.hierarchy);

  absl::flat_hash_map<std::string, PIDCgroupEntry> pid_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));

  // Expecting an entry listing both controllers, that matches the previous
  // hierarchy ID. Note that the controllers are listed in alphabetical order.
  PIDCgroupEntry pid_e = pid_entries["cpu,memory"];
  EXPECT_EQ(pid_e.hierarchy, mem_e.hierarchy);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
