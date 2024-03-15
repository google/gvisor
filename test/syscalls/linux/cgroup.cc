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

#include <limits.h>
#include <linux/magic.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_split.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"
#include "test/util/cgroup_util.h"
#include "test/util/cleanup.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::Key;
using ::testing::Not;

std::vector<std::string> known_controllers = {
    "cpu", "cpuset", "cpuacct", "devices", "job", "memory", "pids",
};

bool CgroupsAvailable() {
  return IsRunningOnGvisor() &&
         TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN));
}

// NoopThreads spawns a set of threads that do nothing until they're asked to
// exit. Useful for testing functionality that requires a process with multiple
// threads.
class NoopThreads {
 public:
  NoopThreads(int count) {
    auto noop = [this]() { exit_.WaitForNotification(); };

    for (int i = 0; i < count; ++i) {
      threads_.emplace_back(noop);
    }
  }

  ~NoopThreads() { Join(); }

  void Join() {
    if (joined_) {
      return;
    }

    joined_ = true;
    exit_.Notify();
    for (auto& thread : threads_) {
      thread.Join();
    }
  }

 private:
  std::list<ScopedThread> threads_;
  absl::Notification exit_;
  bool joined_ = false;
};

TEST(Cgroup, MountsForAllControllers) {
  SKIP_IF(!CgroupsAvailable());

  for (const auto& ctl : known_controllers) {
    Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/" + ctl);
    EXPECT_NO_ERRNO(c.ContainsCallingProcess());
  }
}

// All supported controllers are mounted by default.
TEST(Cgroup, AllControllersImplicit) {
  SKIP_IF(!CgroupsAvailable());

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

  for (const auto& ctl : known_controllers) {
    Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/" + ctl);
    absl::flat_hash_set<pid_t> pids = ASSERT_NO_ERRNO_AND_VALUE(c.Procs());
    absl::flat_hash_set<pid_t> tids = ASSERT_NO_ERRNO_AND_VALUE(c.Tasks());

    EXPECT_GE(tids.size(), pids.size()) << "Found more processes than threads";

    // Pids should be a strict subset of tids.
    for (auto it = pids.begin(); it != pids.end(); ++it) {
      EXPECT_TRUE(tids.contains(*it))
          << absl::StreamFormat("Have pid %d, but no such tid", *it);
    }
  }
}

TEST(Cgroup, Statfs) {
  SKIP_IF(!CgroupsAvailable());

  for (const auto& ctl : known_controllers) {
    Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/" + ctl);
    struct statfs st;
    EXPECT_THAT(statfs(c.Relpath("cgroup.procs").c_str(), &st),
                SyscallSucceeds());
    EXPECT_EQ(st.f_type, CGROUP_SUPER_MAGIC);

    EXPECT_THAT(statfs(c.Relpath(".").c_str(), &st), SyscallSucceeds());
    EXPECT_EQ(st.f_type, CGROUP_SUPER_MAGIC);
  }
}

TEST(Cgroup, StatfsCgroupDir) {
  SKIP_IF(!CgroupsAvailable());

  struct statfs st;
  EXPECT_THAT(statfs("/sys/fs/cgroup", &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, TMPFS_MAGIC);
}

TEST(Cgroup, CgroupsCannotMountTwice) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  // Cgroups are already mounted.
  EXPECT_THAT(m.MountCgroupfs(""), PosixErrorIs(EBUSY, _))
      << "Cgroups are already mounted";
}

TEST(Cgroup, OnlyContainsControllerSpecificFiles) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup mem = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  EXPECT_THAT(Exists(mem.Relpath("memory.usage_in_bytes")),
              IsPosixErrorOkAndHolds(true));
  // CPU files shouldn't exist in memory cgroups.
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_period_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_quota_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.shares")), IsPosixErrorOkAndHolds(false));

  Cgroup cpu = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");
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

TEST(Cgroup, UnmountRepeated) {
  SKIP_IF(!CgroupsAvailable());

  const DisableSave ds;  // Too many syscalls.

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");

  // First unmount should succeed.
  EXPECT_THAT(umount(c.Path().c_str()), SyscallSucceeds());
  EXPECT_THAT(umount(c.Path().c_str()), SyscallFailsWithErrno(EINVAL));
}

TEST(Cgroup, Create) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  ASSERT_NO_ERRNO(c.CreateChild("child1"));
  EXPECT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(Exists(c.Path())));
}

TEST(Cgroup, SubcontainerInitiallyEmpty) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child1"));
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.empty());
}

TEST(Cgroup, SubcontainersHaveIndependentState) {
  SKIP_IF(!CgroupsAvailable());
  // Use the job cgroup as a simple cgroup with state we can modify.
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/job");

  // Initially job.id should be the default value of 0.
  EXPECT_THAT(c.ReadIntegerControlFile("job.id"), IsPosixErrorOkAndHolds(0));

  // Set id so it is no longer the default.
  ASSERT_NO_ERRNO(c.WriteIntegerControlFile("job.id", 1234));

  // Create a child. The child should inherit the value from the parent, and not
  // the default value of 0.
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child1"));
  EXPECT_THAT(child.ReadIntegerControlFile("job.id"),
              IsPosixErrorOkAndHolds(1234));

  // Setting the parent doesn't change the child.
  ASSERT_NO_ERRNO(c.WriteIntegerControlFile("job.id", 5678));
  EXPECT_THAT(child.ReadIntegerControlFile("job.id"),
              IsPosixErrorOkAndHolds(1234));

  // Likewise, setting the child doesn't change the parent.
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("job.id", 9012));
  EXPECT_THAT(c.ReadIntegerControlFile("job.id"), IsPosixErrorOkAndHolds(5678));
}

TEST(Cgroup, MigrateToSubcontainer) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child1"));

  // Initially, test process should be in the root cgroup c.
  EXPECT_NO_ERRNO(c.ContainsCallingProcess());

  pid_t pid = getpid();

  EXPECT_NO_ERRNO(child.Enter(pid));

  // After migration, child should contain the test process, and the c should
  // not.
  EXPECT_NO_ERRNO(child.ContainsCallingProcess());
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(c.Procs());
  EXPECT_FALSE(procs.contains(pid));
}

TEST(Cgroup, MigrateToSubcontainerThread) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child1"));

  // Ensure there are some threads for this process.
  NoopThreads threads(10);

  // Initially, test process should be in the root cgroup c.
  EXPECT_NO_ERRNO(c.ContainsCallingThread());

  const pid_t tid = syscall(SYS_gettid);

  EXPECT_NO_ERRNO(child.EnterThread(tid));

  // After migration, child should contain the test process, and the c should
  // not.
  EXPECT_NO_ERRNO(child.ContainsCallingThread());
  auto tasks = ASSERT_NO_ERRNO_AND_VALUE(c.Tasks());
  EXPECT_FALSE(tasks.contains(tid));
}

TEST(Cgroup, MigrateInvalidPID) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");

  EXPECT_THAT(c.WriteControlFile("cgroup.procs", "-1"), PosixErrorIs(EINVAL));
  EXPECT_THAT(c.WriteControlFile("cgroup.procs", "not-a-number"),
              PosixErrorIs(EINVAL));

  EXPECT_THAT(c.WriteControlFile("tasks", "-1"), PosixErrorIs(EINVAL));
  EXPECT_THAT(c.WriteControlFile("tasks", "not-a-number"),
              PosixErrorIs(EINVAL));
}

// Regression test for b/222278194.
TEST(Cgroup, DuplicateUnlinkOnDirFD) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuset");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Orphan child directory by opening FD to it then deleting it.
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), 0, 0));
  ASSERT_NO_ERRNO(child.Delete());

  // Replace orphan with new directory of same name, so path resolution
  // succeeds.
  Cgroup child_new = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Attempt to delete orphaned child again through dirfd.
  EXPECT_THAT(UnlinkAt(dirfd, ".", AT_REMOVEDIR), PosixErrorIs(EINVAL));
}

TEST(Cgroup, MkdirWithPermissions) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuset");

  std::string child1_path = JoinPath(c.Path(), "child1");
  std::string child2_path = JoinPath(c.Path(), "child2");

  ASSERT_NO_ERRNO(Mkdir(child1_path, 0444));
  const struct stat s1 = ASSERT_NO_ERRNO_AND_VALUE(Stat(child1_path));
  EXPECT_THAT(s1.st_mode, PermissionIs(0444));
  EXPECT_TRUE(S_ISDIR(s1.st_mode));

  ASSERT_NO_ERRNO(Mkdir(child2_path, 0));
  const struct stat s2 = ASSERT_NO_ERRNO_AND_VALUE(Stat(child2_path));
  EXPECT_THAT(s2.st_mode, PermissionIs(0000));
  EXPECT_TRUE(S_ISDIR(s2.st_mode));
}

TEST(Cgroup, CantRenameControlFile) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");

  const std::string control_file_path = c.Relpath("cgroup.procs");
  EXPECT_THAT(
      rename(c.Relpath("cgroup.procs").c_str(), c.Relpath("foo").c_str()),
      SyscallFailsWithErrno(ENOTDIR));
}

TEST(Cgroup, CrossDirRenameNotAllowed) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");

  Cgroup dir1 = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("dir1"));
  Cgroup dir2 = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("dir2"));

  Cgroup target = ASSERT_NO_ERRNO_AND_VALUE(dir1.CreateChild("target"));
  // Move to sibling directory.
  EXPECT_THAT(rename(target.Path().c_str(), dir2.Relpath("target").c_str()),
              SyscallFailsWithErrno(EIO));
  // Move to parent directory.
  EXPECT_THAT(rename(target.Path().c_str(), c.Relpath("target").c_str()),
              SyscallFailsWithErrno(EIO));

  // Original directory unaffected.
  EXPECT_THAT(Exists(target.Path()), IsPosixErrorOkAndHolds(true));
}

TEST(Cgroup, RenameNameCollision) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");

  Cgroup dir1 = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("dir1"));
  Cgroup dir2 = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("dir2"));

  // Collision with dir.
  EXPECT_THAT(rename(dir1.Path().c_str(), dir2.Path().c_str()),
              SyscallFailsWithErrno(EEXIST));
  // Collision with control file.
  EXPECT_THAT(rename(dir1.Path().c_str(), c.Relpath("cgroup.procs").c_str()),
              SyscallFailsWithErrno(EEXIST));
}

TEST(Cgroup, Rename) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));
  Cgroup target = ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("oldname"));
  ASSERT_THAT(rename(target.Path().c_str(), child.Relpath("newname").c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(child.Relpath("newname")), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(child.Relpath("oldname")), IsPosixErrorOkAndHolds(false));
}

TEST(Cgroup, PIDZeroMovesSelf) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Source contains this process.
  EXPECT_NO_ERRNO(c.ContainsCallingProcess());

  // Move to child by writing PID 0.
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("cgroup.procs", 0));

  // Destination now contains this process, and source does not.
  EXPECT_NO_ERRNO(child.ContainsCallingProcess());
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(c.Procs());
  EXPECT_FALSE(procs.contains(getpid()));
}

TEST(Cgroup, TIDZeroMovesSelf) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Source contains this thread.
  EXPECT_NO_ERRNO(c.ContainsCallingThread());

  // Move to child by writing TID 0.
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("tasks", 0));

  // Destination now contains this thread, and source does not.
  EXPECT_NO_ERRNO(child.ContainsCallingThread());
  auto tasks = ASSERT_NO_ERRNO_AND_VALUE(c.Tasks());
  EXPECT_FALSE(tasks.contains(syscall(SYS_gettid)));
}

TEST(Cgroup, NamedHierarchies) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("none,name=h1"));
  Cgroup c2 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("none,name=h2"));

  // Check that /proc/<pid>/cgroup contains an entry for this task.
  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_TRUE(entries.contains("name=h1"));
  EXPECT_TRUE(entries.contains("name=h2"));
  EXPECT_NO_ERRNO(c1.ContainsCallingProcess());
  EXPECT_NO_ERRNO(c2.ContainsCallingProcess());
}

TEST(Cgroup, NoneExclusiveWithAnyController) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  EXPECT_THAT(m.MountCgroupfs("none,cpu"), PosixErrorIs(EINVAL, _));
}

TEST(Cgroup, EmptyHierarchyMustHaveName) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  // This will fail since it is an empty hierarchy with no name.
  EXPECT_THAT(m.MountCgroupfs("none"), PosixErrorIs(EINVAL, _));
}

TEST(Cgroup, NameMatchButControllersDont) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("none,name=h1"));
  EXPECT_THAT(m.MountCgroupfs("name=h2,memory"), PosixErrorIs(EBUSY, _));
  EXPECT_THAT(m.MountCgroupfs("name=h1,memory"), PosixErrorIs(EBUSY, _));
  EXPECT_THAT(m.MountCgroupfs("name=h2,cpu"), PosixErrorIs(EBUSY, _));
}

TEST(MemoryCgroup, MemoryUsageInBytes) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  const uint64_t usage = ASSERT_NO_ERRNO_AND_VALUE(
      c.ReadIntegerControlFile("memory.usage_in_bytes"));
  EXPECT_GE(usage, 0);
}

TEST(CPUCgroup, ControlFilesHaveDefaultValues) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.cfs_quota_us"),
              IsPosixErrorOkAndHolds(-1));
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.cfs_period_us"),
              IsPosixErrorOkAndHolds(100000));
  EXPECT_THAT(c.ReadIntegerControlFile("cpu.shares"),
              IsPosixErrorOkAndHolds(1024));
}

TEST(CPUAcctCgroup, CPUAcctUsage) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  const int64_t usage =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t usage_user =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpuacct.usage_user"));
  const int64_t usage_sys =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpuacct.usage_sys"));

  EXPECT_GE(usage, 0);
  EXPECT_GE(usage_user, 0);
  EXPECT_GE(usage_sys, 0);

  EXPECT_GE(usage_user + usage_sys, usage);
}

TEST(CPUAcctCgroup, CPUAcctStat) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  std::string stat =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuacct.stat"));

  // We're expecting the contents of "cpuacct.stat" to look similar to this:
  //
  // user 377986
  // system 220662

  std::vector<absl::string_view> lines =
      absl::StrSplit(stat, '\n', absl::SkipEmpty());
  ASSERT_EQ(lines.size(), 2);

  std::vector<absl::string_view> user_tokens =
      StrSplit(lines[0], absl::ByChar(' '));
  EXPECT_EQ(user_tokens[0], "user");
  EXPECT_THAT(Atoi<int64_t>(user_tokens[1]), IsPosixErrorOkAndHolds(Ge(0)));

  std::vector<absl::string_view> sys_tokens =
      StrSplit(lines[1], absl::ByChar(' '));
  EXPECT_EQ(sys_tokens[0], "system");
  EXPECT_THAT(Atoi<int64_t>(sys_tokens[1]), IsPosixErrorOkAndHolds(Ge(0)));
}

TEST(CPUAcctCgroup, HierarchicalAccounting) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup root = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("child1"));

  // The test starts in the root cgroup, so its CPU usage should be accounted
  // there. Since the granularity of cpuacct.usage is unspecified and the test
  // may not have run for very long yet, wait for it to be accounted.
  ASSERT_NO_ERRNO(
      root.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));
  EXPECT_THAT(root.ReadIntegerControlFile("cpuacct.usage"),
              IsPosixErrorOkAndHolds(Gt(0)));

  // Child should have zero usage since it is initially empty.
  EXPECT_THAT(child.ReadIntegerControlFile("cpuacct.usage"),
              IsPosixErrorOkAndHolds(Eq(0)));

  // Move test into child and confirm child starts incurring usage.
  const int64_t before_move =
      ASSERT_NO_ERRNO_AND_VALUE(root.ReadIntegerControlFile("cpuacct.usage"));
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  ASSERT_NO_ERRNO(
      child.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  EXPECT_THAT(child.ReadIntegerControlFile("cpuacct.usage"),
              IsPosixErrorOkAndHolds(Gt(0)));

  // Root shouldn't lose usage due to the migration.
  const int64_t after_move =
      ASSERT_NO_ERRNO_AND_VALUE(root.ReadIntegerControlFile("cpuacct.usage"));
  EXPECT_GE(after_move, before_move);

  // Root should continue to gain usage after the move since child is a
  // subcgroup.
  ASSERT_NO_ERRNO(
      child.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));
  EXPECT_THAT(root.ReadIntegerControlFile("cpuacct.usage"),
              IsPosixErrorOkAndHolds(Ge(after_move)));
}

TEST(CPUAcctCgroup, IndirectCharge) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup root = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  Cgroup child1 = ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("child1"));
  Cgroup child2 = ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("child2"));
  Cgroup child2a = ASSERT_NO_ERRNO_AND_VALUE(child2.CreateChild("child2a"));

  ASSERT_NO_ERRNO(child1.Enter(getpid()));
  ASSERT_NO_ERRNO(
      child1.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  // Only root and child1 should have usage.
  for (auto const& cg : {root, child1}) {
    EXPECT_THAT(cg.ReadIntegerControlFile("cpuacct.usage"),
                IsPosixErrorOkAndHolds(Gt(0)));
  }
  for (auto const& cg : {child2, child2a}) {
    EXPECT_THAT(cg.ReadIntegerControlFile("cpuacct.usage"),
                IsPosixErrorOkAndHolds(Eq(0)));
  }

  ASSERT_NO_ERRNO(child2a.Enter(getpid()));
  ASSERT_NO_ERRNO(
      child2a.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  const int64_t snapshot_root =
      ASSERT_NO_ERRNO_AND_VALUE(root.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t snapshot_child1 =
      ASSERT_NO_ERRNO_AND_VALUE(child1.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t snapshot_child2 =
      ASSERT_NO_ERRNO_AND_VALUE(child2.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t snapshot_child2a = ASSERT_NO_ERRNO_AND_VALUE(
      child2a.ReadIntegerControlFile("cpuacct.usage"));

  ASSERT_NO_ERRNO(
      child2a.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  // Root, child2 and child2a should've accumulated new usage. Child1 should
  // not.
  const int64_t now_root =
      ASSERT_NO_ERRNO_AND_VALUE(root.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t now_child1 =
      ASSERT_NO_ERRNO_AND_VALUE(child1.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t now_child2 =
      ASSERT_NO_ERRNO_AND_VALUE(child2.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t now_child2a = ASSERT_NO_ERRNO_AND_VALUE(
      child2a.ReadIntegerControlFile("cpuacct.usage"));

  EXPECT_GT(now_root, snapshot_root);
  EXPECT_GT(now_child2, snapshot_child2);
  EXPECT_GT(now_child2a, snapshot_child2a);
  EXPECT_EQ(now_child1, snapshot_child1);
}

TEST(CPUAcctCgroup, NoDoubleAccounting) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup root = Cgroup::RootCgroup("/sys/fs/cgroup/cpuacct");
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("parent"));
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("a"));
  Cgroup b = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("b"));

  ASSERT_NO_ERRNO(a.Enter(getpid()));
  ASSERT_NO_ERRNO(
      a.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  ASSERT_NO_ERRNO(b.Enter(getpid()));
  ASSERT_NO_ERRNO(
      b.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  ASSERT_NO_ERRNO(root.Enter(getpid()));
  ASSERT_NO_ERRNO(
      root.PollControlFileForChange("cpuacct.usage", absl::Seconds(5)));

  // The usage for parent, a & b should now be frozen, since they no longer have
  // any tasks. Root will continue to accumulate usage.
  const int64_t usage_root =
      ASSERT_NO_ERRNO_AND_VALUE(root.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t usage_parent =
      ASSERT_NO_ERRNO_AND_VALUE(parent.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t usage_a =
      ASSERT_NO_ERRNO_AND_VALUE(a.ReadIntegerControlFile("cpuacct.usage"));
  const int64_t usage_b =
      ASSERT_NO_ERRNO_AND_VALUE(b.ReadIntegerControlFile("cpuacct.usage"));

  EXPECT_GT(usage_root, 0);
  EXPECT_GT(usage_parent, 0);
  EXPECT_GT(usage_a, 0);
  EXPECT_GT(usage_b, 0);
  EXPECT_EQ(usage_parent, usage_a + usage_b);
  EXPECT_GE(usage_parent, usage_a);
  EXPECT_GE(usage_parent, usage_b);
  EXPECT_GE(usage_root, usage_parent);
}

// WriteAndVerifyControlValue attempts to write val to a cgroup file at path,
// and verify the value by reading it afterwards.
PosixError WriteAndVerifyControlValue(const Cgroup& c, absl::string_view path,
                                      int64_t val) {
  RETURN_IF_ERRNO(c.WriteIntegerControlFile(path, val));
  ASSIGN_OR_RETURN_ERRNO(int64_t newval, c.ReadIntegerControlFile(path));
  if (newval != val) {
    return PosixError(
        EINVAL,
        absl::StrFormat(
            "Unexpected value for control file '%s': expected %d, got %d", path,
            val, newval));
  }
  return NoError();
}

PosixErrorOr<std::vector<bool>> ParseBitmap(std::string s) {
  std::vector<bool> bitmap;
  bitmap.reserve(64);
  for (const absl::string_view& t : absl::StrSplit(s, ',')) {
    std::vector<std::string> parts = absl::StrSplit(t, absl::MaxSplits('-', 2));
    if (parts.size() == 2) {
      ASSIGN_OR_RETURN_ERRNO(uint64_t start, Atoi<uint64_t>(parts[0]));
      ASSIGN_OR_RETURN_ERRNO(uint64_t end, Atoi<uint64_t>(parts[1]));
      // Note: start and end are indices into bitmap.
      if (end >= bitmap.size()) {
        bitmap.resize(end + 1, false);
      }
      for (uint64_t i = start; i <= end; ++i) {
        bitmap[i] = true;
      }
    } else {  // parts.size() == 1, 0 not possible.
      ASSIGN_OR_RETURN_ERRNO(uint64_t i, Atoi<uint64_t>(parts[0]));
      if (i >= bitmap.size()) {
        bitmap.resize(i + 1, false);
      }
      bitmap[i] = true;
    }
  }
  return bitmap;
}

TEST(JobCgroup, ReadWriteRead) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/job");

  EXPECT_THAT(c.ReadIntegerControlFile("job.id"), IsPosixErrorOkAndHolds(0));
  EXPECT_NO_ERRNO(WriteAndVerifyControlValue(c, "job.id", 1234));
  EXPECT_NO_ERRNO(WriteAndVerifyControlValue(c, "job.id", -1));
  EXPECT_NO_ERRNO(WriteAndVerifyControlValue(c, "job.id", LLONG_MIN));
  EXPECT_NO_ERRNO(WriteAndVerifyControlValue(c, "job.id", LLONG_MAX));
}

TEST(CpusetCgroup, Defaults) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuset");
  std::string cpus =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.cpus"));
  std::vector<bool> cpus_bitmap = ASSERT_NO_ERRNO_AND_VALUE(ParseBitmap(cpus));
  EXPECT_GT(cpus_bitmap.size(), 0);
  EXPECT_THAT(cpus_bitmap, Each(Eq(true)));

  std::string mems =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.mems"));
  std::vector<bool> mems_bitmap = ASSERT_NO_ERRNO_AND_VALUE(ParseBitmap(mems));
  EXPECT_GT(mems_bitmap.size(), 0);
  EXPECT_THAT(mems_bitmap, Each(Eq(true)));
}

TEST(CpusetCgroup, SetMask) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuset");
  std::string cpus =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.cpus"));
  std::vector<bool> cpus_bitmap = ASSERT_NO_ERRNO_AND_VALUE(ParseBitmap(cpus));

  SKIP_IF(cpus_bitmap.size() <= 1);  // "Not enough CPUs"

  int max_cpu = cpus_bitmap.size() - 1;
  ASSERT_NO_ERRNO(
      c.WriteControlFile("cpuset.cpus", absl::StrCat("1-", max_cpu)));
  cpus_bitmap[0] = false;
  cpus = ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.cpus"));
  std::vector<bool> cpus_bitmap_after =
      ASSERT_NO_ERRNO_AND_VALUE(ParseBitmap(cpus));
  EXPECT_EQ(cpus_bitmap_after, cpus_bitmap);
}

TEST(CpusetCgroup, SetEmptyMask) {
  SKIP_IF(!CgroupsAvailable());
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/cpuset");
  ASSERT_NO_ERRNO(c.WriteControlFile("cpuset.cpus", ""));
  std::string_view cpus = absl::StripAsciiWhitespace(
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.cpus")));
  EXPECT_EQ(cpus, "");
  ASSERT_NO_ERRNO(c.WriteControlFile("cpuset.mems", ""));
  std::string_view mems = absl::StripAsciiWhitespace(
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.mems")));
  EXPECT_EQ(mems, "");
}

TEST(ProcCgroups, Empty) {
  SKIP_IF(!CgroupsAvailable());

  absl::flat_hash_map<std::string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  // Cgroups are mounted, we should have entries.
  EXPECT_FALSE(entries.empty());
}

TEST(ProcCgroups, ProcCgroupsEntries) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup mem = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  absl::flat_hash_map<std::string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 7);
  ASSERT_TRUE(entries.contains("memory"));
  CgroupsEntry mem_e = entries["memory"];
  EXPECT_EQ(mem_e.subsys_name, "memory");
  EXPECT_GE(mem_e.hierarchy, 1);
  // Expect a single root cgroup.
  EXPECT_EQ(mem_e.num_cgroups, 2);
  // Cgroups are currently always enabled when mounted.
  EXPECT_TRUE(mem_e.enabled);

  // Add a second cgroup, and check for new entry.

  Cgroup cpu = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 7);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  ASSERT_TRUE(entries.contains("cpu"));
  CgroupsEntry cpu_e = entries["cpu"];
  EXPECT_EQ(cpu_e.subsys_name, "cpu");
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.num_cgroups, 2);
  EXPECT_TRUE(cpu_e.enabled);

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcPIDCgroup, Entries) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  // All controllers are mounted.
  EXPECT_EQ(entries.size(), 7);
  PIDCgroupEntry mem_e = entries["memory"];
  EXPECT_GE(mem_e.hierarchy, 1);
  EXPECT_EQ(mem_e.controllers, "memory");
  // The path is /<container-id>.
  EXPECT_NE(mem_e.path, "/");

  Cgroup c1 = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  // All controllers are mounted.
  EXPECT_EQ(entries.size(), 7);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  PIDCgroupEntry cpu_e = entries["cpu"];
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.controllers, "cpu");
  // The path is /<container-id>.
  EXPECT_NE(cpu_e.path, "/");

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcCgroup, PIDCgroupMatchesCgroups) {
  SKIP_IF(!CgroupsAvailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/memory");
  Cgroup c1 = Cgroup::RootCgroup("/sys/fs/cgroup/cpu");

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

TEST(PIDsCgroup, ControlFilesExist) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/pids");

  const std::string root_limit =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("pids.max"));
  EXPECT_EQ(root_limit, "max\n");

  // There should be at least one PID in use in the root controller, since the
  // test process is running in the root controller.
  const int64_t current =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("pids.current"));
  EXPECT_GE(current, 1);

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // The limit file should exist for any child cgroups, and should be unlimited
  // by default.
  const std::string child_limit =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadControlFile("pids.max"));
  EXPECT_EQ(child_limit, "max\n");

  // The child cgroup should have no tasks, and thus no pids usage.
  const int64_t current_child =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadIntegerControlFile("pids.current"));
  EXPECT_EQ(current_child, 0);
}

TEST(PIDsCgroup, ChargeMigration) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/pids");
  const int64_t root_start =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("pids.current"));
  // Root should have at least one task.
  ASSERT_GE(root_start, 1);

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Child initially has no charge.
  EXPECT_THAT(child.ReadIntegerControlFile("pids.current"),
              IsPosixErrorOkAndHolds(0));

  // Move the test process. The root cgroup should lose charges equal to the
  // number of tasks moved to the child.
  ASSERT_NO_ERRNO(child.Enter(getpid()));

  const int64_t child_after =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadIntegerControlFile("pids.current"));
  EXPECT_GE(child_after, 1);

  const int64_t root_after =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("pids.current"));
  EXPECT_EQ(root_start - root_after, child_after);
}

TEST(PIDsCgroup, MigrationCanExceedLimit) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/pids");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Set child limit to 0, and try move tasks into it. This should be allowed,
  // as the limit isn't enforced on migration.
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("pids.max", 0));
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_THAT(child.ReadIntegerControlFile("pids.current"),
              IsPosixErrorOkAndHolds(Gt(0)));
}

TEST(PIDsCgroup, SetInvalidLimit) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/pids");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));

  // Set a valid limit, so we can verify it doesn't change after invalid writes.
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("pids.max", 1234));

  EXPECT_THAT(child.WriteControlFile("pids.max", "m a x"),
              PosixErrorIs(EINVAL, _));
  EXPECT_THAT(child.WriteControlFile("pids.max", "some-invalid-string"),
              PosixErrorIs(EINVAL, _));
  EXPECT_THAT(child.WriteControlFile("pids.max", "-1"),
              PosixErrorIs(EINVAL, _));
  EXPECT_THAT(child.WriteControlFile("pids.max", "-3894732"),
              PosixErrorIs(EINVAL, _));
  // This value is much larger than the maximum allowed value of ~ 1<<22.
  EXPECT_THAT(child.WriteIntegerControlFile("pids.max", LLONG_MAX - 1),
              PosixErrorIs(EINVAL, _));

  // The initial valid limit should remain unchanged.
  EXPECT_THAT(child.ReadIntegerControlFile("pids.max"),
              IsPosixErrorOkAndHolds(1234));
}

TEST(PIDsCgroup, CanLowerLimitBelowCurrentCharge) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/pids");
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c.CreateChild("child"));
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  // Confirm current charge is non-zero.
  ASSERT_THAT(child.ReadIntegerControlFile("pids.current"),
              IsPosixErrorOkAndHolds(Gt(0)));
  // Try set limit to zero.
  EXPECT_NO_ERRNO(child.WriteIntegerControlFile("pids.max", 0));
}

TEST(DevicesCgroup, ControlFilesExist) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/devices");

  // The root group starts with allowing rwm to all.
  EXPECT_THAT(c.ReadControlFile("devices.allow"), IsPosixErrorOkAndHolds(""));
  EXPECT_THAT(c.ReadControlFile("devices.deny"), IsPosixErrorOkAndHolds(""));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("a *:* rwm"));
}

TEST(DevicesCgroup, DenyAll) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/devices");

  ASSERT_NO_ERRNO(c.WriteControlFile("devices.allow", "b *:* rw\n"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("b *:* rw\n"));

  ASSERT_NO_ERRNO(c.WriteControlFile("devices.deny", "a"));
  EXPECT_THAT(c.ReadControlFile("devices.list"), IsPosixErrorOkAndHolds(""));
}

TEST(DevicesCgroup, AddDeviceRule) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/devices");

  ASSERT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("a *:* rwm"));
  // Gives character devices with major device number 7 read and write
  // permission.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.allow", "c 7:* rw\n"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* rw\n"));

  // Diasllows all devices.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.deny", "a"));
  EXPECT_THAT(c.ReadControlFile("devices.list"), IsPosixErrorOkAndHolds(""));

  // Adds one more rule.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.allow", "b *:* rw\n"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("b *:* rw\n"));
}

TEST(DevicesCgroup, RemoveDeviceRule) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/devices");
  // The root group starts with allowing rwm to all.
  ASSERT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("a *:* rwm"));
  // Gives character devices with the major device number 7 read and write
  // permission.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.allow", "c 7:* rw"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* rw\n"));

  // Removes the write permission from the character devices with the major
  // device number 7.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.deny", "c 7:* w"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* r\n"));
}

TEST(DevicesCgroup, IgnorePartialMatchRule) {
  SKIP_IF(!CgroupsAvailable());

  Cgroup c = Cgroup::RootCgroup("/sys/fs/cgroup/devices");

  // Gives character devices with the major device number 7 read and write
  // permission.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.allow", "c 7:* rw"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* rw\n"));

  // Expect no change to the allow list since minor device matches partially a
  // exsting rule for character devices 7:*.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.deny", "c 7:0 w"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* rw\n"));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
