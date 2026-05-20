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
#include <poll.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cgroup_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
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
using ::testing::HasSubstr;
using ::testing::Key;
using ::testing::Not;

std::vector<std::string> known_controllers = {
    "cpu", "cpuset", "cpuacct", "devices", "job", "memory", "pids",
};

bool CgroupsAvailable() {
  return IsRunningOnGvisor() &&
         TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN));
}

bool Cgroup2Available() {
  return !IsRunningOnGvisor() &&
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
  std::string cpus = std::string(absl::StripAsciiWhitespace(
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.cpus"))));
  EXPECT_EQ(cpus, "");
  ASSERT_NO_ERRNO(c.WriteControlFile("cpuset.mems", ""));
  std::string mems = std::string(absl::StripAsciiWhitespace(
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadControlFile("cpuset.mems"))));
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
  // existing rule for character devices 7:*.
  ASSERT_NO_ERRNO(c.WriteControlFile("devices.deny", "c 7:0 w"));
  EXPECT_THAT(c.ReadControlFile("devices.list"),
              IsPosixErrorOkAndHolds("c 7:* rw\n"));
}

class Cgroup2Test : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!Cgroup2Available()) {
      GTEST_SKIP() << "Cgroup v2 not available or ignored on gVisor";
    }
  }

  void CleanCgroupDirs(absl::string_view dir) {
    auto children = ListDir(dir, /*skipdots=*/true);
    if (children.ok()) {
      for (const auto& child : children.ValueOrDie()) {
        std::string full_path = JoinPath(dir, child);
        auto is_dir = IsDirectory(full_path);
        if (is_dir.ok() && is_dir.ValueOrDie()) {
          CleanCgroupDirs(full_path);
        }
      }
    }
    absl::Time deadline = absl::Now() + absl::Seconds(5);
    PosixError err;
    while (true) {
      err = Rmdir(dir);
      if (err.ok()) {
        break;
      }
      if (absl::Now() >= deadline) {
        ASSERT_NO_ERRNO(err);
        break;
      }
      absl::SleepFor(absl::Milliseconds(10));
    }
  }

  void TearDown() override {
    if (root_) {
      root_->Enter(getpid()).IgnoreError();
    }
    if (c_) {
      CleanCgroupDirs(c_->Path());
    }
  }

  void Init() {
    if (m_) return;
    m_.emplace(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    root_.emplace(ASSERT_NO_ERRNO_AND_VALUE(m_->MountCgroup2fs()));

    auto controllers = root_->ReadControlFile("cgroup.controllers");
    if (controllers.ok()) {
      std::vector<std::string> list = absl::StrSplit(
          controllers.ValueOrDie(), absl::ByAnyChar(" \n"), absl::SkipEmpty());
      for (const std::string& ctrl : list) {
        ASSERT_NO_ERRNO(
            root_->WriteControlFile("cgroup.subtree_control", "+" + ctrl));
      }
    }

    c_.emplace(ASSERT_NO_ERRNO_AND_VALUE(root_->CreateChild("test")));
  }

  const Cgroup& c() {
    Init();
    return *c_;
  }

  const Cgroup& root() {
    Init();
    return *root_;
  }

  void ExpectInotifyEventOrTimeout(int fd) {
    struct pollfd pfd = {fd, POLLIN, 0};
    ASSERT_GT(poll(&pfd, 1, 5000), 0);
    char buf[4096];
    EXPECT_GT(read(fd, buf, sizeof(buf)), 0);
  }

  void ExpectDefaultControlFiles(const Cgroup& cg, bool is_root = false) {
    EXPECT_THAT(Exists(cg.Relpath("cgroup.procs")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.controllers")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.subtree_control")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.stat")),
                IsPosixErrorOkAndHolds(true));
    if (!is_root) {
      EXPECT_THAT(Exists(cg.Relpath("cgroup.events")),
                  IsPosixErrorOkAndHolds(true));
      EXPECT_THAT(Exists(cg.Relpath("cgroup.type")),
                  IsPosixErrorOkAndHolds(true));
      EXPECT_THAT(Exists(cg.Relpath("cgroup.kill")),
                  IsPosixErrorOkAndHolds(true));
    }
  }

 private:
  std::optional<Mounter> m_;
  std::optional<Cgroup> root_;
  std::optional<Cgroup> c_;
};

TEST_F(Cgroup2Test, RootControlFilesPopulated) {
  ExpectDefaultControlFiles(c(), /*is_root=*/true);
}

TEST_F(Cgroup2Test, Create) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child1"));
  EXPECT_THAT(Exists(child.Path()), IsPosixErrorOkAndHolds(true));
  ExpectDefaultControlFiles(child, /*is_root=*/false);

  // Defaults.
  EXPECT_THAT(child.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain")));
  EXPECT_THAT(child.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Eq("")));
  EXPECT_THAT(child.ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 0")));

  // No tasks.
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.empty());
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
}

TEST_F(Cgroup2Test, MkdirWithPermissions) {
  std::string child_path = JoinPath(c().Path(), "child");
  ASSERT_NO_ERRNO(Mkdir(child_path, 0444));

  const struct stat s1 = ASSERT_NO_ERRNO_AND_VALUE(Stat(child_path));
  EXPECT_THAT(s1.st_mode, PermissionIs(0444));
  EXPECT_TRUE(S_ISDIR(s1.st_mode));
}

TEST_F(Cgroup2Test, CannotRenameControlFile) {
  EXPECT_THAT(
      rename(c().Relpath("cgroup.procs").c_str(), c().Relpath("foo").c_str()),
      SyscallFailsWithErrno(EPERM));
}

TEST_F(Cgroup2Test, CannotMountOverBusy) {
  EXPECT_THAT(Mount("none", root().Path(), "cgroup2", 0, "", 0),
              PosixErrorIs(EBUSY));
}

TEST_F(Cgroup2Test, DestroyConstraints) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));

  // Cannot destroy a cgroup node that has a live sub-directory.
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  EXPECT_THAT(parent.Delete(), PosixErrorIs(EBUSY));

  // Cannot destroy a cgroup node with a live attached process.
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_THAT(child.Delete(), PosixErrorIs(EBUSY));

  // Destroy successfully once leaf node is empty.
  ASSERT_NO_ERRNO(root().Enter(getpid()));
  clean.Release();
  EXPECT_NO_ERRNO(child.Delete());
  EXPECT_NO_ERRNO(parent.Delete());
}

TEST_F(Cgroup2Test, CannotEnableControllerDisabledInParent) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  EXPECT_THAT(parent.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Not(HasSubstr("pids"))));

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  EXPECT_THAT(child.WriteControlFile("cgroup.subtree_control", "+pids"),
              PosixErrorIs(ENOENT));
}

TEST_F(Cgroup2Test, CannotDisableControllerEnabledInChild) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "+pids"));
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "-pids"),
              PosixErrorIs(EBUSY));

  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "-pids"));
  EXPECT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "-pids"));
}

TEST_F(Cgroup2Test, SubtreeControlPids) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // Once we enabled "pids" in the parent...
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  auto clean = Cleanup([&] {
    c().WriteControlFile("cgroup.subtree_control", "-pids").IgnoreError();
  });
  // ...it becomes available in the child.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));
  ExpectDefaultControlFiles(child);
  EXPECT_THAT(Exists(child.Relpath("pids.max")), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(::testing::HasSubstr("pids")));

  // Invalid writes to the subtree_control file must fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "+garbage"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "pids"),
              PosixErrorIs(EINVAL));
  // Attempting to write to the read-only cgroup.controllers list must fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.controllers", "+pids"),
              PosixErrorIs(EINVAL));

  // Disabling a controller in the parent makes it unavailable in the child.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "-pids"));
  EXPECT_THAT(Exists(child.Relpath("pids.max")), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(Not(HasSubstr("pids"))));
}

TEST_F(Cgroup2Test, PidsEnforcement) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);
  ASSERT_NO_ERRNO(child.WriteControlFile("pids.max", "1"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  constexpr int kCantFork = 2;
  pid_t pid = fork();
  if (pid == 0) {
    wfd.reset();
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    pid_t grand_pid = fork();
    if (grand_pid < 0) {
      _exit(kCantFork);
    } else if (grand_pid == 0) {
      _exit(0);
    }
    _exit(3);
  }
  rfd.reset();
  ASSERT_GT(pid, 0);

  ASSERT_NO_ERRNO(child.Enter(pid));
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), kCantFork);
}

TEST_F(Cgroup2Test, NoInternalProcesses) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "memory"));
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));
  auto clean_mem = Cleanup([&] {
    c().WriteControlFile("cgroup.subtree_control", "-memory").IgnoreError();
  });
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // A cgroup may contain both member child cgroups and member processes
  // as long as no controllers are enabled in its subtree_control.
  ASSERT_THAT(parent.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Eq("")));
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(parent.Enter(getpid()));

  // Attempting to subsequently enable any resource controllers while
  // member processes exist should fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "+memory"),
              PosixErrorIs(EBUSY));

  // Moving the process down into the sub-cgroup renders the parent empty,
  // allowing us to enable controllers in the parent.
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_TRUE(
      parent.WriteControlFile("cgroup.subtree_control", "+memory").ok());

  // Finally, moving the process back up into the parent is now
  // strictly denied by the rule since subtree_control is active/non-empty.
  EXPECT_THAT(parent.Enter(getpid()), PosixErrorIs(EBUSY));
}

TEST_F(Cgroup2Test, PIDZeroMovesSelf) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("cgroup.procs", 0));

  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.contains(getpid()));

  std::string content;
  ASSERT_NO_ERRNO(GetContents("/proc/self/cgroup", &content));
  EXPECT_THAT(content, HasSubstr("0::/test/child\n"));
}

TEST_F(Cgroup2Test, TaskMigration) {
  Cgroup src = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("src"));
  ExpectDefaultControlFiles(src);
  Cgroup dst = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dst"));
  ExpectDefaultControlFiles(dst);

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(src.Enter(getpid()));
  EXPECT_THAT(src.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  EXPECT_THAT(dst.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  EXPECT_NO_ERRNO(dst.Enter(getpid()));
  EXPECT_THAT(src.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
  EXPECT_THAT(dst.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
}

TEST_F(Cgroup2Test, InotifyEventsOnEntry) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  FileDescriptor inotify_fd(inotify_init1(IN_NONBLOCK));
  int wd = inotify_add_watch(inotify_fd.get(),
                             child.Relpath("cgroup.events").c_str(), IN_MODIFY);
  ASSERT_GE(wd, 0);

  // Enter the cgroup.
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.Enter(getpid()));

  // Entry is observed via inotify and the events file.
  ExpectInotifyEventOrTimeout(inotify_fd.get());
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
}

TEST_F(Cgroup2Test, InotifyEventsOnExit) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  FileDescriptor inotify_fd(inotify_init1(IN_NONBLOCK));
  int wd = inotify_add_watch(inotify_fd.get(),
                             child.Relpath("cgroup.events").c_str(), IN_MODIFY);
  ASSERT_GE(wd, 0);

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    wfd.reset();
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  rfd.reset();
  ASSERT_GT(pid, 0);

  // Enter the cgroup and consume the entry event.
  ASSERT_NO_ERRNO(child.Enter(pid));
  ExpectInotifyEventOrTimeout(inotify_fd.get());

  // Instruct task to exit, creating an unreaped zombie.
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();
  // Zombies are considered to have left the cgroup.
  ExpectInotifyEventOrTimeout(inotify_fd.get());
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, ZombieCgroupMembership) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    wfd.reset();
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  rfd.reset();
  ASSERT_GT(pid, 0);
  ASSERT_NO_ERRNO(child.Enter(pid));

  // Zombify the child.
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();
  siginfo_t info = {};
  ASSERT_THAT(waitid(P_PID, pid, &info, WEXITED | WNOWAIT), SyscallSucceeds());

  // A zombie process does not appear in cgroup.procs...
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_FALSE(procs.contains(pid));
  // ...and thus cannot be moved to another cgroup: the write succeeds,
  // but the process is not moved, as shown by the subsequent read.
  EXPECT_NO_ERRNO(c().WriteIntegerControlFile("cgroup.procs", pid));
  auto root_procs = ASSERT_NO_ERRNO_AND_VALUE(c().Procs());
  EXPECT_FALSE(root_procs.contains(pid));

  // Delete the child cgroup.
  ASSERT_NO_ERRNO(child.Delete());
  // To see "deleted".
  std::string content;
  ASSERT_NO_ERRNO(
      GetContents(absl::StrFormat("/proc/%d/cgroup", pid), &content));
  EXPECT_THAT(content, HasSubstr(" (deleted)\n"));

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, Threaded) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  // "domain" is the default.
  EXPECT_THAT(child.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain")));

  // Make the child a threaded cgroup.
  EXPECT_NO_ERRNO(child.WriteControlFile("cgroup.type", "threaded"));
  EXPECT_THAT(child.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("threaded")));

  // The parent automatically becomes "domain threaded".
  EXPECT_THAT(parent.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain threaded")));
  // Removing the threaded child clears the condition, reverting parent to
  // normal domain.
  ASSERT_NO_ERRNO(child.Delete());
  EXPECT_THAT(parent.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain")));
}

TEST_F(Cgroup2Test, ThreadedDomainViaSubtreeControl) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(c().Enter(getpid()));

  // Enabling threaded controllers in subtree_control while a process exists
  // makes it domain threaded.
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  EXPECT_THAT(c().ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain threaded")));
}

TEST_F(Cgroup2Test, ThreadedSubtreeBecomesInvalidDomain) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  Cgroup grandchild =
      ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("grandchild"));

  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.type", "threaded"));
  EXPECT_THAT(grandchild.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain invalid")));

  // Cannot add processes to an invalid domain.
  EXPECT_THAT(grandchild.Enter(getpid()), PosixErrorIs(EOPNOTSUPP));
}

TEST_F(Cgroup2Test, ThreadedNodeCanHaveInternalProcesses) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  auto clean_pids = Cleanup([&] {
    c().WriteControlFile("cgroup.subtree_control", "-pids").IgnoreError();
  });
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.type", "threaded"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.type", "threaded"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  EXPECT_NO_ERRNO(parent.Enter(getpid()));
}

TEST_F(Cgroup2Test, ThreadedSubtreeMasking) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "memory") ||
          !absl::StrContains(controllers, "pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+memory"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));

  // Cannot make child threaded while parent has domain controllers enabled.
  EXPECT_THAT(child.WriteControlFile("cgroup.type", "threaded"),
              PosixErrorIs(EOPNOTSUPP));
  // Disable the domain controllers.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "-memory"));

  // Make the child threaded and verify that the domain controllers are masked.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.type", "threaded"));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(Not(HasSubstr("memory"))));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(HasSubstr("pids")));

  // Cannot enable domain controllers in the child.
  EXPECT_THAT(child.WriteControlFile("cgroup.subtree_control", "+memory"),
              PosixErrorIs(ENOENT));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "+pids"));
}

TEST_F(Cgroup2Test, ThreadedCannotBeEnabledWithPopulatedDomainChildren) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child1 = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child1"));
  Cgroup child2 = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child2"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child1.Enter(getpid()));

  // Attempting to make child2 threaded should fail because parent has a
  // populated domain child in child1.
  EXPECT_THAT(child2.WriteControlFile("cgroup.type", "threaded"),
              PosixErrorIs(EOPNOTSUPP));
}

TEST_F(Cgroup2Test, ThreadgroupMigration) {
  Cgroup dst = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dst"));
  constexpr int kNumThreads = 10;
  std::vector<std::unique_ptr<ScopedThread>> threads;
  std::vector<pid_t> tids;
  absl::Mutex mu;
  absl::Notification ready;
  absl::Notification exit;

  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.push_back(std::make_unique<ScopedThread>([&]() {
      pid_t tid = gettid();
      {
        absl::MutexLock lock(mu);
        tids.push_back(tid);
        if (tids.size() == kNumThreads) {
          ready.Notify();
        }
      }
      exit.WaitForNotification();
    }));
  }
  ready.WaitForNotification();

  // Move the thread group to dst.
  ASSERT_NO_ERRNO(dst.WriteIntegerControlFile("cgroup.procs", getpid()));
  auto clean_dst = Cleanup([&] {
    ASSERT_NO_ERRNO(c().WriteIntegerControlFile("cgroup.procs", getpid()));
  });

  // The subthreads must be moved too.
  auto thread_set = ASSERT_NO_ERRNO_AND_VALUE(dst.Threads());
  EXPECT_THAT(thread_set, Contains(gettid()));
  for (pid_t tid : tids) {
    EXPECT_THAT(thread_set, Contains(tid));
  }
  exit.Notify();
}

TEST_F(Cgroup2Test, ThreadMigration) {
  Cgroup dom = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dom"));
  Cgroup src = ASSERT_NO_ERRNO_AND_VALUE(dom.CreateChild("src"));
  Cgroup dst = ASSERT_NO_ERRNO_AND_VALUE(dom.CreateChild("dst"));

  ASSERT_NO_ERRNO(src.WriteControlFile("cgroup.type", "threaded"));
  ASSERT_NO_ERRNO(dst.WriteControlFile("cgroup.type", "threaded"));

  // The main process must reside within the threaded subtree root domain
  // ('dom') before individual sub-threads can be mapped across its threaded
  // descendant directories.
  ASSERT_NO_ERRNO(dom.WriteIntegerControlFile("cgroup.procs", getpid()));
  auto clean_dom = Cleanup([&] {
    ASSERT_NO_ERRNO(c().WriteIntegerControlFile("cgroup.procs", getpid()));
  });

  absl::Notification done;
  bool failed = false;
  ScopedThread t([&]() {
    // Oscillate vigorously.
    for (int i = 0; i < 1000; ++i) {
      const Cgroup& target = (i % 2 == 0) ? dst : src;
      if (!target.WriteIntegerControlFile("cgroup.threads", gettid()).ok()) {
        failed = true;
        break;
      }
    }
    done.Notify();
  });
  done.WaitForNotification();

  EXPECT_FALSE(failed);
  auto dom_threads = ASSERT_NO_ERRNO_AND_VALUE(dom.Threads());
  EXPECT_THAT(dom_threads, Contains(gettid()));
}

TEST_F(Cgroup2Test, ThreadBoundarySplittingDisallowed) {
  Cgroup dom = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dom"));
  Cgroup threaded = ASSERT_NO_ERRNO_AND_VALUE(dom.CreateChild("threaded"));
  ASSERT_NO_ERRNO(threaded.WriteControlFile("cgroup.type", "threaded"));

  absl::Notification ready;
  absl::Notification exit;
  int err = 0;

  // The test process resides outside dom.
  ScopedThread t([&]() {
    // Attempting to map a single sub-thread directly into a threaded
    // subtree while its sibling resides completely outside the subtree
    // violates the thread-splitting rule.
    auto status = threaded.WriteIntegerControlFile("cgroup.threads", gettid());
    if (!status.ok()) {
      err = status.errno_value();
    }
    ready.Notify();
    exit.WaitForNotification();
  });
  ready.WaitForNotification();

  EXPECT_EQ(err, EOPNOTSUPP);
  exit.Notify();
}

TEST_F(Cgroup2Test, PermChecksUseOpenTimeCreds) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(parent.Enter(getpid()));

  // Grant unprivileged user read/write permissions to cgroup.procs.
  constexpr uid_t kFeebleEUID = 65534;
  ASSERT_THAT(chown(child.Relpath("cgroup.procs").c_str(), kFeebleEUID, -1),
              SyscallSucceeds());

  FileDescriptor child_procs_fd;
  absl::Notification ready;
  ScopedThread t([&]() {
    ASSERT_THAT(syscall(SYS_setresuid, kFeebleEUID, kFeebleEUID, kFeebleEUID),
                SyscallSucceeds());
    child_procs_fd.reset(open(child.Relpath("cgroup.procs").c_str(), O_RDWR));
    ready.Notify();
  });
  ready.WaitForNotification();
  SKIP_IF(child_procs_fd.get() < 0);

  // Open-time creds of the feeble subthread are not sufficient for access.
  EXPECT_THAT(write(child_procs_fd.get(), "0", 1),
              SyscallFailsWithErrno(EACCES));

  // But if the feeble uid owns the common ancestor, then the write succeeds.
  ASSERT_THAT(chown(parent.Relpath("cgroup.procs").c_str(), kFeebleEUID, -1),
              SyscallSucceeds());
  EXPECT_THAT(write(child_procs_fd.get(), "0", 1), SyscallSucceedsWithValue(1));
}

TEST_F(Cgroup2Test, KillTree) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid1 = fork();
  if (pid1 == 0) {
    wfd.reset();
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid1, 0);

  pid_t pid2 = fork();
  if (pid2 == 0) {
    wfd.reset();
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid2, 0);
  rfd.reset();

  ASSERT_NO_ERRNO(parent.Enter(pid1));
  ASSERT_NO_ERRNO(child.Enter(pid2));

  // Writing 1 to cgroup.kill kills all descendant tasks across the entire tree.
  EXPECT_TRUE(parent.WriteControlFile("cgroup.kill", "1").ok());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid1, &status, 0), pid1);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);

  ASSERT_EQ(waitpid(pid2, &status, 0), pid2);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);
}

TEST_F(Cgroup2Test, DescendantsStatAndLimit) {
  // Verify defaults.
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 0")));
  EXPECT_THAT(c().ReadControlFile("cgroup.max.descendants"),
              IsPosixErrorOkAndHolds("max\n"));
  EXPECT_THAT(c().ReadControlFile("cgroup.max.depth"),
              IsPosixErrorOkAndHolds("max\n"));

  // A single descendant.
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 1")));

  // Set max descendants to 1 on the child...
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.descendants", "1"));
  // ...thereby allowing the birth of the first grandchild.
  Cgroup grandchild =
      ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("grandchild"));
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 2")));
  // ...but not the second.
  auto second_grandchild = child.CreateChild("second_grandchild");
  EXPECT_FALSE(second_grandchild.ok());

  // Allow unlimited descendants on the child, but deny depth.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.descendants", "max"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.depth", "1"));
  auto great_grandchild = grandchild.CreateChild("great_grandchild");
  EXPECT_FALSE(great_grandchild.ok());
}

struct CloneArgs {
  int cgroup_fd;
  int ready_fd;
};

int CloneSubthreadFunc(void* arg) {
  auto args = static_cast<CloneArgs*>(arg);
  pid_t tid = gettid();
  char buf[32];
  int len = snprintf(buf, sizeof(buf), "%d", tid);
  if (write(args->cgroup_fd, buf, len) < 0) {
    _exit(1);
  }
  char ready = 'x';
  if (write(args->ready_fd, &ready, 1) < 0) {
    _exit(1);
  }
  pause();
  return 0;
}

// A slightly complex topology:
//
// [ dom ] (Type: "domain threaded")
//    ├── Parent leader (getpid())
//    ├── [ child1 ] (Type: "threaded")
//    │      ├── Parent subthread (via ScopedThread)
//    │      └── Child subthread (via raw clone)
//    └── [ child2 ] (Type: "threaded")
//           └── Child leader
TEST_F(Cgroup2Test, ThreadedDomainComplexTopology) {
  Cgroup dom = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dom"));
  Cgroup child1 = ASSERT_NO_ERRNO_AND_VALUE(dom.CreateChild("child1"));
  Cgroup child2 = ASSERT_NO_ERRNO_AND_VALUE(dom.CreateChild("child2"));

  ASSERT_NO_ERRNO(child1.WriteControlFile("cgroup.type", "threaded"));
  ASSERT_NO_ERRNO(child2.WriteControlFile("cgroup.type", "threaded"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(dom.Enter(getpid()));

  absl::Notification start;
  absl::Notification exit;
  pid_t parent_subthread_tid = -1;
  ScopedThread parent_subthread([&]() {
    parent_subthread_tid = gettid();
    ASSERT_NO_ERRNO(child1.WriteIntegerControlFile("cgroup.threads", gettid()));
    start.Notify();
    exit.WaitForNotification();
  });
  start.WaitForNotification();

  // So we can write to it from the child subthread.
  FileDescriptor child1_threads_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(child1.Relpath("cgroup.threads"), O_WRONLY));

  int exit_fds[2];
  ASSERT_THAT(pipe(exit_fds), SyscallSucceeds());
  FileDescriptor exit_rfd(exit_fds[0]);
  FileDescriptor exit_wfd(exit_fds[1]);

  int start_fds[2];
  ASSERT_THAT(pipe(start_fds), SyscallSucceeds());
  FileDescriptor start_rfd(start_fds[0]);
  FileDescriptor start_wfd(start_fds[1]);

  pid_t p2 = fork();
  if (p2 == 0) {
    exit_wfd.reset();
    start_rfd.reset();
    // Move the child leader into child2.
    ASSERT_NO_ERRNO(child2.WriteIntegerControlFile("cgroup.threads", gettid()));

    int ready_fds[2];
    if (pipe(ready_fds) < 0) {
      _exit(1);
    }
    CloneArgs args = {
        .cgroup_fd = child1_threads_fd.get(),
        .ready_fd = ready_fds[1],
    };
    char stack[65536];
    pid_t tid = clone(CloneSubthreadFunc, stack + sizeof(stack),
                      CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, &args);
    if (tid < 0) {
      _exit(1);
    }
    close(ready_fds[1]);

    // Wait till subthread has entered the child1 cgroup.
    char ready_token;
    if (read(ready_fds[0], &ready_token, 1) <= 0) {
      _exit(1);
    }
    close(ready_fds[0]);

    // Tell parent we're completely ready.
    char sync = 'x';
    if (write(start_wfd.get(), &sync, 1) < 0) {
      _exit(1);
    }
    start_wfd.reset();

    // Wait till parent signals to exit.
    char token;
    if (read(exit_rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  exit_rfd.reset();
  start_wfd.reset();
  ASSERT_GT(p2, 0);

  char sync_token;
  ASSERT_THAT(read(start_rfd.get(), &sync_token, 1),
              SyscallSucceedsWithValue(1));
  start_rfd.reset();

  // Sanity check for the topology.
  EXPECT_THAT(child2.Threads(), IsPosixErrorOkAndHolds(Contains(p2)));
  EXPECT_THAT(child1.Threads(),
              IsPosixErrorOkAndHolds(Contains(parent_subthread_tid)));

  // Reading cgroup.procs on dom returns both processes.
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(dom.Procs());
  EXPECT_TRUE(procs.contains(getpid()));
  EXPECT_TRUE(procs.contains(p2));

  // Reading cgroup.procs from a threaded child inside the subtree must be
  // disallowed.
  EXPECT_THAT(child1.Procs(), PosixErrorIs(EOPNOTSUPP));

  // Move the p2 process into child1.
  EXPECT_NO_ERRNO(child1.WriteIntegerControlFile("cgroup.procs", p2));
  EXPECT_THAT(child2.Threads(), IsPosixErrorOkAndHolds(::testing::IsEmpty()));
  auto child1_threads = ASSERT_NO_ERRNO_AND_VALUE(child1.Threads());
  // That should migrate both threads.
  EXPECT_THAT(child1_threads, Contains(p2));
  EXPECT_EQ(child1_threads.size(), 3);

  // Signal child leader to exit and reap it.
  ASSERT_THAT(write(exit_wfd.get(), "x", 1), SyscallSucceeds());
  exit_wfd.reset();
  int status;
  ASSERT_EQ(waitpid(p2, &status, 0), p2);
  EXPECT_TRUE(WIFEXITED(status));

  exit.Notify();  // Join with subthread.
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
