// Copyright 2026 The gVisor Authors.
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

#include <linux/capability.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "test/util/cgroup_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/time_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {
namespace {

class Cgroup2Test : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN))) {
      GTEST_SKIP() << "Cgroup v2 not available or ignored on gVisor";
    }
  }
};

// Disabling a v2 controller starts asynchronous destruction of its child
// states. Linux may return EBUSY until those states release their references.
PosixErrorOr<Cgroup> MountV1WhenAvailable(Mounter& mounter,
                                          const std::string& controller) {
  MonotonicTimer timer;
  timer.Start();
  while (true) {
    auto cg = mounter.MountCgroupfs(controller);
    if (cg.ok() || cg.error().errno_value() != EBUSY ||
        timer.Duration() >= absl::Seconds(5)) {
      return cg;
    }
    SleepSafe(absl::Milliseconds(10));
  }
}

// The final v1 unmount also releases controller state asynchronously, so the
// controller need not be available to v2 when unmount returns.
PosixError WaitForV2Controller(const Cgroup& cg, absl::string_view controller) {
  MonotonicTimer timer;
  timer.Start();
  while (true) {
    ASSIGN_OR_RETURN_ERRNO(const std::string available,
                           cg.ReadControlFile("cgroup.controllers"));
    for (absl::string_view name :
         absl::StrSplit(available, absl::ByAnyChar(" \n"), absl::SkipEmpty())) {
      if (name == controller) {
        return NoError();
      }
    }
    if (timer.Duration() >= absl::Seconds(5)) {
      return PosixError(
          ETIMEDOUT,
          absl::StrCat("Controller ", controller,
                       " did not return to v2; available: ", available));
    }
    SleepSafe(absl::Milliseconds(10));
  }
}

// Controller membership survives unmounting cgroupfs. Restore it after the
// temporary v1 mounts are destroyed, including when a test assertion aborts.
PosixErrorOr<Cleanup> DisableV2Controller(const Cgroup& cg,
                                          std::string controller) {
  ASSIGN_OR_RETURN_ERRNO(const std::string enabled,
                         cg.ReadControlFile("cgroup.subtree_control"));
  RETURN_IF_ERRNO(cg.WriteControlFile("cgroup.subtree_control",
                                      absl::StrCat("-", controller)));
  if (!absl::StrContains(enabled, controller)) {
    return Cleanup();
  }
  return Cleanup([&cg, controller = std::move(controller)] {
    ASSERT_NO_ERRNO(WaitForV2Controller(cg, controller));
    EXPECT_NO_ERRNO(cg.WriteControlFile("cgroup.subtree_control",
                                        absl::StrCat("+", controller)));
  });
}

TEST_F(Cgroup2Test, V1MountSucceedsAndV2OwnershipReturnsOnUnmount) {
  auto v2_mount = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v2_mounter(std::move(v2_mount));
  auto v2_cg = ASSERT_NO_ERRNO_AND_VALUE(v2_mounter.MountCgroup2fs());

  // Skip if v2 doesn't have pids to begin with.
  auto available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(available, "pids"));
  // Skip if we can't drain pids from below v2 root.
  auto drain = DisableV2Controller(v2_cg, "pids");
  SKIP_IF(!drain.ok() && drain.error().errno_value() == EBUSY);
  auto restore = ASSERT_NO_ERRNO_AND_VALUE(std::move(drain));

  // Steal the pids controller away from v2 by mounting it in v1.
  auto v1_mount1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v1_mounter1(std::move(v1_mount1));
  auto v1_cg1 =
      ASSERT_NO_ERRNO_AND_VALUE(MountV1WhenAvailable(v1_mounter1, "pids"));
  // Mount it again in another v1 hierarchy for good measure.
  auto v1_mount2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v1_mounter2(std::move(v1_mount2));
  auto v1_cg2 = ASSERT_NO_ERRNO_AND_VALUE(v1_mounter2.MountCgroupfs("pids"));

  // Now pids should be gone from v2 root's cgroup.controllers
  available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  EXPECT_THAT(available, ::testing::Not(::testing::HasSubstr("pids")));

  // Unmount the first v1 mount. Pids should still be absent from v2.
  ASSERT_NO_ERRNO(v1_mounter1.Unmount(v1_cg1));
  available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  EXPECT_THAT(available, ::testing::Not(::testing::HasSubstr("pids")));

  // Unmount the second v1 mount, restoring pids ownership to v2.
  ASSERT_NO_ERRNO(v1_mounter2.Unmount(v1_cg2));
  EXPECT_NO_ERRNO(WaitForV2Controller(v2_cg, "pids"));
}

// Exercises cgroup.kill while the memory controller is mounted in a v1
// hierarchy. Stealing the memory controller from v2 acquires the v2 tasks
// lock under the cgroup registry lock, and cgroup.kill sends signals while
// holding the same tasks lock; task creation meanwhile enters the initial v1
// cgroups while holding the signal handlers lock. Together these form a lock
// order cycle that gVisor builds with lock dependency checking (the "lockdep"
// go build tag) detect and panic on.
TEST_F(Cgroup2Test, KillWithV1MemoryMounted) {
  if (!IsRunningOnGvisor()) {
    // v2 can advertise memory with CONFIG_MEMCG_V1 disabled. Check the
    // legacy controller inventory before attempting the v1 mount.
    const auto controllers = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
    SKIP_IF(!controllers.contains("memory"));
  }

  auto v2_mount = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v2_mounter(std::move(v2_mount));
  auto v2_cg = ASSERT_NO_ERRNO_AND_VALUE(v2_mounter.MountCgroup2fs());

  // Skip if v2 doesn't have memory to begin with.
  auto available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(available, "memory"));
  // Skip if we can't drain memory from below v2 root.
  auto drain = DisableV2Controller(v2_cg, "memory");
  SKIP_IF(!drain.ok() && drain.error().errno_value() == EBUSY);
  auto restore = ASSERT_NO_ERRNO_AND_VALUE(std::move(drain));

  // Steal the memory controller away from v2 by mounting it in v1.
  auto v1_mount = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v1_mounter(std::move(v1_mount));
  auto v1_cg =
      ASSERT_NO_ERRNO_AND_VALUE(MountV1WhenAvailable(v1_mounter, "memory"));

  Cgroup child_cg =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.CreateChild("kill_v1mem_test"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  rfd.reset();

  ASSERT_NO_ERRNO(child_cg.Enter(pid));

  // Killing the cgroup sends SIGKILL to its tasks while the stolen memory
  // controller's v1 hierarchy is mounted.
  EXPECT_TRUE(child_cg.WriteControlFile("cgroup.kill", "1").ok());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);

  // The killed task may leave the cgroup asynchronously; retry the removal.
  MonotonicTimer timer;
  timer.Start();
  PosixError err;
  while (true) {
    err = Rmdir(child_cg.Path());
    if (err.ok() || err.errno_value() != EBUSY ||
        timer.Duration() >= absl::Seconds(5)) {
      break;
    }
    SleepSafe(absl::Milliseconds(10));
  }
  ASSERT_NO_ERRNO(err);

  // Return the memory controller to v2.
  ASSERT_NO_ERRNO(v1_mounter.Unmount(v1_cg));
  ASSERT_NO_ERRNO(WaitForV2Controller(v2_cg, "memory"));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
