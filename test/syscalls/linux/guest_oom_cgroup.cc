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

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <ctime>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/cgroup_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

// These tests exercise the in-sentry guest OOM killer's per-cgroup memory.max
// enforcement. They are deterministic regardless of the (possibly enormous)
// host RAM available to the test sandbox, because the limit that triggers the
// killer is a cgroup memory.max the test sets itself - not the sandbox-wide
// limit, which the syscall-test harness does not configure. This is what makes
// it correct to assert real OOM killing at the syscall-test level, unlike a
// sandbox-wide limit which cannot be reliably tripped on a high-RAM host.

namespace gvisor {
namespace testing {
namespace {

constexpr size_t kMiB = 1024 * 1024;
constexpr size_t kPageSize = 4096;

// Exit codes used by the child hog to distinguish failure modes from a SIGKILL.
constexpr int kExitMmapFailed = 42;
constexpr int kExitEnterFailed = 43;
constexpr int kExitNotKilled = 44;

// HogUntilKilled allocates `bytes` of anonymous memory and repeatedly touches
// every page so the memory stays resident, far exceeding the enclosing cgroup's
// memory.max. If the guest OOM killer is working it SIGKILLs this process well
// before the safety deadline; otherwise the process exits with kExitNotKilled
// so the test fails deterministically instead of hanging.
[[noreturn]] void HogUntilKilled(size_t bytes) {
  void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    _exit(kExitMmapFailed);
  }
  volatile char* c = static_cast<volatile char*>(p);
  const time_t start = time(nullptr);
  for (;;) {
    for (size_t i = 0; i < bytes; i += kPageSize) {
      c[i] = static_cast<char>(i);
    }
    if (time(nullptr) - start > 10) {
      _exit(kExitNotKilled);
    }
  }
}

// A memory hog confined to a cgroup with a small memory.max is SIGKILLed by the
// guest OOM killer once it exceeds the limit, while the test process (acting as
// the surviving "sandbox supervisor") keeps running.
TEST(GuestOOMCgroupTest, HogExceedingMemoryMaxIsKilled) {
  SKIP_IF(!IsRunningOnGvisor());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup root = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroup2fs());

  // Enable the memory controller for children so the leaf cgroup can enforce
  // memory.max.
  ASSERT_NO_ERRNO(root.WriteControlFile("cgroup.subtree_control", "+memory"));
  Cgroup victim = ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("victim"));

  // Cap the cgroup well below what the hog allocates. The cap - not host RAM -
  // is what trips the killer, making this test host-size independent.
  constexpr int64_t kLimitBytes = 64 * kMiB;
  ASSERT_NO_ERRNO(victim.WriteIntegerControlFile("memory.max", kLimitBytes));

  pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    // Child: join the capped cgroup, then allocate far beyond its limit.
    if (!victim.Enter(getpid()).ok()) {
      _exit(kExitEnterFailed);
    }
    HogUntilKilled(256 * kMiB);
  }

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));

  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitMmapFailed)
      << "hog's mmap failed unexpectedly";
  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitEnterFailed)
      << "hog could not enter the capped cgroup";
  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitNotKilled)
      << "hog exceeded memory.max but was never killed by the guest OOM killer";

  EXPECT_TRUE(WIFSIGNALED(status))
      << "hog exited without a signal; status=" << status;
  EXPECT_EQ(WTERMSIG(status), SIGKILL)
      << "hog terminated by unexpected signal " << WTERMSIG(status);

  // The test process itself survived the guest OOM event and can still interact
  // with the sandbox: reading the cgroup back proves the sandbox is alive.
  EXPECT_NO_ERRNO(victim.ReadIntegerControlFile("memory.current"));
}

// A memory hog that requests MAP_POPULATE far exceeding the enclosing cgroup's
// memory.max is SIGKILLed once touched memory exceeds the limit, while the
// supervisor process survives.
TEST(GuestOOMCgroupTest, MapPopulateExceedingMemoryMaxIsKilled) {
  SKIP_IF(!IsRunningOnGvisor());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup root = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroup2fs());

  ASSERT_NO_ERRNO(root.WriteControlFile("cgroup.subtree_control", "+memory"));
  Cgroup victim =
      ASSERT_NO_ERRNO_AND_VALUE(root.CreateChild("victim_populate"));

  constexpr int64_t kLimitBytes = 64 * kMiB;
  ASSERT_NO_ERRNO(victim.WriteIntegerControlFile("memory.max", kLimitBytes));

  pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    if (!victim.Enter(getpid()).ok()) {
      _exit(kExitEnterFailed);
    }
    constexpr size_t kPopulateBytes = 256 * kMiB;
    void* p = mmap(nullptr, kPopulateBytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED) {
      _exit(kExitMmapFailed);
    }
    volatile char* c = static_cast<volatile char*>(p);
    const time_t start = time(nullptr);
    for (;;) {
      for (size_t i = 0; i < kPopulateBytes; i += kPageSize) {
        c[i] = static_cast<char>(i);
      }
      if (time(nullptr) - start > 10) {
        _exit(kExitNotKilled);
      }
    }
  }

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));

  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitMmapFailed)
      << "populate hog's mmap failed unexpectedly";
  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitEnterFailed)
      << "populate hog could not enter the capped cgroup";
  ASSERT_FALSE(WIFEXITED(status) && WEXITSTATUS(status) == kExitNotKilled)
      << "populate hog exceeded memory.max but was not killed";

  EXPECT_TRUE(WIFSIGNALED(status))
      << "populate hog exited without a signal; status=" << status;
  EXPECT_EQ(WTERMSIG(status), SIGKILL)
      << "populate hog terminated by unexpected signal " << WTERMSIG(status);

  EXPECT_NO_ERRNO(victim.ReadIntegerControlFile("memory.current"));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
