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

#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// glibc does not provide a prototype for arch_prctl() so declare it here.
extern "C" int arch_prctl(int code, uintptr_t addr);

namespace gvisor {
namespace testing {

namespace {

// Helper function to issue a raw inline-assembly getpid() system call.
// This uses the exact 7-byte instruction sequence (mov $sysno, %eax; syscall)
// that Systrap binary patches in user memory.
inline pid_t RawGetpid() {
  pid_t pid;
  asm volatile(
      "movl %[sysno], %%eax\n"
      "syscall\n"
      : "=a"(pid)
      : [sysno] "i"(SYS_getpid)
      : "rcx", "r11", "memory");
  return pid;
}

TEST(ArchPrctlTest, GetSetFS) {
  uintptr_t orig;
  const uintptr_t kNonCanonicalFsbase = 0x4141414142424242;

  // Get the original FS.base and then set it to the same value (this is
  // intentional because FS.base is the TLS pointer so we cannot change it
  // arbitrarily).
  ASSERT_THAT(arch_prctl(ARCH_GET_FS, reinterpret_cast<uintptr_t>(&orig)),
              SyscallSucceeds());
  ASSERT_THAT(arch_prctl(ARCH_SET_FS, orig), SyscallSucceeds());

  // Trying to set FS.base to a non-canonical value should return an error.
  ASSERT_THAT(arch_prctl(ARCH_SET_FS, kNonCanonicalFsbase),
              SyscallFailsWithErrno(EPERM));
}

TEST(ArchPrctlTest, GetSetGS) {
  uintptr_t orig;
  const uintptr_t kNonCanonicalGsbase = 0x4141414142424242;

  // Get the original GS.base and then set it to the same value.
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig)),
              SyscallSucceeds());
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig), SyscallSucceeds());

  // Allocate a page of memory to use as our GS base.
  void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  uint64_t* data = static_cast<uint64_t*>(page);
  *data = 0xdeadbeefcafebabeULL;

  // Point GS to the page.
  uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  // Verify GS base is set.
  uintptr_t read_gs = 0;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
              SyscallSucceeds());
  EXPECT_EQ(read_gs, new_gs);

  // Verify we can read it.
  uint64_t val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0xdeadbeefcafebabeULL);

  // Ensure we don't crash when performing a syscall after changing GS.
  EXPECT_GT(getpid(), 0);
  EXPECT_GE(getppid(), 0);

  // Verify GS remains unchanged.
  val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0xdeadbeefcafebabeULL);

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig), SyscallSucceeds());
  munmap(page, 4096);

  // Trying to set GS.base to a non-canonical value should return an error.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, kNonCanonicalGsbase),
              SyscallFailsWithErrno(EPERM));
}

// Tests that executing binary-patched syscalls before ARCH_SET_GS gets cleanly
// unpatched when ARCH_SET_GS is invoked, and that the unpatched callsites
// continue to execute correctly.
TEST(ArchPrctlTest, UnpatchSyscallsOnArchSetGS) {
  uintptr_t orig_gs;
  uint64_t val = 0;

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  // Execute raw inline assembly syscalls repeatedly to ensure the callsite is
  // binary-patched by Systrap.
  const pid_t expected_pid = getpid();
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(RawGetpid(), expected_pid);
  }

  // Allocate memory for the application's GS base.
  void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  uint64_t* data = static_cast<uint64_t*>(page);
  *data = 0x123456789abcdef0ULL;

  // Setting GS reverts all binary syscall patches and disables future patching.
  uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0x123456789abcdef0ULL);

  // Re-execute the exact same raw syscall callsite.
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(RawGetpid(), expected_pid);
  }

  // Ensure %gs:0 was not corrupted by syscall handling.
  val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0x123456789abcdef0ULL);

  // Clean up.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page, 4096);
}

// Tests that multithreaded applications calling syscalls are safely interrupted
// and unpatched without crashing when another thread invokes ARCH_SET_GS.
TEST(ArchPrctlTest, MultithreadedUnpatchSyscalls) {
  uintptr_t orig_gs;
  uint64_t val = 0;

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  *static_cast<uint64_t*>(page) = 0xbeefdeadcafeULL;
  uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);

  std::atomic<bool> stop_worker{false};
  std::atomic<int> worker_syscall_count{0};
  const pid_t expected_pid = getpid();

  // Background thread repeatedly issues raw syscalls.
  ScopedThread worker([&stop_worker, &worker_syscall_count, expected_pid]() {
    while (!stop_worker.load(std::memory_order_relaxed)) {
      EXPECT_EQ(RawGetpid(), expected_pid);
      worker_syscall_count.fetch_add(1, std::memory_order_relaxed);
    }
  });

  while (worker_syscall_count.load(std::memory_order_relaxed) < 100) {
    absl::SleepFor(absl::Microseconds(100));
  }

  // Set GS base, triggering unpatching and interrupting all sysmsg threads.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0xbeefdeadcafeULL);

  // Let the worker run more iterations after unpatching.
  const int count_after_set =
      worker_syscall_count.load(std::memory_order_relaxed);
  while (worker_syscall_count.load(std::memory_order_relaxed) <
         count_after_set + 100) {
    absl::SleepFor(absl::Microseconds(100));
  }

  stop_worker.store(true, std::memory_order_relaxed);
  worker.Join();

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page, 4096);
}

// Tests setting GS to 0.
TEST(ArchPrctlTest, SetGSToZero) {
  uintptr_t orig_gs;
  uintptr_t read_gs = 0x1234;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, 0), SyscallSucceeds());

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
              SyscallSucceeds());
  EXPECT_EQ(read_gs, 0);

  // Syscalls should still work smoothly.
  EXPECT_GT(getpid(), 0);
  EXPECT_EQ(RawGetpid(), getpid());

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
}

// Tests setting GS multiple times consecutively.
TEST(ArchPrctlTest, MultipleSetGSCalls) {
  uintptr_t orig_gs;
  uint64_t val = 0;
  uintptr_t test_val_one = 0x1111222233334444ULL;
  uintptr_t test_val_two = 0x5555666677778888ULL;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* page1 = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page1, MAP_FAILED);
  *static_cast<uint64_t*>(page1) = test_val_one;

  void* page2 = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page2, MAP_FAILED);
  *static_cast<uint64_t*>(page2) = test_val_two;

  // Set to page 1.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(page1)),
              SyscallSucceeds());
  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, test_val_one);

  // Set to page 2.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(page2)),
              SyscallSucceeds());
  val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, test_val_two);

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page1, 4096);
  munmap(page2, 4096);
}

// Tests that /proc/cpuinfo advertised to the guest workload has
// FSGSBASE disabled so workloads do not execute WRGSBASE directly.
TEST(ArchPrctlTest, FSGSBaseDisabledInCpuInfo) {
  SKIP_IF(!IsRunningOnGvisor());
  std::string cpuinfo;
  ASSERT_NO_ERRNO(GetContents("/proc/cpuinfo", &cpuinfo));
  EXPECT_THAT(cpuinfo, ::testing::Not(::testing::HasSubstr(" fsgsbase ")))
      << "gVisor must not advertise fsgsbase in /proc/cpuinfo";
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
