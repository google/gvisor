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
#include <cpuid.h>
#include <sched.h>
#include <setjmp.h>  // IWYU pragma: keep
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// glibc does not provide a prototype for arch_prctl() so declare it here.
extern "C" int arch_prctl(int code, uintptr_t addr);

// AMX-related arch_prctl() codes and xfeature indices, which may be absent from
// older <asm/prctl.h>. See Linux's arch/x86/include/uapi/asm/prctl.h.
#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP 0x1021
#endif
#ifndef ARCH_GET_XCOMP_PERM
#define ARCH_GET_XCOMP_PERM 0x1022
#endif
#ifndef ARCH_REQ_XCOMP_PERM
#define ARCH_REQ_XCOMP_PERM 0x1023
#endif
#ifndef XFEATURE_XTILECFG
#define XFEATURE_XTILECFG 17
#endif
#ifndef XFEATURE_XTILEDATA
#define XFEATURE_XTILEDATA 18
#endif

namespace gvisor {
namespace testing {

namespace {

// Issues a raw inline-assembly system call with the exact 7-byte instruction
// sequence (mov $sysno, %eax; syscall) that Systrap binary patches.
// Marked noinline so each template instantiation forms a distinct callsite.
template <int Sysno, int Instance = 0, typename T = int64_t>
ABSL_ATTRIBUTE_NOINLINE T RawSyscall() {
  T ret;
  asm volatile(
      "movl %[sysno], %%eax\n"
      "syscall\n"
      : "=a"(ret)
      : [sysno] "i"(Sysno)
      : "rcx", "r11", "memory");
  return ret;
}

pid_t RawGetpid() { return RawSyscall<SYS_getpid, 0, pid_t>(); }

// CpuidHasAMXTile returns true if CPUID advertises the AMX-TILE feature
// (CPUID leaf 7, subleaf 0, EDX bit 24).
bool CpuidHasAMXTile() {
  uint32_t eax, ebx, ecx, edx;
  if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
    return false;
  }
  return (edx & (1u << 24)) != 0;
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

// Tests that /proc/cpuinfo advertised to the workload has FSGSBASE disabled
// under Systrap, so workloads do not execute WRGSBASE directly.
TEST(ArchPrctlTest, FSGSBaseDisabledInCpuInfo) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);
  std::string cpuinfo;
  ASSERT_NO_ERRNO(GetContents("/proc/cpuinfo", &cpuinfo));
  EXPECT_THAT(cpuinfo,
              ::testing::Not(::testing::ContainsRegex(R"(\bfsgsbase\b)")))
      << "gVisor must not advertise fsgsbase in /proc/cpuinfo under systrap";
}

// Tests that ARCH_GET_FS returns unique FS base addresses for each thread
// (corresponding to each thread's TLS), that setting FS to its current value
// succeeds in each thread, and that setting a non-canonical address fails.
TEST(ArchPrctlTest, MultithreadedGetSetFS) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t main_fs = 0;
  const uintptr_t kNonCanonicalFsbase = 0x4141414142424242;

  ASSERT_THAT(arch_prctl(ARCH_GET_FS, reinterpret_cast<uintptr_t>(&main_fs)),
              SyscallSucceeds());
  EXPECT_NE(main_fs, 0);

  constexpr int kNumThreads = 4;
  std::vector<uintptr_t> thread_fs(kNumThreads, 0);
  std::vector<std::unique_ptr<ScopedThread>> threads;
  threads.reserve(kNumThreads);

  for (int i = 0; i < kNumThreads; ++i) {
    threads.push_back(std::make_unique<ScopedThread>([&thread_fs, i]() {
      uintptr_t fs = 0;
      ASSERT_THAT(arch_prctl(ARCH_GET_FS, reinterpret_cast<uintptr_t>(&fs)),
                  SyscallSucceeds());
      EXPECT_NE(fs, 0);
      thread_fs[i] = fs;

      // Setting FS to its own value should succeed.
      EXPECT_THAT(arch_prctl(ARCH_SET_FS, fs), SyscallSucceeds());

      // Trying to set FS to a non-canonical value should return an error.
      EXPECT_THAT(arch_prctl(ARCH_SET_FS, kNonCanonicalFsbase),
                  SyscallFailsWithErrno(EPERM));

      // Verify FS was not modified by the failed call.
      uintptr_t fs_after = 0;
      EXPECT_THAT(
          arch_prctl(ARCH_GET_FS, reinterpret_cast<uintptr_t>(&fs_after)),
          SyscallSucceeds());
      EXPECT_EQ(fs_after, fs);
    }));
  }

  for (auto& t : threads) {
    t->Join();
  }

  // Verify that all threads (and the main thread) have distinct FS bases.
  for (int i = 0; i < kNumThreads; ++i) {
    EXPECT_NE(thread_fs[i], main_fs);
    for (int j = i + 1; j < kNumThreads; ++j) {
      EXPECT_NE(thread_fs[i], thread_fs[j]);
    }
  }
}

TEST(ArchPrctlTest, GetSetGS) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig;
  const uintptr_t kNonCanonicalGsbase = 0x4141414142424242;

  // Get the original GS.base and then set it to the same value.
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig)),
              SyscallSucceeds());
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig), SyscallSucceeds());

  // Allocate a page of memory to use as our GS base.
  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
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
  munmap(page, kPageSize);

  // Trying to set GS.base to a non-canonical value should return an error.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, kNonCanonicalGsbase),
              SyscallFailsWithErrno(EPERM));
}

// Tests that ARCH_SET_GS and ARCH_GET_GS manage per-thread state independently,
// verifying that different threads can maintain distinct GS bases, that
// modifying one thread's GS does not affect other threads, that syscalls do not
// clobber per-thread GS values, and that thread exit preserves other threads'
// GS.
TEST(ArchPrctlTest, MultithreadedGetSetGS) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  constexpr uint64_t kVal1 = 0x1111222233334444ULL;
  constexpr uint64_t kVal2 = 0x5555666677778888ULL;
  constexpr uint64_t kVal1New = 0x9999aaaabbbbccccULL;
  constexpr uint64_t kVal1Written = 0x12345678abcdef01ULL;

  void* page1 = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page1, MAP_FAILED);
  *static_cast<uint64_t*>(page1) = kVal1;

  void* page2 = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page2, MAP_FAILED);
  *static_cast<uint64_t*>(page2) = kVal2;

  void* page1_new = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page1_new, MAP_FAILED);
  *static_cast<uint64_t*>(page1_new) = kVal1New;

  std::atomic<int> phase{0};
  std::atomic<int> ready_count{0};
  std::atomic<bool> t1_exited{false};

  auto wait_for_phase = [&phase](int p) {
    while (phase.load(std::memory_order_acquire) != p) {
      absl::SleepFor(absl::Microseconds(50));
    }
  };

  auto wait_for_ready = [&ready_count](int expected) {
    const absl::Time deadline = absl::Now() + absl::Seconds(10);
    while (ready_count.load(std::memory_order_acquire) != expected) {
      if (absl::Now() > deadline) {
        return false;
      }
      absl::SleepFor(absl::Microseconds(50));
    }
    return true;
  };

  std::unique_ptr<ScopedThread> t1;
  std::unique_ptr<ScopedThread> t2;
  std::unique_ptr<ScopedThread> t3;

  // Thread 1 sets GS to page1, then changes to page1_new, and exits.
  t1 = std::make_unique<ScopedThread>([&]() {
    ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(page1)),
                SyscallSucceeds());
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 1: Verify initial GS and syscall preservation.
    wait_for_phase(1);
    uintptr_t read_gs = 0;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, reinterpret_cast<uintptr_t>(page1));

    uint64_t val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal1);

    EXPECT_GT(getpid(), 0);
    EXPECT_EQ(RawGetpid(), getpid());

    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal1);
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 2: Change GS to page1_new and write through %gs:0.
    wait_for_phase(2);
    ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(page1_new)),
                SyscallSucceeds());

    read_gs = 0;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, reinterpret_cast<uintptr_t>(page1_new));

    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal1New);

    asm volatile("movq %0, %%gs:0" : : "r"(kVal1Written) : "memory");
    EXPECT_EQ(*static_cast<uint64_t*>(page1_new), kVal1Written);

    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 3: Restore GS and exit thread.
    wait_for_phase(3);
    EXPECT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  });

  // Thread 2 sets GS to page2 and remains running while Thread 1 modifies and
  // exits.
  t2 = std::make_unique<ScopedThread>([&]() {
    ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(page2)),
                SyscallSucceeds());
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 1: Verify initial GS and syscall preservation.
    wait_for_phase(1);
    uintptr_t read_gs = 0;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, reinterpret_cast<uintptr_t>(page2));

    uint64_t val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal2);

    EXPECT_GT(getpid(), 0);
    EXPECT_EQ(RawGetpid(), getpid());

    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal2);
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 2: Verify Thread 2's GS is unaffected by Thread 1 modifying its GS.
    wait_for_phase(2);
    read_gs = 0;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, reinterpret_cast<uintptr_t>(page2));

    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal2);
    EXPECT_EQ(*static_cast<uint64_t*>(page2), kVal2);

    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 3: Verify Thread 2's GS is unaffected by Thread 1 exiting.
    wait_for_phase(3);
    while (!t1_exited.load(std::memory_order_acquire)) {
      absl::SleepFor(absl::Microseconds(50));
    }

    read_gs = 0;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, reinterpret_cast<uintptr_t>(page2));

    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal2);

    EXPECT_GT(getpid(), 0);
    val = 0;
    asm volatile("movq %%gs:0, %0" : "=r"(val));
    EXPECT_EQ(val, kVal2);

    EXPECT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
    ready_count.fetch_add(1, std::memory_order_release);
  });

  // Thread 3 never calls ARCH_SET_GS and verifies its GS remains default.
  t3 = std::make_unique<ScopedThread>([&]() {
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 1: Untouched GS should equal orig_gs.
    wait_for_phase(1);
    uintptr_t read_gs = 0xdead;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, orig_gs);

    EXPECT_GT(getpid(), 0);
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 2: Still orig_gs after other threads modified GS.
    wait_for_phase(2);
    read_gs = 0xdead;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, orig_gs);
    ready_count.fetch_add(1, std::memory_order_release);

    // Phase 3: Still orig_gs after Thread 1 exited.
    wait_for_phase(3);
    while (!t1_exited.load(std::memory_order_acquire)) {
      absl::SleepFor(absl::Microseconds(50));
    }

    read_gs = 0xdead;
    EXPECT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
                SyscallSucceeds());
    EXPECT_EQ(read_gs, orig_gs);
    ready_count.fetch_add(1, std::memory_order_release);
  });

  // Wait for all 3 threads to finish initialization.
  ASSERT_TRUE(wait_for_ready(3));
  ready_count.store(0, std::memory_order_release);
  phase.store(1, std::memory_order_release);

  // Wait for Phase 1 verification.
  ASSERT_TRUE(wait_for_ready(3));
  ready_count.store(0, std::memory_order_release);
  phase.store(2, std::memory_order_release);

  // Wait for Phase 2 verification.
  ASSERT_TRUE(wait_for_ready(3));
  ready_count.store(0, std::memory_order_release);
  phase.store(3, std::memory_order_release);

  // Wait for t1 to exit and join it in main thread.
  t1->Join();
  t1_exited.store(true, std::memory_order_release);

  // Wait for Phase 3 completion from t2 and t3.
  ASSERT_TRUE(wait_for_ready(2));

  t2->Join();
  t3->Join();

  // Verify main thread's GS was never modified.
  uintptr_t main_read_gs = 0xdead;
  ASSERT_THAT(
      arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&main_read_gs)),
      SyscallSucceeds());
  EXPECT_EQ(main_read_gs, orig_gs);

  munmap(page1, kPageSize);
  munmap(page2, kPageSize);
  munmap(page1_new, kPageSize);
}

// Tests that multiple threads concurrently calling ARCH_SET_GS, ARCH_GET_GS,
// dereferencing %gs:0, and making syscalls do not interfere with each other.
TEST(ArchPrctlTest, ConcurrentGetSetGS) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  constexpr int kNumThreads = 4;
  constexpr int kIterations = 100;
  const uintptr_t kNonCanonicalGsbase = 0x4141414142424242;

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  std::atomic<bool> start{false};
  std::vector<std::unique_ptr<ScopedThread>> threads;
  threads.reserve(kNumThreads);

  for (int tid = 0; tid < kNumThreads; ++tid) {
    threads.push_back(std::make_unique<ScopedThread>([&start, tid, orig_gs]() {
      void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      ASSERT_NE(page, MAP_FAILED);
      uint64_t* data = static_cast<uint64_t*>(page);
      uintptr_t page_addr = reinterpret_cast<uintptr_t>(page);

      while (!start.load(std::memory_order_acquire)) {
        absl::SleepFor(absl::Microseconds(50));
      }

      for (int iter = 0; iter < kIterations; ++iter) {
        const uint64_t magic = (static_cast<uint64_t>(tid + 1) << 32) |
                               static_cast<uint64_t>(iter + 1);
        *data = magic;

        EXPECT_THAT(arch_prctl(ARCH_SET_GS, page_addr), SyscallSucceeds());

        uintptr_t read_gs = 0;
        EXPECT_THAT(
            arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
            SyscallSucceeds());
        EXPECT_EQ(read_gs, page_addr);

        uint64_t val = 0;
        asm volatile("movq %%gs:0, %0" : "=r"(val));
        EXPECT_EQ(val, magic);

        // Perform syscalls to ensure kernel preserves GS across syscall
        // handling.
        EXPECT_GT(getpid(), 0);
        EXPECT_EQ(RawGetpid(), getpid());

        // Verify GS is unchanged after syscalls.
        val = 0;
        asm volatile("movq %%gs:0, %0" : "=r"(val));
        EXPECT_EQ(val, magic);

        // Write through %gs:0 and verify memory updated.
        const uint64_t updated_magic = magic ^ 0xa5a5a5a5a5a5a5a5ULL;
        asm volatile("movq %0, %%gs:0" : : "r"(updated_magic) : "memory");
        EXPECT_EQ(*data, updated_magic);

        // Non-canonical GS must fail and not corrupt current GS.
        EXPECT_THAT(arch_prctl(ARCH_SET_GS, kNonCanonicalGsbase),
                    SyscallFailsWithErrno(EPERM));

        val = 0;
        asm volatile("movq %%gs:0, %0" : "=r"(val));
        EXPECT_EQ(val, updated_magic);
      }

      EXPECT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
      munmap(page, kPageSize);
    }));
  }

  start.store(true, std::memory_order_release);
  for (auto& t : threads) {
    t->Join();
  }

  uintptr_t read_gs = 0xdead;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
              SyscallSucceeds());
  EXPECT_EQ(read_gs, orig_gs);
}

// Tests that executing binary-patched syscalls before ARCH_SET_GS gets cleanly
// unpatched when ARCH_SET_GS is invoked, and that the unpatched callsites
// continue to execute correctly.
TEST(ArchPrctlTest, UnpatchSyscallsOnArchSetGS) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

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
  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
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
  munmap(page, kPageSize);
}

ABSL_ATTRIBUTE_NO_SANITIZE_CFI pid_t CallStub(pid_t (*stub)()) {
  return stub();
}

TEST(ArchPrctlTest, UnpatchSyscallsSkipsStaleSites) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  constexpr uint8_t kSyscallStub[] = {0xb8, SYS_getpid, 0x00, 0x00,
                                      0x00, 0x0f,       0x05, 0xc3};
  constexpr uint8_t kReplacement[] = {0xb8, 42,   0x00, 0x00,
                                      0x00, 0xc3, 0x90, 0x90};
  constexpr uint8_t kJmpOpcode = 0xff;

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());
  void* gs_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(gs_page, MAP_FAILED);
  void* unmapped_page =
      mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(unmapped_page, MAP_FAILED);
  void* reused_page =
      mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(reused_page, MAP_FAILED);

  const uintptr_t unmapped_addr = reinterpret_cast<uintptr_t>(unmapped_page);
  const uintptr_t reused_addr = reinterpret_cast<uintptr_t>(reused_page);
  const auto cleanup = Cleanup([&] {
    EXPECT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
    munmap(reinterpret_cast<void*>(unmapped_addr), kPageSize);
    munmap(reinterpret_cast<void*>(reused_addr), kPageSize);
    munmap(gs_page, kPageSize);
  });

  uint8_t* unmapped_code = static_cast<uint8_t*>(unmapped_page) + 16;
  uint8_t* reused_code = static_cast<uint8_t*>(reused_page) + 16;
  memcpy(unmapped_code, kSyscallStub, sizeof(kSyscallStub));
  memcpy(reused_code, kSyscallStub, sizeof(kSyscallStub));
  ASSERT_EQ(CallStub(reinterpret_cast<pid_t (*)()>(unmapped_code)), getpid());
  ASSERT_EQ(CallStub(reinterpret_cast<pid_t (*)()>(reused_code)), getpid());
  if (unmapped_code[0] != kJmpOpcode || reused_code[0] != kJmpOpcode) {
    GTEST_SKIP() << "Syscall patching is disabled";
  }

  ASSERT_THAT(munmap(unmapped_page, kPageSize), SyscallSucceeds());
  ASSERT_THAT(munmap(reused_page, kPageSize), SyscallSucceeds());
  reused_page = mmap(reinterpret_cast<void*>(reused_addr), kPageSize,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  ASSERT_EQ(reinterpret_cast<uintptr_t>(reused_page), reused_addr);
  reused_code = static_cast<uint8_t*>(reused_page) + 16;
  memcpy(reused_code, kReplacement, sizeof(kReplacement));

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(gs_page)),
              SyscallSucceeds());

  unsigned char resident;
  EXPECT_THAT(
      mincore(reinterpret_cast<void*>(unmapped_addr), kPageSize, &resident),
      SyscallFailsWithErrno(ENOMEM));
  EXPECT_EQ(memcmp(reused_code, kReplacement, sizeof(kReplacement)), 0);
  EXPECT_EQ(CallStub(reinterpret_cast<pid_t (*)()>(reused_code)), 42);
}

// Tests that multithreaded applications calling syscalls are safely interrupted
// and unpatched without crashing when another thread invokes ARCH_SET_GS.
TEST(ArchPrctlTest, MultithreadedUnpatchSyscalls) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  uint64_t val = 0;
  int num_iterations = 100;

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
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

  while (worker_syscall_count.load(std::memory_order_relaxed) <
         num_iterations) {
    absl::SleepFor(absl::Microseconds(100));
  }

  // Set GS base, triggering unpatching of binary-patched syscalls.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  asm volatile("movq %%gs:0, %0" : "=r"(val));
  EXPECT_EQ(val, 0xbeefdeadcafeULL);

  // Let the worker run more iterations after unpatching.
  const int count_after_set =
      worker_syscall_count.load(std::memory_order_relaxed);
  while (worker_syscall_count.load(std::memory_order_relaxed) <
         count_after_set + num_iterations) {
    absl::SleepFor(absl::Microseconds(100));
  }

  stop_worker.store(true, std::memory_order_relaxed);
  worker.Join();

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page, kPageSize);
}

// Tests setting GS to 0.
TEST(ArchPrctlTest, SetGSToZero) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  uintptr_t read_gs = 0x1234;

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, 0), SyscallSucceeds());

  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&read_gs)),
              SyscallSucceeds());
  EXPECT_EQ(read_gs, 0);

  EXPECT_EXIT(
      {
        uint64_t val = 0;
        asm volatile("movq %%gs:0, %0" : "=r"(val));
        (void)val;
      },
      ::testing::KilledBySignal(SIGSEGV), "");

  // Syscalls should still work smoothly.
  EXPECT_GT(getpid(), 0);
  EXPECT_EQ(RawGetpid(), getpid());

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
}

// Tests setting GS multiple times consecutively.
TEST(ArchPrctlTest, MultipleSetGSCalls) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  uint64_t val = 0;
  uintptr_t test_val_one = 0x1111222233334444ULL;
  uintptr_t test_val_two = 0x5555666677778888ULL;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* page1 = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page1, MAP_FAILED);
  *static_cast<uint64_t*>(page1) = test_val_one;

  void* page2 = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
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
  munmap(page1, kPageSize);
  munmap(page2, kPageSize);
}

// Multiple threads concurrently execute different raw syscalls while
// ARCH_SET_GS initiates unpatching across all callsites. Ensures racing
// threads safely fault on the 0x06 barrier and restart rather than executing
// torn/garbage instructions.
TEST(ArchPrctlTest, MultithreadedMultiSyscallUnpatchStress) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());
  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  *static_cast<uint64_t*>(page) = 0xcafebabedeadbeefULL;
  uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);

  const pid_t expected_pid = getpid();
  const pid_t expected_ppid = getppid();
  const uid_t expected_uid = getuid();
  const gid_t expected_gid = getgid();
  const uid_t expected_euid = geteuid();
  const gid_t expected_egid = getegid();

  auto verify_all_syscalls = [&]() {
    EXPECT_EQ(RawSyscall<SYS_getpid>(), expected_pid);
    EXPECT_EQ(RawSyscall<SYS_getppid>(), expected_ppid);
    EXPECT_EQ(RawSyscall<SYS_getuid>(), expected_uid);
    EXPECT_EQ(RawSyscall<SYS_getgid>(), expected_gid);
    EXPECT_EQ(RawSyscall<SYS_geteuid>(), expected_euid);
    EXPECT_EQ(RawSyscall<SYS_getegid>(), expected_egid);
    EXPECT_EQ(RawSyscall<SYS_sched_yield>(), 0);
  };

  // Warmup each distinct callsite so Systrap binary-patches all of them.
  for (int i = 0; i < 100; ++i) {
    verify_all_syscalls();
  }

  const int num_threads = std::max<int>(8, sysconf(_SC_NPROCESSORS_ONLN));
  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> total_syscalls{0};
  std::vector<std::unique_ptr<ScopedThread>> workers;
  workers.reserve(num_threads);

  for (int tid = 0; tid < num_threads; ++tid) {
    workers.push_back(std::make_unique<ScopedThread>([&]() {
      while (!start.load(std::memory_order_acquire)) {
        absl::SleepFor(absl::Microseconds(10));
      }
      uint64_t local_count = 0;
      while (!stop.load(std::memory_order_relaxed)) {
        verify_all_syscalls();
        local_count += 7;
        if ((local_count % 350) == 0) {
          total_syscalls.fetch_add(350, std::memory_order_relaxed);
        }
      }
      total_syscalls.fetch_add(local_count % 350, std::memory_order_relaxed);
    }));
  }

  // Start concurrent work.
  start.store(true, std::memory_order_release);

  // Let threads start patching.
  while (total_syscalls.load(std::memory_order_relaxed) < 10000) {
    absl::SleepFor(absl::Milliseconds(1));
  }

  // Unpatch all callsites while all worker threads are in full swing.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  uint64_t gs_val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(gs_val));
  EXPECT_EQ(gs_val, 0xcafebabedeadbeefULL);

  // Allow threads to continue running against unpatched callsites.
  const uint64_t count_after_unpatch =
      total_syscalls.load(std::memory_order_relaxed);
  while (total_syscalls.load(std::memory_order_relaxed) <
         count_after_unpatch + 20000) {
    absl::SleepFor(absl::Milliseconds(1));
  }

  stop.store(true, std::memory_order_relaxed);
  for (auto& w : workers) {
    w->Join();
  }

  verify_all_syscalls();
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page, kPageSize);
}

// Tests concurrent patching and unpatching. Worker threads invoke fresh,
// raw syscall callsites triggering a patch, while ARCH_SET_GS simultaneously
// initiates unpatching.
TEST(ArchPrctlTest, ConcurrentPatchAndUnpatchRace) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  *static_cast<uint64_t*>(page) = 0x1122334455667788ULL;
  uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);

  const pid_t expected_pid = getpid();
  const pid_t expected_ppid = getppid();
  const uid_t expected_uid = getuid();

  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  constexpr int kNumWorkers = 8;
  std::vector<std::unique_ptr<ScopedThread>> workers;
  workers.reserve(kNumWorkers);

  for (int tid = 0; tid < kNumWorkers; ++tid) {
    workers.push_back(std::make_unique<ScopedThread>([&, tid]() {
      while (!start.load(std::memory_order_acquire)) {
        absl::SleepFor(absl::Microseconds(10));
      }

      while (!stop.load(std::memory_order_relaxed)) {
        switch (tid % 4) {
          case 0:
            EXPECT_EQ((RawSyscall<SYS_getpid, 1>()), expected_pid);
            EXPECT_EQ((RawSyscall<SYS_getppid, 1>()), expected_ppid);
            EXPECT_EQ((RawSyscall<SYS_getuid, 1>()), expected_uid);
            break;
          case 1:
            EXPECT_EQ((RawSyscall<SYS_getpid, 2>()), expected_pid);
            EXPECT_EQ((RawSyscall<SYS_getppid, 2>()), expected_ppid);
            EXPECT_EQ((RawSyscall<SYS_getuid, 2>()), expected_uid);
            break;
          case 2:
            EXPECT_EQ((RawSyscall<SYS_getpid, 3>()), expected_pid);
            EXPECT_EQ((RawSyscall<SYS_getppid, 3>()), expected_ppid);
            EXPECT_EQ((RawSyscall<SYS_getuid, 3>()), expected_uid);
            break;
          default:
            EXPECT_EQ((RawSyscall<SYS_getpid, 4>()), expected_pid);
            EXPECT_EQ((RawSyscall<SYS_getppid, 4>()), expected_ppid);
            EXPECT_EQ((RawSyscall<SYS_getuid, 4>()), expected_uid);
            break;
        }
      }
    }));
  }

  // Release workers to start executing the brand-new callsites.
  start.store(true, std::memory_order_release);

  // Concurrently initiate unpatching while threads are in the middle of
  // patching (thus faulting on the 0x06 byte).
  EXPECT_THAT(arch_prctl(ARCH_SET_GS, new_gs), SyscallSucceeds());

  uint64_t gs_val = 0;
  asm volatile("movq %%gs:0, %0" : "=r"(gs_val));
  EXPECT_EQ(gs_val, 0x1122334455667788ULL);

  absl::SleepFor(absl::Milliseconds(50));
  stop.store(true, std::memory_order_relaxed);

  for (auto& w : workers) {
    w->Join();
  }

  EXPECT_EQ((RawSyscall<SYS_getpid, 1>()), expected_pid);
  EXPECT_EQ((RawSyscall<SYS_getppid, 1>()), expected_ppid);
  EXPECT_EQ((RawSyscall<SYS_getuid, 1>()), expected_uid);
  EXPECT_EQ((RawSyscall<SYS_getpid, 2>()), expected_pid);
  EXPECT_EQ((RawSyscall<SYS_getppid, 2>()), expected_ppid);
  EXPECT_EQ((RawSyscall<SYS_getuid, 2>()), expected_uid);
  EXPECT_EQ((RawSyscall<SYS_getpid, 3>()), expected_pid);
  EXPECT_EQ((RawSyscall<SYS_getppid, 3>()), expected_ppid);
  EXPECT_EQ((RawSyscall<SYS_getuid, 3>()), expected_uid);
  EXPECT_EQ((RawSyscall<SYS_getpid, 4>()), expected_pid);
  EXPECT_EQ((RawSyscall<SYS_getppid, 4>()), expected_ppid);
  EXPECT_EQ((RawSyscall<SYS_getuid, 4>()), expected_uid);

  ASSERT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
  munmap(page, kPageSize);
}

// Tests that a child process reverts the syscall patches that it inherited
// from its parent when a user sets GS. The child runs in a new address space,
// which does not remember the patches that were applied before the fork, so
// they are recovered using the inherited trap table.
TEST(ArchPrctlTest, UnpatchInheritedSyscallsAfterFork) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  const pid_t parent_pid = getpid();
  void* page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  constexpr uint64_t kGSData = 0x0f0e0d0c0b0a0908ULL;
  *static_cast<uint64_t*>(page) = kGSData;
  const uintptr_t new_gs = reinterpret_cast<uintptr_t>(page);

  // Patch a few callsites
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ((RawSyscall<SYS_getpid, 5>()), parent_pid);
  }

  EXPECT_THAT(InForkedProcess([&] {
                TEST_CHECK(arch_prctl(ARCH_SET_GS, new_gs) == 0);

                uint64_t gs_val = 0;
                asm volatile("movq %%gs:0, %0" : "=r"(gs_val));
                TEST_CHECK(gs_val == kGSData);

                // The inherited patch must have been reverted; otherwise this
                // jumps into the trap table, which clobbers GS.
                const pid_t child_pid = getpid();
                for (int i = 0; i < 100; ++i) {
                  TEST_CHECK((RawSyscall<SYS_getpid, 5>()) == child_pid);
                }

                gs_val = 0;
                asm volatile("movq %%gs:0, %0" : "=r"(gs_val));
                TEST_CHECK(gs_val == kGSData);
              }),
              IsPosixErrorOkAndHolds(0));

  // The parent keeps its patches and is unaffected by the child.
  EXPECT_EQ((RawSyscall<SYS_getpid, 5>()), parent_pid);

  munmap(page, kPageSize);
}

// Shared state for the signal handlers.
sigjmp_buf reverted_patch_site_env;
volatile sig_atomic_t reverted_patch_site_signal = 0;
std::atomic<uintptr_t> reverted_patch_site_sigill_ip{0};

// SIGILL is used to catch faults at the reverted patch site.
void RevertedPatchSiteSigillHandler(int sig, siginfo_t*, void* uc) {
  reverted_patch_site_signal = sig;
  reverted_patch_site_sigill_ip.store(static_cast<uintptr_t>(
      static_cast<ucontext_t*>(uc)->uc_mcontext.gregs[REG_RIP]));
  siglongjmp(reverted_patch_site_env, 1);
}

// SIGALRM is used to terminate the test if the fault is restarted forever.
void RevertedPatchSiteSigalrmHandler(int sig) {
  reverted_patch_site_signal = sig;
  siglongjmp(reverted_patch_site_env, 1);
}

// The Sentry remembers former patch sites so that it can restart threads that
// fault on an unpatch in progress, but it must not restart faults on code that
// the app has since placed there as it would restart forever.
TEST(ArchPrctlTest, SigillAtRevertedPatchSiteIsDelivered) {
  SKIP_IF(GvisorPlatform() != Platform::kSystrap);

  // mov $SYS_getpid, %eax; syscall; ret
  constexpr uint8_t kSyscallStub[] = {0xb8, SYS_getpid, 0x00, 0x00,
                                      0x00, 0x0f,       0x05, 0xc3};
  // ud2
  constexpr uint8_t kInvalidInst[] = {0x0f, 0x0b};
  // The first byte of "jmp *addr", which replaces a patched syscall.
  constexpr uint8_t kJmpOpcode = 0xff;

  uintptr_t orig_gs;
  ASSERT_THAT(arch_prctl(ARCH_GET_GS, reinterpret_cast<uintptr_t>(&orig_gs)),
              SyscallSucceeds());

  void* gs_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(gs_page, MAP_FAILED);
  void* code_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(code_page, MAP_FAILED);

  const auto gs_cleanup = Cleanup([&] {
    EXPECT_THAT(arch_prctl(ARCH_SET_GS, orig_gs), SyscallSucceeds());
    munmap(code_page, kPageSize);
    munmap(gs_page, kPageSize);
  });

  // Systrap only patches a syscall if it can read the byte before its mov
  // instruction.
  uint8_t* code = static_cast<uint8_t*>(code_page) + 16;
  auto stub = reinterpret_cast<pid_t (*)()>(code);

  // Systrap patches the stub the first time it runs.
  memcpy(code, kSyscallStub, sizeof(kSyscallStub));
  const pid_t pid = getpid();
  ASSERT_EQ(CallStub(stub), pid);
  if (code[0] != kJmpOpcode) {
    GTEST_SKIP() << "Syscall patching is disabled";
  }

  // Setting GS reverts the patch and disables syscall patching.
  ASSERT_THAT(arch_prctl(ARCH_SET_GS, reinterpret_cast<uintptr_t>(gs_page)),
              SyscallSucceeds());
  ASSERT_EQ(memcmp(code, kSyscallStub, sizeof(kSyscallStub)), 0);
  ASSERT_EQ(CallStub(stub), pid);

  // Signal handler setup
  struct sigaction sa = {};
  sa.sa_sigaction = RevertedPatchSiteSigillHandler;
  sa.sa_flags = SA_SIGINFO;
  const auto sigill_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGILL, sa));
  sa = {};
  sa.sa_handler = RevertedPatchSiteSigalrmHandler;
  const auto sigalrm_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGALRM, sa));

  // Place an invalid instruction at the former patch site (offset 0) and then
  // again at the former syscall instruction (offset 5).
  for (int offset : {0, 5}) {
    SCOPED_TRACE(::testing::Message() << "ud2 at offset " << offset);
    memcpy(code, kSyscallStub, sizeof(kSyscallStub));
    memcpy(code + offset, kInvalidInst, sizeof(kInvalidInst));
    reverted_patch_site_signal = 0;
    reverted_patch_site_sigill_ip.store(0);

    // Set a save point for a future siglongjmp to return to.
    if (sigsetjmp(reverted_patch_site_env, 1) == 0) {
      // SIGALRM ends the test if the fault is restarted forever.
      alarm(5);
      CallStub(stub);
    }
    alarm(0);

    // Verify that SIGILL was delivered and the IP is correct (not rewound).
    EXPECT_EQ(reverted_patch_site_signal, SIGILL);
    EXPECT_EQ(reverted_patch_site_sigill_ip.load(),
              reinterpret_cast<uintptr_t>(code + offset));
  }
}

// AMX (Advanced Matrix Extensions).
//
// Workloads that see AMX-TILE in CPUID (e.g. oneDNN) enable it with
// arch_prctl(). On a native host without AMX kernel support the tests skip;
// gVisor must not skip when CPUID advertises AMX-TILE, since it only
// advertises AMX where it supports it.
//
// AMX permission can't be revoked, and is inherited by fork. The tests that
// check it before requesting it rely on the test runner, which runs each test
// in a new process.

TEST(ArchPrctlTest, AmxGetXcompSupp) {
  SKIP_IF(!CpuidHasAMXTile());

  unsigned long supp = 0;
  int ret = arch_prctl(ARCH_GET_XCOMP_SUPP, reinterpret_cast<uintptr_t>(&supp));
  // On a native host without AMX kernel support, this call fails; there is
  // nothing to test. Under gVisor it must succeed because AMX is advertised.
  SKIP_IF(ret != 0 && !IsRunningOnGvisor());

  ASSERT_THAT(ret, SyscallSucceeds());
  EXPECT_NE(supp & (1UL << XFEATURE_XTILECFG), 0UL)
      << "ARCH_GET_XCOMP_SUPP must advertise XTILECFG, got " << std::hex
      << supp;
  EXPECT_NE(supp & (1UL << XFEATURE_XTILEDATA), 0UL)
      << "ARCH_GET_XCOMP_SUPP must advertise XTILEDATA, got " << std::hex
      << supp;
}

TEST(ArchPrctlTest, AmxReqXcompPermEnablesTileData) {
  SKIP_IF(!CpuidHasAMXTile());

  unsigned long supp = 0;
  int supp_ret =
      arch_prctl(ARCH_GET_XCOMP_SUPP, reinterpret_cast<uintptr_t>(&supp));
  SKIP_IF(supp_ret != 0 && !IsRunningOnGvisor());
  ASSERT_THAT(supp_ret, SyscallSucceeds());

  // Requesting permission for XTILEDATA must succeed and must then be reflected
  // in ARCH_GET_XCOMP_PERM.
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());

  unsigned long perm = 0;
  ASSERT_THAT(
      arch_prctl(ARCH_GET_XCOMP_PERM, reinterpret_cast<uintptr_t>(&perm)),
      SyscallSucceeds());
  EXPECT_NE(perm & (1UL << XFEATURE_XTILEDATA), 0UL)
      << "XTILEDATA permission not granted after ARCH_REQ_XCOMP_PERM, perm="
      << std::hex << perm;
}

// KernelSupportsAMX returns true if CPUID advertises AMX-TILE and the kernel
// supports AMX permission requests. gVisor advertises AMX only if it supports
// it, so on gVisor it fails the test if CPUID advertises AMX-TILE but
// ARCH_GET_XCOMP_SUPP fails.
bool KernelSupportsAMX() {
  if (!CpuidHasAMXTile()) {
    return false;
  }
  unsigned long supp = 0;
  if (arch_prctl(ARCH_GET_XCOMP_SUPP, reinterpret_cast<uintptr_t>(&supp)) !=
      0) {
    if (IsRunningOnGvisor()) {
      ADD_FAILURE() << "CPUID advertises AMX-TILE, but ARCH_GET_XCOMP_SUPP "
                       "failed: "
                    << strerror(errno);
    }
    return false;
  }
  return true;
}

// HasAMXPermission returns true if the process has XTILEDATA permission.
bool HasAMXPermission() {
  unsigned long perm = 0;
  TEST_PCHECK(
      arch_prctl(ARCH_GET_XCOMP_PERM, reinterpret_cast<uintptr_t>(&perm)) == 0);
  return perm & (1UL << XFEATURE_XTILEDATA);
}

// An alternate signal stack too small for a signal frame with AMX state, and
// one large enough for it.
constexpr size_t kSmallAltStackSize = 8 << 10;
constexpr size_t kLargeAltStackSize = 64 << 10;

// SetAltStack sets the calling thread's alternate signal stack to size bytes
// of stack, or disables it if size is 0.
int SetAltStack(std::vector<char>& stack, size_t size) {
  stack_t ss = {};
  if (size == 0) {
    ss.ss_flags = SS_DISABLE;
  } else {
    stack.resize(size);
    ss.ss_sp = stack.data();
    ss.ss_size = size;
  }
  return sigaltstack(&ss, nullptr);
}

TEST(ArchPrctlTest, AmxReqXcompPermChecksOwnSigaltstack) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  stack_t old = {};
  ASSERT_THAT(sigaltstack(nullptr, &old), SyscallSucceeds());
  std::vector<char> stack;
  ASSERT_THAT(SetAltStack(stack, kSmallAltStackSize), SyscallSucceeds());
  auto cleanup = Cleanup([&old] { sigaltstack(&old, nullptr); });
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallFailsWithErrno(ENOSPC));
  EXPECT_FALSE(HasAMXPermission());

  ASSERT_THAT(SetAltStack(stack, kLargeAltStackSize), SyscallSucceeds());
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  EXPECT_TRUE(HasAMXPermission());
}

TEST(ArchPrctlTest, AmxReqXcompPermChecksOtherThreadSigaltstack) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  std::atomic<bool> installed(false);
  std::atomic<bool> done(false);
  ScopedThread thread([&] {
    std::vector<char> stack;
    TEST_PCHECK(SetAltStack(stack, kSmallAltStackSize) == 0);
    installed.store(true);
    while (!done.load()) {
      absl::SleepFor(absl::Milliseconds(1));
    }
    TEST_PCHECK(SetAltStack(stack, 0) == 0);
  });
  while (!installed.load()) {
    absl::SleepFor(absl::Milliseconds(1));
  }
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallFailsWithErrno(ENOSPC));
  EXPECT_FALSE(HasAMXPermission());

  done.store(true);
  thread.Join();
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  EXPECT_TRUE(HasAMXPermission());
}

TEST(ArchPrctlTest, AmxSigaltstackSizeCheckedAfterReqXcompPerm) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  stack_t old = {};
  ASSERT_THAT(sigaltstack(nullptr, &old), SyscallSucceeds());
  std::vector<char> stack;
  auto cleanup = Cleanup([&old] { sigaltstack(&old, nullptr); });

  // A small alternate signal stack is allowed without AMX permission.
  ASSERT_THAT(SetAltStack(stack, kSmallAltStackSize), SyscallSucceeds());
  ASSERT_THAT(SetAltStack(stack, 0), SyscallSucceeds());

  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  EXPECT_THAT(SetAltStack(stack, kSmallAltStackSize),
              SyscallFailsWithErrno(ENOMEM));
  stack_t cur = {};
  ASSERT_THAT(sigaltstack(nullptr, &cur), SyscallSucceeds());
  EXPECT_EQ(cur.ss_flags, SS_DISABLE);

  ASSERT_THAT(SetAltStack(stack, kLargeAltStackSize), SyscallSucceeds());
  EXPECT_THAT(SetAltStack(stack, 0), SyscallSucceeds());
}

// Tile configuration with palette 1, and %tmm0 holding kTileRows rows of
// kTileRowBytes bytes.
constexpr int kTileRows = 16;
constexpr int kTileRowBytes = 64;
struct alignas(64) TileConfig {
  uint8_t bytes[64];
};

TileConfig MakeTileConfig() {
  TileConfig cfg = {};
  cfg.bytes[0] = 1;               // Palette.
  cfg.bytes[16] = kTileRowBytes;  // %tmm0 bytes per row.
  cfg.bytes[48] = kTileRows;      // %tmm0 rows.
  return cfg;
}

const TileConfig kTileConfig = MakeTileConfig();

using TileData = std::array<uint8_t, kTileRows * kTileRowBytes>;

// AMX tile instructions, for assemblers that don't know them. All of them use
// %tmm0 and a stride of kTileRowBytes.

void LoadTileConfig(const TileConfig& cfg) {
  asm volatile(".byte 0xc4, 0xe2, 0x78, 0x49, 0x00"  // ldtilecfg (%rax)
               :
               : "a"(cfg.bytes)
               : "memory");
}

void LoadTile(const TileData& data) {
  asm volatile(".byte 0xc4, 0xe2, 0x7b, 0x4b, 0x04, 0x08"  // tileloadd
                                                           // (%rax,%rcx), %tmm0
               :
               : "a"(data.data()), "c"(static_cast<int64_t>(kTileRowBytes))
               : "memory");
}

void StoreTile(TileData& data) {
  asm volatile(".byte 0xc4, 0xe2, 0x7a, 0x4b, 0x04, 0x08"  // tilestored %tmm0,
                                                           // (%rax,%rcx)
               :
               : "a"(data.data()), "c"(static_cast<int64_t>(kTileRowBytes))
               : "memory");
}

void ZeroTile() {
  asm volatile(".byte 0xc4, 0xe2, 0x7b, 0x49, 0xc0" ::: "memory");  // tilezero
}

void ReleaseTiles() {
  asm volatile(".byte 0xc4, 0xe2, 0x78, 0x49, 0xc0" ::
                   : "memory");  // tilerelease
}

TileData TilePattern(uint8_t b) {
  TileData d;
  d.fill(b);
  return d;
}

TEST(ArchPrctlTest, AmxGetXcompPermBeforeRequest) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  unsigned long supp = 0, perm = 0;
  ASSERT_THAT(
      arch_prctl(ARCH_GET_XCOMP_SUPP, reinterpret_cast<uintptr_t>(&supp)),
      SyscallSucceeds());
  ASSERT_THAT(
      arch_prctl(ARCH_GET_XCOMP_PERM, reinterpret_cast<uintptr_t>(&perm)),
      SyscallSucceeds());
  EXPECT_EQ(perm, supp & ~(1UL << XFEATURE_XTILEDATA));
}

TEST(ArchPrctlTest, AmxReqXcompPermBadFeature) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  // Features that are not dynamic.
  for (unsigned long idx : {0, 1, 2, XFEATURE_XTILECFG}) {
    EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, idx),
                SyscallFailsWithErrno(EOPNOTSUPP))
        << "idx=" << idx;
  }
  // Features that don't exist.
  for (unsigned long idx : {64UL, 1000UL, ~0UL}) {
    EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, idx),
                SyscallFailsWithErrno(EINVAL))
        << "idx=" << idx;
  }
  EXPECT_FALSE(HasAMXPermission());

  // Requesting granted permission again succeeds, and XTILECFG is still not
  // dynamic.
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILECFG),
              SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_TRUE(HasAMXPermission());
}

TEST(ArchPrctlTest, AmxGetXcompBadAddress) {
  SKIP_IF(!KernelSupportsAMX());

  constexpr uintptr_t kBadAddr = 8;
  EXPECT_THAT(arch_prctl(ARCH_GET_XCOMP_SUPP, kBadAddr),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(arch_prctl(ARCH_GET_XCOMP_PERM, kBadAddr),
              SyscallFailsWithErrno(EFAULT));
}

constexpr char kAmxExecHelperEnv[] = "ARCH_PRCTL_TEST_AMX_EXEC_HELPER";

// AmxExecHelper checks that a process started by execve has no AMX
// permission. It runs only if kAmxExecHelperEnv is set.
TEST(ArchPrctlTest, AmxExecHelper) {
  SKIP_IF(getenv(kAmxExecHelperEnv) == nullptr);
  EXPECT_FALSE(HasAMXPermission());
}

TEST(ArchPrctlTest, AmxPermissionInheritedByForkResetByExec) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());

  EXPECT_THAT(InForkedProcess([] { TEST_CHECK(HasAMXPermission()); }),
              IsPosixErrorOkAndHolds(0));

  pid_t child;
  int execve_errno;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      "/proc/self/exe",
      {"/proc/self/exe", "--gtest_filter=ArchPrctlTest.AmxExecHelper"},
      {absl::StrCat(kAmxExecHelperEnv, "=1")}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status=" << status;
}

void ClobberTilesHandler(int, siginfo_t*, void*) {
  LoadTileConfig(kTileConfig);
  ZeroTile();
}

// TileDataSurvives loads a tile, then does things that switch, save and
// restore FP state, and checks that the tile is unchanged.
void TileDataSurvives(uint8_t b, bool save) {
  const TileData want = TilePattern(b);
  LoadTileConfig(kTileConfig);
  LoadTile(want);
  for (int i = 0; i < 100; i++) {
    sched_yield();
    syscall(SYS_getpid);
    // The handler clobbers the tiles, which sigreturn must restore.
    TEST_PCHECK(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1) ==
                0);
    if (save && i % 25 == 0) {
      MaybeSave();
    }
  }
  TileData got = {};
  StoreTile(got);
  ReleaseTiles();
  TEST_CHECK(got == want);
}

TEST(ArchPrctlTest, AmxTileDataPreserved) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  struct sigaction sa = {};
  sa.sa_sigaction = ClobberTilesHandler;
  sa.sa_flags = SA_SIGINFO;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  std::vector<std::unique_ptr<ScopedThread>> threads;
  for (uint8_t b = 1; b <= 4; b++) {
    threads.push_back(
        std::make_unique<ScopedThread>([b] { TileDataSurvives(b, false); }));
  }
  TileDataSurvives(0x5a, true);
}

// The tile patterns that ReplaceFrameTileDataHandler expects in %tmm0 in the
// signal frame, and writes there.
uint8_t frame_tile_old, frame_tile_new;
std::atomic<bool> frame_tile_found;

void ReplaceFrameTileDataHandler(int, siginfo_t*, void* uc) {
  uint8_t* fp = reinterpret_cast<uint8_t*>(
      reinterpret_cast<ucontext_t*>(uc)->uc_mcontext.fpregs);
  // struct _fpx_sw_bytes is at offset 464; xfeatures is at offset 8 in it,
  // and xstate_size at offset 16. XSTATE_BV is at offset 512.
  uint64_t xfeatures, xstate_bv;
  uint32_t xstate_size;
  memcpy(&xfeatures, fp + 464 + 8, sizeof(xfeatures));
  memcpy(&xstate_size, fp + 464 + 16, sizeof(xstate_size));
  memcpy(&xstate_bv, fp + 512, sizeof(xstate_bv));
  // CPUID leaf 0xD subleaf 18 gives the size and offset of tile data, which
  // starts with %tmm0.
  uint32_t size, offset, ecx, edx;
  TEST_CHECK(
      __get_cpuid_count(0xd, XFEATURE_XTILEDATA, &size, &offset, &ecx, &edx));
  constexpr uint64_t kTileDataBit = 1UL << XFEATURE_XTILEDATA;
  if ((xfeatures & kTileDataBit) == 0 || (xstate_bv & kTileDataBit) == 0 ||
      xstate_size < offset + size) {
    frame_tile_found = false;
    return;
  }
  const TileData old_tile = TilePattern(frame_tile_old);
  frame_tile_found = memcmp(fp + offset, old_tile.data(), old_tile.size()) == 0;
  const TileData new_tile = TilePattern(frame_tile_new);
  memcpy(fp + offset, new_tile.data(), new_tile.size());
}

// sigreturn restores tile data from the signal frame.
TEST(ArchPrctlTest, AmxSigreturnRestoresFrameTileData) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  struct sigaction sa = {};
  sa.sa_sigaction = ReplaceFrameTileDataHandler;
  sa.sa_flags = SA_SIGINFO;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  LoadTileConfig(kTileConfig);
  for (uint8_t i = 0; i < 4; i++) {
    frame_tile_old = 0x10 + i;
    frame_tile_new = 0x20 + i;
    LoadTile(TilePattern(frame_tile_old));
    if (i % 2 == 1) {
      MaybeSave();
    }
    frame_tile_found = false;
    ASSERT_THAT(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1),
                SyscallSucceeds());
    TileData got = {};
    StoreTile(got);
    EXPECT_TRUE(frame_tile_found.load()) << "i=" << static_cast<int>(i);
    EXPECT_TRUE(got == TilePattern(frame_tile_new))
        << "i=" << static_cast<int>(i);
  }
  ReleaseTiles();
}

alignas(16) char small_uc_stack[kSmallAltStackSize];

void SetSmallUcStackHandler(int, siginfo_t*, void* uc) {
  stack_t& ss = reinterpret_cast<ucontext_t*>(uc)->uc_stack;
  ss.ss_sp = small_uc_stack;
  ss.ss_size = sizeof(small_uc_stack);
  ss.ss_flags = 0;
}

// sigreturn doesn't install an alternate signal stack from the signal frame
// that is too small for AMX state.
TEST(ArchPrctlTest, AmxSigreturnKeepsSigaltstackIfFrameStackTooSmall) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
  stack_t old = {};
  ASSERT_THAT(sigaltstack(nullptr, &old), SyscallSucceeds());
  struct sigaction sa = {};
  sa.sa_sigaction = SetSmallUcStackHandler;
  sa.sa_flags = SA_SIGINFO;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));

  ASSERT_THAT(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1),
              SyscallSucceeds());
  stack_t cur = {};
  ASSERT_THAT(sigaltstack(nullptr, &cur), SyscallSucceeds());
  EXPECT_EQ(cur.ss_sp, old.ss_sp);
  EXPECT_EQ(cur.ss_size, old.ss_size);
  EXPECT_EQ(cur.ss_flags, old.ss_flags);
}

// A thread that was running when another thread was granted AMX can use it.
TEST(ArchPrctlTest, AmxRunningThreadCanUseGrantedPermission) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  std::atomic<bool> granted(false);
  std::atomic<bool> ok(false);
  ScopedThread thread([&] {
    // Spin without system calls.
    while (!granted.load()) {
    }
    if (!ok.load()) {
      return;
    }
    const TileData want = TilePattern(0x3c);
    LoadTileConfig(kTileConfig);
    LoadTile(want);
    for (int i = 0; i < 100; i++) {
      syscall(SYS_getpid);
    }
    TileData got = {};
    StoreTile(got);
    ReleaseTiles();
    TEST_CHECK(got == want);
  });
  absl::SleepFor(absl::Milliseconds(100));
  const int ret = arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA);
  ok.store(ret == 0);
  granted.store(true);
  EXPECT_THAT(ret, SyscallSucceeds());
}

sigjmp_buf tile_read_jmp;

void TileReadSigillHandler(int) { siglongjmp(tile_read_jmp, 1); }

// ReadTile returns true and stores the tile in got if the caller can read its
// tile registers.
bool ReadTile(TileData& got) {
  if (sigsetjmp(tile_read_jmp, 1) != 0) {
    return false;
  }
  StoreTile(got);
  return true;
}

constexpr uint8_t kSecretTileByte = 0xa5;

// LoadSecretTile loads a tile that other processes must not see, and keeps it
// loaded while yielding.
void LoadSecretTile(int yields) {
  TEST_PCHECK(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA) == 0);
  LoadTileConfig(kTileConfig);
  LoadTile(TilePattern(kSecretTileByte));
  for (int i = 0; i < yields; i++) {
    sched_yield();
  }
}

TEST(ArchPrctlTest, AmxNoTileLeakToThreadGroupSharingMemory) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  // Run both thread groups on one CPU, so that they switch often.
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  ASSERT_THAT(sched_setaffinity(0, sizeof(set), &set), SyscallSucceeds());

  constexpr int kReads = 2000;
  static std::atomic<bool> loaded, done;
  static std::atomic<int> leaks;
  loaded = false;
  done = false;
  leaks = 0;
  // The child has its own thread group without AMX permission, and shares
  // memory with the parent.
  std::vector<char> stack(1 << 20);
  pid_t child = clone(
      +[](void*) {
        TEST_PCHECK(signal(SIGILL, TileReadSigillHandler) != SIG_ERR);
        while (!loaded.load()) {
          sched_yield();
        }
        for (int i = 0; i < kReads; i++) {
          sched_yield();
          TileData got = {};
          if (ReadTile(got) && got == TilePattern(kSecretTileByte)) {
            leaks++;
          }
        }
        done = true;
        return 0;
      },
      stack.data() + stack.size(), CLONE_VM | SIGCHLD, nullptr);
  ASSERT_THAT(child, SyscallSucceeds());

  // An ASSERT here would leave the child waiting forever.
  LoadSecretTile(0);
  loaded = true;
  while (!done.load()) {
    sched_yield();
  }
  ReleaseTiles();
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status=" << status;
  EXPECT_EQ(leaks.load(), 0);
}

std::atomic<int> signal_frame_leaks;
std::atomic<int> signal_frames_without_tile_data;

void CheckSignalFrameTileDataHandler(int, siginfo_t*, void* uc) {
  const uint8_t* fp = reinterpret_cast<const uint8_t*>(
      reinterpret_cast<ucontext_t*>(uc)->uc_mcontext.fpregs);
  // struct _fpx_sw_bytes is at offset 464; xfeatures is at offset 8 in it,
  // and xstate_size at offset 16.
  uint64_t xfeatures;
  memcpy(&xfeatures, fp + 464 + 8, sizeof(xfeatures));
  uint32_t xstate_size;
  memcpy(&xstate_size, fp + 464 + 16, sizeof(xstate_size));
  // CPUID leaf 0xD subleaf 18 gives the size and offset of tile data.
  uint32_t size, offset, ecx, edx;
  TEST_CHECK(
      __get_cpuid_count(0xd, XFEATURE_XTILEDATA, &size, &offset, &ecx, &edx));
  if ((xfeatures & (1UL << XFEATURE_XTILEDATA)) == 0 ||
      xstate_size < offset + size) {
    signal_frames_without_tile_data++;
  }
  const TileData secret = TilePattern(kSecretTileByte);
  for (uint32_t off = 512; off + kTileRowBytes <= xstate_size;
       off += kTileRowBytes) {
    if (memcmp(fp + off, secret.data(), kTileRowBytes) == 0) {
      signal_frame_leaks++;
      return;
    }
  }
}

TEST(ArchPrctlTest, AmxNoTileLeakToLaterProcess) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  for (int round = 0; round < 5; round++) {
    // The first process uses a tile, then exits.
    EXPECT_THAT(InForkedProcess([] {
                  LoadSecretTile(100);
                  ReleaseTiles();
                  for (int i = 0; i < 100; i++) {
                    sched_yield();
                  }
                }),
                IsPosixErrorOkAndHolds(0));
    // The next process gets AMX-sized signal frames, and must not see the
    // tile in them.
    EXPECT_THAT(
        InForkedProcess([] {
          struct sigaction sa = {};
          sa.sa_sigaction = CheckSignalFrameTileDataHandler;
          sa.sa_flags = SA_SIGINFO;
          TEST_PCHECK(sigaction(SIGUSR1, &sa, nullptr) == 0);
          TEST_PCHECK(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA) == 0);
          // Use tile data once, so that signal frames have room for it.
          LoadTileConfig(kTileConfig);
          ZeroTile();
          for (int i = 0; i < 10; i++) {
            ReleaseTiles();
            TEST_PCHECK(raise(SIGUSR1) == 0);
          }
          TEST_CHECK(signal_frame_leaks.load() == 0);
          // The frames have room for tile data, so the check above is
          // meaningful.
          TEST_CHECK(signal_frames_without_tile_data.load() == 0);
        }),
        IsPosixErrorOkAndHolds(0));
  }
}

// Where gVisor hides AMX, it hides all of it.
TEST(ArchPrctlTest, AmxHiddenConsistently) {
  SKIP_IF(!IsRunningOnGvisor() || CpuidHasAMXTile());

  unsigned long supp = 0;
  ASSERT_THAT(
      arch_prctl(ARCH_GET_XCOMP_SUPP, reinterpret_cast<uintptr_t>(&supp)),
      SyscallSucceeds());
  EXPECT_EQ(supp & ((1UL << XFEATURE_XTILECFG) | (1UL << XFEATURE_XTILEDATA)),
            0UL)
      << std::hex << supp;
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallFailsWithErrno(EOPNOTSUPP));

  uint32_t eax, ebx, ecx, edx;
  ASSERT_TRUE(__get_cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx));
  EXPECT_EQ(eax & ((1U << XFEATURE_XTILECFG) | (1U << XFEATURE_XTILEDATA)), 0U)
      << std::hex << eax;

  // Tile instructions don't work.
  EXPECT_THAT(InForkedProcess([] {
                TEST_PCHECK(signal(SIGILL, TileReadSigillHandler) != SIG_ERR);
                if (sigsetjmp(tile_read_jmp, 1) == 0) {
                  LoadTileConfig(kTileConfig);
                  ZeroTile();
                  _exit(1);
                }
              }),
              IsPosixErrorOkAndHolds(0));
}

void NopHandler(int) {}

// A signal frame with AMX state fits in the smallest alternate signal stack
// that sigaltstack accepts.
TEST(ArchPrctlTest, AmxSignalFrameFitsSmallestSigaltstack) {
  SKIP_IF(!KernelSupportsAMX());

  EXPECT_THAT(
      InForkedProcess([] {
        TEST_PCHECK(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA) == 0);
        // Find the smallest size that sigaltstack accepts.
        constexpr size_t kMaxSize = 64 << 10;
        const size_t page = getpagesize();
        const size_t map_len = page + kMaxSize;
        void* m = mmap(nullptr, map_len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        TEST_PCHECK(m != MAP_FAILED);
        // Put the stack right above a guard page, so that a frame
        // that doesn't fit faults.
        char* base = static_cast<char*>(m) + page;
        TEST_PCHECK(mprotect(m, page, PROT_NONE) == 0);
        size_t lo = 1, hi = kMaxSize;
        while (lo < hi) {
          size_t mid = lo + (hi - lo) / 2;
          stack_t ss = {};
          ss.ss_sp = base;
          ss.ss_size = mid;
          if (sigaltstack(&ss, nullptr) == 0) {
            hi = mid;
          } else {
            TEST_CHECK(errno == ENOMEM);
            lo = mid + 1;
          }
        }
        stack_t ss = {};
        ss.ss_sp = base;
        ss.ss_size = lo;
        TEST_PCHECK(sigaltstack(&ss, nullptr) == 0);

        struct sigaction sa = {};
        sa.sa_handler = NopHandler;
        sa.sa_flags = SA_ONSTACK;
        TEST_PCHECK(sigaction(SIGUSR1, &sa, nullptr) == 0);
        const TileData want = TilePattern(0x77);
        LoadTileConfig(kTileConfig);
        LoadTile(want);
        TEST_PCHECK(raise(SIGUSR1) == 0);
        TileData got = {};
        StoreTile(got);
        ReleaseTiles();
        TEST_CHECK(got == want);
      }),
      IsPosixErrorOkAndHolds(0));
}

// An alternate signal stack of AT_MINSIGSTKSZ bytes, as some runtimes allocate,
// is large enough for AMX.
TEST(ArchPrctlTest, AmxReqXcompPermWithMinSigstkszSigaltstack) {
  SKIP_IF(!KernelSupportsAMX());
  ASSERT_FALSE(HasAMXPermission());

  const unsigned long min_size = getauxval(AT_MINSIGSTKSZ);
  ASSERT_NE(min_size, 0UL);
  stack_t old = {};
  ASSERT_THAT(sigaltstack(nullptr, &old), SyscallSucceeds());
  std::vector<char> stack;
  auto cleanup = Cleanup([&old] { sigaltstack(&old, nullptr); });
  ASSERT_THAT(SetAltStack(stack, min_size), SyscallSucceeds());
  EXPECT_THAT(arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA),
              SyscallSucceeds());
}

// The XSTATE_BV bits that SetXstateBVInFrameHandler sets.
uint64_t frame_xstate_bv_bits;

void SetXstateBVInFrameHandler(int, siginfo_t*, void* uc) {
  uint8_t* fp = reinterpret_cast<uint8_t*>(
      reinterpret_cast<ucontext_t*>(uc)->uc_mcontext.fpregs);
  // XSTATE_BV is at offset 512 of the XSAVE area.
  uint64_t xstate_bv;
  memcpy(&xstate_bv, fp + 512, sizeof(xstate_bv));
  xstate_bv |= frame_xstate_bv_bits;
  memcpy(fp + 512, &xstate_bv, sizeof(xstate_bv));
}

// Returning from a signal handler that set AMX bits in XSTATE_BV succeeds
// where CPUID advertises AMX. Elsewhere, it either succeeds or kills the
// process with SIGSEGV.
void AmxSigreturnWithXstateBV(uint64_t bits) {
  frame_xstate_bv_bits = bits;
  const int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    struct sigaction sa = {};
    sa.sa_sigaction = SetXstateBVInFrameHandler;
    sa.sa_flags = SA_SIGINFO;
    TEST_PCHECK(sigaction(SIGUSR1, &sa, nullptr) == 0);
    TEST_PCHECK(raise(SIGUSR1) == 0);
  }));
  if (CpuidHasAMXTile()) {
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
        << "status=" << status;
  } else {
    EXPECT_TRUE((WIFEXITED(status) && WEXITSTATUS(status) == 0) ||
                (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV))
        << "status=" << status;
  }
}

TEST(ArchPrctlTest, AmxSigreturnWithXtilecfg) {
  AmxSigreturnWithXstateBV(1UL << XFEATURE_XTILECFG);
}

TEST(ArchPrctlTest, AmxSigreturnWithXtiledata) {
  AmxSigreturnWithXstateBV((1UL << XFEATURE_XTILECFG) |
                           (1UL << XFEATURE_XTILEDATA));
}

// A signal frame fits an alternate signal stack of AT_MINSIGSTKSZ bytes.
TEST(ArchPrctlTest, SignalFrameFitsMinSigstkszSigaltstack) {
  const unsigned long min_size = getauxval(AT_MINSIGSTKSZ);
  SKIP_IF(min_size == 0 && !IsRunningOnGvisor());
  ASSERT_NE(min_size, 0UL);

  EXPECT_THAT(InForkedProcess([min_size] {
                const size_t page = getpagesize();
                const size_t map_len = page + min_size;
                void* m = mmap(nullptr, map_len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                TEST_PCHECK(m != MAP_FAILED);
                // A frame that doesn't fit faults on the guard page.
                TEST_PCHECK(mprotect(m, page, PROT_NONE) == 0);
                stack_t ss = {};
                ss.ss_sp = static_cast<char*>(m) + page;
                ss.ss_size = min_size;
                TEST_PCHECK(sigaltstack(&ss, nullptr) == 0);
                struct sigaction sa = {};
                sa.sa_handler = NopHandler;
                sa.sa_flags = SA_ONSTACK;
                TEST_PCHECK(sigaction(SIGUSR1, &sa, nullptr) == 0);
                TEST_PCHECK(raise(SIGUSR1) == 0);
              }),
              IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
