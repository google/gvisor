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

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// glibc does not provide a prototype for arch_prctl() so declare it here.
extern "C" int arch_prctl(int code, uintptr_t addr);

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

}  // namespace

}  // namespace testing
}  // namespace gvisor
