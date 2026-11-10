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

#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int kThreads = 8;

// Touch one page per huge page, since faults on private anonymous memory may
// map a whole huge page.
constexpr size_t kStride = 2 << 20;
constexpr int kTouches = 32;

// Touch stores val to page[2] and page[3] from %xmm1, which is loaded before
// the store to page[0] faults.
void Touch(uint64_t* page, uint64_t val) {
  asm volatile(
      "movq %[val], %%xmm1\n"
      "punpcklqdq %%xmm1, %%xmm1\n"
      "movq %[val], (%[page])\n"
      "movups %%xmm1, 0x10(%[page])\n"
      :
      : [page] "r"(page), [val] "r"(val)
      : "xmm1", "memory");
}

bool Worker(uint64_t id, const std::atomic<bool>& stop,
            std::atomic<uint64_t>& iters) {
  for (uint64_t n = 0; !stop.load(); n++) {
    void* p = mmap(nullptr, kTouches * kStride, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
      fprintf(stderr, "mmap failed: %d\n", errno);
      return false;
    }
    for (int i = 0; i < kTouches; i++) {
      uint64_t* page =
          reinterpret_cast<uint64_t*>(static_cast<char*>(p) + i * kStride);
      uint64_t val = (id << 48) | (n << 8) | i;
      // Interleave system calls and page faults.
      getppid();
      Touch(page, val);
      if (page[2] != val || page[3] != val) {
        fprintf(stderr, "thread %lu: got {%#lx, %#lx}, want %#lx\n", id,
                page[2], page[3], val);
        return false;
      }
    }
    munmap(p, kTouches * kStride);
    iters++;
  }
  return true;
}

// FPU state that is live across a page fault must be preserved when the
// faulting thread is stopped and continued.
TEST(FPStateTest, PreservedAcrossStops) {
  pid_t child = fork();
  if (child == 0) {
    std::atomic<bool> stop(false);
    std::atomic<bool> ok(true);
    std::atomic<uint64_t> iters(0);
    std::vector<std::unique_ptr<ScopedThread>> threads;
    for (uint64_t i = 0; i < kThreads; i++) {
      threads.push_back(std::make_unique<ScopedThread>([&, i] {
        if (!Worker(i, stop, iters)) {
          ok = false;
        }
      }));
    }
    absl::SleepFor(absl::Seconds(3));
    stop = true;
    threads.clear();
    _exit(ok && iters > 0 ? 0 : 1);
  }
  ASSERT_THAT(child, SyscallSucceeds());

  int status;
  pid_t ret;
  while ((ret = waitpid(child, &status, WNOHANG)) == 0) {
    ASSERT_EQ(kill(child, SIGSTOP), 0);
    ASSERT_EQ(kill(child, SIGCONT), 0);
  }
  ASSERT_EQ(ret, child);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
