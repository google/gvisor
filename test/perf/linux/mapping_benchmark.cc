// Copyright 2020 The gVisor Authors.
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

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Conservative value for /proc/sys/vm/max_map_count, which limits the number of
// VMAs, minus a safety margin for VMAs that already exist for the test binary.
// The default value for max_map_count is
// include/linux/mm.h:DEFAULT_MAX_MAP_COUNT = 65530.
constexpr size_t kMaxVMAs = 64001;

// Map then unmap pages without touching them.
void BM_MapUnmap(benchmark::State& state) {
  // Number of pages to map.
  const int pages = state.range(0);

  while (state.KeepRunning()) {
    void* addr = mmap(0, pages * kPageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_CHECK_MSG(addr != MAP_FAILED, "mmap failed");

    int ret = munmap(addr, pages * kPageSize);
    TEST_CHECK_MSG(ret == 0, "munmap failed");
  }
}

BENCHMARK(BM_MapUnmap)->Range(1, 1 << 17)->UseRealTime();

// Map, touch, then unmap pages.
void BM_MapTouchUnmap(benchmark::State& state) {
  // Number of pages to map.
  const int pages = state.range(0);

  while (state.KeepRunning()) {
    void* addr = mmap(0, pages * kPageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_CHECK_MSG(addr != MAP_FAILED, "mmap failed");

    char* c = reinterpret_cast<char*>(addr);
    char* end = c + pages * kPageSize;
    while (c < end) {
      *c = 42;
      c += kPageSize;
    }

    int ret = munmap(addr, pages * kPageSize);
    TEST_CHECK_MSG(ret == 0, "munmap failed");
  }
}

BENCHMARK(BM_MapTouchUnmap)->Range(1, 1 << 17)->UseRealTime();

// Map and touch many pages, unmapping all at once.
//
// NOTE(b/111429208): This is a regression test to ensure performant mapping and
// allocation even with tons of mappings.
void BM_MapTouchMany(benchmark::State& state) {
  // Number of pages to map.
  const int page_count = state.range(0);

  while (state.KeepRunning()) {
    std::vector<void*> pages;

    for (int i = 0; i < page_count; i++) {
      void* addr = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      TEST_CHECK_MSG(addr != MAP_FAILED, "mmap failed");

      char* c = reinterpret_cast<char*>(addr);
      *c = 42;

      pages.push_back(addr);
    }

    for (void* addr : pages) {
      int ret = munmap(addr, kPageSize);
      TEST_CHECK_MSG(ret == 0, "munmap failed");
    }
  }

  state.SetBytesProcessed(kPageSize * page_count * state.iterations());
}

BENCHMARK(BM_MapTouchMany)->Range(1, 1 << 12)->UseRealTime();

void BM_PageFault(benchmark::State& state) {
  // Map the region in which we will take page faults. To ensure that each page
  // fault maps only a single page, each page we touch must correspond to a
  // distinct VMA. Thus we need a 1-page gap between each 1-page VMA. However,
  // each gap consists of a PROT_NONE VMA, instead of an unmapped hole, so that
  // if there are background threads running, they can't inadvertently creating
  // mappings in our gaps that are unmapped when the test ends.
  size_t test_pages = kMaxVMAs;
  // Ensure that test_pages is odd, since we want the test region to both
  // begin and end with a mapped page.
  if (test_pages % 2 == 0) {
    test_pages--;
  }
  const size_t test_region_bytes = test_pages * kPageSize;
  // Use MAP_SHARED here because madvise(MADV_DONTNEED) on private mappings on
  // gVisor won't force future sentry page faults (by design). Use MAP_POPULATE
  // so that Linux pre-allocates the shmem file used to back the mapping.
  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(test_region_bytes, PROT_READ, MAP_SHARED | MAP_POPULATE));
  for (size_t i = 0; i < test_pages / 2; i++) {
    ASSERT_THAT(
        mprotect(reinterpret_cast<void*>(m.addr() + ((2 * i + 1) * kPageSize)),
                 kPageSize, PROT_NONE),
        SyscallSucceeds());
  }

  const size_t mapped_pages = test_pages / 2 + 1;
  // "Start" at the end of the mapped region to force the mapped region to be
  // reset, since we mapped it with MAP_POPULATE.
  size_t cur_page = mapped_pages;
  for (auto _ : state) {
    if (cur_page >= mapped_pages) {
      // We've reached the end of our mapped region and have to reset it to
      // incur page faults again.
      state.PauseTiming();
      ASSERT_THAT(madvise(m.ptr(), test_region_bytes, MADV_DONTNEED),
                  SyscallSucceeds());
      cur_page = 0;
      state.ResumeTiming();
    }
    const uintptr_t addr = m.addr() + (2 * cur_page * kPageSize);
    const char c = *reinterpret_cast<volatile char*>(addr);
    benchmark::DoNotOptimize(c);
    cur_page++;
  }
}

BENCHMARK(BM_PageFault)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
