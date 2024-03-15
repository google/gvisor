// Copyright 2024 The gVisor Authors.
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

#include <cstddef>
#include <cstdint>

#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

// If we don't run the benchmark as the library expects (i.e. by exhausting
// state), it retries the benchmark.
#define SKIP_IF_NO_SAVE_RESTORE(state)                          \
  do {                                                          \
    if (!::gvisor::testing::IsRunningWithSaveRestore()) { \
      for (auto _ : state) {                                    \
      }                                                         \
      return;                                                   \
    }                                                           \
  } while (0)

namespace gvisor {
namespace testing {

namespace {

// These benchmarks measure the amount of time required to perform a
// cooperative checkpoint/restore cycle via the test runner. More detailed
// metrics can be found in sandbox logs.

void BM_NoExtraMemory(benchmark::State& state) {
  SKIP_IF_NO_SAVE_RESTORE(state);
  for (auto _ : state) {
    MaybeSave();
  }
}

// All benchmarks must UseRealTime() since the monotonic clock does not advance
// between save and restore.
BENCHMARK(BM_NoExtraMemory)->UseRealTime();

void RandomizeMapping(Mapping const& m) {
  RandomizeBuffer(static_cast<char*>(m.ptr()), m.len());
}

// This benchmark allocates 5 GB of memory and fills it with random data, which
// should be incompressible.
void BM_Random5GB(benchmark::State& state) {
  SKIP_IF_NO_SAVE_RESTORE(state);
  DisableSave ds;

  // Use mmap()s rather than heap allocations since we have no control over the
  // release of the latter to the OS.
  constexpr std::size_t kExtraMemorySize = 5ULL << 30;
  Mapping m = TEST_CHECK_NO_ERRNO_AND_VALUE(
      MmapAnon(kExtraMemorySize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  RandomizeMapping(m);

  ds.reset();
  for (auto _ : state) {
    MaybeSave();
  }
}

BENCHMARK(BM_Random5GB)->UseRealTime();

// This benchmark allocates 5 GB of memory and fills it with base64-encoded
// random data, which is theoretically compressible to a ratio of 0.75 (6 bits
// per 8 bits).
void BM_Base64Random5GB(benchmark::State& state) {
  SKIP_IF_NO_SAVE_RESTORE(state);
  DisableSave ds;

  // Use mmap()s rather than heap allocations since we have no control over the
  // release of the latter to the OS.
  // (We can't use absl::Base64Escape() for this reason.)
  constexpr std::size_t kExtraMemorySize = 5ULL << 30;
  constexpr std::size_t kExtraMemoryUnencodedSize = kExtraMemorySize * 3 / 4;
  Mapping m_tmp = TEST_CHECK_NO_ERRNO_AND_VALUE(
      MmapAnon(kExtraMemoryUnencodedSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  RandomizeMapping(m_tmp);
  Mapping m = TEST_CHECK_NO_ERRNO_AND_VALUE(
      MmapAnon(kExtraMemorySize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  {
    constexpr char kBase64Enc[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static_assert(sizeof(kBase64Enc) == 65);  // 64 + 1 for trailing NUL
    char const* const in = static_cast<char*>(m_tmp.ptr());
    char* const out = static_cast<char*>(m.ptr());
    std::size_t j = 0;
    // This relies on kExtraMemoryUnencodedSize being a multiple of 3.
    for (std::size_t i = 0; i < kExtraMemoryUnencodedSize; i += 3) {
      std::uint32_t tmp = (static_cast<std::uint32_t>(in[i]) << 16) |
                          (static_cast<std::uint32_t>(in[i + 1]) << 8) |
                          static_cast<std::uint32_t>(in[i + 2]);
      out[j] = kBase64Enc[tmp >> 18];
      out[j + 1] = kBase64Enc[(tmp >> 12) & 63];
      out[j + 2] = kBase64Enc[(tmp >> 6) & 63];
      out[j + 3] = kBase64Enc[tmp & 63];
      j += 4;
    }
  }
  m_tmp.reset();

  ds.reset();
  for (auto _ : state) {
    MaybeSave();
  }
}

BENCHMARK(BM_Base64Random5GB)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
