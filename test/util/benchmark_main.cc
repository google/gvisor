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

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "third_party/benchmark/src/commandlineflags.h"
#include "test/util/test_util.h"

DECLARE_bool(benchmark_list_internal);
DECLARE_string(benchmark_filter_internal);
ABSL_FLAG(bool, benchmark_enable_random_interleaving_internal, false,
          "forward");
ABSL_FLAG(double, benchmark_min_time_internal, -1.0, "forward");
ABSL_FLAG(int, benchmark_repetitions_internal, 1, "forward");

// From //third_party/benchmark.
//
// These conflict with the internal definitions, but all the benchmark binaries
// link against the external benchmark library for compatibility with the open
// source build. We massage the internal-only flags into the external ones, and
// call the function to actually run all registered external benchmarks.
namespace benchmark {
BM_DECLARE_bool(benchmark_list_tests);
BM_DECLARE_string(benchmark_filter);
BM_DECLARE_int32(benchmark_repetitions);
BM_DECLARE_double(benchmark_min_time);
BM_DECLARE_bool(benchmark_enable_random_interleaving);
extern size_t RunSpecifiedBenchmarks();
}  // namespace benchmark

using benchmark::FLAGS_benchmark_enable_random_interleaving;
using benchmark::FLAGS_benchmark_filter;
using benchmark::FLAGS_benchmark_list_tests;
using benchmark::FLAGS_benchmark_min_time;
using benchmark::FLAGS_benchmark_repetitions;

int main(int argc, char** argv) {
  gvisor::testing::TestInit(&argc, &argv);
  absl::SetFlag(&FLAGS_benchmark_list_tests,
                absl::GetFlag(FLAGS_benchmark_list_internal));
  absl::SetFlag(&FLAGS_benchmark_filter,
                absl::GetFlag(FLAGS_benchmark_filter_internal));
  absl::SetFlag(&FLAGS_benchmark_repetitions,
                absl::GetFlag(FLAGS_benchmark_repetitions_internal));
  absl::SetFlag(
      &FLAGS_benchmark_enable_random_interleaving,
      absl::GetFlag(FLAGS_benchmark_enable_random_interleaving_internal));
  absl::SetFlag(&FLAGS_benchmark_min_time,
                absl::GetFlag(FLAGS_benchmark_min_time_internal));

  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
