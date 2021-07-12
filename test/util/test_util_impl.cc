// Copyright 2019 The gVisor Authors.
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

#include <signal.h>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"

extern bool FLAGS_gtest_list_tests;
extern bool FLAGS_benchmark_list_tests;
extern std::string FLAGS_benchmark_filter;

namespace gvisor {
namespace testing {

void SetupGvisorDeathTest() {}

void TestInit(int* argc, char*** argv) {
  ::testing::InitGoogleTest(argc, *argv);
  benchmark::Initialize(argc, *argv);
  ::absl::ParseCommandLine(*argc, *argv);

  // Always mask SIGPIPE as it's common and tests aren't expected to handle it.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  TEST_CHECK(sigaction(SIGPIPE, &sa, nullptr) == 0);
}

int RunAllTests() {
  if (::testing::FLAGS_gtest_list_tests) {
    return RUN_ALL_TESTS();
  }
  if (FLAGS_benchmark_list_tests) {
    benchmark::RunSpecifiedBenchmarks();
    return 0;
  }

  // Run selected tests & benchmarks.
  int rc = RUN_ALL_TESTS();
  benchmark::RunSpecifiedBenchmarks();
  return rc;
}

}  // namespace testing
}  // namespace gvisor
