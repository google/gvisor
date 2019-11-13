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
#include "test/util/logging.h"

namespace gvisor {
namespace testing {

void SetupGvisorDeathTest() {}

void TestInit(int* argc, char*** argv) {
  ::testing::InitGoogleTest(argc, *argv);
  ::absl::ParseCommandLine(*argc, *argv);

  // Always mask SIGPIPE as it's common and tests aren't expected to handle it.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  TEST_CHECK(sigaction(SIGPIPE, &sa, nullptr) == 0);
}

}  // namespace testing
}  // namespace gvisor
