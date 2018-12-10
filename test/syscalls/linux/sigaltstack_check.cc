// Copyright 2018 Google LLC
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

// Checks that there is no alternate signal stack by default.
//
// Used by a test in sigaltstack.cc.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test/util/logging.h"

int main(int /* argc */, char** /* argv */) {
  stack_t stack;
  TEST_CHECK(sigaltstack(nullptr, &stack) >= 0);
  TEST_CHECK(stack.ss_flags == SS_DISABLE);
  TEST_CHECK(stack.ss_sp == 0);
  TEST_CHECK(stack.ss_size == 0);
  return 0;
}
