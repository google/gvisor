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

#include <signal.h>
#include <string.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void FixupHandler(int sig, siginfo_t* si, void* void_ctx) {
  static unsigned int dataval = 0;

  // Skip the offending instruction.
  ucontext_t* ctx = reinterpret_cast<ucontext_t*>(void_ctx);
  ctx->uc_mcontext.gregs[REG_RAX] = reinterpret_cast<greg_t>(&dataval);
}

void BM_FaultSignalFixup(benchmark::State& state) {
  // Set up the signal handler.
  struct sigaction sa = {};
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = FixupHandler;
  sa.sa_flags = SA_SIGINFO;
  TEST_CHECK(sigaction(SIGSEGV, &sa, nullptr) == 0);

  // Fault, fault, fault.
  for (auto _ : state) {
    // Trigger the segfault.
    asm volatile(
        "movq $0, %%rax\n"
        "movq $0x77777777, (%%rax)\n"
        :
        :
        : "rax");
  }
}

BENCHMARK(BM_FaultSignalFixup)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
