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

#include <sys/syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "benchmark/benchmark.h"

namespace gvisor {
namespace testing {

namespace {

void BM_Getpid(benchmark::State& state) {
  for (auto _ : state) {
    syscall(SYS_getpid);
  }
}

BENCHMARK(BM_Getpid);

#ifdef __x86_64__

#define SYSNO_STR1(x) #x
#define SYSNO_STR(x) SYSNO_STR1(x)

// BM_GetpidOpt uses the most often pattern of calling system calls:
// mov $SYS_XXX, %eax; syscall.
void BM_GetpidOpt(benchmark::State& state) {
  for (auto s : state) {
    __asm__("movl $" SYSNO_STR(SYS_getpid) ", %%eax\n"
            "syscall\n"
            : : : "rax", "rcx", "r11");
  }
}

BENCHMARK(BM_GetpidOpt);
#endif  // __x86_64__

}  // namespace

}  // namespace testing
}  // namespace gvisor
