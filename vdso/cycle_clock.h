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

#ifndef VDSO_CYCLE_CLOCK_H_
#define VDSO_CYCLE_CLOCK_H_

#include <stdint.h>

#include "vdso/barrier.h"

namespace vdso {

#if __x86_64__

// TODO: The appropriate barrier instruction to use with rdtsc on
// x86_64 depends on the vendor. Intel processors can use lfence but AMD may
// need mfence, depending on MSR_F10H_DECFG_LFENCE_SERIALIZE_BIT.

static inline uint64_t cycle_clock(void) {
  uint32_t lo, hi;
  asm volatile("lfence" : : : "memory");
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

#elif __aarch64__

static inline uint64_t cycle_clock(void) {
  uint64_t val;
  asm volatile("mrs %0, CNTVCT_EL0" : "=r"(val)::"memory");
  return val;
}

#else
#error "unsupported architecture"
#endif

}  // namespace vdso

#endif  // VDSO_CYCLE_CLOCK_H_
