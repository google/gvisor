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

#include "vdso/vdso_time.h"

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "vdso/cycle_clock.h"
#include "vdso/seqlock.h"
#include "vdso/syscalls.h"

// struct params defines the layout of the parameter page maintained by the
// kernel (i.e., sentry).
//
// This is similar to the VVAR page maintained by the normal Linux kernel for
// its VDSO, but it has a different layout.
//
// It must be kept in sync with VDSOParamPage in pkg/sentry/kernel/vdso.go.
struct params {
  uint64_t seq_count;

  uint64_t monotonic_ready;
  int64_t monotonic_base_cycles;
  int64_t monotonic_base_ref;
  uint64_t monotonic_frequency;

  uint64_t realtime_ready;
  int64_t realtime_base_cycles;
  int64_t realtime_base_ref;
  uint64_t realtime_frequency;
};

// Returns a pointer to the global parameter page.
//
// This page lives in the page just before the VDSO binary itself. The linker
// defines _params as the page before the VDSO.
//
// Ideally, we'd simply declare _params as an extern struct params.
// Unfortunately various combinations of old/new versions of gcc/clang and
// gold/bfd struggle to generate references to such a global without generating
// relocations.
//
// So instead, we use inline assembly with a construct that seems to have wide
// compatibility across many toolchains.
inline struct params* get_params() {
  struct params* p = nullptr;
  asm volatile("leaq _params(%%rip), %0" : "=r"(p) : :);
  return p;
}

namespace vdso {

const uint64_t kNsecsPerSec = 1000000000UL;

inline struct timespec ns_to_timespec(uint64_t ns) {
  struct timespec ts;
  ts.tv_sec = ns / kNsecsPerSec;
  ts.tv_nsec = ns % kNsecsPerSec;
  return ts;
}

inline uint64_t cycles_to_ns(uint64_t frequency, uint64_t cycles) {
  uint64_t mult = (kNsecsPerSec << 32) / frequency;
  return ((unsigned __int128)cycles * mult) >> 32;
}

// ClockRealtime() is the VDSO implementation of clock_gettime(CLOCK_REALTIME).
int ClockRealtime(struct timespec* ts) {
  struct params* params = get_params();
  uint64_t seq;
  uint64_t ready;
  int64_t base_ref;
  int64_t base_cycles;
  uint64_t frequency;
  int64_t now_cycles;

  do {
    seq = read_seqcount_begin(&params->seq_count);
    ready = params->realtime_ready;
    base_ref = params->realtime_base_ref;
    base_cycles = params->realtime_base_cycles;
    frequency = params->realtime_frequency;
    now_cycles = cycle_clock();
  } while (read_seqcount_retry(&params->seq_count, seq));

  if (!ready) {
    // The sandbox kernel ensures that we won't compute a time later than this
    // once the params are ready.
    return sys_clock_gettime(CLOCK_REALTIME, ts);
  }

  int64_t delta_cycles =
      (now_cycles < base_cycles) ? 0 : now_cycles - base_cycles;
  int64_t now_ns = base_ref + cycles_to_ns(frequency, delta_cycles);
  *ts = ns_to_timespec(now_ns);
  return 0;
}

// ClockMonotonic() is the VDSO implementation of
// clock_gettime(CLOCK_MONOTONIC).
int ClockMonotonic(struct timespec* ts) {
  struct params* params = get_params();
  uint64_t seq;
  uint64_t ready;
  int64_t base_ref;
  int64_t base_cycles;
  uint64_t frequency;
  int64_t now_cycles;

  do {
    seq = read_seqcount_begin(&params->seq_count);
    ready = params->monotonic_ready;
    base_ref = params->monotonic_base_ref;
    base_cycles = params->monotonic_base_cycles;
    frequency = params->monotonic_frequency;
    now_cycles = cycle_clock();
  } while (read_seqcount_retry(&params->seq_count, seq));

  if (!ready) {
    // The sandbox kernel ensures that we won't compute a time later than this
    // once the params are ready.
    return sys_clock_gettime(CLOCK_MONOTONIC, ts);
  }

  int64_t delta_cycles =
      (now_cycles < base_cycles) ? 0 : now_cycles - base_cycles;
  int64_t now_ns = base_ref + cycles_to_ns(frequency, delta_cycles);
  *ts = ns_to_timespec(now_ns);
  return 0;
}

}  // namespace vdso
