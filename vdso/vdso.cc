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

// This is the VDSO for sandboxed binaries. This file just contains the entry
// points to the VDSO. All of the real work is done in vdso_time.cc

#define _DEFAULT_SOURCE  // ensure glibc provides struct timezone.
#include <sys/time.h>
#include <time.h>

#include "vdso/syscalls.h"
#include "vdso/vdso_time.h"

namespace vdso {
namespace {

int __common_clock_gettime(clockid_t clock, struct timespec* ts) {
  int ret;

  switch (clock) {
    case CLOCK_REALTIME_COARSE:
      // Fallthrough, CLOCK_REALTIME_COARSE is an alias for CLOCK_REALTIME
    case CLOCK_REALTIME:
      ret = ClockRealtime(ts);
      break;

    case CLOCK_BOOTTIME:
      // Fallthrough, CLOCK_BOOTTIME is an alias for CLOCK_MONOTONIC
    case CLOCK_MONOTONIC_RAW:
      // Fallthrough, CLOCK_MONOTONIC_RAW is an alias for CLOCK_MONOTONIC
    case CLOCK_MONOTONIC_COARSE:
      // Fallthrough, CLOCK_MONOTONIC_COARSE is an alias for CLOCK_MONOTONIC
    case CLOCK_MONOTONIC:
      ret = ClockMonotonic(ts);
      break;

    default:
      ret = sys_clock_gettime(clock, ts);
      break;
  }

  return ret;
}

int __common_gettimeofday(struct timeval* tv, struct timezone* tz) {
  if (tv) {
    struct timespec ts;
    int ret = ClockRealtime(&ts);
    if (ret) {
      return ret;
    }
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
  }

  // Nobody should be calling gettimeofday() with a non-NULL
  // timezone pointer. If they do then they will get zeros.
  if (tz) {
    tz->tz_minuteswest = 0;
    tz->tz_dsttime = 0;
  }

  return 0;
}
}  // namespace

// __kernel_rt_sigreturn() implements rt_sigreturn()
extern "C" void __kernel_rt_sigreturn(unsigned long unused) {
  // No optimizations yet, just make the real system call.
  sys_rt_sigreturn();
}

#if __x86_64__

// __vdso_clock_gettime() implements clock_gettime()
extern "C" int __vdso_clock_gettime(clockid_t clock, struct timespec* ts) {
  return __common_clock_gettime(clock, ts);
}
extern "C" int clock_gettime(clockid_t clock, struct timespec* ts)
    __attribute__((weak, alias("__vdso_clock_gettime")));

// __vdso_gettimeofday() implements gettimeofday()
extern "C" int __vdso_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return __common_gettimeofday(tv, tz);
}
extern "C" int gettimeofday(struct timeval* tv, struct timezone* tz)
    __attribute__((weak, alias("__vdso_gettimeofday")));

// __vdso_time() implements time()
extern "C" time_t __vdso_time(time_t* t) {
  struct timespec ts;
  ClockRealtime(&ts);
  if (t) {
    *t = ts.tv_sec;
  }
  return ts.tv_sec;
}
extern "C" time_t time(time_t* t) __attribute__((weak, alias("__vdso_time")));

// __vdso_getcpu() implements getcpu()
extern "C" long __vdso_getcpu(unsigned* cpu, unsigned* node,
                              struct getcpu_cache* cache) {
  // No optimizations yet, just make the real system call.
  return sys_getcpu(cpu, node, cache);
}
extern "C" long getcpu(unsigned* cpu, unsigned* node,
                       struct getcpu_cache* cache)
    __attribute__((weak, alias("__vdso_getcpu")));

#elif __aarch64__

// __kernel_clock_gettime() implements clock_gettime()
extern "C" int __kernel_clock_gettime(clockid_t clock, struct timespec* ts) {
  return __common_clock_gettime(clock, ts);
}

// __kernel_gettimeofday() implements gettimeofday()
extern "C" int __kernel_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return __common_gettimeofday(tv, tz);
}

// __kernel_clock_getres() implements clock_getres()
extern "C" int __kernel_clock_getres(clockid_t clock, struct timespec* res) {
  int ret = 0;

  switch (clock) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME: {
      if (res == nullptr) {
        return 0;
      }

      res->tv_sec = 0;
      res->tv_nsec = 1;
      break;
    }

    default:
      ret = sys_clock_getres(clock, res);
      break;
  }

  return ret;
}

#else
#error "unsupported architecture"
#endif
}  // namespace vdso
