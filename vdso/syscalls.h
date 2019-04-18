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

// System call support for the VDSO.
//
// Provides fallback system call interfaces for getcpu()
// and clock_gettime().

#ifndef VDSO_SYSCALLS_H_
#define VDSO_SYSCALLS_H_

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/types.h>

namespace vdso {

#if __x86_64__

struct getcpu_cache;

static inline int sys_clock_gettime(clockid_t clock, struct timespec* ts) {
  int num = __NR_clock_gettime;
  asm volatile("syscall\n"
               : "+a"(num)
               : "D"(clock), "S"(ts)
               : "rcx", "r11", "memory");
  return num;
}

static inline int sys_getcpu(unsigned* cpu, unsigned* node,
                             struct getcpu_cache* cache) {
  int num = __NR_getcpu;
  asm volatile("syscall\n"
               : "+a"(num)
               : "D"(cpu), "S"(node), "d"(cache)
               : "rcx", "r11", "memory");
  return num;
}

#elif __aarch64__

static inline int sys_rt_sigreturn(void) {
  int num = __NR_rt_sigreturn;

  asm volatile(
      "mov x8, %0\n"
      "svc #0    \n"
      : "+r"(num)
      :
      :);
  return num;
}

static inline int sys_clock_gettime(clockid_t _clkid, struct timespec *_ts) {
  register struct timespec *ts asm("x1") = _ts;
  register clockid_t clkid asm("x0") = _clkid;
  register long ret asm("x0");
  register long nr asm("x8") = __NR_clock_gettime;

  asm volatile("svc #0\n"
               : "=r"(ret)
               : "r"(clkid), "r"(ts), "r"(nr)
               : "memory");
  return ret;
}

static inline int sys_clock_getres(clockid_t _clkid, struct timespec *_ts) {
  register struct timespec *ts asm("x1") = _ts;
  register clockid_t clkid asm("x0") = _clkid;
  register long ret asm("x0");
  register long nr asm("x8") = __NR_clock_getres;

  asm volatile("svc #0\n"
               : "=r"(ret)
               : "r"(clkid), "r"(ts), "r"(nr)
               : "memory");
  return ret;
}

#else
#error "unsupported architecture"
#endif
}  // namespace vdso

#endif  // VDSO_SYSCALLS_H_
