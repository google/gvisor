// Copyright 2022 The gVisor Authors.
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

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "sysmsg.h"

// __export_deep_sleep_timeout is the timeout after which the stub thread stops
// polling and fall asleep.
uint64_t __export_deep_sleep_timeout;
uint64_t __export_handshake_timeout;
struct arch_state __export_arch_state;
uint64_t __export_context_decoupling_exp;

// A per-thread memory region is always align to STACK_SIZE.
// *------------*
// | guard page |
// |------------|
// | syshandler |
// |   stack    |
// |            |
// |------------|
// | guard page |
// |------------|
// |            |
// |     ^      |
// |    / \     |
// |     |      |
// |  altstack  |
// |------------|
// |   sysmsg   |
// *------------*

#if defined(__x86_64__)
static __inline__ unsigned long rdtsc(void) {
  unsigned h, l;
  __asm__ __volatile__("rdtsc" : "=a"(l), "=d"(h));
  return ((unsigned long)l) | (((unsigned long)h) << 32);
}

static __inline__ void spinloop(void) { asm("pause"); }
#elif defined(__aarch64__)
static __inline__ unsigned long rdtsc(void) {
  long val;
  asm volatile("mrs %0, cntvct_el0" : "=r"(val));
  return val;
}

static __inline__ void spinloop(void) { asm volatile("yield" : : : "memory"); }
#endif

int wait_state(struct sysmsg *sysmsg, uint32_t state) {
  unsigned long handshake_timeout;
  uint64_t acked_events_prev;
  unsigned long start;
  int ret, v, fast_path;

  acked_events_prev = __atomic_load_n(&sysmsg->acked_events, __ATOMIC_SEQ_CST);
  // stub_fast_path can be changed non-atomically before we change the state and
  // wake up the Sentry.
  sysmsg->stub_fast_path = 1;
  __atomic_store_n(&sysmsg->state, state, __ATOMIC_SEQ_CST);

  fast_path = __atomic_load_n(&sysmsg->sentry_fast_path, __ATOMIC_SEQ_CST);
  if (!fast_path) {
    ret = sys_futex(&sysmsg->state, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (ret < 0) panic(ret);
  }

  v = __atomic_load_n(&sysmsg->state, __ATOMIC_ACQUIRE);
  if (v == SYSMSG_STATE_DONE || v == SYSMSG_STATE_SIGACT) goto out;

  handshake_timeout = __export_handshake_timeout;
  start = rdtsc();
  while (1) {
    v = __atomic_load_n(&sysmsg->state, __ATOMIC_ACQUIRE);
    if (v == SYSMSG_STATE_DONE || v == SYSMSG_STATE_SIGACT) goto out;

    // The Sentry can change stub_fast_path to zero if it finds out that the
    // user task has to sleep.
    fast_path = __atomic_load_n(&sysmsg->stub_fast_path, __ATOMIC_ACQUIRE);
    if (fast_path) {
      unsigned long delta = rdtsc() - start;

      if (delta > __export_deep_sleep_timeout) {
        fast_path = 0;
        __atomic_store_n(&sysmsg->stub_fast_path, 0, __ATOMIC_SEQ_CST);
      }
      if (handshake_timeout != 0) {
        if (__atomic_load_n(&sysmsg->acked_events, __ATOMIC_SEQ_CST) !=
            acked_events_prev) {
          handshake_timeout = 0;
        } else if (delta > handshake_timeout) {
          __syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
          handshake_timeout += __export_handshake_timeout;
          continue;
        }
      }
    }

    if (fast_path) {
      spinloop();
    } else {
      sys_futex(&sysmsg->state, FUTEX_WAIT, v, NULL, NULL, 0);
    }
  }
out:
  __atomic_fetch_add(&sysmsg->acked_events, 1, __ATOMIC_SEQ_CST);
  return v;
}

void verify_offsets() {
  BUILD_BUG_ON(offsetof_sysmsg_self != offsetof(struct sysmsg, self));
  BUILD_BUG_ON(offsetof_sysmsg_ret_addr != offsetof(struct sysmsg, ret_addr));
  BUILD_BUG_ON(offsetof_sysmsg_syshandler !=
               offsetof(struct sysmsg, syshandler));
  BUILD_BUG_ON(offsetof_sysmsg_syshandler_stack !=
               offsetof(struct sysmsg, syshandler_stack));
  BUILD_BUG_ON(offsetof_sysmsg_app_stack != offsetof(struct sysmsg, app_stack));
  BUILD_BUG_ON(offsetof_sysmsg_interrupt != offsetof(struct sysmsg, interrupt));
  BUILD_BUG_ON(offsetof_sysmsg_type != offsetof(struct sysmsg, type));
  BUILD_BUG_ON(offsetof_sysmsg_state != offsetof(struct sysmsg, state));
  BUILD_BUG_ON(offsetof_sysmsg_context_id !=
               offsetof(struct sysmsg, context_id));
  BUILD_BUG_ON(offsetof_sysmsg_context_region !=
               offsetof(struct sysmsg, context_region));

  BUILD_BUG_ON(offsetof_thread_context_fpstate !=
               offsetof(struct thread_context, fpstate));
  BUILD_BUG_ON(offsetof_thread_context_fpstate_changed !=
               offsetof(struct thread_context, fpstate_changed));
  BUILD_BUG_ON(offsetof_thread_context_ptregs !=
               offsetof(struct thread_context, ptregs));

  BUILD_BUG_ON(kSYSMSG_SYSCALL != SYSMSG_SYSCALL);
  BUILD_BUG_ON(kSYSMSG_INTERRUPT != SYSMSG_INTERRUPT);
  BUILD_BUG_ON(kSYSMSG_STATE_NONE != SYSMSG_STATE_NONE);

  BUILD_BUG_ON(sizeof(struct thread_context) >
               ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT);
}
