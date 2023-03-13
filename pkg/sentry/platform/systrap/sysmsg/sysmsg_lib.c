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
uint64_t __export_context_queue_addr;

// LINT.IfChange
#define MAX_STUB_THREADS (4096)
#define MAX_CONTEXT_QUEUE_ENTRIES (MAX_STUB_THREADS + 1)
#define INVALID_CONTEXT_ID (MAX_STUB_THREADS + 1)
#define INVALID_THREAD_ID (MAX_STUB_THREADS + 1)

// See systrap/context_queue.go
struct context_queue {
  uint32_t start;
  uint32_t end;
  uint32_t polling_index;
  uint32_t polling_index_base;
  uint32_t num_sleeping_threads;
  uint32_t ringbuffer[MAX_CONTEXT_QUEUE_ENTRIES];
};
// LINT.ThenChange(../context_queue.go)

uint32_t is_empty(struct context_queue *queue) {
  return __atomic_load_n(&queue->start, __ATOMIC_ACQUIRE) ==
         __atomic_load_n(&queue->end, __ATOMIC_ACQUIRE);
}

int32_t queued_contexts(struct context_queue *queue) {
  return (__atomic_load_n(&queue->end, __ATOMIC_ACQUIRE) +
          MAX_CONTEXT_QUEUE_ENTRIES -
          __atomic_load_n(&queue->start, __ATOMIC_ACQUIRE)) %
         MAX_CONTEXT_QUEUE_ENTRIES;
}

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

void memcpy(uint8_t *dest, uint8_t *src, size_t n) {
  for (size_t i = 0; i < n; i += 1) {
    dest[i] = src[i];
  }
}

// get_context retrieves a context that is ready to be restored to the user.
// This populates sysmsg->thread_context_id.
struct thread_context *get_context(struct sysmsg *sysmsg) {
  struct context_queue *queue =
      (struct context_queue *)(__export_context_queue_addr);
  for (;;) {
    // Change sysmsg thread state just to indicate thread is not asleep.
    __atomic_store_n(&sysmsg->state, THREAD_STATE_PREP, __ATOMIC_RELEASE);
    unsigned long start = rdtsc();
    for (;;) {
      if (!is_empty(queue)) {
        uint32_t next = __atomic_load_n(&queue->start, __ATOMIC_ACQUIRE) %
                        MAX_CONTEXT_QUEUE_ENTRIES;
        uint32_t context_id = __atomic_exchange_n(
            &queue->ringbuffer[next], INVALID_CONTEXT_ID, __ATOMIC_ACQ_REL);
        if (context_id != INVALID_CONTEXT_ID) {
          __atomic_add_fetch(&queue->start, 1, __ATOMIC_ACQ_REL);
          if (context_id > MAX_STUB_THREADS) {
            panic(context_id);
          }
          sysmsg->context_id = context_id;
          struct thread_context *ctx = thread_context_addr(sysmsg);
          __atomic_store_n(&ctx->acked, 1, __ATOMIC_RELEASE);
          __atomic_store_n(&ctx->thread_id, sysmsg->thread_id,
                           __ATOMIC_RELEASE);
          return ctx;
        } else {
          continue;
        }
      }
      if ((rdtsc() - start) > __export_deep_sleep_timeout) {
        break;
      }

      spinloop();
    }
    __atomic_store_n(&sysmsg->state, THREAD_STATE_ASLEEP, __ATOMIC_RELEASE);

    __atomic_add_fetch(&queue->num_sleeping_threads, 1, __ATOMIC_ACQ_REL);
    sys_futex(&sysmsg->state, FUTEX_WAIT, THREAD_STATE_ASLEEP, NULL, NULL, 0);
    __atomic_sub_fetch(&queue->num_sleeping_threads, 1, __ATOMIC_ACQ_REL);
  }
}

// switch_context signals the sentry that the old context is ready to be worked
// on and retrieves a new context to switch to.
struct thread_context *switch_context(struct sysmsg *sysmsg,
                                      struct thread_context *ctx,
                                      enum context_state new_context_state) {
  __atomic_store_n(&ctx->thread_id, INVALID_THREAD_ID, __ATOMIC_RELEASE);
  __atomic_store_n(&ctx->last_thread_id, sysmsg->thread_id, __ATOMIC_RELEASE);
  __atomic_store_n(&ctx->state, new_context_state, __ATOMIC_RELEASE);
  if (__atomic_load_n(&ctx->sentry_fast_path, __ATOMIC_ACQUIRE) == 0) {
    int ret = sys_futex(&ctx->state, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (ret < 0) {
      panic(ret);
    }
  }
  uint32_t old_ctx_id = sysmsg->context_id;

  ctx = get_context(sysmsg);

  if (old_ctx_id != sysmsg->context_id ||
      ctx->last_thread_id != sysmsg->thread_id) {
    ctx->fpstate_changed = 1;
  }

  return ctx;
}

void __export_start(struct sysmsg *sysmsg, void *_ucontext) {
#if defined(__x86_64__)
  asm volatile("movq %%gs:0, %0\n" : "=r"(sysmsg) : :);
  if (sysmsg->self != sysmsg) {
    panic(0xdeaddead);
  }
#endif

  struct thread_context *ctx = get_context(sysmsg);
  __atomic_store_n(&ctx->fpstate_changed, 1, __ATOMIC_RELEASE);
  __atomic_store_n(&ctx->thread_id, sysmsg->thread_id, __ATOMIC_RELEASE);

  restore_state(sysmsg, ctx, _ucontext);
}

int wait_state(struct sysmsg *sysmsg, enum thread_state new_thread_state) {
  unsigned long handshake_timeout;
  uint64_t acked_events_prev;
  unsigned long start;
  int ret, v, fast_path;

  acked_events_prev = __atomic_load_n(&sysmsg->acked_events, __ATOMIC_SEQ_CST);
  // stub_fast_path can be changed non-atomically before we change the state and
  // wake up the Sentry.
  sysmsg->stub_fast_path = 1;
  __atomic_store_n(&sysmsg->state, new_thread_state, __ATOMIC_SEQ_CST);

  fast_path = __atomic_load_n(&sysmsg->sentry_fast_path, __ATOMIC_SEQ_CST);
  if (!fast_path) {
    ret = sys_futex(&sysmsg->state, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (ret < 0) panic(ret);
  }

  v = __atomic_load_n(&sysmsg->state, __ATOMIC_ACQUIRE);
  if (v == THREAD_STATE_DONE) goto out;

  handshake_timeout = __export_handshake_timeout;
  start = rdtsc();
  while (1) {
    v = __atomic_load_n(&sysmsg->state, __ATOMIC_ACQUIRE);
    if (v == THREAD_STATE_DONE) goto out;

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

  BUILD_BUG_ON(kTHREAD_STATE_NONE != THREAD_STATE_NONE);
  BUILD_BUG_ON(kTHREAD_STATE_INTERRUPT != THREAD_STATE_INTERRUPT);

  BUILD_BUG_ON(sizeof(struct thread_context) >
               ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT);
}
