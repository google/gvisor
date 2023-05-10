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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "atomic.h"
#include "sysmsg.h"

// __export_deep_sleep_timeout is the timeout after which the stub thread stops
// polling and fall asleep.
uint64_t __export_deep_sleep_timeout;

// LINT.IfChange
#define MAX_GUEST_CONTEXTS (4095)
#define MAX_CONTEXT_QUEUE_ENTRIES (MAX_GUEST_CONTEXTS + 1)
#define INVALID_CONTEXT_ID 0xfefefefe
#define INVALID_THREAD_ID 0xfefefefe

// Each element of a context_queue ring buffer is a sum of its index shifted by
// CQ_INDEX_SHIFT and context_id.
#define CQ_INDEX_SHIFT 32
#define CQ_CONTEXT_MASK ((1UL << CQ_INDEX_SHIFT) - 1)

// See systrap/context_queue.go
struct context_queue {
  uint32_t start;
  uint32_t end;
  uint32_t num_active_threads;
  uint32_t num_threads_to_wakeup;
  uint32_t num_active_contexts;
  uint32_t num_awake_contexts;
  uint64_t fast_path_disalbed_ts;
  uint32_t fast_path_failed_in_row;
  uint32_t fast_path_disabled;
  uint64_t ringbuffer[MAX_CONTEXT_QUEUE_ENTRIES];
};

struct context_queue *__export_context_queue_addr;

// LINT.ThenChange(../context_queue.go)

uint32_t is_empty(struct context_queue *queue) {
  return atomic_load(&queue->start) == atomic_load(&queue->end);
}

int32_t queued_contexts(struct context_queue *queue) {
  return (atomic_load(&queue->end) + MAX_CONTEXT_QUEUE_ENTRIES -
          atomic_load(&queue->start)) %
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

void *__export_context_region;

static struct thread_context *thread_context_addr(uint32_t tcid) {
  return (struct thread_context *)(__export_context_region +
                                   tcid *
                                       ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT);
}

void memcpy(uint8_t *dest, uint8_t *src, size_t n) {
  for (size_t i = 0; i < n; i += 1) {
    dest[i] = src[i];
  }
}

// The spinning queue is a queue of spinning threads. It solves the
// fragmentation problem. The idea is to minimize the number of threads
// processing requests. We can't control how system threads are scheduled, so
// can't distribute requests efficiently. The spinning queue emulates virtual
// threads sorted by their spinning time.
//
// This queue is lock-less to be sure that any thread scheduled out
// from CPU doesn't block others.
#define SPINNING_QUEUE_SIZE 128

// MAX_SPINNING_THREADS is half of SPINNING_QUEUE_SIZE to be sure that the tail
// doesn't catch the head. More details are in spinning_queue_remove_first.
#define MAX_SPINNING_THREADS (SPINNING_QUEUE_SIZE / 2)
struct spinning_queue {
  uint32_t start;
  uint32_t end;
  uint64_t start_times[SPINNING_QUEUE_SIZE];
};

struct spinning_queue *__export_spinning_queue_addr;

// spinning_queue_push adds a new thread to the queue. It returns false if the
// queue if full.
static bool spinning_queue_push() __attribute__((warn_unused_result));
static bool spinning_queue_push(void) {
  struct spinning_queue *queue = __export_spinning_queue_addr;
  uint32_t idx, start, end;

  BUILD_BUG_ON(sizeof(struct spinning_queue) > SPINNING_QUEUE_MEM_SIZE);

  end = atomic_add(&queue->end, 1);
  start = atomic_load(&queue->start);
  if (end - start > MAX_SPINNING_THREADS) {
    atomic_sub(&queue->end, 1);
    return false;
  }

  idx = end - 1;
  atomic_store(&queue->start_times[idx % SPINNING_QUEUE_SIZE], rdtsc());
  return true;
}

// spinning_queue_pop() removes one thread from a queue that has been spinning
// the shortest time.
static void spinning_queue_pop() {
  struct spinning_queue *queue = __export_spinning_queue_addr;

  atomic_sub(&queue->end, 1);
}

// spinning_queue_remove_first removes one thread from a queue that has been
// spinning longer than others and longer than a specified timeout.
//
// If `timeout` is zero, it always removes one element and never returns false.
//
// Returns true if one thread has been removed from the queue.
static bool spinning_queue_remove_first(uint64_t timeout)
    __attribute__((warn_unused_result));
static bool spinning_queue_remove_first(uint64_t timeout) {
  struct spinning_queue *queue = __export_spinning_queue_addr;
  uint64_t ts;
  uint32_t idx;

  while (1) {
    idx = atomic_load(&queue->start);
    ts = atomic_load(&queue->start_times[idx % SPINNING_QUEUE_SIZE]);
    if (ts == 0 && timeout == 0) continue;
    if (ts == 0 || rdtsc() - ts < timeout) return false;

    // The current thread is still in a queue and the length of the queue is
    // twice of the maximum number of threads, so we can zero the element and be
    // sure that nobody is trying to set it in a  non-zero value.
    atomic_store(&queue->start_times[idx % SPINNING_QUEUE_SIZE], 0);
    if (atomic_compare_exchange(&queue->start, &idx, idx + 1)) {
      break;
    }
  }

  return true;
}

struct thread_context *queue_get_context(struct sysmsg *sysmsg) {
  struct context_queue *queue = __export_context_queue_addr;

  // Indexes should not jump when start or end are overflowed.
  BUILD_BUG_ON(UINT32_MAX % MAX_CONTEXT_QUEUE_ENTRIES !=
               MAX_CONTEXT_QUEUE_ENTRIES - 1);

  while (!is_empty(queue)) {
    uint64_t idx = atomic_load(&queue->start);
    uint32_t next = idx % MAX_CONTEXT_QUEUE_ENTRIES;
    uint64_t v = atomic_load(&queue->ringbuffer[next]);

    // We need to check the index to be sure that a ring buffer hasn't been
    // recycled.
    if ((v >> CQ_INDEX_SHIFT) != idx) continue;
    if (!atomic_compare_exchange(&queue->ringbuffer[next], &v,
                                 INVALID_CONTEXT_ID)) {
      continue;
    }

    uint32_t context_id = v & CQ_CONTEXT_MASK;
    if (context_id == INVALID_CONTEXT_ID) continue;

    atomic_add(&queue->start, 1);
    if (context_id > MAX_GUEST_CONTEXTS) {
      panic(context_id);
    }
    struct thread_context *ctx = thread_context_addr(context_id);
    sysmsg->context = ctx;
    atomic_store(&ctx->acked, 1);
    atomic_store(&ctx->thread_id, sysmsg->thread_id);
    return ctx;
  }
  return NULL;
}

#define FAILED_FAST_PATH_LIMIT 5
#define FAILED_FAST_PATH_TIMEOUT 20000000  // 10ms

// get_context_fast sets nr_active_threads_p only if it deactivates the thread.
static struct thread_context *get_context_fast(struct sysmsg *sysmsg,
                                               struct context_queue *queue,
                                               uint32_t *nr_active_threads_p) {
  uint32_t nr_active_threads, nr_awake_contexts;

  if (!spinning_queue_push()) return NULL;

  while (1) {
    struct thread_context *ctx;

    ctx = queue_get_context(sysmsg);
    if (ctx) {
      atomic_store(&queue->fast_path_failed_in_row, 0);
      spinning_queue_pop();
      return ctx;
    }

    if (atomic_load(&queue->fast_path_disabled) != 0) {
      if (!spinning_queue_remove_first(0)) panic(0);
      break;
    }

    nr_active_threads = atomic_load(&queue->num_active_threads);
    nr_awake_contexts = atomic_load(&queue->num_awake_contexts);

    if (nr_awake_contexts < nr_active_threads) {
      if (atomic_compare_exchange(&queue->num_active_threads,
                                  &nr_active_threads, nr_active_threads - 1)) {
        nr_active_threads -= 1;
        if (!spinning_queue_remove_first(0)) panic(0);
        *nr_active_threads_p = nr_active_threads;
        break;
      }
    }

    if (spinning_queue_remove_first(__export_deep_sleep_timeout)) {
      uint32_t nr = atomic_add(&queue->fast_path_failed_in_row, 1);
      if (nr >= FAILED_FAST_PATH_LIMIT) {
        atomic_store(&queue->fast_path_disalbed_ts, rdtsc());
      }
      break;
    }
    spinloop();
  }
  return NULL;
}

#define NR_IF_THREAD_IS_ACTIVE (~0)

static bool try_to_dec_threads_to_wakeup(struct context_queue *queue) {
  while (1) {
    uint32_t nr = atomic_load(&queue->num_threads_to_wakeup);
    if (nr == 0) {
      return false;
    }
    if (atomic_compare_exchange(&queue->num_threads_to_wakeup, &nr, nr - 1)) {
      return true;
    };
  }
}

void init_new_thread() {
  struct context_queue *queue = __export_context_queue_addr;

  atomic_add(&queue->num_active_threads, 1);
  try_to_dec_threads_to_wakeup(queue);
}

// get_context retrieves a context that is ready to be restored to the user.
// This populates sysmsg->thread_context_id.
struct thread_context *get_context(struct sysmsg *sysmsg) {
  struct context_queue *queue = __export_context_queue_addr;
  uint32_t nr_active_threads;

  for (;;) {
    struct thread_context *ctx;

    // Change sysmsg thread state just to indicate thread is not asleep.
    atomic_store(&sysmsg->state, THREAD_STATE_PREP);
    ctx = queue_get_context(sysmsg);
    if (ctx) {
      atomic_store(&queue->fast_path_failed_in_row, 0);
      return ctx;
    }

    uint64_t slow_path_ts = atomic_load(&queue->fast_path_disalbed_ts);
    bool fast_path_enabled = true;

    if (!slow_path_ts) {
      if (rdtsc() - slow_path_ts > FAILED_FAST_PATH_TIMEOUT) {
        atomic_store(&queue->fast_path_failed_in_row, 0);
        atomic_store(&queue->fast_path_disalbed_ts, 0);
      } else {
        fast_path_enabled = false;
      }
    }
    if (atomic_load(&queue->fast_path_disabled) != 0) {
      fast_path_enabled = false;
    }

    nr_active_threads = NR_IF_THREAD_IS_ACTIVE;
    if (fast_path_enabled) {
      ctx = get_context_fast(sysmsg, queue, &nr_active_threads);
      if (ctx) return ctx;
    }
    if (nr_active_threads == NR_IF_THREAD_IS_ACTIVE) {
      nr_active_threads = atomic_sub(&queue->num_active_threads, 1);
    }

    atomic_store(&sysmsg->state, THREAD_STATE_ASLEEP);
    uint32_t nr_active_contexts = atomic_load(&queue->num_active_contexts);
    // We have to make another attempt to get a context here to prevent TOCTTOU
    // races with waitOnState and kickSysmsgThread. There are two assumptions:
    // * If the queue isn't empty, one or more threads have to be active.
    // * A new thread isn't kicked, if the number of active threads are not less
    //   than a number of active contexts.
    if (nr_active_threads < nr_active_contexts) {
      ctx = queue_get_context(sysmsg);
      if (ctx) {
        atomic_store(&sysmsg->state, THREAD_STATE_PREP);
        atomic_add(&queue->num_active_threads, 1);
        return ctx;
      }
    }

    while (1) {
      if (!try_to_dec_threads_to_wakeup(queue)) {
        sys_futex(&queue->num_threads_to_wakeup, FUTEX_WAIT, 0, NULL, NULL, 0);
        continue;
      }
      // Mark this thread as being active only if it can get a context.
      ctx = queue_get_context(sysmsg);
      if (ctx) {
        atomic_store(&sysmsg->state, THREAD_STATE_PREP);
        atomic_add(&queue->num_active_threads, 1);
        return ctx;
      }
    }
  }
}

// switch_context signals the sentry that the old context is ready to be worked
// on and retrieves a new context to switch to.
struct thread_context *switch_context(struct sysmsg *sysmsg,
                                      struct thread_context *ctx,
                                      enum context_state new_context_state) {
  struct context_queue *queue = __export_context_queue_addr;

  if (ctx) {
    atomic_sub(&queue->num_active_contexts, 1);
    atomic_store(&ctx->thread_id, INVALID_THREAD_ID);
    atomic_store(&ctx->last_thread_id, sysmsg->thread_id);
    atomic_store(&ctx->state, new_context_state);
    if (atomic_load(&ctx->sentry_fast_path) == 0) {
      int ret = sys_futex(&ctx->state, FUTEX_WAKE, 1, NULL, NULL, 0);
      if (ret < 0) {
        panic(ret);
      }
    }
  }

  return get_context(sysmsg);
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
  BUILD_BUG_ON(offsetof_sysmsg_context != offsetof(struct sysmsg, context));

  BUILD_BUG_ON(offsetof_thread_context_fpstate !=
               offsetof(struct thread_context, fpstate));
  BUILD_BUG_ON(offsetof_thread_context_fpstate_changed !=
               offsetof(struct thread_context, fpstate_changed));
  BUILD_BUG_ON(offsetof_thread_context_ptregs !=
               offsetof(struct thread_context, ptregs));

  BUILD_BUG_ON(kTHREAD_STATE_NONE != THREAD_STATE_NONE);

  BUILD_BUG_ON(sizeof(struct thread_context) >
               ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT);
}
