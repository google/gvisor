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
  uint32_t num_spinning_threads;
  uint32_t num_threads_to_wakeup;
  uint32_t num_active_contexts;
  uint32_t num_awake_contexts;
  uint32_t fast_path_disabled;
  uint32_t used_fast_path;
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
//
// The size of the queue must be a divisor of 2^32, because queue indexes are
// calculated as modules of uint32 values.
#define SPINNING_QUEUE_SIZE 256

// MAX_RE_ENQUEUE defines the amount of time a given entry in the spinning queue
// needs to reach timeout in order to be removed. Re-enqueuing a timeout is done
// in order to mitigate rdtsc inaccuracies.
#define MAX_RE_ENQUEUE 2

struct spinning_queue {
  uint32_t len;
  uint32_t start;
  uint32_t end;
  uint64_t start_times[SPINNING_QUEUE_SIZE];
  uint8_t num_times_re_enqueued[SPINNING_QUEUE_SIZE];
};

struct spinning_queue *__export_spinning_queue_addr;

// spinning_queue_push adds a new thread to the queue. It returns false if the
// queue is full, or if re_enqueue_times has reached MAX_RE_ENQUEUE.
static bool spinning_queue_push(uint8_t re_enqueue_times)
    __attribute__((warn_unused_result));
static bool spinning_queue_push(uint8_t re_enqueue_times) {
  struct spinning_queue *queue = __export_spinning_queue_addr;
  uint32_t idx, end, len;

  BUILD_BUG_ON(sizeof(struct spinning_queue) > SPINNING_QUEUE_MEM_SIZE);
  if (re_enqueue_times >= MAX_RE_ENQUEUE) {
    return false;
  }

  len = atomic_add(&queue->len, 1);
  if (len > SPINNING_QUEUE_SIZE) {
    atomic_sub(&queue->len, 1);
    return false;
  }
  end = atomic_add(&queue->end, 1);

  idx = end - 1;
  atomic_store(&queue->num_times_re_enqueued[idx % SPINNING_QUEUE_SIZE],
               re_enqueue_times);
  atomic_store(&queue->start_times[idx % SPINNING_QUEUE_SIZE], rdtsc());
  return true;
}

// spinning_queue_pop() removes one thread from a queue that has been spinning
// the shortest time.
// However it doesn't take into account the spinning re-enqueue.
static void spinning_queue_pop() {
  struct spinning_queue *queue = __export_spinning_queue_addr;

  atomic_sub(&queue->end, 1);
  atomic_sub(&queue->len, 1);
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
  uint8_t re_enqueue = 0;

  while (1) {
    uint32_t idx, qidx;

    idx = atomic_load(&queue->start);
    qidx = idx % SPINNING_QUEUE_SIZE;
    ts = atomic_load(&queue->start_times[qidx]);

    if (ts == 0) continue;
    if (rdtsc() - ts < timeout) return false;
    if (idx != atomic_load(&queue->start)) continue;  // Lose the race.

    re_enqueue = atomic_load(&queue->num_times_re_enqueued[qidx]);
    if (atomic_compare_exchange(&queue->start_times[qidx], &ts, 0)) {
      atomic_add(&queue->start, 1);
      break;
    }
  }

  atomic_sub(&queue->len, 1);
  if (timeout == 0) return true;
  return !spinning_queue_push(re_enqueue + 1);
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
      panic(STUB_ERROR_BAD_CONTEXT_ID, context_id);
    }
    struct thread_context *ctx = thread_context_addr(context_id);
    sysmsg->context = ctx;
    atomic_store(&ctx->acked_time, rdtsc());
    atomic_store(&ctx->thread_id, sysmsg->thread_id);
    return ctx;
  }
  return NULL;
}

// get_context_fast sets nr_active_threads_p only if it deactivates the thread.
static struct thread_context *get_context_fast(struct sysmsg *sysmsg,
                                               struct context_queue *queue,
                                               uint32_t *nr_active_threads_p) {
  uint32_t nr_active_threads, nr_awake_contexts;

  if (!spinning_queue_push(0)) return NULL;
  atomic_store(&queue->used_fast_path, 1);

  while (1) {
    struct thread_context *ctx;

    ctx = queue_get_context(sysmsg);
    if (ctx) {
      spinning_queue_pop();
      return ctx;
    }

    if (atomic_load(&queue->fast_path_disabled) != 0) {
      if (!spinning_queue_remove_first(0))
        panic(STUB_ERROR_SPINNING_QUEUE_DECREF, 0);
      break;
    }

    nr_active_threads = atomic_load(&queue->num_active_threads);
    nr_awake_contexts = atomic_load(&queue->num_awake_contexts);

    if (nr_awake_contexts < nr_active_threads) {
      if (atomic_compare_exchange(&queue->num_active_threads,
                                  &nr_active_threads, nr_active_threads - 1)) {
        nr_active_threads -= 1;
        if (!spinning_queue_remove_first(0))
          panic(STUB_ERROR_SPINNING_QUEUE_DECREF, 0);
        *nr_active_threads_p = nr_active_threads;
        break;
      }
    }

    if (spinning_queue_remove_first(__export_deep_sleep_timeout)) {
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

  struct thread_context *ctx;
  for (;;) {
    atomic_add(&queue->num_spinning_threads, 1);

    // Change sysmsg thread state just to indicate thread is not asleep.
    atomic_store(&sysmsg->state, THREAD_STATE_PREP);
    ctx = queue_get_context(sysmsg);
    if (ctx) {
      goto exit;
    }

    bool fast_path_enabled = atomic_load(&queue->fast_path_disabled) == 0;

    nr_active_threads = NR_IF_THREAD_IS_ACTIVE;
    if (fast_path_enabled) {
      ctx = get_context_fast(sysmsg, queue, &nr_active_threads);
      if (ctx) goto exit;
    }
    if (nr_active_threads == NR_IF_THREAD_IS_ACTIVE) {
      nr_active_threads = atomic_sub(&queue->num_active_threads, 1);
    }

    atomic_sub(&queue->num_spinning_threads, 1);
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
exit:
  atomic_sub(&queue->num_spinning_threads, 1);
  return ctx;
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
    atomic_store(&ctx->state_changed_time, rdtsc());
    atomic_store(&ctx->state, new_context_state);
    if (atomic_load(&ctx->sentry_fast_path) == 0) {
      int ret = sys_futex(&ctx->state, FUTEX_WAKE, 1, NULL, NULL, 0);
      if (ret < 0) {
        panic(STUB_ERROR_FUTEX, ret);
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
