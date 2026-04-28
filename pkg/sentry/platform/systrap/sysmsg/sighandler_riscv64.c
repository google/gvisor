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

#define _GNU_SOURCE
#include <asm/unistd.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>

#include "atomic.h"
#include "sysmsg.h"
#include "sysmsg_offsets.h"

// TODO: workaround, need to figure out the reason
#define CTX_OFFSET 0x50

// TODO(b/271631387): These globals are shared between AMD64 and ARM64; move to
// sysmsg_lib.c.
struct arch_state __export_arch_state;
uint64_t __export_stub_start;
uint64_t __export_disable_syscall_patching;

long __syscall(long n, long a1_, long a2_, long a3_, long a4_, long a5_, long a6_) {
  // RISCV syscall interface passes the syscall number in a7 and the 6 arguments
  // in a0-a5. The return value is in a0.
  //
  // See: https://man7.org/linux/man-pages/man2/syscall.2.html
  register long a7 __asm__("a7") = n;
  register long a0 __asm__("a0") = a1_;
  register long a1 __asm__("a1") = a2_;
  register long a2 __asm__("a2") = a3_;
  register long a3 __asm__("a3") = a4_;
  register long a4 __asm__("a4") = a5_;
  register long a5 __asm__("a5") = a6_;
  __asm__ __volatile__(
          "ecall"
          : "=r"(a0)
          : "r"(a7), "0"(a0), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
          : "memory", "cc");
  return a0;
}

static __inline void set_tls(uint64_t tls) {
  __asm__("mv tp,%0" : : "r"(tls));
}

static __inline uint64_t get_tls() {
  uint64_t tls;
  __asm__("mv %0,tp" : "=r"(tls));
  return tls;
}

long sys_futex(uint32_t *addr, int op, int val, struct __kernel_timespec *tv,
               uint32_t *addr2, int val3) {
  return __syscall(__NR_futex, (long)addr, (long)op, (long)val, (long)tv,
                   (long)addr2, (long)val3);
}

static void gregs_to_ptregs(ucontext_t *ucontext,
                            struct user_regs_struct *ptregs) {
  // Set all registers.
  memcpy((uint8_t *)ptregs, (uint8_t *)ucontext->uc_mcontext.__gregs, NGREG * sizeof(unsigned long int));
}

static void ptregs_to_gregs(ucontext_t *ucontext,
                            struct user_regs_struct *ptregs) {
  memcpy((uint8_t *)(ucontext->uc_mcontext.__gregs)-CTX_OFFSET, (uint8_t *)ptregs, NGREG * sizeof(unsigned long int));
}

void __export_start(struct sysmsg *sysmsg, void *_ucontext) {
  panic(0x11111111, 0);
}

void __export_sighandler(int signo, siginfo_t *siginfo, void *_ucontext) {
  ucontext_t *ucontext = _ucontext;
  void *sp = sysmsg_sp();
  struct sysmsg *sysmsg = sysmsg_addr(sp);

  if (sysmsg != sysmsg->self) panic(STUB_ERROR_BAD_SYSMSG, 0);
  int32_t thread_state = atomic_load(&sysmsg->state);

  uint32_t ctx_state = CONTEXT_STATE_INVALID;
  struct thread_context *ctx = NULL, *old_ctx = NULL;

  if (thread_state == THREAD_STATE_INITIALIZING) {
    // Find a new context and exit to restore it.
    init_new_thread();
    goto init;
  }

  ctx = sysmsg->context;
  old_ctx = sysmsg->context;

  ctx->signo = signo;

  gregs_to_ptregs(ucontext, &ctx->ptregs);

  memcpy(ctx->fpstate, (uint8_t *)&ucontext->uc_mcontext.__fpregs, __export_arch_state.fp_len);
  ctx->tls = get_tls();
  ctx->siginfo = *siginfo;
  switch (signo) {
    case SIGSYS: {
      ctx_state = CONTEXT_STATE_SYSCALL;
      if (siginfo->si_arch != AUDIT_ARCH_RISCV64) {
        // gVisor doesn't support x32 system calls, so let's change the syscall
        // number so that it returns ENOSYS. The value added here is just a
        // random large number which is large enough to not match any existing
        // syscall number in linux.
        ctx->ptregs.a7 += 0x86000000;
      }
      break;
    }
    case SIGCHLD:
    case SIGSEGV:
    case SIGBUS:
    case SIGFPE:
    case SIGTRAP:
    case SIGILL:
      ctx_state = CONTEXT_STATE_FAULT;
      break;
    default:
      return;
  }

init:
  for (;;) {
    ctx = switch_context(sysmsg, ctx, ctx_state);

    if (atomic_load(&ctx->interrupt) != 0) {
      // This context got interrupted while it was waiting in the queue.
      // Setup all the necessary bits to let the sentry know this context has
      // switched back because of it.
      atomic_store(&ctx->interrupt, 0);
      ctx_state = CONTEXT_STATE_FAULT;
      ctx->signo = SIGCHLD;
      ctx->siginfo.si_signo = SIGCHLD;
    } else {
      break;
    }
  }

  if (old_ctx != ctx || ctx->last_thread_id != sysmsg->thread_id) {
    ctx->fpstate_changed = 1;
  }
  restore_state(sysmsg, ctx, _ucontext);
  // riscv64: call sigreturn directly here
  __syscall(__NR_rt_sigreturn, 0, 0, 0, 0, 0, 0);
}

void restore_state(struct sysmsg *sysmsg, struct thread_context *ctx,
                   void *_ucontext) {
  ucontext_t *ucontext = _ucontext;

  if (atomic_load(&ctx->fpstate_changed)) {
    memcpy((uint8_t *)&ucontext->uc_mcontext.__fpregs-CTX_OFFSET, ctx->fpstate, __export_arch_state.fp_len);
  }
  ptregs_to_gregs(ucontext, &ctx->ptregs);
  set_tls(ctx->tls);
  atomic_store(&sysmsg->state, THREAD_STATE_NONE);
}
