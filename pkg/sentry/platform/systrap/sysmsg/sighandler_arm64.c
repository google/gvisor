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
#include <asm/sigcontext.h>
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

#include "sysmsg.h"
#include "sysmsg_offsets.h"

// TODO(b/271631387): These globals are shared between AMD64 and ARM64; move to
// sysmsg_lib.c.
struct arch_state __export_arch_state;
uint64_t __export_context_decoupling_exp;

long __syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  // ARM64 syscall interface passes the syscall number in x8 and the 6 arguments
  // in x0-x5. The return value is in x0.
  //
  // See: https://man7.org/linux/man-pages/man2/syscall.2.html
  register long x8 __asm__("x8") = n;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;
  __asm__ __volatile__("svc #0"
                       : "=r"(x0)
                       : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                       : "memory", "cc");
  return x0;
}

static __inline void set_tls(uint64_t tls) {
  __asm__("msr tpidr_el0,%0" : : "r"(tls));
}

static __inline uint64_t get_tls() {
  uint64_t tls;
  __asm__("mrs %0,tpidr_el0" : "=r"(tls));
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
  for (int i = 0; i < 31; i++ ) {
    ptregs->regs[i] = ucontext->uc_mcontext.regs[i];
  }
  ptregs->sp = ucontext->uc_mcontext.sp;
  ptregs->pc = ucontext->uc_mcontext.pc;
  ptregs->pstate = ucontext->uc_mcontext.pstate;
}

static void ptregs_to_gregs(ucontext_t *ucontext,
                            struct user_regs_struct *ptregs) {
  for (int i = 0; i < 31; i++ ) {
    ucontext->uc_mcontext.regs[i] = ptregs->regs[i];
  }
  ucontext->uc_mcontext.sp = ptregs->sp;
  ucontext->uc_mcontext.pc = ptregs->pc;
  ucontext->uc_mcontext.pstate = ptregs->pstate;
}

void __export_sighandler(int signo, siginfo_t *siginfo, void *_ucontext) {
  ucontext_t *ucontext = _ucontext;
  void *sp = sysmsg_sp();
  struct sysmsg *sysmsg = sysmsg_addr(sp);

  if (sysmsg != sysmsg->self) panic(0xdeaddead);
  int32_t thread_state = __atomic_load_n(&sysmsg->state, __ATOMIC_ACQUIRE);
  if (__export_context_decoupling_exp &&
      thread_state == THREAD_STATE_INITIALIZING) {
    // Find a new context and exit to restore it.
    __export_start(sysmsg, _ucontext);
    return;
  }

  struct thread_context *ctx = thread_context_addr(sysmsg);

  uint32_t ctx_state = CONTEXT_STATE_INVALID;
  ctx->signo = signo;

  gregs_to_ptregs(ucontext, &ctx->ptregs);

  // Signal frames for ARM64 include 8 byte magic header before the floating
  // point context.
  //
  // See: arch/arm64/include/uapi/asm/sigcontext.h
  const uint64_t kSigframeMagicHeaderLen = sizeof(struct _aarch64_ctx);
  // Verify the header.
  if (((uint32_t *)&ucontext->uc_mcontext.__reserved)[0] != FPSIMD_MAGIC) {
    panic(0xbadf);
  }
  uint8_t *fpStatePointer =
      (uint8_t *)&ucontext->uc_mcontext.__reserved + kSigframeMagicHeaderLen;
  if (__export_context_decoupling_exp) {
    memcpy(ctx->fpstate, fpStatePointer, __export_arch_state.fp_len);
  } else {
    sysmsg->fpstate = (uint64_t)(fpStatePointer) - (uint64_t)sysmsg;
  }
  ctx->tls = get_tls();
  ctx->siginfo = *siginfo;
  switch (signo) {
    case SIGSYS: {
      ctx_state = CONTEXT_STATE_SYSCALL;
      if (siginfo->si_arch != AUDIT_ARCH_AARCH64) {
        // gVisor doesn't support x32 system calls, so let's change the syscall
        // number so that it returns ENOSYS. The value added here is just a
        // random large number which is large enough to not match any existing
        // syscall number in linux.
        ctx->ptregs.regs[8] += 0x86000000;
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

  for (;;) {
    if (__export_context_decoupling_exp) {
      ctx = switch_context(sysmsg, ctx, ctx_state);
    } else {
      ctx->state = ctx_state;
      wait_state(sysmsg, THREAD_STATE_EVENT);
    }

    if (__atomic_load_n(&ctx->interrupt, __ATOMIC_ACQUIRE) != 0) {
      // This context got interrupted while it was waiting in the queue.
      // Setup all the necessary bits to let the sentry know this context has
      // switched back because of it.
      __atomic_store_n(&ctx->interrupt, 0, __ATOMIC_RELEASE);
      ctx_state = CONTEXT_STATE_FAULT;
      ctx->signo = SIGCHLD;
      ctx->siginfo.si_signo = SIGCHLD;
    } else {
      break;
    }
  }
  restore_state(sysmsg, ctx, _ucontext);
}

// On ARM restore_state sets up a correct restore from the sighandler by
// populating _ucontext.
void restore_state(struct sysmsg *sysmsg, struct thread_context *ctx,
                   void *_ucontext) {
  ucontext_t *ucontext = _ucontext;
  struct fpsimd_context *fpctx = &ucontext->uc_mcontext.__reserved;
  uint8_t *fpStatePointer = (uint8_t *)&fpctx->fpsr;

  if (__export_context_decoupling_exp &&
      __atomic_load_n(&ctx->fpstate_changed, __ATOMIC_ACQUIRE)) {
    memcpy(fpStatePointer, ctx->fpstate, __export_arch_state.fp_len);
  }
  ptregs_to_gregs(ucontext, &ctx->ptregs);
  set_tls(ctx->tls);
  __atomic_store_n(&sysmsg->state, THREAD_STATE_NONE, __ATOMIC_RELEASE);
}
