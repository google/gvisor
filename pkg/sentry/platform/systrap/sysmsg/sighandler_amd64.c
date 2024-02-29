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
#include <asm/prctl.h>
#include <asm/unistd_64.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>

#include "atomic.h"
#include "sysmsg.h"
#include "sysmsg_offsets.h"
#include "sysmsg_offsets_amd64.h"

// TODO(b/271631387): These globals are shared between AMD64 and ARM64; move to
// sysmsg_lib.c.
struct arch_state __export_arch_state;
uint64_t __export_stub_start;

long __syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8),
                         "r"(r9)
                       : "rcx", "r11", "memory");
  return ret;
}

long sys_futex(uint32_t *addr, int op, int val, struct __kernel_timespec *tv,
               uint32_t *addr2, int val3) {
  return __syscall(__NR_futex, (long)addr, (long)op, (long)val, (long)tv,
                   (long)addr2, (long)val3);
}

union csgsfs {
  uint64_t csgsfs;  // REG_CSGSFS
  struct {
    uint16_t cs;
    uint16_t gs;
    uint16_t fs;
    uint16_t ss;
  };
};

static void gregs_to_ptregs(ucontext_t *ucontext,
                            struct user_regs_struct *ptregs) {
  union csgsfs csgsfs = {.csgsfs = ucontext->uc_mcontext.gregs[REG_CSGSFS]};

  // Set all registers except:
  // * fs_base and gs_base, because they can be only changed by arch_prctl.
  // * DS and ES are not used on x86_64.
  ptregs->r15 = ucontext->uc_mcontext.gregs[REG_R15];
  ptregs->r14 = ucontext->uc_mcontext.gregs[REG_R14];
  ptregs->r13 = ucontext->uc_mcontext.gregs[REG_R13];
  ptregs->r12 = ucontext->uc_mcontext.gregs[REG_R12];
  ptregs->rbp = ucontext->uc_mcontext.gregs[REG_RBP];
  ptregs->rbx = ucontext->uc_mcontext.gregs[REG_RBX];
  ptregs->r11 = ucontext->uc_mcontext.gregs[REG_R11];
  ptregs->r10 = ucontext->uc_mcontext.gregs[REG_R10];
  ptregs->r9 = ucontext->uc_mcontext.gregs[REG_R9];
  ptregs->r8 = ucontext->uc_mcontext.gregs[REG_R8];
  ptregs->rax = ucontext->uc_mcontext.gregs[REG_RAX];
  ptregs->rcx = ucontext->uc_mcontext.gregs[REG_RCX];
  ptregs->rdx = ucontext->uc_mcontext.gregs[REG_RDX];
  ptregs->rsi = ucontext->uc_mcontext.gregs[REG_RSI];
  ptregs->rdi = ucontext->uc_mcontext.gregs[REG_RDI];
  ptregs->rip = ucontext->uc_mcontext.gregs[REG_RIP];
  ptregs->eflags = ucontext->uc_mcontext.gregs[REG_EFL];
  ptregs->rsp = ucontext->uc_mcontext.gregs[REG_RSP];

  ptregs->cs = csgsfs.cs;
  ptregs->ss = csgsfs.ss;
  ptregs->fs = csgsfs.fs;
  ptregs->gs = csgsfs.gs;
}

static void ptregs_to_gregs(ucontext_t *ucontext,
                            struct user_regs_struct *ptregs) {
  union csgsfs csgsfs = {.csgsfs = ucontext->uc_mcontext.gregs[REG_CSGSFS]};

  ucontext->uc_mcontext.gregs[REG_R15] = ptregs->r15;
  ucontext->uc_mcontext.gregs[REG_R14] = ptregs->r14;
  ucontext->uc_mcontext.gregs[REG_R13] = ptregs->r13;
  ucontext->uc_mcontext.gregs[REG_R12] = ptregs->r12;
  ucontext->uc_mcontext.gregs[REG_RBP] = ptregs->rbp;
  ucontext->uc_mcontext.gregs[REG_RBX] = ptregs->rbx;
  ucontext->uc_mcontext.gregs[REG_R11] = ptregs->r11;
  ucontext->uc_mcontext.gregs[REG_R10] = ptregs->r10;
  ucontext->uc_mcontext.gregs[REG_R9] = ptregs->r9;
  ucontext->uc_mcontext.gregs[REG_R8] = ptregs->r8;
  ucontext->uc_mcontext.gregs[REG_RAX] = ptregs->rax;
  ucontext->uc_mcontext.gregs[REG_RCX] = ptregs->rcx;
  ucontext->uc_mcontext.gregs[REG_RDX] = ptregs->rdx;
  ucontext->uc_mcontext.gregs[REG_RSI] = ptregs->rsi;
  ucontext->uc_mcontext.gregs[REG_RDI] = ptregs->rdi;
  ucontext->uc_mcontext.gregs[REG_RIP] = ptregs->rip;
  ucontext->uc_mcontext.gregs[REG_EFL] = ptregs->eflags;
  ucontext->uc_mcontext.gregs[REG_RSP] = ptregs->rsp;

  csgsfs.cs = ptregs->cs;
  csgsfs.ss = ptregs->ss;
  csgsfs.fs = ptregs->fs;
  csgsfs.gs = ptregs->gs;

  ucontext->uc_mcontext.gregs[REG_CSGSFS] = csgsfs.csgsfs;
}

// get_fsbase writes the current thread's fsbase value to ptregs.
static uint64_t get_fsbase(void) {
  uint64_t fsbase;
  if (__export_arch_state.fsgsbase) {
    asm volatile("rdfsbase %0" : "=r"(fsbase));
  } else {
    int ret =
        __syscall(__NR_arch_prctl, ARCH_GET_FS, (long)&fsbase, 0, 0, 0, 0);
    if (ret) {
      panic(STUB_ERROR_ARCH_PRCTL, ret);
    }
  }
  return fsbase;
}

// set_fsbase sets the current thread's fsbase to the fsbase value in ptregs.
static void set_fsbase(uint64_t fsbase) {
  if (__export_arch_state.fsgsbase) {
    asm volatile("wrfsbase %0" : : "r"(fsbase) : "memory");
  } else {
    int ret = __syscall(__NR_arch_prctl, ARCH_SET_FS, fsbase, 0, 0, 0, 0);
    if (ret) {
      panic(STUB_ERROR_ARCH_PRCTL, ret);
    }
  }
}

// switch_context_amd64 is a wrapper of switch_context() which does checks
// specific to amd64.
struct thread_context *switch_context_amd64(
    struct sysmsg *sysmsg, struct thread_context *ctx,
    enum context_state new_context_state) {
  struct thread_context *old_ctx = sysmsg->context;

  for (;;) {
    ctx = switch_context(sysmsg, ctx, new_context_state);

    // After setting THREAD_STATE_NONE, syshandled can be interrupted by
    // SIGCHLD. In this case, we consider that the current context contains
    // the actual state and sighandler can take control on it.
    atomic_store(&sysmsg->state, THREAD_STATE_NONE);
    if (atomic_load(&ctx->interrupt) != 0) {
      atomic_store(&sysmsg->state, THREAD_STATE_PREP);
      // This context got interrupted while it was waiting in the queue.
      // Setup all the necessary bits to let the sentry know this context has
      // switched back because of it.
      atomic_store(&ctx->interrupt, 0);
      new_context_state = CONTEXT_STATE_FAULT;
      ctx->signo = SIGCHLD;
      ctx->siginfo.si_signo = SIGCHLD;
      ctx->ptregs.orig_rax = -1;
    } else {
      break;
    }
  }
  if (old_ctx != ctx || ctx->last_thread_id != sysmsg->thread_id) {
    ctx->fpstate_changed = 1;
  }
  return ctx;
}

static void prep_fpstate_for_sigframe(void *buf, uint32_t user_size,
                                      bool use_xsave);

void __export_sighandler(int signo, siginfo_t *siginfo, void *_ucontext) {
  ucontext_t *ucontext = _ucontext;
  void *sp = sysmsg_sp();
  struct sysmsg *sysmsg = sysmsg_addr(sp);

  if (sysmsg != sysmsg->self) panic(STUB_ERROR_BAD_SYSMSG, 0);
  int32_t thread_state = atomic_load(&sysmsg->state);
  if (thread_state == THREAD_STATE_INITIALIZING) {
    // This thread was interrupted before it even had a context.
    return;
  }

  struct thread_context *ctx = sysmsg->context;

  // If the current thread is in syshandler, an interrupt has to be postponed,
  // because sysmsg can't be changed.
  if (signo == SIGCHLD && thread_state != THREAD_STATE_NONE) {
    return;
  }

  // Handle faults in syshandler.
  if ((signo == SIGSEGV || signo == SIGBUS) && sysmsg->fault_jump) {
    ucontext->uc_mcontext.gregs[REG_RIP] += sysmsg->fault_jump;
    sysmsg->fault_jump = 0;
    return;
  }

  long fs_base = get_fsbase();

  ctx->signo = signo;
  ctx->siginfo = *siginfo;
  // syshandler sets THREAD_STATE_NONE right before it starts resuming a
  // context. It means the context contains the actual state, and the state of
  // the stub thread is incomplete.
  if (signo != SIGCHLD ||
      ucontext->uc_mcontext.gregs[REG_RIP] < __export_stub_start) {
    ctx->ptregs.fs_base = fs_base;
    gregs_to_ptregs(ucontext, &ctx->ptregs);
    memcpy(ctx->fpstate, (uint8_t *)ucontext->uc_mcontext.fpregs,
           __export_arch_state.fp_len);

    atomic_store(&ctx->fpstate_changed, 0);
  }

  enum context_state ctx_state = CONTEXT_STATE_INVALID;

  switch (signo) {
    case SIGSYS: {
      ctx_state = CONTEXT_STATE_SYSCALL;

      // Check whether this syscall can be replaced on a function call or not.
      // If a syscall instruction set is "mov sysno, %eax, syscall", it can be
      // replaced on a function call which works much faster.
      // Look at pkg/sentry/usertrap for more details.
      if (siginfo->si_arch == AUDIT_ARCH_X86_64) {
        uint8_t *rip = (uint8_t *)ctx->ptregs.rip;
        // FIXME(b/144063246): Even if all five bytes before the syscall
        // instruction match the "mov sysno, %eax" instruction, they can be a
        // part of a longer instruction. Here is not easy way to decode x86
        // instructions in reverse.
        uint64_t syscall_code_int[2];
        uint8_t *syscall_code = (uint8_t *)&syscall_code_int[0];

        // We need to receive 5 bytes before the syscall instruction, but they
        // are not aligned, so we can't read them atomically. Let's read them
        // twice. If the second copy will not contain the FAULT_OPCODE, this
        // will mean that the first copy is in the consistent state.
        for (int i = 0; i < 2; i++) {
          // fault_jump is set to the size of "mov (%rbx)" which is 3 bytes.
          atomic_store(&sysmsg->fault_jump, 3);
          asm volatile("movq (%1), %0\n"
                       : "=a"(syscall_code_int[i])
                       : "b"(rip - 8)
                       : "cc", "memory");
          atomic_store(&sysmsg->fault_jump, 0);
        }
        // The mov instruction is 5 bytes:  b8 <sysno, 4 bytes>.
        // The syscall instruction is 2 bytes: 0f 05.
        uint32_t sysno = *(uint32_t *)(syscall_code + 2);
        int need_trap = *(syscall_code + 6) == 0x0f &&  // syscall
                        *(syscall_code + 7) == 0x05 &&
                        *(syscall_code + 1) == 0xb8 &&  // mov sysno, %eax
                        sysno == siginfo->si_syscall &&
                        sysno == ctx->ptregs.rax;

        // Restart syscall if it has been patched by another thread.  When a
        // syscall instruction set is replaced on a function call, all threads
        // have to call it via the function call. Otherwise the syscall will not
        // be restarted properly if it will be interrupted by signal.
        syscall_code = (uint8_t *)&syscall_code_int[1];
        uint8_t syscall_opcode = *(syscall_code + 6);

        // A binary patch is built so that the first byte of the syscall
        // instruction is changed on the invalid instruction. If we meet this
        // case, this means that another thread has been patched this syscall
        // and we need to restart it.
        if (syscall_opcode == FAULT_OPCODE) {
          ucontext->uc_mcontext.gregs[REG_RIP] -= 7;
          return;
        }

        if (need_trap) {
          // This syscall can be replaced on the function call.
          ctx_state = CONTEXT_STATE_SYSCALL_NEED_TRAP;
        }
      }
      ctx->ptregs.orig_rax = ctx->ptregs.rax;
      ctx->ptregs.rax = (unsigned long)-ENOSYS;
      if (siginfo->si_arch != AUDIT_ARCH_X86_64)
        // gVisor doesn't support x32 system calls, so let's change the syscall
        // number so that it returns ENOSYS.
        ctx->ptregs.orig_rax += 0x86000000;
      break;
    }
    case SIGCHLD:
    case SIGSEGV:
    case SIGBUS:
    case SIGFPE:
    case SIGTRAP:
    case SIGILL:
      ctx->ptregs.orig_rax = -1;
      ctx_state = CONTEXT_STATE_FAULT;
      break;
    default:
      return;
  }

  ctx = switch_context_amd64(sysmsg, ctx, ctx_state);
  if (fs_base != ctx->ptregs.fs_base) {
    set_fsbase(ctx->ptregs.fs_base);
  }

  if (atomic_load(&ctx->fpstate_changed)) {
    prep_fpstate_for_sigframe(
        ctx->fpstate, __export_arch_state.fp_len,
        __export_arch_state.xsave_mode != XSAVE_MODE_FXSAVE);
    ucontext->uc_mcontext.fpregs = (void *)ctx->fpstate;
  }
  ptregs_to_gregs(ucontext, &ctx->ptregs);
}

void __syshandler() {
  struct sysmsg *sysmsg;
  asm volatile("movq %%gs:0, %0\n" : "=r"(sysmsg) : :);
  // SYSMSG_STATE_PREP is set to postpone interrupts. Look at
  // __export_sighandler for more details.
  int state = atomic_load(&sysmsg->state);
  if (state != THREAD_STATE_PREP) panic(STUB_ERROR_BAD_THREAD_STATE, 0);

  struct thread_context *ctx = sysmsg->context;

  enum context_state ctx_state = CONTEXT_STATE_SYSCALL_TRAP;
  ctx->signo = SIGSYS;
  ctx->siginfo.si_addr = 0;
  ctx->siginfo.si_syscall = ctx->ptregs.rax;
  ctx->ptregs.rax = (unsigned long)-ENOSYS;

  long fs_base = get_fsbase();
  ctx->ptregs.fs_base = fs_base;

  ctx = switch_context_amd64(sysmsg, ctx, ctx_state);
  // switch_context_amd64 changed sysmsg->state to THREAD_STATE_NONE, so we can
  // only resume the current process, all other actions are
  // prohibited after this point.

  if (fs_base != ctx->ptregs.fs_base) {
    set_fsbase(ctx->ptregs.fs_base);
  }
}

void __export_start(struct sysmsg *sysmsg, void *_ucontext) {
  init_new_thread();

  asm volatile("movq %%gs:0, %0\n" : "=r"(sysmsg) : :);
  if (sysmsg->self != sysmsg) {
    panic(STUB_ERROR_BAD_SYSMSG, 0);
  }

  struct thread_context *ctx =
      switch_context_amd64(sysmsg, NULL, CONTEXT_STATE_INVALID);

  restore_state(sysmsg, ctx, _ucontext);
}

// asm_restore_state is implemented in syshandler_amd64.S
void asm_restore_state();

// On x86 restore_state jumps straight to user code and does not return.
void restore_state(struct sysmsg *sysmsg, struct thread_context *ctx,
                   void *unused) {
  set_fsbase(ctx->ptregs.fs_base);
  asm_restore_state();
}

void verify_offsets_amd64() {
#define PTREGS_OFFSET offsetof(struct thread_context, ptregs)
  BUILD_BUG_ON(offsetof_thread_context_ptregs != PTREGS_OFFSET);
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r15 !=
               (offsetof(struct user_regs_struct, r15) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r14 !=
               (offsetof(struct user_regs_struct, r14) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r13 !=
               (offsetof(struct user_regs_struct, r13) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r12 !=
               (offsetof(struct user_regs_struct, r12) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rbp !=
               (offsetof(struct user_regs_struct, rbp) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rbx !=
               (offsetof(struct user_regs_struct, rbx) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r11 !=
               (offsetof(struct user_regs_struct, r11) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r10 !=
               (offsetof(struct user_regs_struct, r10) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r9 !=
               (offsetof(struct user_regs_struct, r9) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_r8 !=
               (offsetof(struct user_regs_struct, r8) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rax !=
               (offsetof(struct user_regs_struct, rax) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rcx !=
               (offsetof(struct user_regs_struct, rcx) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rdx !=
               (offsetof(struct user_regs_struct, rdx) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rsi !=
               (offsetof(struct user_regs_struct, rsi) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rdi !=
               (offsetof(struct user_regs_struct, rdi) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_orig_rax !=
               (offsetof(struct user_regs_struct, orig_rax) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rip !=
               (offsetof(struct user_regs_struct, rip) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_cs !=
               (offsetof(struct user_regs_struct, cs) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_eflags !=
               (offsetof(struct user_regs_struct, eflags) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_rsp !=
               (offsetof(struct user_regs_struct, rsp) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_ss !=
               (offsetof(struct user_regs_struct, ss) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_fs_base !=
               (offsetof(struct user_regs_struct, fs_base) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_gs_base !=
               (offsetof(struct user_regs_struct, gs_base) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_ds !=
               (offsetof(struct user_regs_struct, ds) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_es !=
               (offsetof(struct user_regs_struct, es) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_fs !=
               (offsetof(struct user_regs_struct, fs) + PTREGS_OFFSET));
  BUILD_BUG_ON(offsetof_thread_context_ptregs_gs !=
               (offsetof(struct user_regs_struct, gs) + PTREGS_OFFSET));
#undef PTREGS_OFFSET
}

// asm/sigcontext.h conflicts with signal.h.
struct __fpx_sw_bytes {
  uint32_t magic1;
  uint32_t extended_size;
  uint64_t xfeatures;
  uint32_t xstate_size;
  uint32_t padding[7];
};

struct __fpstate {
  uint16_t cwd;
  uint16_t swd;
  uint16_t twd;
  uint16_t fop;
  uint64_t rip;
  uint64_t rdp;
  uint32_t mxcsr;
  uint32_t mxcsr_mask;
  uint32_t st_space[32];
  uint32_t xmm_space[64];
  uint32_t reserved2[12];
  struct __fpx_sw_bytes sw_reserved;
};

// The kernel expects to see some additional info in an FPU state. More details
// can be found in arch/x86/kernel/fpu/signal.c:check_xstate_in_sigframe.
static void prep_fpstate_for_sigframe(void *buf, uint32_t user_size,
                                      bool use_xsave) {
  struct __fpstate *fpstate = buf;
  struct __fpx_sw_bytes *sw_bytes = &fpstate->sw_reserved;

  sw_bytes->magic1 = FP_XSTATE_MAGIC1;
  sw_bytes->extended_size = user_size + FP_XSTATE_MAGIC2_SIZE;
  sw_bytes->xfeatures = ~(0ULL) ^ (XCR0_DISABLED_MASK);
  sw_bytes->xstate_size = user_size;
  *(uint32_t *)(buf + user_size) = use_xsave ? FP_XSTATE_MAGIC2 : 0;
}
