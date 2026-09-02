// Copyright 2026 The gVisor Authors.
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

// runsc-fd-parking holds FD 4 open until the process whose pidfd it
// inherits as FD 3 has exited, then exits. Inherited FDs above 4 are closed
// at startup.
//
// runsc spawns it alongside the sandbox (Sentry) process to hold the "pin
// ring" (inherited as FD 4, see `//pkg/pinring`): a permanently-disabled
// `io_uring` into which the Sentry pins host FDs that should remain open
// during and past the lifetime of the sandbox.
// This includes slow-to-release `AF_PACKET` sockets and KVM VM FDs.
// This makes sandbox teardown faster, because the Sentry process isn't the
// last ref holder of these FDs, so its memory can be released earlier.
// This `fdparking` process's purpose is to be the ring's last ref holder.
//
// Because this process must outlive the sentry, it tries its hardest to
// minimize its runtime CPU and memory usage.
// Therefore, it is a minimal C binary (A Go binary would incur megabytes of
// runtime overhead, and periodic wakeups for Go garbage collection).
//
// Additionally, because it starts during the sandbox startup hot path but its
// work is entirely low-priority work that only matters by the time the sandbox
// *exits*, it makes itself SCHED_IDLE as its very first act so that it never
// competes with the sandbox for CPU, and parks on the pidfd right away,
// deferring all remaining self-memory-minimization work after a 1-second grace
// period (or skipping it entirely for sandboxes that exit sooner).
//
// To minimize its own kernel-object footprint, it pivots onto a single .bss
// stack page (which shares the text's page table entry), then unmaps the
// original stack and the vdso/vvar, which frees their anonymous pages and
// page-table pages. This roughly halves the page-table cost and the anonymous
// memory of the process.

#include <asm/poll.h>      // POLLIN, POLLNVAL, struct pollfd.
#include <asm/unistd.h>    // __NR_* syscall numbers for the target arch.
#include <linux/auxvec.h>  // AT_SYSINFO_EHDR, AT_PAGESZ.
#include <linux/errno.h>   // EINTR.
#include <linux/prctl.h>   // PR_SET_TIMERSLACK.
#include <linux/sched.h>   // SCHED_IDLE.

// The pidfd (see pidfd_open(2)) of the sandbox process.
// Polls readable once the sandbox has exited.
#define SANDBOX_PIDFD 3

// The pin ring FD.
// Never touched, but must remain open until this process exits.
#define PIN_RING_FD 4

// The close_range(2) syscall number is the same across all architectures.
#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#define PAGE 4096UL

// The one page this process runs on after _start pivots off the original
// stack. Non-static so that the asm in _start can name it.
char park_stack[PAGE] __attribute__((aligned(PAGE), used));

// Raw 5-argument syscall function.
#if defined(__x86_64__)
static long sys5(long nr, long a0, long a1, long a2, long a3, long a4) {
  register long r10 __asm__("r10") = a3;
  register long r8 __asm__("r8") = a4;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  return ret;
}
#elif defined(__aarch64__)
static long sys5(long nr, long a0, long a1, long a2, long a3, long a4) {
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                   : "memory", "cc");
  return x0;
}
#else
#error "unsupported architecture"
#endif

static __attribute__((noreturn)) void sys_exit(long code) {
  for (;;) {
    sys5(__NR_exit_group, code, 0, 0, 0, 0);
  }
}

// Basic stderr logging function. Look ma, no libc.
static void write_stderr(const char* s) {
  long len = 0;
  while (s[len] != '\0') {
    len++;
  }
  sys5(__NR_write, 2, (long)s, len, 0, 0);
}

// slim unmaps the original stack (whose bottom `old_stack` points into) and
// the vdso/vvar, none of which are needed by the ppoll loop.
// If we find the wrong page size or a surprising layout, do nothing.
static void slim(long* old_stack) {
  // The initial stack holds: argc, argv[], NULL, envp[], NULL, auxv.
  long argc = old_stack[0];
  char** p = (char**)(old_stack + 1) + argc + 1;
  while (*p) {
    p++;
  }
  unsigned long vdso = 0, pagesz = 0;
  for (unsigned long* a = (unsigned long*)(p + 1); a[0]; a += 2) {
    if (a[0] == AT_SYSINFO_EHDR) {
      vdso = a[1];
    } else if (a[0] == AT_PAGESZ) {
      pagesz = a[1];
    }
  }
  if (pagesz != PAGE) {
    return;
  }
  // Nothing we unmap may sit at or below our own image (text + park_stack).
  unsigned long floor = (unsigned long)park_stack + PAGE;
  unsigned long sp = (unsigned long)old_stack & ~(PAGE - 1);
  unsigned long base = sp - (1UL << 20);  // Covers the whole stack VMA.
  if (vdso > floor && vdso + 4 * PAGE < base) {
    // The vvar pages (up to 6 of them) sit just below the vdso.
    sys5(__NR_munmap, (long)(vdso - 16 * PAGE), 20 * PAGE, 0, 0, 0);
  }
  if (base > floor) {
    // + 4 pages: past the argv/envp/auxv strings above the entry sp.
    sys5(__NR_munmap, (long)base, (sp + 4 * PAGE) - base, 0, 0, 0);
  }
}

// The kernel's native 64-bit timespec.
struct kernel_timespec {
  long tv_sec;
  long tv_nsec;
};

// park ppolls the sandbox pidfd (readable once the sandbox has exited).
static long park(struct pollfd* pfd, struct kernel_timespec* timeout) {
  for (;;) {
    long n = sys5(__NR_ppoll, (long)pfd, 1, (long)timeout, 0, 0);
    if (n != -EINTR) {
      return n;
    }
  }
}

__attribute__((noreturn, used)) void fdparking_main(long* old_stack) {
  // Make ourselves as low-priority as possible.
  int idle_prio = 0;
  sys5(__NR_sched_setscheduler, 0, SCHED_IDLE, (long)&idle_prio, 0, 0);
  sys5(__NR_prctl, PR_SET_TIMERSLACK, 1000000000L, 0, 0, 0);

  // Wait for a second.
  // The rest of the startup work is deferrable, and we don't want to starve
  // the sandbox from CPU while it starts.
  struct pollfd pfd = {.fd = SANDBOX_PIDFD, .events = POLLIN};
  struct kernel_timespec grace = {.tv_sec = 1};
  long n = park(&pfd, &grace);
  if (n == 0) {
    // Grace period elapsed and sandbox still running. Slim down.
    slim(old_stack);
    // Close out any unexpected FD beyond the ones we understand.
    sys5(__NR_close_range, PIN_RING_FD + 1, 0xffffffffL, 0, 0, 0);
    // Long-term parking.
    n = park(&pfd, 0);
  }
  if (n < 0 || (pfd.revents & POLLNVAL)) {
    write_stderr("runsc-fd-parking: cannot poll the sandbox pidfd (FD 3).\n");
    sys_exit(1);
  }
  // Done, and sandbox exited. We're done too.
  sys_exit(0);
}

// Process entry point: hand the initial stack pointer to `fdparking_main`
// and pivot onto `park_stack`.
#if defined(__x86_64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  movq %rsp, %rdi\n"
    "  leaq park_stack+4096(%rip), %rsp\n"
    "  call fdparking_main\n"
    "  ud2\n");
#elif defined(__aarch64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  mov x0, sp\n"
    "  adrp x1, park_stack\n"
    "  add x1, x1, :lo12:park_stack\n"
    "  add x1, x1, 4096\n"
    "  mov sp, x1\n"
    "  bl fdparking_main\n"
    "  brk #0\n");
#endif
