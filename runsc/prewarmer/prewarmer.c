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

// gvisor-sentry-prewarmer grows its host file descriptor table, then execs
// the binary at argv[1], handing it argv[2:] as its argv (so argv[2] is the
// target's argv[0]). It runs just before `runsc boot` (the Sentry) does, and
// is meant to be invoked as such, i.e.:
//   `gvisor-sentry-prewarmer /path/to/gvisor_sentry runsc-sandbox <flags...>
//   boot <flags...>`
//
// You may be asking: wtf, wat, but why? Excellent questions.
// Sit down for some deep kernel lore.
//
// We hold the following truths to be not self-evident, but true nonetheless:
//
// - FDs in Linux are reused, serially by index, but some system calls allow
//   the userspace program to pick an FD number, so the table can be sparse.
// - The Linux kernel backs a process's FD table as an array with sizes that
//   are always powers of 2.
// - When the table needs to grow, it grows to the smallest power of 2 that
//   accommodates the largest FD number that the program needs.
// - When a program `exec`s, its FD table size is maintained, even when the FDs
//   would be closed-on-exec. (Yes, this implies the FD table never shrinks as
//   the genealogy of a process tree goes deeper.)
// - When the table needs to grow, if the program is a multi-threaded program,
//   the kernel waits for a full RCU grace period (which is >10ms, ouch).
//   However, if the process is *not* multi-threaded, there is no such wait!
// - All Go programs are multi-threaded from the kernel's perspective, because
//   the Go runtime spawns off some threads on startup before `main()` is even
//   called.
// - gVisor has this funny behavior of needing to segment its FD table range
//   so that the stdin/stdout/stderr FDs are always remapped to some high
//   indexes (see `startingStdioFD` in `//runsc/boot/loader.go`).
//
// You can see where this is going. We need a single-threaded program that
// runs before `runsc boot` does that inflates its FD table to be large enough
// so that `runsc boot` never hits the FD table expansion RCU grace period
// that the kernel would hit it with otherwise.
// That's what this prewarmer program does.
// It's written in C with very minimal dependencies and fitting in a single
// page (4KiB) because it runs on the hot path of gVisor startup. And,
// despite its existence, it makes gVisor startup faster.

#include <asm/unistd.h>   // __NR_* syscall numbers for the target arch.
#include <linux/fcntl.h>  // F_DUPFD_CLOEXEC, O_* flags, AT_FDCWD.

// The FD number that the boot process remaps its first stdio FD to.
// Must match `startingStdioFD` in `runsc/boot/loader.go`.
// LINT.IfChange
#define STARTING_STDIO_FD 253
// LINT.ThenChange(../boot/loader.go)

// The minimum FD number that the prewarmed fdtable must accommodate.
// Since `startingStdioFD` is mapped to stdin, then `startingStdioFD+1` is
// mapped to stdout, and `startingStdioFD+2` is mapped to stderr.
// We choose this to be just under what would cause the FD table to expand to
// its next power-of-2 size. Here, STARTING_STDIO_FD + 2 = 253 + 2 = 255,
// so the host kernel FD table is of size 256. If we were to bump this any
// further, we would needlessly waste 50% of the host kernel memory dedicated
// to the FD table (which isn't that much, but I write this because the
// previous value of this constant was committing this exact wastefulness).
#define PREWARM_MIN_FD (STARTING_STDIO_FD + 2)

// Raw 3-argument syscall function.
#if defined(__x86_64__)
static long sys3(long nr, long a0, long a1, long a2) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
                   : "rcx", "r11", "memory");
  return ret;
}
#elif defined(__aarch64__)
static long sys3(long nr, long a0, long a1, long a2) {
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2)
                   : "memory", "cc");
  return x0;
}
#else
#error "unsupported architecture"
#endif

static __attribute__((noreturn)) void sys_exit(long code) {
  for (;;) {
    sys3(__NR_exit_group, code, 0, 0);
  }
}

// Basic stderr logging function. Look ma, no libc.
static void write_stderr(const char* s) {
  long len = 0;
  while (s[len] != '\0') {
    len++;
  }
  sys3(__NR_write, 2, (long)s, len);
}

// Forces the host kernel to grow the FD table to allow the FD with index
// `PREWARM_MIN_FD` to exist without needing later FD table expansion.
static void prewarm_fdtable(void) {
  // F_DUPFD_CLOEXEC atomically picks a free FD >= PREWARM_MIN_FD, so this
  // cannot clobber any inherited (donated) FD.
  long fd = sys3(__NR_fcntl, 0, F_DUPFD_CLOEXEC, PREWARM_MIN_FD);
  if (fd < 0) {
    // FD 0 may not be open. Fall back to duplicating an FD we open ourselves.
    long base = sys3(__NR_openat, AT_FDCWD, (long)"/", O_RDONLY | O_CLOEXEC);
    if (base < 0) {
      // OK, whatever is going on is weird. We will hit the RCU stall, but not
      // worth failing on.
      write_stderr(
          "gvisor-sentry-prewarmer: failed to prewarm the FD table. This slows "
          "down gVisor startup.\n");
      return;
    }
    fd = sys3(__NR_fcntl, base, F_DUPFD_CLOEXEC, PREWARM_MIN_FD);
    sys3(__NR_close, base, 0, 0);
  }
  if (fd >= 0) {
    sys3(__NR_close, fd, 0, 0);
  }
}

// Called by `_start` with a pointer to the initial process stack, which per
// the Linux ABI holds: `argc`, `argv[0..argc-1]`, NULL, `envp`, NULL.
__attribute__((noreturn, used)) void prewarmer_main(long* stack) {
  long argc = stack[0];
  char** argv = (char**)(stack + 1);
  char** envp = argv + argc + 1;
  if (argc < 3) {
    write_stderr(
        "gvisor-sentry-prewarmer: usage: gvisor-sentry-prewarmer <binary> "
        "<argv[0]> [argv[1:]...]\n"
        "Do not run this by hand; it is exec'd by runsc ahead of the sandbox "
        "process.\n");
    sys_exit(1);
  }
  prewarm_fdtable();
  // The argv array is NULL-terminated, so &argv[2] is a valid argv.
  sys3(__NR_execve, (long)argv[1], (long)&argv[2], (long)envp);
  write_stderr("gvisor-sentry-prewarmer: exec failed: ");
  write_stderr(argv[1]);
  write_stderr("\n");
  sys_exit(127);
}

// Process entry point. Hand the initial stack pointer to `prewarmer_main`.
#if defined(__x86_64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  movq %rsp, %rdi\n"
    "  call prewarmer_main\n"
    "  ud2\n");
#elif defined(__aarch64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  mov x0, sp\n"
    "  bl prewarmer_main\n"
    "  brk #0\n");
#endif
