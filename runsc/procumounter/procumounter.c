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

// gvisor-proc-umounter waits for one byte on FD `SYNC_FD`, then lazily
// unmounts the directory given as its only argument:
//   `gvisor-proc-umounter <directory>`
//
// The gofer and the Sentry need procfs while they set themselves up, and
// cannot unmount it themselves afterwards because they drop the capabilities
// to do so by then. So they spawn this program beforehand, while they still
// have those capabilities, and write to `SYNC_FD` once they are done with
// procfs. See `ExecProcUmounter` in `//runsc/cmd/sandboxsetup`.
//
// It runs from within the gofer's or the Sentry's chroot, where neither libc
// nor the host filesystem is available, so it is a freestanding static binary.

#include <asm/unistd.h>  // __NR_* syscall numbers for the target arch.

// The FD at which this program inherits the sync pipe.
// Must match `ExecProcUmounter` in `runsc/cmd/sandboxsetup/process.go`.
// LINT.IfChange
#define SYNC_FD 3
// LINT.ThenChange(../cmd/sandboxsetup/process.go)

// The umount2(2) flag to detach the mount lazily.
#define MNT_DETACH 2

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

// Called by `_start` with a pointer to the initial process stack, which per
// the Linux ABI holds: `argc`, `argv[0..argc-1]`, NULL, `envp`, NULL.
__attribute__((noreturn, used)) void procumounter_main(long* stack) {
  long argc = stack[0];
  char** argv = (char**)(stack + 1);
  if (argc != 2) {
    write_stderr("usage: gvisor-proc-umounter <directory>\n");
    sys_exit(2);
  }
  char buf;
  long n;
  do {
    n = sys3(__NR_read, SYNC_FD, (long)&buf, 1);
  } while (n == -4 /* -EINTR */);
  if (n != 1) {
    write_stderr(
        "gvisor-proc-umounter: unable to read from the sync FD.\n"
        "Do not run this by hand; it is spawned by the gofer and the "
        "Sentry.\n");
    sys_exit(1);
  }
  if (sys3(__NR_umount2, (long)argv[1], MNT_DETACH, 0) != 0) {
    write_stderr("gvisor-proc-umounter: unable to unmount ");
    write_stderr(argv[1]);
    write_stderr("\n");
    sys_exit(1);
  }
  sys_exit(0);
}

// Process entry point. Hand the initial stack pointer to `procumounter_main`.
#if defined(__x86_64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  movq %rsp, %rdi\n"
    "  call procumounter_main\n"
    "  ud2\n");
#elif defined(__aarch64__)
__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "  mov x0, sp\n"
    "  bl procumounter_main\n"
    "  brk #0\n");
#endif
