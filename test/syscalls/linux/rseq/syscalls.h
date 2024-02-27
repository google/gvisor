// Copyright 2019 The gVisor Authors.
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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_RSEQ_SYSCALLS_H_
#define GVISOR_TEST_SYSCALLS_LINUX_RSEQ_SYSCALLS_H_

#include "test/syscalls/linux/rseq/types.h"

// Syscall numbers.
#if defined(__x86_64__)
constexpr int kExitGroup = 231;
constexpr int kFutex = 202;
constexpr int kGetpid = 39;
constexpr int kMembarrier = 324;
constexpr int kMmap = 9;
#elif defined(__aarch64__)
constexpr int kExitGroup = 94;
constexpr int kFutex = 98;
constexpr int kGetpid = 172;
constexpr int kMembarrier = 283;
constexpr int kMmap = 222;
#else
#error "Unknown architecture"
#endif

namespace gvisor {
namespace testing {

// Standalone system call interfaces.
// Note that these are all "raw" system call interfaces which encode
// errors by setting the return value to a small negative number.
// Use sys_errno() to check system call return values for errors.

// Maximum Linux error number.
constexpr int kMaxErrno = 4095;

// Errno values.
#define EPERM 1
#define EINTR 4
#define EAGAIN 11
#define EFAULT 14
#define EBUSY 16
#define EINVAL 22

// Get the error number from a raw system call return value.
// Returns a positive error number or 0 if there was no error.
static inline int sys_errno(uintptr_t rval) {
  if (rval >= static_cast<uintptr_t>(-kMaxErrno)) {
    return -static_cast<int>(rval);
  }
  return 0;
}

extern "C" uintptr_t raw_syscall(int number, ...);

extern "C" int clone(int (*fn)(void*), uintptr_t stack, int flags, void* arg,
                     uint32_t* child_tid);

// clone flags:
#define CLONE_VM 0x00000100
#define CLONE_FS 0x00000200
#define CLONE_FILES 0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD 0x00010000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID 0x01000000

static inline void sys_exit_group(int status) {
  raw_syscall(kExitGroup, status);
}

static inline uintptr_t sys_futex(uint32_t* uaddr, int futex_op, uint32_t val,
                                  const struct timespec* timeout) {
  return raw_syscall(kFutex, uaddr, futex_op, val, timeout);
}

// futex ops:
#define FUTEX_WAIT 0

static inline int sys_getpid() {
  return static_cast<int>(raw_syscall(kGetpid));
}

static inline uintptr_t sys_membarrier(int cmd, unsigned int flags) {
  return raw_syscall(kMembarrier, cmd, flags);
}

// membarrier commands:
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ (1 << 7)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1 << 8)

static inline uintptr_t sys_mmap(void* addr, size_t length, int prot, int flags,
                                 int fd, int64_t offset) {
  return raw_syscall(kMmap, addr, length, prot, flags, fd, offset);
}

// mmap options:
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_STACK 0x020000

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_SYSCALLS_H_
