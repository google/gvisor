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
constexpr int kGetpid = 39;
constexpr int kExitGroup = 231;
#elif defined(__aarch64__)
constexpr int kGetpid = 172;
constexpr int kExitGroup = 94;
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

static inline void sys_exit_group(int status) {
  raw_syscall(kExitGroup, status);
}
static inline int sys_getpid() {
  return static_cast<int>(raw_syscall(kGetpid));
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_SYSCALLS_H_
