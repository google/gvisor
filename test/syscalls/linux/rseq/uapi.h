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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_RSEQ_UAPI_H_
#define GVISOR_TEST_SYSCALLS_LINUX_RSEQ_UAPI_H_

#include <stdint.h>

// User-kernel ABI for restartable sequences.

// Syscall numbers.
#if defined(__x86_64__)
constexpr int kRseqSyscall = 334;
#elif defined(__aarch64__)
constexpr int kRseqSyscall = 293;
#else
#error "Unknown architecture"
#endif  // __x86_64__

struct rseq_cs {
  uint32_t version;
  uint32_t flags;
  uint64_t start_ip;
  uint64_t post_commit_offset;
  uint64_t abort_ip;
} __attribute__((aligned(4 * sizeof(uint64_t))));

// N.B. alignment is enforced by the kernel.
struct rseq {
  uint32_t cpu_id_start;
  uint32_t cpu_id;
  struct rseq_cs* rseq_cs;
  uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

constexpr int kRseqFlagUnregister = 1 << 0;

constexpr int kRseqCPUIDUninitialized = -1;

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_UAPI_H_
