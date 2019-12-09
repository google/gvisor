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

// User-kernel ABI for restartable sequences.

// Standard types.
//
// N.B. This header will be included in targets that do have the standard
// library, so we can't shadow the standard type names.
using __u32 = __UINT32_TYPE__;
using __u64 = __UINT64_TYPE__;

#ifdef __x86_64__
// Syscall numbers.
constexpr int kRseqSyscall = 334;
#else
#error "Unknown architecture"
#endif  // __x86_64__

struct rseq_cs {
  __u32 version;
  __u32 flags;
  __u64 start_ip;
  __u64 post_commit_offset;
  __u64 abort_ip;
} __attribute__((aligned(4 * sizeof(__u64))));

// N.B. alignment is enforced by the kernel.
struct rseq {
  __u32 cpu_id_start;
  __u32 cpu_id;
  struct rseq_cs* rseq_cs;
  __u32 flags;
} __attribute__((aligned(4 * sizeof(__u64))));

constexpr int kRseqFlagUnregister = 1 << 0;

constexpr int kRseqCPUIDUninitialized = -1;

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_UAPI_H_
