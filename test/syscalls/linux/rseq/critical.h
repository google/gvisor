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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_RSEQ_CRITICAL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_RSEQ_CRITICAL_H_

#include "test/syscalls/linux/rseq/types.h"
#include "test/syscalls/linux/rseq/uapi.h"

constexpr uint32_t kRseqSignature = 0x90909090;

extern "C" {

extern void rseq_loop(struct rseq* r, struct rseq_cs* cs);
extern void* rseq_loop_early_abort;
extern void* rseq_loop_start;
extern void* rseq_loop_pre_commit;
extern void* rseq_loop_post_commit;
extern void* rseq_loop_abort;

extern int rseq_getpid(struct rseq* r, struct rseq_cs* cs);
extern void* rseq_getpid_start;
extern void* rseq_getpid_post_commit;
extern void* rseq_getpid_abort;

}  // extern "C"

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_CRITICAL_H_
