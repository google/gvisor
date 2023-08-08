// Copyright 2022 The gVisor Authors.
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

#ifndef THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_AMD64_H_
#define THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_AMD64_H_

// LINT.IfChange

#define offsetof_arch_state_xsave_mode (0x0)
#define offsetof_arch_state_fpLen (0x4)
#define offsetof_arch_state_fsgsbase (0x8)

#define XSAVE_MODE_FXSAVE (0x0)
#define XSAVE_MODE_XSAVE (0x1)
#define XSAVE_MODE_XSAVEOPT (0x2)

// LINT.ThenChange(sysmsg.h, sysmsg_amd64.go)
// LINT.IfChange

#define offsetof_thread_context_ptregs_r15 \
  (0x0 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r14 \
  (0x8 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r13 \
  (0x10 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r12 \
  (0x18 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rbp \
  (0x20 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rbx \
  (0x28 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r11 \
  (0x30 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r10 \
  (0x38 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r9 \
  (0x40 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_r8 \
  (0x48 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rax \
  (0x50 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rcx \
  (0x58 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rdx \
  (0x60 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rsi \
  (0x68 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rdi \
  (0x70 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_orig_rax \
  (0x78 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rip \
  (0x80 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_cs \
  (0x88 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_eflags \
  (0x90 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_rsp \
  (0x98 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_ss \
  (0xa0 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_fs_base \
  (0xa8 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_gs_base \
  (0xb0 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_ds \
  (0xb8 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_es \
  (0xc0 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_fs \
  (0xc8 + offsetof_thread_context_ptregs)
#define offsetof_thread_context_ptregs_gs \
  (0xd0 + offsetof_thread_context_ptregs)

// LINT.ThenChange(sysmsg.h, sighandler_amd64.c)

#endif  // THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_AMD64_H_
