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

#ifndef THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_H_
#define THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_H_

// FAULT_OPCODE is the opcode of the invalid instruction that is used to replace
// the first byte of the syscall instruction. More details in the description
// for the pkg/sentry/platform/systrap/usertrap package.
#define FAULT_OPCODE 0x06

// The value for XCR0 is defined to xsave/xrstor everything except for PKRU and
// AMX regions.
// TODO(gvisor.dev/issues/9896): Implement AMX support.
// TODO(gvisor.dev/issues/10087): Implement PKRU support.
#define XCR0_DISABLED_MASK ((1 << 9) | (1 << 17) | (1 << 18))
#define XCR0_EAX (0xffffffff ^ XCR0_DISABLED_MASK)
#define XCR0_EDX 0xffffffff

// LINT.IfChange
#define MAX_FPSTATE_LEN 3584
// Note: To be explicit, 2^12 = 4096; if ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT
//       is changed, make sure to change the code that relies on the bitshift.
#define ALLOCATED_SIZEOF_THREAD_CONTEXT_STRUCT 4096
#define THREAD_CONTEXT_STRUCT_BITSHIFT 12
// LINT.ThenChange(sysmsg.go)

// LINT.IfChange

// Define offsets in the struct sysmsg to use them in assembly files.
// Each offset has to have BUILD_BUG_ON in sighandler.c.
#define offsetof_sysmsg_self 0x0
#define offsetof_sysmsg_ret_addr 0x8
#define offsetof_sysmsg_syshandler 0x10
#define offsetof_sysmsg_syshandler_stack 0x18
#define offsetof_sysmsg_app_stack 0x20
#define offsetof_sysmsg_interrupt 0x28
#define offsetof_sysmsg_state 0x2c
#define offsetof_sysmsg_context 0x30

#define offsetof_thread_context_fpstate 0x0
#define offsetof_thread_context_fpstate_changed MAX_FPSTATE_LEN
#define offsetof_thread_context_ptregs 0x8 + MAX_FPSTATE_LEN

#define kTHREAD_STATE_NONE 0
#define kTHREAD_STATE_INTERRUPT 3

// LINT.ThenChange(sysmsg.h, sysmsg_lib.c)

#endif  // THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_H_
