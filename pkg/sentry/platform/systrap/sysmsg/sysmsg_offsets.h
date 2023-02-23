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

// LINT.IfChange

// Define offsets in the struct sysmsg to use them in assembly files.
// Each offset has to have BUILD_BUG_ON in sighandler.c.
#define offsetof_sysmsg_self 0x0
#define offsetof_sysmsg_ret_addr 0x8
#define offsetof_sysmsg_syshandler 0x10
#define offsetof_sysmsg_syshandler_stack 0x18
#define offsetof_sysmsg_app_stack 0x20
#define offsetof_sysmsg_interrupt 0x28
#define offsetof_sysmsg_type 0x30
#define offsetof_sysmsg_state 0x34

#define kSYSMSG_SYSCALL 1
#define kSYSMSG_INTERRUPT 5

// LINT.ThenChange(sysmsg.h, sighandler.c)

#endif  // THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_H_
