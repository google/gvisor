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

#include "sysmsg_offsets.h"
#include "sysmsg_offsets_amd64.h"

// Helper macros:
////////////////////////////////////////

// prepare_enter_syshandler does the following:
//   - saves all registers that are restorable onto the thread_context struct.
//   - loads the address of the thread_context struct into %rcx.
.macro prepare_enter_syshandler
  // Syshandler clobbers rflags (load_thread_context_addr does so for example).
  // Therefore save it as the first thing we do.
  pushfq
  // load_thread_context_addr overwrites %rcx.
  push %rcx

  movq %gs:offsetof_sysmsg_context, %rcx

  // Registers listed in order as written in ptregs:
  movq %r15, offsetof_thread_context_ptregs_r15(%rcx)
  movq %r14, offsetof_thread_context_ptregs_r14(%rcx)
  movq %r13, offsetof_thread_context_ptregs_r13(%rcx)
  movq %r12, offsetof_thread_context_ptregs_r12(%rcx)
  movq %rbp, offsetof_thread_context_ptregs_rbp(%rcx)
  movq %rbx, offsetof_thread_context_ptregs_rbx(%rcx)
  movq %r11, offsetof_thread_context_ptregs_r11(%rcx)
  movq %r10, offsetof_thread_context_ptregs_r10(%rcx)
  movq %r9, offsetof_thread_context_ptregs_r9(%rcx)
  movq %r8, offsetof_thread_context_ptregs_r8(%rcx)
  movq %rax, offsetof_thread_context_ptregs_rax(%rcx)
  pop %r15
  movq %r15, offsetof_thread_context_ptregs_rcx(%rcx)
  movq %rdx, offsetof_thread_context_ptregs_rdx(%rcx)
  movq %rsi, offsetof_thread_context_ptregs_rsi(%rcx)
  movq %rdi, offsetof_thread_context_ptregs_rdi(%rcx)
  movq %rax, offsetof_thread_context_ptregs_orig_rax(%rcx)

  movw %cs, offsetof_thread_context_ptregs_cs(%rcx)
  movw %ss, offsetof_thread_context_ptregs_ss(%rcx)
  // Don't bother save/restoring ds/es on amd64
  // movw %ds, offsetof_thread_context_ptregs_ds(%rcx)
  // movw %es, offsetof_thread_context_ptregs_es(%rcx)
  movw %fs, offsetof_thread_context_ptregs_fs(%rcx)
  movw %gs, offsetof_thread_context_ptregs_gs(%rcx)

  pop %rax
  movq %rax, offsetof_thread_context_ptregs_eflags(%rcx)

  movq %gs:offsetof_sysmsg_app_stack, %r8
  movq %r8, offsetof_thread_context_ptregs_rsp(%rcx)
  movq %gs:offsetof_sysmsg_ret_addr, %r9
  movq %r9, offsetof_thread_context_ptregs_rip(%rcx)
.endm

// prepare_exit_syshandler assumes that:
//   - the memory address of the thread_context is loaded in %rcx.
// prepare_exit_syshandler does the following:
//   - sets sysmsg->ret_addr
//   - restores all registers that were saved inside the thread_context struct except for
//     %rsp and rflags.
//   - %rcx will be restored as well, and will no longer contain the memory address to the
//     thread context.
//   - puts user %rsp and rflags onto the syshandler stack (in that order). rflags cannot
//     be restored at this point because syshandler will clobber it before it exits.
.macro prepare_exit_syshandler
  movq offsetof_thread_context_ptregs_rsp(%rcx), %rax
  push %rax
  movq offsetof_thread_context_ptregs_eflags(%rcx), %rbx
  push %rbx

  // set sysmsg->ret_addr
  movq offsetof_thread_context_ptregs_rip(%rcx), %r9
  movq %r9, %gs:offsetof_sysmsg_ret_addr

  // Restore segments. Because restoring segments is slow, restore them only if necessary.
  movw %fs, %dx
  cmpw %dx, offsetof_thread_context_ptregs_fs(%rcx)
  je restored_fs
  movw offsetof_thread_context_ptregs_fs(%rcx), %fs
restored_fs:
  movw %gs, %si
  cmpw %si, offsetof_thread_context_ptregs_gs(%rcx)
  je restored_gs
  movw offsetof_thread_context_ptregs_gs(%rcx), %gs
restored_gs:
  // Restore other GP registers
  movq offsetof_thread_context_ptregs_r15(%rcx), %r15
  movq offsetof_thread_context_ptregs_r14(%rcx), %r14
  movq offsetof_thread_context_ptregs_r13(%rcx), %r13
  movq offsetof_thread_context_ptregs_r12(%rcx), %r12
  movq offsetof_thread_context_ptregs_rbp(%rcx), %rbp
  movq offsetof_thread_context_ptregs_rbx(%rcx), %rbx
  movq offsetof_thread_context_ptregs_r11(%rcx), %r11
  movq offsetof_thread_context_ptregs_r10(%rcx), %r10
  movq offsetof_thread_context_ptregs_r9(%rcx), %r9
  movq offsetof_thread_context_ptregs_r8(%rcx), %r8
  movq offsetof_thread_context_ptregs_rax(%rcx), %rax
  // %rcx restored last
  movq offsetof_thread_context_ptregs_rdx(%rcx), %rdx
  movq offsetof_thread_context_ptregs_rsi(%rcx), %rsi
  movq offsetof_thread_context_ptregs_rdi(%rcx), %rdi

  movq offsetof_thread_context_ptregs_rcx(%rcx), %rcx
.endm

// save_fpstate saves the current fpstate onto thread_context.fpstate.
// It assumes that:
//   - the memory address of the thread_context is loaded in %rcx.
.macro save_fpstate
  lea offsetof_thread_context_fpstate(%rcx), %rdi
  movl $XCR0_EAX, %eax
  movl $XCR0_EDX, %edx
  movl __export_arch_state+offsetof_arch_state_xsave_mode(%rip), %esi
  cmpl $XSAVE_MODE_XSAVEOPT, %esi
  jl use_xsave
  xsaveopt (%rdi)
  jmp fpu_saved
use_xsave:
  cmpl $XSAVE_MODE_XSAVE, %esi
  jl use_fxsave
  xsave (%rdi)
  jmp fpu_saved
use_fxsave:
  fxsave (%rdi)
fpu_saved:
.endm

// restore_fpstate restores the fpstate previously saved onto thread_context.fpstate.
// It assumes that:
//   - the memory address of the thread_context is loaded in %rcx.
.macro restore_fpstate
  // We only need to restore fpstate if we were signalled that it changed (syshandler
  // does not modify fpstate).
  cmpl $0, offsetof_thread_context_fpstate_changed(%rcx)
  je fpu_restored

  lea offsetof_thread_context_fpstate(%rcx), %rdi
  mov __export_arch_state+offsetof_arch_state_xsave_mode(%rip), %eax
  cmpl $XSAVE_MODE_FXSAVE, %eax
  jz use_fxrstor
use_xrstor:
  movl $XCR0_EAX, %eax
  movl $XCR0_EDX, %edx
  xrstor (%rdi)
  jmp fpu_restored
use_fxrstor:
  fxrstor (%rdi)
fpu_restored:
.endm

// Syshandler:
////////////////////////////////////////
.globl __export_syshandler;
.type __export_syshandler, @function;
.align 4, 0x00;
__export_syshandler:
  // The start of this function is in a usertrap trampoline:
  // mov    sysmsg.ThreadStatePrep, %gs:offset(msg.State)
  // mov    %rsp,%gs:0x20 // msg.AppStack
  // mov    %gs:0x18,%rsp // msg.SyshandlerStack
  // movabs $ret_addr, %rax
  // mov    %rax,%gs:0x8  // msg.RetAddr
  // mov    sysno,%eax
  // jmpq   *%gs:0x10     // msg.Syshandler
  prepare_enter_syshandler
  save_fpstate

  callq __syshandler

.globl asm_restore_state;
.type asm_restore_state, @function;
asm_restore_state:
  // thread_context may have changed, therefore we reload it into %rcx anew.
  movq %gs:offsetof_sysmsg_context, %rcx
  restore_fpstate

  prepare_exit_syshandler

  // Now syshandler is exiting for good; restore user rflags and %rsp.
  popfq
  movq 0(%rsp), %rsp
  jmp *%gs:offsetof_sysmsg_ret_addr // msg->ret_addr

.size __export_syshandler, . - __export_syshandler
