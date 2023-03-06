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

.globl __export_syshandler;
.type __export_syshandler, @function;
.align 4, 0x00;
__export_syshandler:
  // The start of this function is in a usertrap trampoline:
  // mov %rsp,%gs:0x20
  // mov %gs:0x18,%rs
  // movabs $ret_addr, %rax
  // mov %rax, %fs:0x8
  // mov sysno, %eax
  // jmpq *%gs,0x10

  // Save registers which are not preserved across function calls.
  // http://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
  push %rbp
  push %r11
  push %r10
  push %r9
  push %r8
  push %rdi
  push %rsi
  push %rdx
  push %rcx

  // We have to avoid races with sighandler, so if sysmsg isn't equal to
  // SYSMSG_STATE_NONE, we can't fault on a user stack.
  //
  // We can fault on a user stack, what a page isn't mapped yet or when a
  // process is dieing and a process address spaces has been cleaned up (see
  // subprocess.Release).
  callq __syshandler

  // Restore registers and return back to a guest code.
  pop %rcx
  pop %rdx
  pop %rsi
  pop %rdi
  pop %r8
  pop %r9
  pop %r10
  pop %r11
  pop %rbp

  movq %gs:offsetof_sysmsg_app_stack,%rsp

  cmpl $kTHREAD_STATE_SIGACT, %gs:offsetof_sysmsg_state // msg->state
  jne skipsyscall
  mov $0xffff, %eax // any syscall which isn't allowed by seccomp.
  // nop is here to avoid matching the `mov sysno, %eax; syscall` pattern that
  // we are substituting with function calls.
  nop
  syscall
  jmp skipint
skipsyscall:
  cmpl $0, %gs:offsetof_sysmsg_interrupt // msg->interrupt
  je skipint
  movl $kTHREAD_STATE_INTERRUPT, %gs:offsetof_sysmsg_state
  .byte FAULT_OPCODE // Re-trigger the interrupt.
skipint:
  jmp *%gs:offsetof_sysmsg_ret_addr // msg->ret_addr

.size __export_syshandler, . - __export_syshandler
