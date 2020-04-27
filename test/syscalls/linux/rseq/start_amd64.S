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


  .text
  .align 4
  .type  _start,@function
  .globl  _start

_start:
  movq  %rsp,%rdi
  call  __init
  hlt

  .size  _start,.-_start
  .section  .note.GNU-stack,"",@progbits

  .text
  .globl  raw_syscall
  .type   raw_syscall, @function

raw_syscall:
  mov  %rdi,%rax      // syscall #
  mov  %rsi,%rdi      // arg0
  mov  %rdx,%rsi      // arg1
  mov  %rcx,%rdx      // arg2
  mov  %r8,%r10       // arg3 (goes in r10 instead of rcx for system calls)
  mov  %r9,%r8        // arg4
  mov  0x8(%rsp),%r9  // arg5
  syscall
  ret

  .size  raw_syscall,.-raw_syscall
  .section  .note.GNU-stack,"",@progbits
