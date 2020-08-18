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


  .text
  .align 4
  .type  _start,@function
  .globl  _start

_start:
  mov  x29, sp
  bl   __init
  wfi

  .size  _start,.-_start
  .section  .note.GNU-stack,"",@progbits

  .text
  .globl  raw_syscall
  .type   raw_syscall, @function

raw_syscall:
  mov  x8,x0   // syscall #
  mov  x0,x1   // arg0
  mov  x1,x2   // arg1
  mov  x2,x3   // arg2
  mov  x3,x4   // arg3
  mov  x4,x5   // arg4
  mov  x5,x6   // arg5
  svc  #0
  ret

  .size  raw_syscall,.-raw_syscall
  .section  .note.GNU-stack,"",@progbits
