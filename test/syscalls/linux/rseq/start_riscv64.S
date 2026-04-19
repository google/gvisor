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
  add  fp, sp, zero
  jal  ra, __init
  wfi

  .size  _start,.-_start
  .section  .note.GNU-stack,"",@progbits

  .text
  .globl  raw_syscall
  .type   raw_syscall, @function

raw_syscall:
  add  a7,a0,zero   // syscall #
  add  a0,a1,zero   // arg0
  add  a1,a2,zero   // arg1
  add  a2,a3,zero   // arg2
  add  a3,a4,zero   // arg3
  add  a4,a5,zero   // arg4
  add  a5,a6,zero   // arg5
  ecall
  ret

  .size  raw_syscall,.-raw_syscall
  .section  .note.GNU-stack,"",@progbits

  .text
  .globl  clone
  .type   clone, @function

clone:
  // NOTE(b/326665974): implement me
  li  a0,-38  // ENOSYS
  ret

  .size  clone,.-clone
  .section  .note.GNU-stack,"",@progbits
