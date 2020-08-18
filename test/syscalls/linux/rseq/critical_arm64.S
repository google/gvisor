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

// Restartable sequences critical sections.

// Loops continuously until aborted.
//
// void rseq_loop(struct rseq* r, struct rseq_cs* cs)

  .text
  .globl  rseq_loop
  .type   rseq_loop, @function

rseq_loop:
  b begin

  // Abort block before the critical section.
  // Abort signature.
  .byte 0x90, 0x90, 0x90, 0x90
  .globl  rseq_loop_early_abort
rseq_loop_early_abort:
  ret

begin:
  // r->rseq_cs = cs
  str x1, [x0, #8]

  // N.B. rseq_cs will be cleared by any preempt, even outside the critical
  // section. Thus it must be set in or immediately before the critical section
  // to ensure it is not cleared before the section begins.
  .globl  rseq_loop_start
rseq_loop_start:
  b rseq_loop_start

  // "Pre-commit": extra instructions inside the critical section.  These are
  // used as the abort point in TestAbortPreCommit, which is not valid.
  .globl  rseq_loop_pre_commit
rseq_loop_pre_commit:
  // Extra abort signature + nop for TestAbortPostCommit.
  .byte 0x90, 0x90, 0x90, 0x90
  nop

  // "Post-commit": never reached in this case.
  .globl  rseq_loop_post_commit
rseq_loop_post_commit:

  // Abort signature.
  .byte 0x90, 0x90, 0x90, 0x90

  .globl  rseq_loop_abort
rseq_loop_abort:
  ret

  .size  rseq_loop,.-rseq_loop
  .section  .note.GNU-stack,"",@progbits
