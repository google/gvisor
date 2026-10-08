// Copyright 2021 The gVisor Authors.
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

package systrap

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

const (
	seccompDataOffsetIPLow    = 8
	seccompDataOffsetIPHigh   = 12
	seccompDataOffsetArg0Low  = 16
	seccompDataOffsetArg0High = 20
)

func appendSysThreadArchSeccompRules(rules []seccomp.RuleSet) []seccomp.RuleSet {
	return rules
}

// trapRestartArgs traps a guest syscall whose first argument's low 32 bits
// are a restart code, passing the code, plus restartArgZeroExtended when the
// upper 32 bits are zero, in SECCOMP_RET_DATA. Stub syscalls skip this.
func trapRestartArgs(stubStart uintptr, rules []bpf.Instruction) []bpf.Instruction {
	p := bpf.NewProgramBuilder()
	addLabel := func(name string) {
		if err := p.AddLabel(name); err != nil {
			panic(fmt.Sprintf("failed to add label %q to rules for sysmsg threads: %v", name, err))
		}
	}
	p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetIPHigh)
	p.AddJumpTrueLabel(bpf.Jmp|bpf.Jgt|bpf.K, uint32(stubStart>>32), "rules", 0)
	p.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, uint32(stubStart>>32), 0, "arg")
	p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetIPLow)
	p.AddJumpTrueLabel(bpf.Jmp|bpf.Jgt|bpf.K, uint32(stubStart), "rules", 0)
	addLabel("arg")
	p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArg0Low)
	for _, code := range restartArgCodes {
		p.AddJumpTrueLabel(bpf.Jmp|bpf.Jeq|bpf.K, uint32(-int32(code)), fmt.Sprintf("restart%d", code), 0)
	}
	p.AddDirectJumpLabel("rules")
	for _, code := range restartArgCodes {
		addLabel(fmt.Sprintf("restart%d", code))
		p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArg0High)
		p.AddJump(bpf.Jmp|bpf.Jeq|bpf.K, 0, 0, 1)
		p.AddStmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_TRAP)|uint32(code)|restartArgZeroExtended)
		p.AddStmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_TRAP)|uint32(code))
	}
	addLabel("rules")
	for _, ins := range rules {
		p.AddJump(ins.OpCode, ins.K, ins.JumpIfTrue, ins.JumpIfFalse)
	}
	instrs, err := p.Instructions()
	if err != nil {
		panic(fmt.Sprintf("failed to trap restart arguments in rules for sysmsg threads: %v", err))
	}
	return instrs
}
