// Copyright 2026 The gVisor Authors.
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

package precompiledseccomp

import (
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// testVarSyscalls is a set of syscalls whose syscall numbers are variables.
var testVarSyscalls = []VarSyscall{
	{
		Name: "a",
		Rule: seccomp.PerArg{seccomp.EqualTo(1)},
	},
	{
		Name: "b",
		Rule: seccomp.MatchAll{},
	},
	{
		Name: "c",
		Rule: seccomp.Or{
			seccomp.PerArg{seccomp.EqualTo(1)},
			seccomp.PerArg{seccomp.EqualTo(2)},
		},
	},
	{
		Name: "d",
		Rule: seccomp.MatchAll{},
	},
}

// testSyscallVarsProgram returns a program with rules for some fixed
// syscall numbers, and for the syscalls in `sn` using the syscall number
// variables in `vars`.
func testSyscallVarsProgram(sn VarSyscallNumbers, vars Values) *seccomp.Program {
	rules := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		0:           seccomp.MatchAll{},
		1:           seccomp.PerArg{seccomp.EqualTo(2)},
		2:           seccomp.MatchAll{},
		3:           seccomp.PerArg{seccomp.EqualTo(1)},
		100:         seccomp.PerArg{seccomp.EqualTo(0)},
		101:         seccomp.MatchAll{},
		102:         seccomp.MatchAll{},
		200:         seccomp.PerArg{seccomp.EqualTo(1)},
		201:         seccomp.PerArg{seccomp.EqualTo(2)},
		498:         seccomp.MatchAll{},
		499:         seccomp.PerArg{seccomp.EqualTo(1)},
		^uintptr(0): seccomp.MatchAll{}, // Syscall number -1 for funsies.
	})
	rules.Merge(VarSyscallRules(testVarSyscalls, sn, vars))
	return &seccomp.Program{
		RuleSets: []seccomp.RuleSet{{
			Rules:  rules,
			Action: seccomp.Allow,
		}},
		Options: seccomp.ProgramOptions{
			DefaultAction: seccomp.KillProcess,
			BadArchAction: seccomp.KillProcess,
			HotSyscalls:   []uintptr{1, 200},
		},
	}
}

// TestSyscallVars verifies that programs precompiled with syscall number
// *variables* behave the same as programs compiled with the actual syscall
// numbers.
func TestSyscallVars(t *testing.T) {
	precompiled, err := Precompile("test", []string{
		SyscallVarName("a"),
		SyscallVarName("b"),
		SyscallVarName("c"),
		SyscallVarName("d"),
	}, func(vars Values) *seccomp.Program {
		return testSyscallVarsProgram(AllVarSyscallNumbers(testVarSyscalls), vars)
	})
	if err != nil {
		t.Fatalf("Precompile failed: %v", err)
	}
	buf := make([]byte, (&linux.SeccompData{}).SizeBytes())
	for _, test := range []struct {
		name    string
		sn      VarSyscallNumbers
		wantErr bool
	}{
		{
			name: "consecutive",
			sn:   VarSyscallNumbers{"a": 500, "b": 501, "c": 502, "d": 503},
		},
		{
			name: "sparse",
			sn:   VarSyscallNumbers{"a": 601, "b": 602, "c": 617, "d": 623},
		},
		{
			name:    "too low",
			sn:      VarSyscallNumbers{"a": 499, "b": 501, "c": 502, "d": 503},
			wantErr: true,
		},
		{
			name:    "too high",
			sn:      VarSyscallNumbers{"a": 601, "b": 602, "c": 617, "d": MaxSyscallVarValue},
			wantErr: true,
		},
		{
			name:    "out of order",
			sn:      VarSyscallNumbers{"a": 601, "b": 617, "c": 602, "d": 623},
			wantErr: true,
		},
		{
			name:    "duplicate",
			sn:      VarSyscallNumbers{"a": 601, "b": 602, "c": 602, "d": 623},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			vars := Values{}
			test.sn.SetVars(vars)
			program := precompiled // Modified in-place, so copy.
			program.Bytecode32 = append([]uint32(nil), precompiled.Bytecode32...)
			rendered, err := program.RenderInstructions(vars)
			if test.wantErr {
				if !errors.Is(err, ErrSyscallVarsNotRenderable) {
					t.Fatalf("RenderInstructions returned error %v, want %v", err, ErrSyscallVarsNotRenderable)
				}
				return
			}
			if err != nil {
				t.Fatalf("RenderInstructions failed: %v", err)
			}
			compiled, _, err := testSyscallVarsProgram(test.sn, vars).Build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}
			renderedProg, err := bpf.Compile(rendered, false /* optimize */)
			if err != nil {
				t.Fatalf("cannot compile rendered program: %v", err)
			}
			compiledProg, err := bpf.Compile(compiled, false /* optimize */)
			if err != nil {
				t.Fatalf("cannot compile program: %v", err)
			}
			for nr := int32(-1); nr < 1000; nr++ {
				for arg := uint64(0); arg < 4; arg++ {
					data := linux.SeccompData{
						Nr:   nr,
						Arch: seccomp.LINUX_AUDIT_ARCH,
						Args: [6]uint64{arg},
					}
					got, err := bpf.Exec[bpf.NativeEndian](renderedProg, seccomp.DataAsBPFInput(&data, buf))
					if err != nil {
						t.Fatalf("cannot execute rendered program on %+v: %v", data, err)
					}
					want, err := bpf.Exec[bpf.NativeEndian](compiledProg, seccomp.DataAsBPFInput(&data, buf))
					if err != nil {
						t.Fatalf("cannot execute program on %+v: %v", data, err)
					}
					if got != want {
						t.Errorf("rendered program returned %#x on %+v, want %#x", got, data, want)
					}
				}
			}
		})
	}
}
