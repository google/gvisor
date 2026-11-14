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

package kernel

import (
	"fmt"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// TestCopiedSeccompCacheArchitecture checks that an inherited cache cannot
// allow a syscall denied by the filters for a different architecture.
func TestCopiedSeccompCacheArchitecture(t *testing.T) {
	const denied = linux.SECCOMP_RET_ERRNO | 42
	program, err := bpf.Compile([]bpf.Instruction{
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 4),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, linux.AUDIT_ARCH_X86_64, 1, 0),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(denied)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	parent := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: linux.AUDIT_ARCH_X86_64}}}
	filters := taskSeccomp{filters: []SyscallFilter{NewSyscallFilter(program)}}
	filters.populateCache(parent)
	child := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: linux.AUDIT_ARCH_AARCH64}}}
	child.seccomp.Store(filters.copy())
	if got := child.evaluateSyscallFilters(0, arch.SyscallArguments{}, 0); got != uint32(denied) {
		t.Fatalf("different architecture: got %#x, want %#x", got, uint32(denied))
	}
	child.image.st = parent.image.st
	if got := child.evaluateSyscallFilters(0, arch.SyscallArguments{}, 0); got != uint32(linux.SECCOMP_RET_ALLOW) {
		t.Fatalf("original architecture: got %#x, want %#x", got, uint32(linux.SECCOMP_RET_ALLOW))
	}
}

// TestSeccompCacheableInputSize checks the cacheable prefix against the ABI
// layout.
func TestSeccompCacheableInputSize(t *testing.T) {
	var sd linux.SeccompData
	if got, want := unsafe.Offsetof(sd.Arch), unsafe.Sizeof(sd.Nr); unsafe.Offsetof(sd.Nr) != 0 || got != want {
		t.Fatalf("Nr and Arch are not adjacent at the start: Arch offset = %d, want %d", got, want)
	}
	if got := unsafe.Offsetof(sd.InstructionPointer); got != seccompCacheableInputSize {
		t.Errorf("InstructionPointer offset = %d, want %d", got, seccompCacheableInputSize)
	}
}

// TestSeccompCacheInput checks that argument and instruction pointer reads stay
// uncacheable, including when the previous syscall read different input bytes.
func TestSeccompCacheInput(t *testing.T) {
	const auditNumber = linux.AUDIT_ARCH_X86_64
	task := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: auditNumber}}}
	var sd linux.SeccompData
	for offset := 0; offset < sd.SizeBytes(); offset++ {
		t.Run(fmt.Sprintf("byte-%d", offset), func(t *testing.T) {
			program, err := bpf.Compile([]bpf.Instruction{
				bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 0),
				bpf.Jump(bpf.Jmp|bpf.Jset|bpf.K, 1, 0, 1),
				bpf.Stmt(bpf.Ld|bpf.Abs|bpf.B, uint32(offset)),
				bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
			}, false)
			if err != nil {
				t.Fatal(err)
			}
			ts := taskSeccomp{filters: []SyscallFilter{NewSyscallFilter(program)}}
			ts.populateCache(task)
			if ts.cacheAuditNumber != auditNumber {
				t.Fatalf("cache architecture: got %#x, want %#x", ts.cacheAuditNumber, auditNumber)
			}
			for sysno, got := range ts.cache {
				want := linux.BPFAction(linux.SECCOMP_RET_ALLOW)
				if offset >= seccompCacheableInputSize && sysno&1 != 0 {
					want = noBPFAction
				}
				if got != want {
					t.Fatalf("syscall %d: got %#x, want %#x", sysno, uint32(got), uint32(want))
				}
			}
		})
	}
}

// TestSeccompFixedActions checks that a filter with fixed actions does not
// evaluate its program for the syscalls that do have a fixed action.
func TestSeccompFixedActions(t *testing.T) {
	const (
		auditNumber  = linux.AUDIT_ARCH_X86_64
		fixedSysno   = 1
		programSysno = 2
		fixed        = linux.SECCOMP_RET_ERRNO | 1
		fromProgram  = linux.SECCOMP_RET_ERRNO | 2
		readsArgs    = linux.SECCOMP_RET_ERRNO | 3
	)
	// The program reads an argument for programSysno only.
	program, err := bpf.Compile([]bpf.Instruction{
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 0),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, programSysno, 0, 2),
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 16),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(readsArgs)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(fromProgram)),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := NewSyscallFilterWithFixedActions(auditNumber, program, func(sysno int32) (linux.BPFAction, bool) {
		return fixed, sysno != programSysno
	})
	// The second filter is more permissive, so it does not change the results.
	allow, err := bpf.Compile([]bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW))}, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		filters []SyscallFilter
	}{
		{"alone", []SyscallFilter{filter}},
		{"first", []SyscallFilter{filter, NewSyscallFilter(allow)}},
		{"last", []SyscallFilter{NewSyscallFilter(allow), filter}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: auditNumber}}}
			ts := &taskSeccomp{filters: tc.filters}
			ts.populateCache(task)
			task.seccomp.Store(ts)
			if got := ts.cache[fixedSysno]; got != fixed {
				t.Errorf("cache of syscall %d: got %#x, want %#x", fixedSysno, uint32(got), uint32(fixed))
			}
			if got := ts.cache[programSysno]; got != noBPFAction {
				t.Errorf("cache of syscall %d: got %#x, want %#x", programSysno, uint32(got), uint32(noBPFAction))
			}
			for _, sc := range []struct {
				sysno int32
				want  linux.BPFAction
			}{
				{0, fixed},
				{fixedSysno, fixed},
				{programSysno, readsArgs},
				{sentry.MaxSyscallNum, fixed},
				{-1, fromProgram},
				{sentry.MaxSyscallNum + 1, fromProgram},
			} {
				if got := task.evaluateSyscallFilters(sc.sysno, arch.SyscallArguments{}, 0); got != uint32(sc.want) {
					t.Errorf("syscall %d: got %#x, want %#x", sc.sysno, got, uint32(sc.want))
				}
			}

			// The fixed actions do not apply to other architectures.
			task.image.st = &SyscallTable{AuditNumber: linux.AUDIT_ARCH_AARCH64}
			if got := task.evaluateSyscallFilters(fixedSysno, arch.SyscallArguments{}, 0); got != uint32(fromProgram) {
				t.Errorf("syscall %d on another architecture: got %#x, want %#x", fixedSysno, got, uint32(fromProgram))
			}
			ts.populateCache(task)
			if got := ts.cache[fixedSysno]; got != fromProgram {
				t.Errorf("cache of syscall %d on another architecture: got %#x, want %#x", fixedSysno, uint32(got), uint32(fromProgram))
			}
		})
	}
}

// TestSeccompFixedActionsWithOtherFilter checks the results of a filter with
// fixed actions together with a filter that has a different result.
func TestSeccompFixedActionsWithOtherFilter(t *testing.T) {
	const (
		auditNumber = linux.AUDIT_ARCH_X86_64
		sysno       = 1
		fixed       = linux.SECCOMP_RET_ERRNO | 1
		fromProgram = linux.SECCOMP_RET_ALLOW
	)
	// The fixed action is the only correct result of this filter: its
	// program gives another result.
	fixedProgram, err := bpf.Compile([]bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(fromProgram))}, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := NewSyscallFilterWithFixedActions(auditNumber, fixedProgram, func(int32) (linux.BPFAction, bool) {
		return fixed, true
	})

	for _, tc := range []struct {
		name string
		// other is the result of the other filter.
		other linux.BPFAction
		// readsArgs is true if the other filter reads a syscall argument.
		readsArgs bool
		want      linux.BPFAction
	}{
		{name: "stricter", other: linux.SECCOMP_RET_KILL_THREAD, want: linux.SECCOMP_RET_KILL_THREAD},
		{name: "more_permissive", other: linux.SECCOMP_RET_ALLOW, want: fixed},
		{name: "stricter_reads_args", other: linux.SECCOMP_RET_KILL_THREAD, readsArgs: true, want: linux.SECCOMP_RET_KILL_THREAD},
		{name: "more_permissive_reads_args", other: linux.SECCOMP_RET_ALLOW, readsArgs: true, want: fixed},
		{name: "kill_process", other: linux.SECCOMP_RET_KILL_PROCESS, want: linux.SECCOMP_RET_KILL_PROCESS},
		{name: "kill_process_reads_args", other: linux.SECCOMP_RET_KILL_PROCESS, readsArgs: true, want: linux.SECCOMP_RET_KILL_PROCESS},
	} {
		instructions := []bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(tc.other))}
		if tc.readsArgs {
			instructions = append([]bpf.Instruction{bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 16)}, instructions...)
		}
		program, err := bpf.Compile(instructions, false)
		if err != nil {
			t.Fatal(err)
		}
		other := NewSyscallFilter(program)
		for _, order := range []struct {
			name    string
			filters []SyscallFilter
		}{
			{"fixed_first", []SyscallFilter{filter, other}},
			{"fixed_last", []SyscallFilter{other, filter}},
		} {
			t.Run(tc.name+"/"+order.name, func(t *testing.T) {
				task := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: auditNumber}}}
				ts := &taskSeccomp{filters: order.filters}
				ts.populateCache(task)
				task.seccomp.Store(ts)
				wantCache := tc.want
				if tc.readsArgs {
					wantCache = noBPFAction
				}
				if got := ts.cache[sysno]; got != wantCache {
					t.Errorf("cache: got %#x, want %#x", uint32(got), uint32(wantCache))
				}
				if got := task.evaluateSyscallFilters(sysno, arch.SyscallArguments{}, 0); got != uint32(tc.want) {
					t.Errorf("result: got %#x, want %#x", got, uint32(tc.want))
				}
			})
		}
	}
}

// TestSeccompFixedActionKillProcess checks that a fixed
// SECCOMP_RET_KILL_PROCESS takes precedence over the results of other
// filters.
func TestSeccompFixedActionKillProcess(t *testing.T) {
	const (
		auditNumber = linux.AUDIT_ARCH_X86_64
		sysno       = 1
	)
	allow, err := bpf.Compile([]bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW))}, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := NewSyscallFilterWithFixedActions(auditNumber, allow, func(int32) (linux.BPFAction, bool) {
		return linux.SECCOMP_RET_KILL_PROCESS, true
	})
	for _, other := range []linux.BPFAction{linux.SECCOMP_RET_KILL_THREAD, linux.SECCOMP_RET_ERRNO | 1, linux.SECCOMP_RET_ALLOW} {
		program, err := bpf.Compile([]bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(other))}, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, filters := range [][]SyscallFilter{{filter, NewSyscallFilter(program)}, {NewSyscallFilter(program), filter}} {
			task := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: auditNumber}}}
			ts := &taskSeccomp{filters: filters}
			ts.populateCache(task)
			if got := ts.cache[sysno]; got != linux.SECCOMP_RET_KILL_PROCESS {
				t.Errorf("other filter returns %#x: cache: got %#x, want %#x", uint32(other), uint32(got), uint32(linux.SECCOMP_RET_KILL_PROCESS))
			}
		}
	}
}

// TestSeccompFixedActionSameAction checks that when a fixed action and the
// result of another filter only differ by their data, the filter that was
// installed last gives the result.
func TestSeccompFixedActionSameAction(t *testing.T) {
	const (
		auditNumber = linux.AUDIT_ARCH_X86_64
		sysno       = 1
		fixed       = linux.SECCOMP_RET_ERRNO | 1
		fromOther   = linux.SECCOMP_RET_ERRNO | 2
	)
	allow, err := bpf.Compile([]bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW))}, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := NewSyscallFilterWithFixedActions(auditNumber, allow, func(int32) (linux.BPFAction, bool) {
		return fixed, true
	})
	for _, readsArgs := range []bool{false, true} {
		instructions := []bpf.Instruction{bpf.Stmt(bpf.Ret|bpf.K, uint32(fromOther))}
		if readsArgs {
			instructions = append([]bpf.Instruction{bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 16)}, instructions...)
		}
		program, err := bpf.Compile(instructions, false)
		if err != nil {
			t.Fatal(err)
		}
		other := NewSyscallFilter(program)
		for _, tc := range []struct {
			name    string
			filters []SyscallFilter
			want    linux.BPFAction
		}{
			{"fixed_last", []SyscallFilter{other, filter}, fixed},
			{"fixed_first", []SyscallFilter{filter, other}, fromOther},
		} {
			t.Run(fmt.Sprintf("%s/reads_args_%t", tc.name, readsArgs), func(t *testing.T) {
				task := &Task{image: TaskImage{st: &SyscallTable{AuditNumber: auditNumber}}}
				ts := &taskSeccomp{filters: tc.filters}
				ts.populateCache(task)
				task.seccomp.Store(ts)
				wantCache := tc.want
				if readsArgs {
					wantCache = noBPFAction
				}
				if got := ts.cache[sysno]; got != wantCache {
					t.Errorf("cache: got %#x, want %#x", uint32(got), uint32(wantCache))
				}
				if got := task.evaluateSyscallFilters(sysno, arch.SyscallArguments{}, 0); got != uint32(tc.want) {
					t.Errorf("result: got %#x, want %#x", got, uint32(tc.want))
				}
			})
		}
	}
}
