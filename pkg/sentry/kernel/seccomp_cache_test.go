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
	filters := taskSeccomp{filters: []bpf.Program{program}}
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
			ts := taskSeccomp{filters: []bpf.Program{program}}
			ts.populateCache(task)
			if ts.cacheAuditNumber != auditNumber {
				t.Fatalf("cache architecture: got %#x, want %#x", ts.cacheAuditNumber, auditNumber)
			}
			for sysno, got := range ts.cache {
				want := linux.BPFAction(linux.SECCOMP_RET_ALLOW)
				if offset >= seccompCacheableInputSize && sysno&1 != 0 {
					want = uncacheableBPFAction
				}
				if got != want {
					t.Fatalf("syscall %d: got %#x, want %#x", sysno, uint32(got), uint32(want))
				}
			}
		})
	}
}
