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
	"testing"

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
