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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
)

// TestSeccompCacheableInputSize checks the cacheable prefix against the ABI
// layout.
func TestSeccompCacheableInputSize(t *testing.T) {
	typ := reflect.TypeFor[linux.SeccompData]()
	var end uintptr
	for _, name := range []string{"Nr", "Arch"} {
		field, _ := typ.FieldByName(name)
		if field.Offset != end {
			t.Fatalf("%s offset = %d, want %d", name, field.Offset, end)
		}
		end += field.Type.Size()
	}
	if end != seccompCacheableInputSize {
		t.Errorf("Nr and Arch occupy %d bytes, want %d", end, seccompCacheableInputSize)
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
				// SeccompData's first 8 ABI bytes are nr and arch.
				if offset >= 8 && sysno&1 != 0 {
					want = uncacheableBPFAction
				}
				if got != want {
					t.Fatalf("syscall %d: got %#x, want %#x", sysno, uint32(got), uint32(want))
				}
			}
		})
	}
}
