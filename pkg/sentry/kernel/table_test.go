// Copyright 2018 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

const (
	maxTestSyscall = 1000
)

func createSyscallTable() *SyscallTable {
	m := make(map[uintptr]Syscall)
	for i := uintptr(0); i <= maxTestSyscall; i++ {
		j := i
		m[i] = Syscall{
			Fn: func(*Task, arch.SyscallArguments) (uintptr, *SyscallControl, error) {
				return j, nil, nil
			},
		}
	}

	s := &SyscallTable{
		OS:    abi.Linux,
		Arch:  arch.AMD64,
		Table: m,
	}

	RegisterSyscallTable(s)
	return s
}

func TestTable(t *testing.T) {
	table := createSyscallTable()
	defer func() {
		// Cleanup registered tables to keep tests separate.
		allSyscallTables = []*SyscallTable{}
	}()

	// Go through all functions and check that they return the right value.
	for i := uintptr(0); i < maxTestSyscall; i++ {
		fn := table.Lookup(i)
		if fn == nil {
			t.Errorf("Syscall %v is set to nil", i)
			continue
		}

		v, _, _ := fn(nil, arch.SyscallArguments{})
		if v != i {
			t.Errorf("Wrong return value for syscall %v: expected %v, got %v", i, i, v)
		}
	}

	// Check that values outside the range return nil.
	for i := uintptr(maxTestSyscall + 1); i < maxTestSyscall+100; i++ {
		fn := table.Lookup(i)
		if fn != nil {
			t.Errorf("Syscall %v is not nil: %v", i, fn)
			continue
		}
	}
}

func BenchmarkTableLookup(b *testing.B) {
	table := createSyscallTable()

	b.ResetTimer()

	j := uintptr(0)
	for i := 0; i < b.N; i++ {
		table.Lookup(j)
		j = (j + 1) % 310
	}

	b.StopTimer()
	// Cleanup registered tables to keep tests separate.
	allSyscallTables = []*SyscallTable{}
}

func BenchmarkTableMapLookup(b *testing.B) {
	table := createSyscallTable()

	b.ResetTimer()

	j := uintptr(0)
	for i := 0; i < b.N; i++ {
		table.mapLookup(j)
		j = (j + 1) % 310
	}

	b.StopTimer()
	// Cleanup registered tables to keep tests separate.
	allSyscallTables = []*SyscallTable{}
}
