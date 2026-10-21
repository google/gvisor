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
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/metric"
)

func TestIncrementUnimplementedSyscallCounter(t *testing.T) {
	createSyscallTable()
	defer func() {
		// Cleanup registered tables to keep tests separate.
		allSyscallTables = []*SyscallTable{}
	}()

	if got, want := len(unimplementedSyscallNumbers), sentry.MaxSyscallNum+2; got != want {
		t.Fatalf("len(unimplementedSyscallNumbers) = %d, want %d", got, want)
	}
	for i, fv := range unimplementedSyscallNumbers[:sentry.MaxSyscallNum+1] {
		if want := strconv.Itoa(i); fv.Value != want {
			t.Fatalf("unimplementedSyscallNumbers[%d] = %q, want %q", i, fv.Value, want)
		}
	}
	if got := unimplementedSyscallNumbers[sentry.MaxSyscallNum+1]; got != outOfRangeSyscallNumber {
		t.Fatalf("last element of unimplementedSyscallNumbers = %q, want %q", got.Value, outOfRangeSyscallNumber.Value)
	}

	value := func(fv *metric.FieldValue) uint64 {
		return unimplementedSyscallCounter.Value(fv)
	}
	before := make(map[*metric.FieldValue]uint64)
	for _, fv := range unimplementedSyscallNumbers {
		before[fv] = value(fv)
	}

	for _, sysno := range []uintptr{0, 1, 1, sentry.MaxSyscallNum, sentry.MaxSyscallNum + 1, ^uintptr(0)} {
		IncrementUnimplementedSyscallCounter(sysno)
	}

	for _, tc := range []struct {
		fv   *metric.FieldValue
		want uint64
	}{
		{unimplementedSyscallNumbers[0], 1},
		{unimplementedSyscallNumbers[1], 2},
		{unimplementedSyscallNumbers[2], 0},
		{unimplementedSyscallNumbers[sentry.MaxSyscallNum], 1},
		{outOfRangeSyscallNumber, 2},
	} {
		if got := value(tc.fv) - before[tc.fv]; got != tc.want {
			t.Errorf("counter for sysno %q increased by %d, want %d", tc.fv.Value, got, tc.want)
		}
	}

	if allocs := testing.AllocsPerRun(100, func() {
		IncrementUnimplementedSyscallCounter(42)
		IncrementUnimplementedSyscallCounter(sentry.MaxSyscallNum + 1)
	}); allocs != 0 {
		t.Errorf("IncrementUnimplementedSyscallCounter allocated %v times per run, want 0", allocs)
	}
}
