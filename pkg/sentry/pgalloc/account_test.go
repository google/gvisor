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

package pgalloc

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// newAccountingTestMemoryFile creates a MemoryFile for testing memory
// accounting. It is backed by a real memfd (so that decommit works) but has no
// releaser goroutine, allowing tests to deterministically control page state
// transitions.
func newAccountingTestMemoryFile(t *testing.T, opts MemoryFileOpts) *MemoryFile {
	t.Helper()
	mfd, err := memutil.CreateMemFD("pgalloc-accounting-test", 0)
	if err != nil {
		t.Fatalf("memutil.CreateMemFD() failed: %v", err)
	}
	file := os.NewFile(uintptr(mfd), "pgalloc-accounting-test")
	t.Cleanup(func() {
		file.Close()
	})

	f := &MemoryFile{opts: opts}
	f.initFields()
	f.file = file
	return f
}

func requireUsageInit(t *testing.T) {
	t.Helper()
	if err := usage.Init(); err != nil {
		t.Fatalf("usage.Init() failed: %v", err)
	}
}

// checkAccounting verifies that the aggregate memory accounting matches the
// given delta relative to the provided baseline.
func checkAccounting(t *testing.T, before usage.MemoryStats, beforeTotal, deltaTotal uint64, delta usage.MemoryStats) {
	t.Helper()
	got, gotTotal := usage.MemoryAccounting.Copy()
	want := usage.MemoryStats{
		System:    before.System + delta.System,
		Anonymous: before.Anonymous + delta.Anonymous,
		PageCache: before.PageCache + delta.PageCache,
		Tmpfs:     before.Tmpfs + delta.Tmpfs,
		Mapped:    before.Mapped + delta.Mapped,
		Ramdiskfs: before.Ramdiskfs + delta.Ramdiskfs,
	}
	if got != want {
		t.Errorf("memory accounting = %+v; want %+v", got, want)
	}
	if gotTotal != beforeTotal+deltaTotal {
		t.Errorf("total memory accounting = %d; want %d", gotTotal, beforeTotal+deltaTotal)
	}
}

func TestAccountAllocated(t *testing.T) {
	requireUsageInit(t)

	const allocLen = 4 * hostarch.PageSize

	f := newAccountingTestMemoryFile(t, MemoryFileOpts{MemoryAccounting: MemoryAccountingAllocated})

	before, totalBefore := usage.MemoryAccounting.Copy()
	cg1Before := usage.MemoryAccounting.TotalPerCg(1)
	cg2Before := usage.MemoryAccounting.TotalPerCg(2)

	// Allocate two ranges.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Tmpfs, MemCgID: 2, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}

	// In allocation-based accounting mode, memory is accounted as soon as it is
	// allocated, under the allocation's kind and cgroup.
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before+allocLen {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before+allocLen)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before+allocLen {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before+allocLen)
	}

	// UpdateUsage() has no effect in allocation-based accounting mode.
	if err := f.UpdateUsage(nil); err != nil {
		t.Fatalf("UpdateUsage() failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})

	// Decommitting does not affect allocation-based accounting.
	f.Decommit(fr1)
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})

	// Dropping the last reference on fr1 reclassifies it as System.
	f.DecRef(fr1)
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		System: allocLen,
		Tmpfs:  allocLen,
	})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before+allocLen {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before+allocLen)
	}

	// Releasing fr1 stops accounting it entirely.
	f.mu.Lock()
	f.releaseLocked(fr1, false)
	f.mu.Unlock()
	checkAccounting(t, before, totalBefore, allocLen, usage.MemoryStats{
		Tmpfs: allocLen,
	})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}

	// Dropping the last reference on fr2 and releasing it returns accounting
	// to the baseline.
	f.DecRef(fr2)
	checkAccounting(t, before, totalBefore, allocLen, usage.MemoryStats{
		System: allocLen,
	})
	f.mu.Lock()
	f.releaseLocked(fr2, false)
	f.mu.Unlock()
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}
}

func TestAccountAllocatedRecycle(t *testing.T) {
	requireUsageInit(t)

	const allocLen = 4 * hostarch.PageSize

	f := newAccountingTestMemoryFile(t, MemoryFileOpts{MemoryAccounting: MemoryAccountingAllocated})

	before, totalBefore := usage.MemoryAccounting.Copy()
	cg1Before := usage.MemoryAccounting.TotalPerCg(1)
	cg2Before := usage.MemoryAccounting.TotalPerCg(2)

	// Allocate a range, then drop the last reference on it to make it waste.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	f.DecRef(fr1)
	checkAccounting(t, before, totalBefore, allocLen, usage.MemoryStats{
		System: allocLen,
	})

	// An allocation that may commit recycles the waste pages, reclassifying
	// them under the new allocation's kind and cgroup.
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Tmpfs, MemCgID: 2, Mode: AllocateCallerIndirectCommit})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	if fr2 != fr1 {
		t.Fatalf("recycled allocation = %v; want %v", fr2, fr1)
	}
	checkAccounting(t, before, totalBefore, allocLen, usage.MemoryStats{
		Tmpfs: allocLen,
	})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before+allocLen {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before+allocLen)
	}
}

// TestCommittedAccountingBaseline verifies that commitment-based accounting
// (the default) is unchanged: uncommitted pages are unaccounted until they
// become known-committed, and committing pages does not unaccount them until
// they are decommitted.
func TestCommittedAccountingBaseline(t *testing.T) {
	requireUsageInit(t)

	const allocLen = 4 * hostarch.PageSize

	f := newAccountingTestMemoryFile(t, MemoryFileOpts{})

	before, totalBefore := usage.MemoryAccounting.Copy()

	// An uncommitted allocation is not accounted for.
	fr, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})

	// Fault the pages in, then scanning accounts them.
	f.manuallyZero(fr)
	if err := f.commitFile(fr); err != nil {
		t.Fatalf("commitFile() failed: %v", err)
	}
	if err := f.UpdateUsage(nil); err != nil {
		t.Fatalf("UpdateUsage() failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, allocLen, usage.MemoryStats{
		Anonymous: allocLen,
	})

	// Decommiting unaccounts them.
	f.Decommit(fr)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
}
