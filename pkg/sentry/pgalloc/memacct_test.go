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

// newTestNoReleaseMemoryFile creates a MemoryFile for testing memory
// accounting. It has no releaser goroutine, allowing tests to
// deterministically control page state transitions.
func newTestNoReleaseMemoryFile(t *testing.T, opts MemoryFileOpts) *MemoryFile {
	t.Helper()
	mfd, err := memutil.CreateMemFD("pgalloc-norelease-test", 0)
	if err != nil {
		t.Fatalf("memutil.CreateMemFD() failed: %v", err)
	}
	file := os.NewFile(uintptr(mfd), "pgalloc-norelease-test")
	t.Cleanup(func() {
		_ = file.Close()
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
	if wantTotal := beforeTotal + deltaTotal; gotTotal != wantTotal {
		t.Errorf("total memory accounting = %d; want %d", gotTotal, wantTotal)
	}
}

func TestMemoryAccountingAllocated(t *testing.T) {
	requireUsageInit(t)

	allocLen := uint64(4 << hostarch.PageShift)

	f := newTestNoReleaseMemoryFile(t, MemoryFileOpts{
		MemoryAccounting: MemoryAccountingAllocated,
	})

	before, totalBefore := usage.MemoryAccounting.Copy()
	cg1Before := usage.MemoryAccounting.TotalPerCg(1)
	cg2Before := usage.MemoryAccounting.TotalPerCg(2)

	// Under MemoryAccountingAllocated, allocations are accounted immediately.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Tmpfs, MemCgID: 2, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
	}
	if got, want := usage.MemoryAccounting.TotalPerCg(2), cg2Before+allocLen; got != want {
		t.Errorf("cgroup 2 total = %d; want %d", got, want)
	}

	// Under MemoryAccountingAllocated, commitment does not affect accounting.
	f.manuallyZero(fr1)
	f.manuallyZero(fr2)
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
	}
	if got, want := usage.MemoryAccounting.TotalPerCg(2), cg2Before+allocLen; got != want {
		t.Errorf("cgroup 2 total = %d; want %d", got, want)
	}
	if err := f.UpdateUsage(nil); err != nil {
		t.Fatalf("UpdateUsage failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
	}
	if got, want := usage.MemoryAccounting.TotalPerCg(2), cg2Before+allocLen; got != want {
		t.Errorf("cgroup 2 total = %d; want %d", got, want)
	}
	f.Decommit(fr1)
	f.Decommit(fr2)
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
	}
	if got, want := usage.MemoryAccounting.TotalPerCg(2), cg2Before+allocLen; got != want {
		t.Errorf("cgroup 2 total = %d; want %d", got, want)
	}

	// Dropping the last reference on fr1 reclassifies it as System.
	f.DecRef(fr1)
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		System: allocLen,
		Tmpfs:  allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
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

func TestMemoryAccountingCommitted(t *testing.T) {
	requireUsageInit(t)

	allocLen := uint64(4 << hostarch.PageShift)

	f := newTestNoReleaseMemoryFile(t, MemoryFileOpts{
		MemoryAccounting: MemoryAccountingCommitted,
	})

	before, totalBefore := usage.MemoryAccounting.Copy()
	cg1Before := usage.MemoryAccounting.TotalPerCg(1)
	cg2Before := usage.MemoryAccounting.TotalPerCg(2)

	// Under MemoryAccountingCommitted, allocations are not accounted
	// immediately.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	defer f.DecRef(fr1)
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Tmpfs, MemCgID: 2, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	defer f.DecRef(fr2)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}

	// Under MemoryAccountingCommitted, commitment detected by UpdateUsage is
	// accounted.
	f.manuallyZero(fr1)
	f.manuallyZero(fr2)
	if err := f.UpdateUsage(nil); err != nil {
		t.Fatalf("UpdateUsage failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 2*allocLen, usage.MemoryStats{
		Anonymous: allocLen,
		Tmpfs:     allocLen,
	})
	if got, want := usage.MemoryAccounting.TotalPerCg(1), cg1Before+allocLen; got != want {
		t.Errorf("cgroup 1 total = %d; want %d", got, want)
	}
	if got, want := usage.MemoryAccounting.TotalPerCg(2), cg2Before+allocLen; got != want {
		t.Errorf("cgroup 2 total = %d; want %d", got, want)
	}
	f.Decommit(fr1)
	f.Decommit(fr2)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}
}

func TestMemoryAccountingDisabled(t *testing.T) {
	requireUsageInit(t)

	allocLen := uint64(4 << hostarch.PageShift)

	f := newTestNoReleaseMemoryFile(t, MemoryFileOpts{
		MemoryAccounting: MemoryAccountingDisabled,
	})

	before, totalBefore := usage.MemoryAccounting.Copy()
	cg1Before := usage.MemoryAccounting.TotalPerCg(1)
	cg2Before := usage.MemoryAccounting.TotalPerCg(2)

	// Under MemoryAccountingDisabled, allocations are not accounted.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	defer f.DecRef(fr1)
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Tmpfs, MemCgID: 2, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	defer f.DecRef(fr2)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}

	// Under MemoryAccountingDisabled, commitment is not accounted.
	f.manuallyZero(fr1)
	f.manuallyZero(fr2)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}
	if err := f.UpdateUsage(nil); err != nil {
		t.Fatalf("UpdateUsage failed: %v", err)
	}
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}
	f.Decommit(fr1)
	f.Decommit(fr2)
	checkAccounting(t, before, totalBefore, 0, usage.MemoryStats{})
	if got := usage.MemoryAccounting.TotalPerCg(1); got != cg1Before {
		t.Errorf("cgroup 1 total = %d; want %d", got, cg1Before)
	}
	if got := usage.MemoryAccounting.TotalPerCg(2); got != cg2Before {
		t.Errorf("cgroup 2 total = %d; want %d", got, cg2Before)
	}
}

func TestRecyclingMemoryAccounting(t *testing.T) {
	requireUsageInit(t)

	allocLen := uint64(4 << hostarch.PageShift)

	f := newTestNoReleaseMemoryFile(t, MemoryFileOpts{
		MemoryAccounting: MemoryAccountingAllocated,
	})

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
