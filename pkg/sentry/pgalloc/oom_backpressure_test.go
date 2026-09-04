// Copyright 2024 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// killableContext wraps a context.Context so a test can toggle Killed(), which
// WaitForOOMHeadroom uses to detect that the caller is the OOM victim.
type killableContext struct {
	context.Context
	killed atomicbitops.Bool
}

func (k *killableContext) Killed() bool { return k.killed.Load() }

// newOOMTestMemoryFile returns a memfd-backed MemoryFile for back-pressure
// tests. TotalUsage() reflects the memfd's committed blocks, so committing and
// decommitting ranges deterministically drives usage above/below the limit.
func newOOMTestMemoryFile(t *testing.T) *MemoryFile {
	t.Helper()
	memfd, err := memutil.CreateMemFD("pgalloc-oom-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	file := os.NewFile(uintptr(memfd), "pgalloc-oom-test")
	mf, err := NewMemoryFile(file, MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return mf
}

// commitPages commits n pages so TotalUsage() reports at least n*page bytes, and
// returns the committed range so the caller can decommit it to simulate reclaim.
func commitPages(t *testing.T, mf *MemoryFile, n uint64) memmap.FileRange {
	t.Helper()
	fr, err := mf.Allocate(n*page, AllocOpts{Kind: usage.Anonymous, Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate(%d pages): %v", n, err)
	}
	got, err := mf.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage: %v", err)
	}
	if got < n*page {
		t.Fatalf("TotalUsage after committing %d pages = %d, want >= %d", n, got, n*page)
	}
	return fr
}

// runWaitAsync runs WaitForOOMHeadroom on a goroutine and returns a channel that
// is closed when it returns.
func runWaitAsync(ctx context.Context, mf *MemoryFile) chan struct{} {
	done := make(chan struct{})
	go func() {
		mf.WaitForOOMHeadroom(ctx)
		close(done)
	}()
	return done
}

// TestWaitForOOMHeadroomDisabled verifies that with no hard limit configured the
// fast path returns immediately (the common case: killer disabled).
func TestWaitForOOMHeadroomDisabled(t *testing.T) {
	mf := newOOMTestMemoryFile(t)
	// oomHardLimit defaults to 0 and oomKick is nil: must be a no-op.
	select {
	case <-runWaitAsync(context.Background(), mf):
	case <-time.After(time.Second):
		t.Fatal("WaitForOOMHeadroom blocked while the killer is disabled")
	}
}

// TestWaitForOOMHeadroomUnderLimit verifies no pause and no kick when committed
// memory is below the hard limit.
func TestWaitForOOMHeadroomUnderLimit(t *testing.T) {
	mf := newOOMTestMemoryFile(t)
	kick := make(chan struct{}, 1)
	mf.SetOOMKick(0 /*watermark*/, 100*page /*hardLimit*/, kick)
	commitPages(t, mf, 4) // well under 100 pages

	select {
	case <-runWaitAsync(context.Background(), mf):
	case <-time.After(time.Second):
		t.Fatal("WaitForOOMHeadroom blocked while under the limit")
	}
	select {
	case <-kick:
		t.Error("unexpected kick sent while under the limit")
	default:
	}
}

// TestWaitForOOMHeadroomKilledReturns verifies that a caller which is itself the
// OOM victim (ctx.Killed()) stops waiting promptly so its fault can unwind and
// the pending SIGKILL is delivered, and that it first kicked the manager.
func TestWaitForOOMHeadroomKilledReturns(t *testing.T) {
	mf := newOOMTestMemoryFile(t)
	kick := make(chan struct{}, 1)
	commitPages(t, mf, 10)
	mf.SetOOMKick(0, 5*page, kick) // 10 pages committed >= 5 page limit

	kctx := &killableContext{Context: context.Background()}
	kctx.killed.Store(true)

	select {
	case <-runWaitAsync(kctx, mf):
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForOOMHeadroom did not return despite ctx.Killed()")
	}
	select {
	case <-kick:
	default:
		t.Error("expected the victim to kick the OOM manager before returning")
	}
}

// TestWaitForOOMHeadroomReclaimReturns verifies the happy path: the caller pauses
// while over the limit, kicks the manager, and resumes once memory is reclaimed
// (simulated here by decommitting the committed range).
func TestWaitForOOMHeadroomReclaimReturns(t *testing.T) {
	mf := newOOMTestMemoryFile(t)
	kick := make(chan struct{}, 8)
	fr := commitPages(t, mf, 10)
	mf.SetOOMKick(0, 5*page, kick)

	done := runWaitAsync(context.Background(), mf)

	// Confirm it entered the slow path by waiting for a kick.
	select {
	case <-kick:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a kick after crossing the hard limit")
	}
	// It must still be paused (usage is above the limit).
	select {
	case <-done:
		t.Fatal("WaitForOOMHeadroom returned while still over the limit")
	case <-time.After(10 * time.Millisecond):
	}
	// Simulate the OOM killer reclaiming the victim's memory.
	mf.Decommit(fr)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForOOMHeadroom did not resume after memory was reclaimed")
	}
}

// TestWaitForOOMHeadroomTimeout verifies the fail-open safety valve: if memory is
// never reclaimed (e.g. the only consumers are OOM-immune) the caller is not
// stalled forever but proceeds after the timeout.
func TestWaitForOOMHeadroomTimeout(t *testing.T) {
	oldTimeout := oomBackpressureTimeout
	oomBackpressureTimeout = 100 * time.Millisecond
	defer func() { oomBackpressureTimeout = oldTimeout }()

	mf := newOOMTestMemoryFile(t)
	kick := make(chan struct{}, 64)
	commitPages(t, mf, 10)
	mf.SetOOMKick(0, 5*page, kick) // stays over the limit; never reclaimed

	start := time.Now()
	select {
	case <-runWaitAsync(context.Background(), mf):
		if elapsed := time.Since(start); elapsed < oomBackpressureTimeout {
			t.Errorf("WaitForOOMHeadroom returned after %v, want >= %v (fail-open too early)", elapsed, oomBackpressureTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForOOMHeadroom did not fail open after the timeout")
	}
}

// TestMemoryFileHeadroom tests MemoryFile.Headroom calculations under different
// limit and usage configurations.
func TestMemoryFileHeadroom(t *testing.T) {
	mf := newOOMTestMemoryFile(t)

	// No limit configured: headroom is unlimited (^uint64(0)).
	if got := mf.Headroom(); got != ^uint64(0) {
		t.Errorf("Headroom with no limit = %d, want ^uint64(0)", got)
	}

	kick := make(chan struct{}, 1)
	mf.SetOOMKick(0, 10*page, kick)

	// Under limit: 0 committed, limit 10*page.
	if got := mf.Headroom(); got != 10*page {
		t.Errorf("Headroom with 0 committed = %d, want %d", got, 10*page)
	}

	// Commit 4 pages: headroom should be 6*page.
	fr := commitPages(t, mf, 4)
	if got := mf.Headroom(); got != 6*page {
		t.Errorf("Headroom with 4 committed = %d, want %d", got, 6*page)
	}

	// Commit 6 more pages (total 10): at limit -> headroom 0.
	commitPages(t, mf, 6)
	if got := mf.Headroom(); got != 0 {
		t.Errorf("Headroom at limit = %d, want 0", got)
	}

	// Reclaim 4 pages: headroom should be 4*page again.
	mf.Decommit(fr)
	if got := mf.Headroom(); got != 4*page {
		t.Errorf("Headroom after decommit = %d, want %d", got, 4*page)
	}
}

// TestWaitForEvictionsTimeout verifies that WaitForEvictionsTimeout returns true
// when there are no active evictions.
func TestWaitForEvictionsTimeout(t *testing.T) {
	mf := newOOMTestMemoryFile(t)
	if !mf.WaitForEvictionsTimeout(time.Second) {
		t.Error("WaitForEvictionsTimeout returned false with no active evictions")
	}
}
