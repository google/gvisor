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

package mm

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"
)

func testMemoryManagerWithMmapDirection(ctx context.Context, t *testing.T, mmapDirection arch.MmapDirection) *MemoryManager {
	p := platform.FromContext(ctx)
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("failed to create MemoryManager: %s", err)
	}
	mm.layout = arch.MmapLayout{
		MinAddr:          p.MinUserAddress(),
		MaxAddr:          p.MaxUserAddress(),
		BottomUpBase:     p.MinUserAddress(),
		TopDownBase:      p.MaxUserAddress(),
		DefaultDirection: mmapDirection,
	}
	return mm
}

func testMemoryManager(ctx context.Context, t *testing.T) *MemoryManager {
	return testMemoryManagerWithMmapDirection(ctx, t, arch.MmapBottomUp)
}

func (mm *MemoryManager) realUsageAS() uint64 {
	return uint64(mm.vmas.Span())
}

func TestUsageASUpdates(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:  2 * hostarch.PageSize,
		Private: true,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	realUsage := mm.realUsageAS()
	if mm.usageAS != realUsage {
		t.Fatalf("usageAS believes %v bytes are mapped; %v bytes are actually mapped", mm.usageAS, realUsage)
	}

	mm.MUnmap(ctx, addr, hostarch.PageSize)
	realUsage = mm.realUsageAS()
	if mm.usageAS != realUsage {
		t.Fatalf("usageAS believes %v bytes are mapped; %v bytes are actually mapped", mm.usageAS, realUsage)
	}
}

func (mm *MemoryManager) realDataAS() uint64 {
	var sz uint64
	for seg := mm.vmas.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		vma := seg.ValuePtr()
		if vma.isPrivateDataLocked() {
			sz += uint64(seg.Range().Length())
		}
	}
	return sz
}

func TestDataASUpdates(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   3 * hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.Write,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if mm.dataAS == 0 {
		t.Fatalf("dataAS is 0, wanted not 0")
	}
	realDataAS := mm.realDataAS()
	if mm.dataAS != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", mm.dataAS, realDataAS)
	}

	mm.MUnmap(ctx, addr, hostarch.PageSize)
	realDataAS = mm.realDataAS()
	if mm.dataAS != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", mm.dataAS, realDataAS)
	}

	mm.MProtect(addr+hostarch.PageSize, hostarch.PageSize, hostarch.Read, false)
	realDataAS = mm.realDataAS()
	if mm.dataAS != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", mm.dataAS, realDataAS)
	}

	mm.MRemap(ctx, addr+2*hostarch.PageSize, hostarch.PageSize, 2*hostarch.PageSize, MRemapOpts{
		Move: MRemapMayMove,
	})
	realDataAS = mm.realDataAS()
	if mm.dataAS != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", mm.dataAS, realDataAS)
	}
}

func TestBrkDataLimitUpdates(t *testing.T) {
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.Data, limits.Limit{}, true /* privileged */) // zero RLIMIT_DATA

	ctx := contexttest.WithLimitSet(contexttest.Context(t), limitSet)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Try to extend the brk by one page and expect doing so to fail.
	oldBrk, _ := mm.Brk(ctx, 0)
	if newBrk, _ := mm.Brk(ctx, oldBrk+hostarch.PageSize); newBrk != oldBrk {
		t.Errorf("brk() increased data segment above RLIMIT_DATA (old brk = %#x, new brk = %#x", oldBrk, newBrk)
	}
}

// TestIOAfterUnmap ensures that IO fails after unmap.
func TestIOAfterUnmap(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.Read,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}

	// IO works before munmap.
	b := make([]byte, 1)
	n, err := mm.CopyIn(ctx, addr, b, usermem.IOOpts{})
	if err != nil {
		t.Errorf("CopyIn got err %v want nil", err)
	}
	if n != 1 {
		t.Errorf("CopyIn got %d want 1", n)
	}

	err = mm.MUnmap(ctx, addr, hostarch.PageSize)
	if err != nil {
		t.Fatalf("MUnmap got err %v want nil", err)
	}

	n, err = mm.CopyIn(ctx, addr, b, usermem.IOOpts{})
	if !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyIn got err %v want EFAULT", err)
	}
	if n != 0 {
		t.Errorf("CopyIn got %d want 0", n)
	}
}

// TestIOAfterMProtect tests IO interaction with mprotect permissions.
func TestIOAfterMProtect(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}

	// Writing works before mprotect.
	b := make([]byte, 1)
	n, err := mm.CopyOut(ctx, addr, b, usermem.IOOpts{})
	if err != nil {
		t.Errorf("CopyOut got err %v want nil", err)
	}
	if n != 1 {
		t.Errorf("CopyOut got %d want 1", n)
	}

	err = mm.MProtect(addr, hostarch.PageSize, hostarch.Read, false)
	if err != nil {
		t.Errorf("MProtect got err %v want nil", err)
	}

	// Without IgnorePermissions, CopyOut should no longer succeed.
	n, err = mm.CopyOut(ctx, addr, b, usermem.IOOpts{})
	if !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyOut got err %v want EFAULT", err)
	}
	if n != 0 {
		t.Errorf("CopyOut got %d want 0", n)
	}

	// With IgnorePermissions, CopyOut should succeed despite mprotect.
	n, err = mm.CopyOut(ctx, addr, b, usermem.IOOpts{
		IgnorePermissions: true,
	})
	if err != nil {
		t.Errorf("CopyOut got err %v want nil", err)
	}
	if n != 1 {
		t.Errorf("CopyOut got %d want 1", n)
	}
}

// TestAIOPrepareAfterDestroy tests that AIOContext should not be able to be
// prepared after destruction.
func TestAIOPrepareAfterDestroy(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	id, err := mm.NewAIOContext(ctx, 1)
	if err != nil {
		t.Fatalf("mm.NewAIOContext got err %v want nil", err)
	}
	aioCtx, ok := mm.LookupAIOContext(ctx, id)
	if !ok {
		t.Fatalf("AIOContext not found")
	}
	mm.DestroyAIOContext(ctx, id)

	// Prepare should fail because aioCtx should be destroyed.
	if err := aioCtx.Prepare(); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("aioCtx.Prepare got err %v want nil", err)
	} else if err == nil {
		aioCtx.CancelPendingRequest()
	}
}

// TestAIOLookupAfterDestroy tests that AIOContext should not be able to be
// looked up after memory manager is destroyed.
func TestAIOLookupAfterDestroy(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)

	id, err := mm.NewAIOContext(ctx, 1)
	if err != nil {
		mm.DecUsers(ctx)
		t.Fatalf("mm.NewAIOContext got err %v want nil", err)
	}
	mm.DecUsers(ctx) // This destroys the AIOContext manager.

	if _, ok := mm.LookupAIOContext(ctx, id); ok {
		t.Errorf("AIOContext found even after AIOContext manager is destroyed")
	}
}

func TestGetAllocationDirection(t *testing.T) {
	testCases := []struct {
		name          string
		mmapDirection arch.MmapDirection
		ar            hostarch.AddrRange
		vma           *vma
		expected      pgalloc.Direction
	}{
		{
			"No last fault in vma with mmap direction BottomUp",
			arch.MmapBottomUp,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 0},
			pgalloc.BottomUp,
		},
		{
			"No last fault in vma with mmap direction TopDown",
			arch.MmapTopDown,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 0},
			pgalloc.TopDown,
		},
		{
			"Last fault in vma equals to addr range, with mmap direction BottomUp",
			arch.MmapBottomUp,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 123},
			pgalloc.BottomUp,
		},
		{
			"Last fault in vma equals to addr range, with mmap direction TopDown",
			arch.MmapTopDown,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 123},
			pgalloc.TopDown,
		},
		{
			"Last fault in vma greater than addr range",
			arch.MmapTopDown,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 456},
			pgalloc.TopDown,
		},
		{
			"Last fault in vma smaller than addr range",
			arch.MmapTopDown,
			hostarch.AddrRange{123, 456},
			&vma{lastFault: 100},
			pgalloc.BottomUp,
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			mm := testMemoryManagerWithMmapDirection(ctx, t, test.mmapDirection)
			actual := mm.getAllocationDirection(test.ar, test.vma)
			if actual != test.expected {
				t.Errorf("Unexpected allocation direction. Expected: %s, Actual: %s", test.expected, actual)
			}
		})
	}
}

// readPinnedRange returns the current contents of the pinned range pr.
func readPinnedRange(t *testing.T, pr PinnedRange) []byte {
	t.Helper()
	ims, err := pr.File.MapInternal(pr.FileRange(), hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal got err %v want nil", err)
	}
	buf := make([]byte, pr.Source.Length())
	if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), ims); err != nil {
		t.Fatalf("CopySeq got err %v want nil", err)
	}
	return buf
}

// TestPinnedPagesCopiedOnFork tests that Fork copies pinned pages to the
// child immediately instead of making them copy-on-write, so that the
// parent's mappings never diverge from pages registered for DMA.
func TestPinnedPagesCopiedOnFork(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Map 3 pages, but pin only the middle page, so that Fork must handle
	// both the pinned page and the copy-on-write pages surrounding it.
	const npages = 3
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   npages * hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, npages*hostarch.PageSize)
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	pinAR := hostarch.AddrRange{
		Start: addr + hostarch.PageSize,
		End:   addr + 2*hostarch.PageSize,
	}
	prs, err := mm.Pin(ctx, pinAR, hostarch.ReadWrite, false /* ignorePermissions */)
	if err != nil {
		t.Fatalf("Pin got err %v want nil", err)
	}
	defer Unpin(prs)

	// Fork twice so that both the first fork of a pinned pma, and the fork
	// of the resulting parent pma state, are tested.
	for i := 0; i < 2; i++ {
		mm2, err := mm.Fork(ctx)
		if err != nil {
			t.Fatalf("Fork got err %v want nil", err)
		}
		defer mm2.DecUsers(ctx)

		// The parent's writes to the pinned page must be visible through the
		// pinned range, i.e. the parent must not have been moved to a new
		// copy of the page by copy-on-write.
		postFork := bytes.Repeat([]byte{'B' + byte(i)}, npages*hostarch.PageSize)
		if _, err := mm.CopyOut(ctx, addr, postFork, usermem.IOOpts{}); err != nil {
			t.Fatalf("CopyOut got err %v want nil", err)
		}
		if got, want := readPinnedRange(t, prs[0]), postFork[:hostarch.PageSize]; !bytes.Equal(got, want) {
			t.Errorf("pinned page contains %q..., want %q...; parent's mapping of the pinned page diverged", got[:4], want[:4])
		}

		// The child must see the pre-fork contents of all pages.
		childBuf := make([]byte, npages*hostarch.PageSize)
		if _, err := mm2.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
			t.Fatalf("CopyIn got err %v want nil", err)
		}
		if !bytes.Equal(childBuf, preFork) {
			t.Errorf("child read %q..., want %q...", childBuf[:4], preFork[:4])
		}

		// The child's writes must not be visible through the pinned range.
		if _, err := mm2.CopyOut(ctx, addr, bytes.Repeat([]byte{'z'}, npages*hostarch.PageSize), usermem.IOOpts{}); err != nil {
			t.Fatalf("CopyOut got err %v want nil", err)
		}
		if got, want := readPinnedRange(t, prs[0]), postFork[:hostarch.PageSize]; !bytes.Equal(got, want) {
			t.Errorf("pinned page contains %q..., want %q...; child's writes are visible through the pinned range", got[:4], want[:4])
		}

		preFork = postFork
	}
}

// TestPinUnsharesCopyOnWritePages tests that pinning copy-on-write pages
// breaks copy-on-write, so that the pinned pages are those mapped by the
// pinning process, even if the pin does not require write access.
func TestPinUnsharesCopyOnWritePages(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, hostarch.PageSize)
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	// Make the page copy-on-write by forking, then pin it for reading only.
	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)
	ar := hostarch.AddrRange{
		Start: addr,
		End:   addr + hostarch.PageSize,
	}
	prs, err := mm.Pin(ctx, ar, hostarch.Read, false /* ignorePermissions */)
	if err != nil {
		t.Fatalf("Pin got err %v want nil", err)
	}
	defer Unpin(prs)

	// The parent's writes must be visible through the pinned range, and must
	// not be visible to the child.
	postFork := bytes.Repeat([]byte{'B'}, hostarch.PageSize)
	if _, err := mm.CopyOut(ctx, addr, postFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	if got := readPinnedRange(t, prs[0]); !bytes.Equal(got, postFork) {
		t.Errorf("pinned page contains %q..., want %q...; pin did not unshare the copy-on-write page", got[:4], postFork[:4])
	}
	childBuf := make([]byte, hostarch.PageSize)
	if _, err := mm2.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(childBuf, preFork) {
		t.Errorf("child read %q..., want %q...", childBuf[:4], preFork[:4])
	}
}

// TestUnpinnedPagesCopyOnWriteAfterFork tests that pages that were pinned but
// have been unpinned are once again made copy-on-write by Fork.
func TestUnpinnedPagesCopyOnWriteAfterFork(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if _, err := mm.CopyOut(ctx, addr, bytes.Repeat([]byte{'A'}, hostarch.PageSize), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	ar := hostarch.AddrRange{
		Start: addr,
		End:   addr + hostarch.PageSize,
	}
	prs, err := mm.Pin(ctx, ar, hostarch.ReadWrite, false /* ignorePermissions */)
	if err != nil {
		t.Fatalf("Pin got err %v want nil", err)
	}
	Unpin(prs)

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)

	// Since no pages remain pinned, all pages should be copy-on-write, not
	// copied for the child.
	mm.activeMu.RLock()
	pseg := mm.pmas.FindSegment(addr)
	if !pseg.Ok() {
		mm.activeMu.RUnlock()
		t.Fatalf("no pma for addr %#x", addr)
	}
	needCOW := pseg.ValuePtr().needCOW
	mm.activeMu.RUnlock()
	if !needCOW {
		t.Errorf("pma is not copy-on-write after fork of unpinned page")
	}
}

func TestMRemapMappableOffsetOverflow(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(3*hostarch.PageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatalf("failed to allocate memory file range: %v", err)
	}
	mappable := NewSpecialMappable("test_mappable", mf, fr)
	defer mappable.DecRef(ctx)

	// Map a page at a high offset (2^64 - 2*PageSize).
	// This mapping itself is valid because offset + length (2^64 - PageSize) does not overflow.
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          hostarch.PageSize,
		MappingIdentity: mappable,
		Mappable:        mappable,
		Offset:          ^uint64(0) - 2*hostarch.PageSize + 1,
		Private:         true,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}

	// 1. A shrink should succeed, even if offset+newSize overflows.
	// We remap with oldSize = 3*PageSize, newSize = 2*PageSize.
	if _, err := mm.MRemap(ctx, addr, 3*hostarch.PageSize, 2*hostarch.PageSize, MRemapOpts{}); err != nil {
		t.Errorf("MRemap shrink got err %v want nil", err)
	}

	// 2. A grow should fail if offset+newSize overflows.
	// We remap with oldSize = PageSize, newSize = 3*PageSize.
	if _, err := mm.MRemap(ctx, addr, hostarch.PageSize, 3*hostarch.PageSize, MRemapOpts{}); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("MRemap grow got err %v want EINVAL", err)
	}
}
