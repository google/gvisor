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
	"sync"
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

func mmapPrivateAnon(ctx context.Context, t *testing.T, mm *MemoryManager, pages int) hostarch.Addr {
	t.Helper()
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   uint64(pages) * hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	return addr
}

func faultPagesErr(ctx context.Context, mm *MemoryManager, addr hostarch.Addr, pages int) error {
	buf := []byte{1}
	for i := 0; i < pages; i++ {
		if _, err := mm.CopyOut(ctx, addr+hostarch.Addr(i)*hostarch.PageSize, buf, usermem.IOOpts{}); err != nil {
			return err
		}
	}
	return nil
}

func faultPages(ctx context.Context, t *testing.T, mm *MemoryManager, addr hostarch.Addr, pages int) {
	t.Helper()
	if err := faultPagesErr(ctx, mm, addr, pages); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
}

type reservedVMA struct {
	ar       hostarch.AddrRange
	off      uint64
	reserved bool
}

func lookupReservedVMA(t *testing.T, mm *MemoryManager, addr hostarch.Addr) reservedVMA {
	t.Helper()
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	vseg := mm.vmas.FindSegment(addr)
	if !vseg.Ok() {
		t.Fatalf("no vma at %#x", addr)
	}
	v := vseg.ValuePtr()
	return reservedVMA{ar: vseg.Range(), off: v.off, reserved: v.memfileReserved}
}

func pmaFileOffAt(t *testing.T, mm *MemoryManager, addr hostarch.Addr) uint64 {
	t.Helper()
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	pseg := mm.pmas.FindSegment(addr)
	if !pseg.Ok() {
		t.Fatalf("no pma at %#x", addr)
	}
	return pseg.ValuePtr().off + uint64(addr-pseg.Start())
}

func TestAnonymousVMAReservesContiguousSpan(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const pages = 4
	addr := mmapPrivateAnon(ctx, t, mm, pages)
	v := lookupReservedVMA(t, mm, addr)
	if !v.reserved {
		t.Fatal("anonymous vma did not reserve a MemoryFile span")
	}
	if v.ar.Length() != pages*hostarch.PageSize {
		t.Fatalf("vma length got %#x want %#x", v.ar.Length(), pages*hostarch.PageSize)
	}

	faultPages(ctx, t, mm, addr, pages)
	for i := 0; i < pages; i++ {
		pageAddr := addr + hostarch.Addr(i)*hostarch.PageSize
		got := pmaFileOffAt(t, mm, pageAddr)
		want := v.off + uint64(i)*hostarch.PageSize
		if got != want {
			t.Errorf("page %d file offset got %#x want %#x", i, got, want)
		}
	}
}

func TestAnonymousVMAsDoNotInterleaveOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const pages = 8
	addr1 := mmapPrivateAnon(ctx, t, mm, pages)
	addr2, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   uint64(pages) * hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite.Union(hostarch.Execute),
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap 2 got err %v want nil", err)
	}
	v1 := lookupReservedVMA(t, mm, addr1)
	v2 := lookupReservedVMA(t, mm, addr2)
	if !v1.reserved || !v2.reserved {
		t.Fatal("anonymous vmas did not reserve MemoryFile spans")
	}
	fr1 := memmap.FileRange{Start: v1.off, End: v1.off + uint64(v1.ar.Length())}
	fr2 := memmap.FileRange{Start: v2.off, End: v2.off + uint64(v2.ar.Length())}
	if fr1.Start < fr2.End && fr2.Start < fr1.End {
		t.Fatalf("reserved spans overlap: %v and %v", fr1, fr2)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- faultPagesErr(ctx, mm, addr1, pages)
	}()
	go func() {
		defer wg.Done()
		errCh <- faultPagesErr(ctx, mm, addr2, pages)
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent fault: %v", err)
		}
	}

	for i := 0; i < pages; i++ {
		off1 := pmaFileOffAt(t, mm, addr1+hostarch.Addr(i)*hostarch.PageSize)
		off2 := pmaFileOffAt(t, mm, addr2+hostarch.Addr(i)*hostarch.PageSize)
		if off1 != v1.off+uint64(i)*hostarch.PageSize {
			t.Errorf("vma1 page %d offset got %#x want %#x", i, off1, v1.off+uint64(i)*hostarch.PageSize)
		}
		if off2 != v2.off+uint64(i)*hostarch.PageSize {
			t.Errorf("vma2 page %d offset got %#x want %#x", i, off2, v2.off+uint64(i)*hostarch.PageSize)
		}
		if i > 0 {
			prev1 := pmaFileOffAt(t, mm, addr1+hostarch.Addr(i-1)*hostarch.PageSize)
			if off1 != prev1+hostarch.PageSize {
				t.Errorf("vma1 page %d offset %#x is not adjacent to previous %#x", i, off1, prev1)
			}
		}
	}
}

func TestMprotectSplitKeepsLinearFileOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const pages = 3
	addr := mmapPrivateAnon(ctx, t, mm, pages)
	before := lookupReservedVMA(t, mm, addr)
	if !before.reserved {
		t.Fatal("anonymous vma did not reserve a MemoryFile span")
	}

	mid := addr + hostarch.PageSize
	if err := mm.MProtect(mid, hostarch.PageSize, hostarch.Read, false); err != nil {
		t.Fatalf("MProtect got err %v want nil", err)
	}

	left := lookupReservedVMA(t, mm, addr)
	middle := lookupReservedVMA(t, mm, mid)
	right := lookupReservedVMA(t, mm, addr+2*hostarch.PageSize)
	if !left.reserved || !middle.reserved || !right.reserved {
		t.Fatal("split vmas lost MemoryFile reservation")
	}
	if left.off != before.off {
		t.Errorf("left vma off got %#x want %#x", left.off, before.off)
	}
	if middle.off != before.off+hostarch.PageSize {
		t.Errorf("middle vma off got %#x want %#x", middle.off, before.off+hostarch.PageSize)
	}
	if right.off != before.off+2*hostarch.PageSize {
		t.Errorf("right vma off got %#x want %#x", right.off, before.off+2*hostarch.PageSize)
	}

	buf := []byte{1}
	if _, err := mm.CopyOut(ctx, addr, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut left got err %v want nil", err)
	}
	if _, err := mm.CopyIn(ctx, mid, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn middle got err %v want nil", err)
	}
	if _, err := mm.CopyOut(ctx, addr+2*hostarch.PageSize, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut right got err %v want nil", err)
	}

	if got, want := pmaFileOffAt(t, mm, addr), before.off; got != want {
		t.Errorf("left page offset got %#x want %#x", got, want)
	}
	if got, want := pmaFileOffAt(t, mm, mid), before.off+hostarch.PageSize; got != want {
		t.Errorf("middle page offset got %#x want %#x", got, want)
	}
	if got, want := pmaFileOffAt(t, mm, addr+2*hostarch.PageSize), before.off+2*hostarch.PageSize; got != want {
		t.Errorf("right page offset got %#x want %#x", got, want)
	}
}

func TestForkDoesNotInheritMemfileReservation(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr := mmapPrivateAnon(ctx, t, mm, 2)
	if v := lookupReservedVMA(t, mm, addr); !v.reserved {
		t.Fatal("parent anonymous vma did not reserve a MemoryFile span")
	}

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)

	if v := lookupReservedVMA(t, mm2, addr); v.reserved {
		t.Fatal("child inherited parent MemoryFile reservation")
	}
	if v := lookupReservedVMA(t, mm, addr); !v.reserved {
		t.Fatal("parent lost MemoryFile reservation after fork")
	}
}

func TestReservedAnonymousDoesNotCountUnfaultedRSS(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Mappings larger than a huge page are not eagerly populated.
	length := uint64(hostarch.HugePageSize + hostarch.PageSize)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   length,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if v := lookupReservedVMA(t, mm, addr); !v.reserved {
		t.Fatal("anonymous vma did not reserve a MemoryFile span")
	}
	if got := mm.ResidentSetSize(); got != 0 {
		t.Fatalf("unfaulted reserved mapping RSS got %#x want 0", got)
	}

	faultPages(ctx, t, mm, addr, 1)
	if got := mm.ResidentSetSize(); got == 0 {
		t.Fatal("RSS still 0 after fault")
	}
	if got, want := mm.ResidentSetSize(), length; got > want {
		t.Fatalf("RSS %#x exceeds mapping length %#x", got, want)
	}
}

func TestMunmapDropsReservedRSS(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const pages = 4
	addr := mmapPrivateAnon(ctx, t, mm, pages)
	faultPages(ctx, t, mm, addr, pages)
	if got, want := mm.ResidentSetSize(), uint64(pages*hostarch.PageSize); got != want {
		t.Fatalf("RSS after fault got %#x want %#x", got, want)
	}

	if err := mm.MUnmap(ctx, addr, uint64(pages)*hostarch.PageSize); err != nil {
		t.Fatalf("MUnmap got err %v want nil", err)
	}
	if got := mm.ResidentSetSize(); got != 0 {
		t.Fatalf("RSS after munmap got %#x want 0", got)
	}

	addr2 := mmapPrivateAnon(ctx, t, mm, pages)
	faultPages(ctx, t, mm, addr2, pages)
	buf := []byte{0xab}
	if _, err := mm.CopyOut(ctx, addr2, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut after remap got err %v want nil", err)
	}
}

func TestMremapInPlaceGrowKeepsLinearFileOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const oldPages = 2
	addr := mmapPrivateAnon(ctx, t, mm, oldPages)
	before := lookupReservedVMA(t, mm, addr)

	newAddr, err := mm.MRemap(ctx, addr, uint64(oldPages)*hostarch.PageSize, uint64(oldPages+1)*hostarch.PageSize, MRemapOpts{
		Move: MRemapNoMove,
	})
	if err != nil {
		t.Fatalf("MRemap grow got err %v want nil", err)
	}
	if newAddr != addr {
		t.Fatalf("MRemap grow moved mapping to %#x, want in-place %#x", newAddr, addr)
	}

	after := lookupReservedVMA(t, mm, addr)
	if !after.reserved {
		t.Fatal("grown vma lost MemoryFile reservation")
	}
	if after.ar.Length() != hostarch.Addr(oldPages+1)*hostarch.PageSize {
		t.Fatalf("grown vma length got %#x want %#x", after.ar.Length(), uint64(oldPages+1)*hostarch.PageSize)
	}
	if after.off != before.off {
		t.Fatalf("grown vma off got %#x want %#x (merged with original span)", after.off, before.off)
	}

	faultPages(ctx, t, mm, addr, oldPages+1)
	for i := 0; i < oldPages+1; i++ {
		got := pmaFileOffAt(t, mm, addr+hostarch.Addr(i)*hostarch.PageSize)
		want := after.off + uint64(i)*hostarch.PageSize
		if got != want {
			t.Errorf("page %d file offset got %#x want %#x", i, got, want)
		}
	}
}

func TestMremapCopyDoesNotAliasSource(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const pages = 2
	addr := mmapPrivateAnon(ctx, t, mm, pages)
	src := lookupReservedVMA(t, mm, addr)

	dst, err := mm.MRemap(ctx, addr, 0, uint64(pages)*hostarch.PageSize, MRemapOpts{
		Move: MRemapMayMove,
	})
	if err != nil {
		t.Fatalf("MRemap copy got err %v want nil", err)
	}
	if dst == addr {
		t.Fatal("MRemap copy returned the source address")
	}

	copyV := lookupReservedVMA(t, mm, dst)
	if copyV.reserved {
		t.Fatal("copied vma kept source MemoryFile reservation")
	}
	srcAfter := lookupReservedVMA(t, mm, addr)
	if !srcAfter.reserved {
		t.Fatal("source vma lost MemoryFile reservation after copy")
	}
	if srcAfter.off != src.off {
		t.Fatalf("source off changed %#x -> %#x", src.off, srcAfter.off)
	}

	faultPages(ctx, t, mm, addr, pages)
	faultPages(ctx, t, mm, dst, pages)
	srcPat := []byte{0x11}
	dstPat := []byte{0x22}
	if _, err := mm.CopyOut(ctx, addr, srcPat, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut source: %v", err)
	}
	if _, err := mm.CopyOut(ctx, dst, dstPat, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut copy: %v", err)
	}
	got := make([]byte, 1)
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn source: %v", err)
	}
	if got[0] != srcPat[0] {
		t.Errorf("source page got %#x want %#x; copy shared memory with source", got[0], srcPat[0])
	}
	if _, err := mm.CopyIn(ctx, dst, got, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn copy: %v", err)
	}
	if got[0] != dstPat[0] {
		t.Errorf("copy page got %#x want %#x", got[0], dstPat[0])
	}
}

func TestAdjacentAnonymousMmapsKeepLinearFileOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr := mmapPrivateAnon(ctx, t, mm, 1)
	first := lookupReservedVMA(t, mm, addr)
	next, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
		Addr:     addr + hostarch.PageSize,
		Fixed:    true,
	})
	if err != nil {
		t.Fatalf("adjacent MMap got err %v want nil", err)
	}
	if next != addr+hostarch.PageSize {
		t.Fatalf("adjacent MMap got %#x want %#x", next, addr+hostarch.PageSize)
	}

	merged := lookupReservedVMA(t, mm, addr)
	if !merged.reserved {
		t.Fatal("merged mapping lost MemoryFile reservation")
	}
	if merged.ar.Length() != 2*hostarch.PageSize {
		t.Fatalf("adjacent reserved vmas did not merge: length %#x", merged.ar.Length())
	}
	if merged.off != first.off {
		t.Fatalf("merged off got %#x want %#x", merged.off, first.off)
	}

	faultPages(ctx, t, mm, addr, 2)
	if got, want := pmaFileOffAt(t, mm, addr), merged.off; got != want {
		t.Errorf("page 0 file offset got %#x want %#x", got, want)
	}
	if got, want := pmaFileOffAt(t, mm, next), merged.off+hostarch.PageSize; got != want {
		t.Errorf("page 1 file offset got %#x want %#x", got, want)
	}
}

func TestMremapMoveAndGrowKeepsLinearFileOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const oldPages = 2
	addr := mmapPrivateAnon(ctx, t, mm, oldPages)
	before := lookupReservedVMA(t, mm, addr)
	dst := addr + hostarch.Addr(16)*hostarch.PageSize

	newAddr, err := mm.MRemap(ctx, addr, uint64(oldPages)*hostarch.PageSize, uint64(oldPages+1)*hostarch.PageSize, MRemapOpts{
		Move:    MRemapMustMove,
		NewAddr: dst,
	})
	if err != nil {
		t.Fatalf("MRemap move+grow got err %v want nil", err)
	}
	if newAddr != dst {
		t.Fatalf("MRemap move+grow got %#x want %#x", newAddr, dst)
	}

	after := lookupReservedVMA(t, mm, newAddr)
	if !after.reserved {
		t.Fatal("moved+grown vma lost MemoryFile reservation")
	}
	if after.ar.Length() != hostarch.Addr(oldPages+1)*hostarch.PageSize {
		t.Fatalf("moved+grown vma length got %#x want %#x", after.ar.Length(), uint64(oldPages+1)*hostarch.PageSize)
	}
	if after.off != before.off {
		t.Fatalf("moved+grown vma off got %#x want %#x", after.off, before.off)
	}

	faultPages(ctx, t, mm, newAddr, oldPages+1)
	for i := 0; i < oldPages+1; i++ {
		got := pmaFileOffAt(t, mm, newAddr+hostarch.Addr(i)*hostarch.PageSize)
		want := after.off + uint64(i)*hostarch.PageSize
		if got != want {
			t.Errorf("page %d file offset got %#x want %#x", i, got, want)
		}
	}
}

func TestReservedAnonymousForkCopyOnWrite(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr := mmapPrivateAnon(ctx, t, mm, 1)
	preFork := []byte{'A'}
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)

	if v := lookupReservedVMA(t, mm2, addr); v.reserved {
		t.Fatal("child inherited parent MemoryFile reservation")
	}

	if _, err := mm.CopyOut(ctx, addr, []byte{'B'}, usermem.IOOpts{}); err != nil {
		t.Fatalf("parent CopyOut got err %v want nil", err)
	}
	childBuf := make([]byte, 1)
	if _, err := mm2.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
		t.Fatalf("child CopyIn got err %v want nil", err)
	}
	if childBuf[0] != 'A' {
		t.Errorf("child saw %#x want 'A'; parent write was visible in child", childBuf[0])
	}

	if _, err := mm2.CopyOut(ctx, addr, []byte{'C'}, usermem.IOOpts{}); err != nil {
		t.Fatalf("child CopyOut got err %v want nil", err)
	}
	parentBuf := make([]byte, 1)
	if _, err := mm.CopyIn(ctx, addr, parentBuf, usermem.IOOpts{}); err != nil {
		t.Fatalf("parent CopyIn got err %v want nil", err)
	}
	if parentBuf[0] != 'B' {
		t.Errorf("parent saw %#x want 'B'; child write was visible in parent", parentBuf[0])
	}
}

func TestDontNeedZerosReservedAnonymous(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr := mmapPrivateAnon(ctx, t, mm, 1)
	before := lookupReservedVMA(t, mm, addr)
	if _, err := mm.CopyOut(ctx, addr, []byte{0xab}, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	off := pmaFileOffAt(t, mm, addr)
	if off != before.off {
		t.Fatalf("file offset after fault got %#x want %#x", off, before.off)
	}
	if got, want := mm.ResidentSetSize(), uint64(hostarch.PageSize); got != want {
		t.Fatalf("RSS after fault got %#x want %#x", got, want)
	}

	if err := mm.Decommit(addr, hostarch.PageSize); err != nil {
		t.Fatalf("Decommit got err %v want nil", err)
	}
	after := lookupReservedVMA(t, mm, addr)
	if !after.reserved {
		t.Fatal("DONTNEED dropped MemoryFile reservation")
	}
	if after.off != before.off {
		t.Fatalf("DONTNEED changed file offset %#x -> %#x", before.off, after.off)
	}
	if got := mm.ResidentSetSize(); got != 0 {
		t.Fatalf("RSS after DONTNEED got %#x want 0", got)
	}

	got := make([]byte, 1)
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn after DONTNEED got err %v want nil", err)
	}
	if got[0] != 0 {
		t.Errorf("after DONTNEED got %#x want 0", got[0])
	}
	if pmaFileOffAt(t, mm, addr) != before.off {
		t.Errorf("refault file offset got %#x want %#x", pmaFileOffAt(t, mm, addr), before.off)
	}
	if got, want := mm.ResidentSetSize(), uint64(hostarch.PageSize); got != want {
		t.Fatalf("RSS after refault got %#x want %#x", got, want)
	}
}

func TestOversizedAnonymousMmapDoesNotReserve(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	length := pgalloc.MaxAnonymousReserve + uint64(hostarch.PageSize)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   length,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap oversized got err %v want nil", err)
	}
	if v := lookupReservedVMA(t, mm, addr); v.reserved {
		t.Fatal("mmap larger than MaxAnonymousReserve reserved a MemoryFile span")
	}

	small := mmapPrivateAnon(ctx, t, mm, 1)
	if v := lookupReservedVMA(t, mm, small); !v.reserved {
		t.Fatal("small anonymous mmap did not reserve")
	}
}

func TestMapFixedBelowReservedKeepsLinearFileOffsets(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManagerWithMmapDirection(ctx, t, arch.MmapTopDown)
	defer mm.DecUsers(ctx)

	upper := mmapPrivateAnon(ctx, t, mm, 1)
	if upper < mm.layout.MinAddr+hostarch.PageSize {
		t.Fatalf("upper mapping %#x has no room below", upper)
	}
	uv := lookupReservedVMA(t, mm, upper)
	if !uv.reserved {
		t.Fatal("upper mapping did not reserve")
	}
	if uv.off < hostarch.PageSize {
		t.Fatalf("upper file offset %#x has no room below; top-down Reserve should leave a gap", uv.off)
	}

	lower, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
		Addr:     upper - hostarch.PageSize,
		Fixed:    true,
	})
	if err != nil {
		t.Fatalf("MAP_FIXED below got err %v want nil", err)
	}
	if lower != upper-hostarch.PageSize {
		t.Fatalf("MAP_FIXED below got %#x want %#x", lower, upper-hostarch.PageSize)
	}

	merged := lookupReservedVMA(t, mm, lower)
	if !merged.reserved {
		t.Fatal("lower mapping did not reserve")
	}
	if merged.ar.Length() != 2*hostarch.PageSize {
		t.Fatalf("adjacent reserved vmas did not merge: length %#x", merged.ar.Length())
	}
	if merged.off+uint64(hostarch.PageSize) != uv.off && merged.off != uv.off-hostarch.PageSize {
		t.Fatalf("file offsets not contiguous: merged off %#x upper off %#x", merged.off, uv.off)
	}

	faultPages(ctx, t, mm, lower, 2)
	if got, want := pmaFileOffAt(t, mm, lower), merged.off; got != want {
		t.Errorf("lower page offset got %#x want %#x", got, want)
	}
	if got, want := pmaFileOffAt(t, mm, upper), merged.off+hostarch.PageSize; got != want {
		t.Errorf("upper page offset got %#x want %#x", got, want)
	}
}
