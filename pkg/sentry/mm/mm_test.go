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
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Typed versions of hostarch.PageSize, which is not a constant on all
// architectures.
var (
	pageSize     = uint64(hostarch.PageSize)
	pageSizeAddr = hostarch.Addr(hostarch.PageSize)
	pageSizeInt  = int(hostarch.PageSize)
)

func testMemoryManagerWithMmapDirection(ctx context.Context, t testing.TB, mmapDirection arch.MmapDirection) *MemoryManager {
	p := platform.FromContext(ctx)
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("failed to create MemoryManager: %s", err)
	}
	minAddr, ok := p.MinUserAddress().RoundUp()
	if !ok {
		t.Fatalf("MinUserAddress %#x overflows when rounded up", p.MinUserAddress())
	}
	maxAddr := p.MaxUserAddress().RoundDown()
	mm.layout = arch.MmapLayout{
		MinAddr:          minAddr,
		MaxAddr:          maxAddr,
		BottomUpBase:     minAddr,
		TopDownBase:      maxAddr,
		DefaultDirection: mmapDirection,
	}
	return mm
}

func testMemoryManager(ctx context.Context, t testing.TB) *MemoryManager {
	return testMemoryManagerWithMmapDirection(ctx, t, arch.MmapBottomUp)
}

// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) realUsageAS() uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return uint64(mm.vmas.Span())
}

func TestUsageASUpdates(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:  2 * pageSize,
		Private: true,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	realUsage := mm.realUsageAS()
	if got := mm.VirtualMemorySize(); got != realUsage {
		t.Fatalf("usageAS believes %v bytes are mapped; %v bytes are actually mapped", got, realUsage)
	}

	mm.MUnmap(ctx, addr, pageSize)
	realUsage = mm.realUsageAS()
	if got := mm.VirtualMemorySize(); got != realUsage {
		t.Fatalf("usageAS believes %v bytes are mapped; %v bytes are actually mapped", got, realUsage)
	}
}

// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) realDataAS() uint64 {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
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
		Length:   3 * pageSize,
		Private:  true,
		Perms:    hostarch.Write,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if mm.VirtualDataSize() == 0 {
		t.Fatalf("dataAS is 0, wanted not 0")
	}
	realDataAS := mm.realDataAS()
	if got := mm.VirtualDataSize(); got != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", got, realDataAS)
	}

	mm.MUnmap(ctx, addr, pageSize)
	realDataAS = mm.realDataAS()
	if got := mm.VirtualDataSize(); got != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", got, realDataAS)
	}

	mm.MProtect(addr+pageSizeAddr, pageSize, hostarch.Read, false)
	realDataAS = mm.realDataAS()
	if got := mm.VirtualDataSize(); got != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", got, realDataAS)
	}

	mm.MRemap(ctx, addr+2*pageSizeAddr, pageSize, 2*pageSize, MRemapOpts{
		Move: MRemapMayMove,
	})
	realDataAS = mm.realDataAS()
	if got := mm.VirtualDataSize(); got != realDataAS {
		t.Fatalf("dataAS believes %v bytes are mapped; %v bytes are actually mapped", got, realDataAS)
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
	if newBrk, _ := mm.Brk(ctx, oldBrk+pageSizeAddr); newBrk != oldBrk {
		t.Errorf("brk() increased data segment above RLIMIT_DATA (old brk = %#x, new brk = %#x", oldBrk, newBrk)
	}
}

// TestIOAfterUnmap ensures that IO fails after unmap.
func TestIOAfterUnmap(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
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

	err = mm.MUnmap(ctx, addr, pageSize)
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

func TestCopyOutFromLargeRead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	data := make([]byte, 1<<20+pageSizeInt)
	for i := range data {
		data[i] = byte(i/pageSizeInt%251 + 1)
	}
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   uint64(len(data)),
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	src := &safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + hostarch.Addr(len(data))})
	n, err := mm.CopyOutFrom(ctx, ars, src, usermem.IOOpts{})
	if n != int64(len(data)) || err != nil || src.Blocks.NumBytes() != 0 {
		t.Fatalf("copyOutFromPinned got n=%d err=%v remaining=%d", n, err, src.Blocks.NumBytes())
	}
	got := make([]byte, len(data))
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("CopyOutFrom wrote different data")
	}
}

func TestCopyOutFromBatchesVectors(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	const count = 1024
	const bytesPerVector = 1024
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length: count * pageSize, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	ranges := make([]hostarch.AddrRange, count)
	for i := range ranges {
		start := addr + hostarch.Addr(i)*pageSizeAddr
		ranges[i] = hostarch.AddrRange{Start: start, End: start + bytesPerVector}
	}
	want := make([]byte, count*bytesPerVector)
	for i := range want {
		want[i] = byte(i/bytesPerVector%251 + 1)
	}
	remaining := want
	calls := 0
	src := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		calls++
		n, err := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(remaining)))
		remaining = remaining[n:]
		return n, err
	})
	n, err := mm.CopyOutFrom(ctx, hostarch.AddrRangeSeqFromSlice(ranges), src, usermem.IOOpts{})
	if n != int64(len(want)) || err != nil {
		t.Fatalf("copy got n=%d err=%v", n, err)
	}
	if calls != 1 {
		t.Fatalf("source called %d times, want 1", calls)
	}
	for i, ar := range ranges {
		got := make([]byte, bytesPerVector)
		if _, err := mm.CopyIn(ctx, ar.Start, got, usermem.IOOpts{}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want[i*bytesPerVector:(i+1)*bytesPerVector]) {
			t.Fatalf("vector %d contains incorrect data", i)
		}
	}
}

func TestPinnedCopyOutFromOverlappingVectorsDuringFork(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	const size = 2 << 20
	const chunk = 1 << 20
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length: size, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := bytes.Repeat([]byte{'A'}, size)
	if _, err := mm.CopyOut(ctx, addr, initial, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	ranges := []hostarch.AddrRange{
		{Start: addr + size, End: addr + size},
		{Start: addr + chunk/2, End: addr + 3*chunk/2},
		{Start: addr, End: addr + chunk},
		{Start: addr + size, End: addr + size},
		{Start: addr + chunk/2, End: addr + 3*chunk/2},
	}
	data := append(bytes.Repeat([]byte{'B'}, chunk), bytes.Repeat([]byte{'C'}, chunk)...)
	data = append(data, bytes.Repeat([]byte{'D'}, chunk)...)
	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))}
	var child *MemoryManager
	src := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		var err error
		child, err = mm.Fork(ctx)
		if err != nil {
			return 0, err
		}
		return reader.ReadToBlocks(dsts)
	})
	n, err := mm.CopyOutFrom(ctx, hostarch.AddrRangeSeqFromSlice(ranges), src, usermem.IOOpts{})
	if child != nil {
		defer child.DecUsers(ctx)
	}
	if n != int64(len(data)) || err != nil {
		t.Fatalf("CopyOutFrom got n=%d err=%v, want n=%d err=nil", n, err, len(data))
	}
	got := make([]byte, size)
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(initial)
	copy(want[:chunk/2], bytes.Repeat([]byte{'C'}, chunk/2))
	copy(want[chunk/2:3*chunk/2], bytes.Repeat([]byte{'D'}, chunk))
	if !bytes.Equal(got, want) {
		t.Error("overlapping vectors did not preserve I/O order")
	}
	if _, err := child.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Error("writes through pinned vectors changed the child's snapshot")
	}
}

func BenchmarkCopyOutFrom(b *testing.B) {
	for _, bc := range []struct {
		name    string
		size    int
		vectors int
		stride  int
		reverse bool
	}{
		{name: "contiguous-4KiB", size: 4 << 10, vectors: 1},
		{name: "contiguous-1MiB", size: 1 << 20, vectors: 1},
		{name: "contiguous-80MiB", size: 80 << 20, vectors: 1},
		{name: "fragmented-1MiB", size: 1 << 20, vectors: 1024},
		{name: "packed-1MiB", size: 1 << 20, vectors: 1024, stride: 1 << 10},
		{name: "sparse-1MiB", size: 1 << 20, vectors: 1024, stride: 16 << 10},
		{name: "reversed-1MiB", size: 1 << 20, vectors: 1024, reverse: true},
	} {
		for _, pinned := range []bool{false, true} {
			name := "locked"
			if pinned {
				name = "pinned"
			}
			b.Run(bc.name+"/"+name, func(b *testing.B) {
				ctx := contexttest.Context(b)
				defer pgalloc.MemoryFileFromContext(ctx).Destroy()
				mm := testMemoryManager(ctx, b)
				defer mm.DecUsers(ctx)
				stride := bc.size / bc.vectors
				if bc.vectors != 1 {
					stride = pageSizeInt
				}
				if bc.stride != 0 {
					stride = bc.stride
				}
				addr, err := mm.MMap(ctx, memmap.MMapOpts{
					Length: uint64(stride * bc.vectors), Private: true,
					Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
				})
				if err != nil {
					b.Fatal(err)
				}
				ranges := make([]hostarch.AddrRange, bc.vectors)
				for i := range ranges {
					index := i
					if bc.reverse {
						index = len(ranges) - 1 - i
					}
					start := addr + hostarch.Addr(index*stride)
					ranges[i] = hostarch.AddrRange{Start: start, End: start + hostarch.Addr(bc.size/bc.vectors)}
				}
				ars := hostarch.AddrRangeSeqFromSlice(ranges)
				data := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes.Repeat([]byte{'x'}, bc.size)))
				src := safemem.BlockSeqReader{Blocks: data}
				if _, err := mm.withVecInternalMappings(ctx, ars, hostarch.Write, false, src.ReadToBlocks); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(bc.size))
				b.ReportAllocs()
				for b.Loop() {
					src.Blocks = data
					var n int64
					if pinned {
						n, err = mm.copyOutFromPinned(ctx, ars, &src, usermem.IOOpts{})
					} else {
						n, err = mm.withVecInternalMappings(ctx, ars, hostarch.Write, false, src.ReadToBlocks)
					}
					if n != int64(bc.size) || err != nil {
						b.Fatalf("copy got n=%d err=%v", n, err)
					}
				}
			})
		}
	}
}

func TestPinnedCopyOutFromPartialFault(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + 2*pageSizeAddr})
	src := &safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes.Repeat([]byte{'x'}, 2*pageSizeInt)))}
	n, err := mm.copyOutFromPinned(ctx, ars, src, usermem.IOOpts{})
	if n != int64(pageSize) || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("partial fault: n=%d err=%v", n, err)
	}
}

func TestPinnedCopyOutFromSharedMappingShortRead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(2<<20+2*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mappable := NewSpecialMappable("test_mappable", mf, fr)
	defer mappable.DecRef(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          2<<20 + 2*pageSize,
		MappingIdentity: mappable,
		Mappable:        mappable,
		Perms:           hostarch.ReadWrite,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := bytes.Repeat([]byte{'A'}, 2<<20+2*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, initial, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}

	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + 2<<20 + 2*pageSizeAddr})
	data := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes.Repeat([]byte{'B'}, 1<<20+pageSizeInt)))
	src := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		return safemem.CopySeq(dsts, data)
	})
	n, err := mm.copyOutFromPinned(ctx, ars, src, usermem.IOOpts{})
	if n != int64(1<<20+pageSizeInt) || err != nil {
		t.Fatalf("CopyOutFrom got n=%d err=%v, want n=%d err=nil", n, err, 1<<20+pageSizeInt)
	}
	got := make([]byte, len(initial))
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{'B'}, 1<<20+pageSizeInt), initial[1<<20+pageSizeInt:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("shared mapping contains %q..., want %q...", got[:4], want[:4])
	}
}

func TestPinnedCopyOutFromForkAfterMRemapMove(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	before := bytes.Repeat([]byte{'A'}, pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, before, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	after := bytes.Repeat([]byte{'B'}, pageSizeInt)
	g := startGatedPinnedRead(t, ctx, mm, addr, after)
	defer g.finish()

	newAddr := mm.layout.MaxAddr - pageSizeAddr
	if got, err := mm.MRemap(ctx, addr, pageSize, pageSize, MRemapOpts{Move: MRemapMustMove, NewAddr: newAddr}); err != nil || got != newAddr {
		t.Fatalf("MRemap got addr=%#x err=%v, want addr=%#x err=nil", got, err, newAddr)
	}

	child, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer child.DecUsers(ctx)
	if got := g.finish(); got.n != int64(pageSize) || got.err != nil {
		t.Fatalf("copyOutFromPinned got n=%d err=%v, want n=%d err=nil", got.n, got.err, pageSize)
	}

	parentData := make([]byte, pageSizeInt)
	if _, err := mm.CopyIn(ctx, newAddr, parentData, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	childData := make([]byte, pageSizeInt)
	if _, err := child.CopyIn(ctx, newAddr, childData, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(parentData, after) || !bytes.Equal(childData, before) {
		t.Errorf("moved or forked mapping observed the pinned write: parent %q..., child %q..., want parent %q..., child %q...", parentData[:4], childData[:4], after[:4], before[:4])
	}
	parentOff, parentCOW := pmaAt(t, mm, newAddr)
	childOff, _ := pmaAt(t, child, newAddr)
	if parentCOW || parentOff == childOff {
		t.Errorf("moved pinned mapping was shared with child: parent off=%#x COW=%v, child off=%#x", parentOff, parentCOW, childOff)
	}
}

func TestPinnedCopyOutFromForkCopiesOnlyPinnedPageWithinPMA(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const npages = 64
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   npages * pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if _, err := mm.CopyOut(ctx, addr, bytes.Repeat([]byte{'A'}, npages*pageSizeInt), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	const pinnedPage = npages / 2
	pinnedAddr := addr + pinnedPage*pageSizeAddr
	g := startGatedPinnedRead(t, ctx, mm, pinnedAddr, bytes.Repeat([]byte{'B'}, pageSizeInt))
	defer g.finish()

	child, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer child.DecUsers(ctx)
	if got := g.finish(); got.n != int64(pageSize) || got.err != nil {
		t.Fatalf("copyOutFromPinned got n=%d err=%v, want n=%d err=nil", got.n, got.err, pageSizeInt)
	}

	var copied []int
	for i := 0; i < npages; i++ {
		pageAddr := addr + hostarch.Addr(i)*pageSizeAddr
		parentOff, parentCOW := pmaAt(t, mm, pageAddr)
		childOff, _ := pmaAt(t, child, pageAddr)
		if parentOff != childOff {
			copied = append(copied, i)
			if parentCOW {
				t.Errorf("page %d: copied but parent pma is copy-on-write", i)
			}
		} else if !parentCOW {
			t.Errorf("page %d: parent pma is not copy-on-write", i)
		}
	}
	if len(copied) != 1 || copied[0] != pinnedPage {
		t.Errorf("Fork eagerly copied pages %v, want only page %d", copied, pinnedPage)
	}

	childData := make([]byte, npages*pageSizeInt)
	if _, err := child.CopyIn(ctx, addr, childData, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(childData, bytes.Repeat([]byte{'A'}, npages*pageSizeInt)) {
		t.Errorf("child observed the pinned write")
	}
}

func TestPinnedCopyOutFromForkDuringLargeRead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	const size = 8 << 20
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length: size, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Repeat([]byte{'A'}, size)
	if _, err := mm.CopyOut(ctx, addr, before, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	after := bytes.Repeat([]byte{'B'}, size)
	g := startGatedPinnedRead(t, ctx, mm, addr, after)
	defer g.finish()
	child, err := mm.Fork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer child.DecUsers(ctx)
	requireReadResult(t, g.finish(), size, nil)
	got := make([]byte, size)
	if _, err := child.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) {
		t.Fatal("child observed the parent's in-flight read")
	}
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, after) {
		t.Fatal("parent lost its in-flight read")
	}
}

func TestPinnedCopyOutFromForkAfterUnpinIsCopyOnWrite(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	read := bytes.Repeat([]byte{'B'}, pageSizeInt)
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + pageSizeAddr})
	src := &safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(read))}
	if n, err := mm.copyOutFromPinned(ctx, ars, src, usermem.IOOpts{}); n != int64(pageSize) || err != nil {
		t.Fatalf("copyOutFromPinned got n=%d err=%v, want n=%d err=nil", n, err, pageSizeInt)
	}

	child, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer child.DecUsers(ctx)

	parentOff, parentCOW := pmaAt(t, mm, addr)
	childOff, _ := pmaAt(t, child, addr)
	if !parentCOW || parentOff != childOff {
		t.Errorf("page not copy-on-write after fork: parent off=%#x COW=%v, child off=%#x", parentOff, parentCOW, childOff)
	}

	if _, err := mm.CopyOut(ctx, addr, bytes.Repeat([]byte{'C'}, pageSizeInt), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	childBuf := make([]byte, pageSizeInt)
	if _, err := child.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(childBuf, read) {
		t.Errorf("child read %q..., want %q...", childBuf[:4], read[:4])
	}
}

func TestCopyOutFromIterVectoredRead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	const size = 2 << 20
	const firstSize = 1 << 19
	secondSize := firstSize + pageSizeInt
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length: size, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := bytes.Repeat([]byte{'?'}, size)
	if _, err := mm.CopyOut(ctx, addr, initial, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	data := append(bytes.Repeat([]byte{'a'}, firstSize), bytes.Repeat([]byte{'b'}, secondSize)...)
	src := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))}
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: addr, End: addr},
		{Start: addr, End: addr + firstSize},
		{Start: addr + 1<<20, End: addr + 1<<20 + hostarch.Addr(secondSize)},
		{Start: addr + size, End: addr + size},
	})
	if n, err := mm.CopyOutFromIter(ctx, ars, &src, usermem.IOOpts{}); n != int64(len(data)) || err != nil {
		t.Fatalf("CopyOutFromIter got n=%d err=%v, want n=%d err=nil", n, err, len(data))
	}
	got := make([]byte, size)
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(initial)
	copy(want[:firstSize], data[:firstSize])
	copy(want[1<<20:], data[firstSize:])
	if !bytes.Equal(got, want) {
		t.Fatal("CopyOutFromIter wrote incorrect vector data or changed a gap")
	}
}

func TestCopyOutFromIterPartialFault(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + 2*pageSizeAddr})
	src := &safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes.Repeat([]byte{'x'}, 2*pageSizeInt)))}
	n, err := mm.CopyOutFromIter(ctx, ars, src, usermem.IOOpts{})
	if n != int64(pageSize) || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("partial fault: n=%d err=%v", n, err)
	}
}

func TestCopyOutFromIterSharedMappingShortRead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(2*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mappable := NewSpecialMappable("test_mappable", mf, fr)
	defer mappable.DecRef(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          2 * pageSize,
		MappingIdentity: mappable,
		Mappable:        mappable,
		Perms:           hostarch.ReadWrite,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := bytes.Repeat([]byte{'A'}, 2*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, initial, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}

	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + 2*pageSizeAddr})
	src := &safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes.Repeat([]byte{'B'}, pageSizeInt)))}
	n, err := mm.CopyOutFromIter(ctx, ars, src, usermem.IOOpts{})
	if n != int64(pageSize) || err != io.EOF {
		t.Fatalf("CopyOutFrom got n=%d err=%v, want n=%d err=EOF", n, err, pageSize)
	}
	got := make([]byte, len(initial))
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{'B'}, pageSizeInt), initial[pageSizeInt:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("shared mapping contains %q..., want %q...", got[:4], want[:4])
	}
}

func TestCopyOutFromIterSharedAndPrivateMappings(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(2*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mappable := NewSpecialMappable("test_mappable", mf, fr)
	defer mappable.DecRef(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          2 * pageSize,
		MappingIdentity: mappable,
		Mappable:        mappable,
		Perms:           hostarch.ReadWrite,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mm.MMap(ctx, memmap.MMapOpts{
		Addr: addr + pageSizeAddr, Length: pageSize, Fixed: true, Unmap: true, Private: true,
		Perms: hostarch.ReadWrite, MaxPerms: hostarch.AnyAccess,
	}); err != nil {
		t.Fatal(err)
	}
	initial := bytes.Repeat([]byte{'A'}, 2*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, initial, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	child, err := mm.Fork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer child.DecUsers(ctx)

	data := bytes.Repeat([]byte{'B'}, len(initial))
	src := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + 2*pageSizeAddr})
	if n, err := mm.CopyOutFromIter(ctx, ars, &src, usermem.IOOpts{}); n != int64(len(data)) || err != nil {
		t.Fatalf("CopyOutFromIter got n=%d err=%v, want n=%d err=nil", n, err, len(data))
	}
	got := make([]byte, len(data))
	if _, err := mm.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("parent contains incorrect restored data")
	}
	if _, err := child.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{'B'}, pageSizeInt), bytes.Repeat([]byte{'A'}, pageSizeInt)...)
	if !bytes.Equal(got, want) {
		t.Error("child did not preserve shared visibility and private copy-on-write isolation")
	}
}

// TestIOAfterMProtect tests IO interaction with mprotect permissions.
func TestIOAfterMProtect(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
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

	err = mm.MProtect(addr, pageSize, hostarch.Read, false)
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
		Length:   npages * pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, npages*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	pinAR := hostarch.AddrRange{
		Start: addr + pageSizeAddr,
		End:   addr + 2*pageSizeAddr,
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
		postFork := bytes.Repeat([]byte{'B' + byte(i)}, npages*pageSizeInt)
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
		if _, err := mm2.CopyOut(ctx, addr, bytes.Repeat([]byte{'z'}, npages*pageSizeInt), usermem.IOOpts{}); err != nil {
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
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, pageSizeInt)
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
		End:   addr + pageSizeAddr,
	}
	prs, err := mm.Pin(ctx, ar, hostarch.Read, false /* ignorePermissions */)
	if err != nil {
		t.Fatalf("Pin got err %v want nil", err)
	}
	defer Unpin(prs)

	// The parent's writes must be visible through the pinned range, and must
	// not be visible to the child.
	postFork := bytes.Repeat([]byte{'B'}, pageSizeInt)
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
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if _, err := mm.CopyOut(ctx, addr, bytes.Repeat([]byte{'A'}, pageSizeInt), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	ar := hostarch.AddrRange{
		Start: addr,
		End:   addr + pageSizeAddr,
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
	fr, err := mf.Allocate(3*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatalf("failed to allocate memory file range: %v", err)
	}
	mappable := NewSpecialMappable("test_mappable", mf, fr)
	defer mappable.DecRef(ctx)

	// Map a page at a high offset (2^64 - 2*PageSize).
	// This mapping itself is valid because offset + length (2^64 - PageSize) does not overflow.
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          pageSize,
		MappingIdentity: mappable,
		Mappable:        mappable,
		Offset:          ^uint64(0) - 2*pageSize + 1,
		Private:         true,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}

	// 1. A shrink should succeed, even if offset+newSize overflows.
	// We remap with oldSize = 3*PageSize, newSize = 2*PageSize.
	if _, err := mm.MRemap(ctx, addr, 3*pageSize, 2*pageSize, MRemapOpts{}); err != nil {
		t.Errorf("MRemap shrink got err %v want nil", err)
	}

	// 2. A grow should fail if offset+newSize overflows.
	// We remap with oldSize = PageSize, newSize = 3*PageSize.
	if _, err := mm.MRemap(ctx, addr, pageSize, 3*pageSize, MRemapOpts{}); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("MRemap grow got err %v want EINVAL", err)
	}
}

// pmaAt returns the offset into the backing file for the page at addr that is in mm,
// and whether the pma mapping is COW.
func pmaAt(t *testing.T, mm *MemoryManager, addr hostarch.Addr) (uint64, bool) {
	t.Helper()
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	pseg := mm.pmas.FindSegment(addr)
	if !pseg.Ok() {
		t.Fatalf("no pma for addr %#x", addr)
	}
	fr := pseg.fileRangeOf(hostarch.AddrRange{
		Start: addr,
		End:   addr + pageSizeAddr,
	})
	return fr.Start, pseg.ValuePtr().needCOW
}

// TestForkSkipsDontForkMappings tests that Fork does not give the child
// MADV_DONTFORK mappings or the pages in them, and does not mark those pages
// as COW in the parent.
func TestForkSkipsDontForkMappings(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Populate both pages before applying MADV_DONTFORK to only the second, so
	// that Fork must split a pma so it can skip the MADV_DONTFORK mapping.
	const npages = 2
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   npages * pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, npages*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	dontForkAddr := addr + pageSizeAddr
	if err := mm.SetDontFork(dontForkAddr, pageSize, true); err != nil {
		t.Fatalf("SetDontFork got err %v want nil", err)
	}

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)

	// The child must see the pre-fork contents of the first page, and must not
	// have the second page mapped.
	buf := make([]byte, hostarch.PageSize)
	if _, err := mm2.CopyIn(ctx, addr, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(buf, preFork[:hostarch.PageSize]) {
		t.Errorf("child read %q..., want %q...", buf[:4], preFork[:4])
	}
	if _, err := mm2.CopyIn(ctx, dontForkAddr, buf, usermem.IOOpts{}); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyIn of MADV_DONTFORK page got err %v want EFAULT", err)
	}

	if _, needCOW := pmaAt(t, mm, dontForkAddr); needCOW {
		t.Errorf("parent's MADV_DONTFORK pma is copy-on-write after fork")
	}
}

// testMemoryManagerWithExhaustibleMemory returns a MemoryManager whose memory
// file is backed by a new memfd, and a function that exhausts the memory file
// by sealing the memfd against growth and allocating all of its free pages,
// causing later allocations from it to fail. Since the memory file releases
// freed pages asynchronously, pages freed before calling exhaust may become
// allocatable after it returns, so callers must not free memory from the
// memory file before calling exhaust.
func testMemoryManagerWithExhaustibleMemory(ctx context.Context, t *testing.T) (*MemoryManager, func()) {
	const name = "mm-test-memory"
	memfd, err := memutil.CreateMemFD(name, unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatalf("CreateMemFD got err %v want nil", err)
	}
	memfile := os.NewFile(uintptr(memfd), name)
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{
		DisableMemoryAccounting: true,
	})
	if err != nil {
		memfile.Close()
		t.Fatalf("NewMemoryFile got err %v want nil", err)
	}
	mm := testMemoryManager(ctx, t)
	mm.mf = mf // mm has no mappings yet.

	exhaust := func() {
		t.Helper()
		if _, err := unix.FcntlInt(uintptr(memfd), unix.F_ADD_SEALS, unix.F_SEAL_GROW); err != nil {
			t.Fatalf("fcntl(F_ADD_SEALS, F_SEAL_GROW) got err %v want nil", err)
		}
		var frs []memmap.FileRange
		t.Cleanup(func() {
			for _, fr := range frs {
				mf.DecRef(fr)
			}
		})
		// Since mf can no longer grow, this terminates once all of its free
		// pages are allocated. The allocated pages are never committed.
		for length := uint64(1 << 30); length >= pageSize; length /= 2 {
			for {
				fr, err := mf.Allocate(length, pgalloc.AllocOpts{})
				if err != nil {
					break
				}
				frs = append(frs, fr)
			}
		}
	}
	return mm, exhaust
}

// TestForkCopyFailure tests that if Fork fails to copy pages for the child, it
// releases the references that it took for the child, leaving the parent's
// memory unchanged and usable.
func TestForkCopyFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		// eagerForkCopy is memmap.MMapOpts.EagerForkCopy for the second page.
		eagerForkCopy bool
		// If pin is true, the second page is pinned.
		pin bool
	}{
		{
			name:          "EagerForkCopy",
			eagerForkCopy: true,
		},
		{
			name: "Pinned",
			pin:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			// Used to exhaust memory later.
			mm, exhaustMemory := testMemoryManagerWithExhaustibleMemory(ctx, t)
			defer mm.DecUsers(ctx)

			// Map a page that Fork marks COW, followed by a page that
			// Fork must copy, so that Fork fails after taking a reference on
			// the first page for the child. Map the pages separately, rather
			// than replacing part of a larger mapping, since MMap populates
			// small anonymous mappings, and replacing part of one would free
			// memory before exhaustMemory.
			const npages = 2
			opts := memmap.MMapOpts{
				Length:   pageSize,
				Private:  true,
				Perms:    hostarch.ReadWrite,
				MaxPerms: hostarch.AnyAccess,
			}
			addr, err := mm.MMap(ctx, opts)
			if err != nil {
				t.Fatalf("MMap got err %v want nil", err)
			}
			copyAR := hostarch.AddrRange{
				Start: addr + pageSizeAddr,
				End:   addr + npages*pageSizeAddr,
			}
			opts.Addr = copyAR.Start
			opts.Fixed = true
			opts.EagerForkCopy = test.eagerForkCopy
			if _, err := mm.MMap(ctx, opts); err != nil {
				t.Fatalf("MMap got err %v want nil", err)
			}
			if test.pin {
				prs, err := mm.Pin(ctx, copyAR, hostarch.ReadWrite, false /* ignorePermissions */)
				if err != nil {
					t.Fatalf("Pin got err %v want nil", err)
				}
				t.Cleanup(func() { Unpin(prs) })
			}
			preFork := bytes.Repeat([]byte{'A'}, npages*pageSizeInt)
			if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
				t.Fatalf("CopyOut got err %v want nil", err)
			}

			// Also map a MappingIdentity, on which Fork takes a reference for
			// the child.
			mf := pgalloc.MemoryFileFromContext(ctx)
			fr, err := mf.Allocate(pageSize, pgalloc.AllocOpts{})
			if err != nil {
				t.Fatalf("Allocate got err %v want nil", err)
			}
			mappable := NewSpecialMappable("test_mappable", mf, fr)
			defer mappable.DecRef(ctx)
			if _, err := mm.MMap(ctx, memmap.MMapOpts{
				Length:          pageSize,
				MappingIdentity: mappable,
				Mappable:        mappable,
				Private:         true,
				MaxPerms:        hostarch.AnyAccess,
			}); err != nil {
				t.Fatalf("MMap got err %v want nil", err)
			}
			wantRefs := mappable.ReadRefs()

			// Prevent Fork from allocating memory to copy pages for the child.
			exhaustMemory()
			if mm2, err := mm.Fork(ctx); err == nil {
				mm2.DecUsers(ctx)
				t.Fatalf("Fork got err nil want non-nil")
			}

			if got := mappable.ReadRefs(); got != wantRefs {
				t.Errorf("MappingIdentity has %d references after failed fork, want %d", got, wantRefs)
			}
			off, _ := pmaAt(t, mm, addr)
			if !mm.mf.HasUniqueRef(memmap.FileRange{Start: off, End: off + pageSize}) {
				t.Errorf("parent's copy-on-write page is still shared after failed fork")
			}

			// The parent's memory must be unchanged, and since the parent no
			// longer shares its pages with the child, writing to them must not
			// require allocating memory.
			buf := make([]byte, npages*hostarch.PageSize)
			if _, err := mm.CopyIn(ctx, addr, buf, usermem.IOOpts{}); err != nil {
				t.Fatalf("CopyIn got err %v want nil", err)
			}
			if !bytes.Equal(buf, preFork) {
				t.Errorf("parent read %q..., want %q...", buf[:4], preFork[:4])
			}
			if _, err := mm.CopyOut(ctx, addr, buf, usermem.IOOpts{}); err != nil {
				t.Errorf("CopyOut got err %v want nil", err)
			}
		})
	}
}

// TestEagerForkCopy tests that Fork gives the child a copy of pages in
// EagerForkCopy mappings immediately, so that later writes by the parent do
// not break COW, replacing the pages mapped by the parent.
func TestEagerForkCopy(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Mirror the usertrap table: read/execute for the application, but
	// written by the sentry with IgnorePermissions.
	const npages = 2
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:        npages * pageSize,
		Private:       true,
		Perms:         hostarch.ReadExecute,
		MaxPerms:      hostarch.AnyAccess,
		EagerForkCopy: true,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	ignorePerms := usermem.IOOpts{IgnorePermissions: true}
	preFork := bytes.Repeat([]byte{'A'}, npages*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, preFork, ignorePerms); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	offBefore, _ := pmaAt(t, mm, addr)

	// Fork twice to check that the parent's pma remains eligible for eager
	// copying after the first fork.
	for i := 0; i < 2; i++ {
		mm2, err := mm.Fork(ctx)
		if err != nil {
			t.Fatalf("Fork got err %v want nil", err)
		}
		defer mm2.DecUsers(ctx)

		if _, needCOW := pmaAt(t, mm, addr); needCOW {
			t.Errorf("parent pma is copy-on-write after fork")
		}
		childOff, childNeedCOW := pmaAt(t, mm2, addr)
		if childNeedCOW {
			t.Errorf("child pma is copy-on-write after fork")
		}
		if childOff == offBefore {
			t.Errorf("child pma shares memory with the parent at offset %#x", childOff)
		}

		// The parent's writes must not break COW.
		postFork := bytes.Repeat([]byte{'B' + byte(i)}, npages*pageSizeInt)
		if _, err := mm.CopyOut(ctx, addr, postFork, ignorePerms); err != nil {
			t.Fatalf("CopyOut got err %v want nil", err)
		}
		if off, _ := pmaAt(t, mm, addr); off != offBefore {
			t.Errorf("parent pma moved from offset %#x to %#x after write", offBefore, off)
		}

		// The child's view must be unchanged.
		childBuf := make([]byte, npages*hostarch.PageSize)
		if _, err := mm2.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
			t.Fatalf("CopyIn got err %v want nil", err)
		}
		if !bytes.Equal(childBuf, preFork) {
			t.Errorf("child read %q..., want %q...", childBuf[:4], preFork[:4])
		}
		preFork = postFork
	}
}

// TestEagerForkCopyAdjacentMappings tests that Fork only copies pages in
// EagerForkCopy mappings for the child, and still makes pages in adjacent
// mappings marked COW.
func TestEagerForkCopyAdjacentMappings(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Map an EagerForkCopy mapping between two mappings with otherwise
	// identical options, so that only EagerForkCopy distinguishes them.
	const npages = 4
	opts := memmap.MMapOpts{
		Length:   npages * pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	}
	addr, err := mm.MMap(ctx, opts)
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	eagerAR := hostarch.AddrRange{
		Start: addr + pageSizeAddr,
		End:   addr + (npages-1)*pageSizeAddr,
	}
	opts.Length = uint64(eagerAR.Length())
	opts.Addr = eagerAR.Start
	opts.Fixed = true
	opts.Unmap = true
	opts.EagerForkCopy = true
	if _, err := mm.MMap(ctx, opts); err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	preFork := bytes.Repeat([]byte{'A'}, npages*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, preFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)

	// Only the parent's pages outside of the EagerForkCopy mapping should
	// have been made copy-on-write.
	for i := 0; i < npages; i++ {
		pageAddr := addr + hostarch.Addr(i)*pageSizeAddr
		wantCOW := !eagerAR.Contains(pageAddr)
		if _, needCOW := pmaAt(t, mm, pageAddr); needCOW != wantCOW {
			t.Errorf("parent pma for page %d: got needCOW %t want %t", i, needCOW, wantCOW)
		}
	}

	// The child must see the pre-fork contents of all pages, and not the
	// parent's post-fork writes.
	postFork := bytes.Repeat([]byte{'B'}, npages*pageSizeInt)
	if _, err := mm.CopyOut(ctx, addr, postFork, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	childBuf := make([]byte, npages*hostarch.PageSize)
	if _, err := mm2.CopyIn(ctx, addr, childBuf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if !bytes.Equal(childBuf, preFork) {
		t.Errorf("child read %q..., want %q...", childBuf[:4], preFork[:4])
	}
}

// wantError reports a test error if err is not want. op describes the
// operation that returned err.
func wantError(t *testing.T, want *errors.Error, op string, err error) {
	t.Helper()
	if !linuxerr.Equals(want, err) {
		t.Errorf("%s got err %v want %v", op, err, want)
	}
}

// TestSealedMapping tests that application operations that would
// modify a sealed vma fail with EPERM, without modifying other vmas in the
// same range.
func TestSealedMapping(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	// Map three unsealed pages, then replace the middle page with a sealed
	// mapping.
	base, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   3 * pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	sealedAddr := base + pageSizeAddr
	if _, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Addr:     sealedAddr,
		Fixed:    true,
		Unmap:    true,
		Private:  true,
		Perms:    hostarch.ReadExecute,
		MaxPerms: hostarch.AnyAccess,
		Sealed:   true,
	}); err != nil {
		t.Fatalf("MMap(Sealed) got err %v want nil", err)
	}
	all := 3 * pageSize

	wantError(t, linuxerr.EPERM, "MUnmap(sealed)", mm.MUnmap(ctx, sealedAddr, pageSize))
	wantError(t, linuxerr.EPERM, "MUnmap(all)", mm.MUnmap(ctx, base, all))
	wantError(t, linuxerr.EPERM, "MProtect(sealed)", mm.MProtect(sealedAddr, pageSize, hostarch.ReadWrite, false))
	wantError(t, linuxerr.EPERM, "MProtect(all)", mm.MProtect(base, all, hostarch.Read, false))
	wantError(t, linuxerr.EPERM, "Decommit(sealed)", mm.Decommit(sealedAddr, pageSize))
	wantError(t, linuxerr.EPERM, "SetDontFork(all)", mm.SetDontFork(base, all, true))
	_, err = mm.MRemap(ctx, sealedAddr, pageSize, 2*pageSize, MRemapOpts{Move: MRemapMayMove})
	wantError(t, linuxerr.EPERM, "MRemap(grow sealed)", err)
	_, err = mm.MRemap(ctx, sealedAddr, 0, pageSize, MRemapOpts{Move: MRemapMayMove})
	wantError(t, linuxerr.EPERM, "MRemap(copy sealed)", err)
	_, err = mm.MRemap(ctx, base, pageSize, pageSize, MRemapOpts{Move: MRemapMustMove, NewAddr: sealedAddr})
	wantError(t, linuxerr.EPERM, "MRemap(move onto sealed)", err)
	_, err = mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Addr:     sealedAddr,
		Fixed:    true,
		Unmap:    true,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	wantError(t, linuxerr.EPERM, "MMap(MAP_FIXED over sealed)", err)

	// None of the above should have modified the unsealed neighbors.
	b := []byte{'x'}
	for _, addr := range []hostarch.Addr{base, base + 2*pageSizeAddr} {
		if _, err := mm.CopyOut(ctx, addr, b, usermem.IOOpts{}); err != nil {
			t.Errorf("CopyOut(%#x) got err %v want nil", addr, err)
		}
	}
	mm.mappingMu.RLock()
	dontfork := mm.vmas.FindSegment(base).ValuePtr().dontfork
	mm.mappingMu.RUnlock()
	if dontfork {
		t.Errorf("unsealed vma became MADV_DONTFORK after failed SetDontFork")
	}

	// madvise operations are refused on sealed vmas, even ones that
	// would be no-ops.
	wantError(t, linuxerr.EPERM, "SetDontFork(sealed, false)", mm.SetDontFork(sealedAddr, pageSize, false))
	wantError(t, linuxerr.EPERM, "SetVMAAnonName(sealed)", mm.SetVMAAnonName(sealedAddr, pageSize, "x", false))

	// Operations that don't touch the sealed vma still work.
	if err := mm.MUnmap(ctx, base, pageSize); err != nil {
		t.Errorf("MUnmap(unsealed neighbor) got err %v want nil", err)
	}

	// Seals are inherited across fork.
	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)
	wantError(t, linuxerr.EPERM, "child MUnmap(sealed)", mm2.MUnmap(ctx, sealedAddr, pageSize))
}

// gatedReaderAt blocks reads past offset from until `gate` is closed.
type gatedReaderAt struct {
	io.ReaderAt
	from int64
	gate chan struct{}
}

// ReadAt implements `io.ReaderAt.ReadAt`.
func (g *gatedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > g.from {
		<-g.gate
	}
	return g.ReaderAt.ReadAt(p, off)
}

func newTestMemoryFile(t *testing.T) *pgalloc.MemoryFile {
	memfd, err := memutil.CreateMemFD("mm-test-memory", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: got err %v, want nil", err)
	}
	memfile := os.NewFile(uintptr(memfd), "mm-test-memory")
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{
		DisableMemoryAccounting: true,
	})
	if err != nil {
		memfile.Close()
		t.Fatalf("NewMemoryFile: got err %v, want nil", err)
	}
	t.Cleanup(mf.Destroy)
	return mf
}

// TestIODuringAsyncPageLoad tests that I/O to part of a pma whose pages are
// being loaded asynchronously does not wait for the rest of the pma to load.
func TestIODuringAsyncPageLoad(t *testing.T) {
	const (
		size  = 2 * asyncLoadMapUnit
		gated = asyncLoadMapUnit
	)
	ctx := contexttest.Context(t)

	src := newTestMemoryFile(t)
	fr, err := src.Allocate(size, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate got err %v want nil", err)
	}
	if _, err := unix.Pwrite(src.FD(), bytes.Repeat([]byte{1}, size), int64(fr.Start)); err != nil {
		t.Fatalf("Pwrite got err %v want nil", err)
	}
	var metadata, pages bytes.Buffer
	saveDone := make(chan error, 1)
	apfs, err := pgalloc.StartAsyncPagesFileSave(stateio.NewIOWriter(&pages, 1<<20, 1, 1), func(err error) { saveDone <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave got err %v want nil", err)
	}
	if err := src.SaveTo(ctx, &metadata, &pgalloc.SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo got err %v want nil", err)
	}
	apfs.MemoryFilesDone()
	if err := <-saveDone; err != nil {
		t.Fatalf("async page save got err %v want nil", err)
	}

	mf := newTestMemoryFile(t)
	gate := make(chan struct{})
	loadDone := make(chan error, 1)
	apfl, err := pgalloc.StartAsyncPagesFileLoad(stateio.NewIOReader(&gatedReaderAt{bytes.NewReader(pages.Bytes()), gated, gate}, 1<<20, 1, 2), func(err error) { loadDone <- err }, nil, pgalloc.AsyncPagesFileLoadOpts{})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad got err %v want nil", err)
	}
	if err := mf.LoadFrom(ctx, &metadata, &pgalloc.LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom got err %v want nil", err)
	}
	apfl.MemoryFilesDone()

	// Map the restored pages with a single pma.
	mm := testMemoryManager(ctx, t)
	mm.mf = mf // mm has no mappings yet.
	defer mm.DecUsers(ctx)
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   size,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	ar := hostarch.AddrRange{addr, addr + size}
	mm.activeMu.Lock()
	mm.pmas.Insert(mm.pmas.FindGap(ar.Start), ar, pma{
		file:           mf,
		off:            fr.Start,
		translatePerms: hostarch.AnyAccess,
		effectivePerms: hostarch.ReadWrite,
		maxPerms:       hostarch.AnyAccess,
		private:        true,
	})
	mm.addRSSLocked(ar)
	mm.activeMu.Unlock()

	// I/O to pages past offset gated waits until gate is closed, but should
	// not block concurrent I/O to other pages.
	gatedErr := make(chan error, 1)
	go func() {
		_, err := mm.CopyIn(ctx, addr+gated+pageSizeAddr, make([]byte, 8), usermem.IOOpts{})
		gatedErr <- err
	}()
	timer := time.AfterFunc(10*time.Second, func() {
		t.Errorf("CopyIn waited for pages past offset %#x", gated)
		close(gate)
	})
	b := make([]byte, 8)
	for end := time.Now().Add(100 * time.Millisecond); time.Now().Before(end); {
		if _, err = mm.CopyIn(ctx, addr+pageSizeAddr, b, usermem.IOOpts{}); err != nil {
			break
		}
	}
	if timer.Stop() {
		close(gate)
	}
	if err := <-gatedErr; err != nil {
		t.Errorf("CopyIn past offset %#x got err %v want nil", gated, err)
	}
	if err := <-loadDone; err != nil {
		t.Errorf("async page load got err %v want nil", err)
	}
	if err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	if want := bytes.Repeat([]byte{1}, len(b)); !bytes.Equal(b, want) {
		t.Errorf("CopyIn got %v want %v", b, want)
	}
}

type gatedReadResult struct {
	n   int64
	err error
}

type gatedRead struct {
	resume chan struct{}
	done   chan struct{}
	result gatedReadResult
	once   sync.Once
}

func startGatedPinnedRead(t *testing.T, ctx context.Context, mm *MemoryManager, addr hostarch.Addr, fill []byte) *gatedRead {
	t.Helper()
	g := &gatedRead{
		resume: make(chan struct{}),
		done:   make(chan struct{}),
	}
	started := make(chan struct{})
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: addr, End: addr + hostarch.Addr(len(fill))})
	go func() {
		n, err := mm.copyOutFromPinned(ctx, ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
			close(started)
			<-g.resume
			return safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(fill)))
		}), usermem.IOOpts{})
		g.result = gatedReadResult{n, err}
		close(g.done)
	}()
	select {
	case <-started:
	case <-g.done:
		t.Fatalf("copy completed before entering source: n=%d err=%v", g.result.n, g.result.err)
	}
	return g
}

func (g *gatedRead) finish() gatedReadResult {
	g.once.Do(func() { close(g.resume) })
	<-g.done
	return g.result
}

func mmapRacePage(t *testing.T, ctx context.Context, mm *MemoryManager, fill []byte) hostarch.Addr {
	t.Helper()
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	if _, err := mm.CopyOut(ctx, addr, fill, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut got err %v want nil", err)
	}
	return addr
}

func requireReadResult(t *testing.T, res gatedReadResult, wantN int64, wantErr *errors.Error) {
	t.Helper()
	if res.n != wantN || !linuxerr.Equals(wantErr, res.err) {
		t.Fatalf("read got n=%d err=%v, want n=%d err=%v", res.n, res.err, wantN, wantErr)
	}
}

func copyInPage(t *testing.T, ctx context.Context, mm *MemoryManager, addr hostarch.Addr, ignorePermissions bool) []byte {
	t.Helper()
	buf := make([]byte, pageSizeInt)
	if _, err := mm.CopyIn(ctx, addr, buf, usermem.IOOpts{IgnorePermissions: ignorePermissions}); err != nil {
		t.Fatalf("CopyIn got err %v want nil", err)
	}
	return buf
}

func TestPinnedCopyOutFromRacingMunmap(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr := mmapRacePage(t, ctx, mm, bytes.Repeat([]byte{'A'}, pageSizeInt))

	g := startGatedPinnedRead(t, ctx, mm, addr, bytes.Repeat([]byte{'B'}, pageSizeInt))
	defer g.finish()
	if err := mm.MUnmap(ctx, addr, pageSize); err != nil {
		t.Fatalf("MUnmap got err %v want nil", err)
	}
	requireReadResult(t, g.finish(), int64(pageSize), nil)

	buf := make([]byte, pageSizeInt)
	if n, err := mm.CopyIn(ctx, addr, buf, usermem.IOOpts{}); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyIn after unmap got n=%d err=%v, want EFAULT", n, err)
	}
}

func TestPinnedCopyOutFromRacingMMapFixedReplace(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)
	addr := mmapRacePage(t, ctx, mm, bytes.Repeat([]byte{'A'}, pageSizeInt))

	g := startGatedPinnedRead(t, ctx, mm, addr, bytes.Repeat([]byte{'B'}, pageSizeInt))
	defer g.finish()
	if _, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   pageSize,
		Addr:     addr,
		Fixed:    true,
		Unmap:    true,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	}); err != nil {
		t.Fatalf("MMap(MAP_FIXED) got err %v want nil", err)
	}
	requireReadResult(t, g.finish(), int64(pageSize), nil)

	want := make([]byte, pageSizeInt)
	if got := copyInPage(t, ctx, mm, addr, false /* ignorePermissions */); !bytes.Equal(got, want) {
		t.Errorf("replacement page contains %q..., want %q...", got[:4], want[:4])
	}
}
