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

package mm

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/usermem"
)

// zeroTestMappingLength exceeds a huge page so that MMap doesn't populate
// mappings eagerly.
const zeroTestMappingLength = 2 * hostarch.HugePageSize

// zeroTestMemoryManager returns a MemoryManager that uses zero pmas.
func zeroTestMemoryManager(ctx context.Context, t *testing.T) *MemoryManager {
	t.Helper()
	mm := testMemoryManager(ctx, t)
	t.Cleanup(func() { mm.DecUsers(ctx) })
	if !mm.haveMapZero {
		t.Fatalf("MemoryManager does not use zero pmas")
	}
	return mm
}

// setZeroPageWriteWindow sets the write window for the rest of the test.
func setZeroPageWriteWindow(t *testing.T, size uint64) {
	t.Helper()
	t.Cleanup(func() { zeroPageWriteWindow.Store(defaultZeroPageWriteWindow) })
	if err := SetZeroPageWriteWindow(size); err != nil {
		t.Fatalf("SetZeroPageWriteWindow(%d) got err %v want nil", size, err)
	}
}

func mmapAnon(ctx context.Context, t *testing.T, mm *MemoryManager, length uint64, perms hostarch.AccessType) hostarch.Addr {
	t.Helper()
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:   length,
		Private:  true,
		Perms:    perms,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap got err %v want nil", err)
	}
	return addr
}

func readBytes(ctx context.Context, t *testing.T, mm *MemoryManager, addr hostarch.Addr, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := mm.CopyIn(ctx, addr, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn(%#x, %d bytes) got err %v want nil", addr, n, err)
	}
	return buf
}

func writeBytes(ctx context.Context, t *testing.T, mm *MemoryManager, addr hostarch.Addr, src []byte) {
	t.Helper()
	if _, err := mm.CopyOut(ctx, addr, src, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut(%#x, %d bytes) got err %v want nil", addr, len(src), err)
	}
}

// pmaInfo describes a pma.
type pmaInfo struct {
	ar      hostarch.AddrRange
	private bool
	zero    bool
}

// pmasIn returns descriptions of all pmas overlapping ar, in order.
//
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) pmasIn(ar hostarch.AddrRange) []pmaInfo {
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	var pis []pmaInfo
	for pseg := mm.pmas.LowerBoundSegment(ar.Start); pseg.Ok() && pseg.Start() < ar.End; pseg = pseg.NextSegment() {
		pma := pseg.ValuePtr()
		pis = append(pis, pmaInfo{
			ar:      pseg.Range(),
			private: pma.private,
			zero:    pma.zero,
		})
	}
	return pis
}

// pmaAt returns the pma containing addr.
func (mm *MemoryManager) pmaAt(t *testing.T, addr hostarch.Addr) pmaInfo {
	t.Helper()
	pis := mm.pmasIn(hostarch.AddrRange{Start: addr, End: addr + 1})
	if len(pis) == 0 || !pis[0].ar.Contains(addr) {
		t.Fatalf("no pma contains %#x", addr)
	}
	return pis[0]
}

// checkPMAs checks that ar is entirely covered by pmas for which want returns
// true.
func (mm *MemoryManager) checkPMAs(t *testing.T, ar hostarch.AddrRange, desc string, want func(pmaInfo) bool) {
	t.Helper()
	next := ar.Start
	for _, pi := range mm.pmasIn(ar) {
		if pi.ar.Start > next {
			break
		}
		if !want(pi) {
			t.Errorf("pma %+v is not %s", pi, desc)
		}
		next = pi.ar.End
	}
	if next < ar.End {
		t.Errorf("addresses [%#x, %#x) have no pmas", next, ar.End)
	}
}

// checkZeroPMAInvariants checks the invariants of all zero pmas and RSS.
//
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) checkZeroPMAInvariants(t *testing.T) {
	t.Helper()
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	var rss uint64
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		ar := pseg.Range()
		pma := pseg.ValuePtr()
		if !pma.zero {
			rss += uint64(ar.Length())
			continue
		}
		if _, ok := pma.file.(zeroFile); !ok {
			t.Errorf("zero pma %v maps file of type %T, want zeroFile", ar, pma.file)
		}
		if pma.off != uint64(ar.Start) {
			t.Errorf("zero pma %v has offset %#x, want %#x", ar, pma.off, ar.Start)
		}
		if !pma.needCOW || pma.effectivePerms.Write || pma.maxPerms.Write {
			t.Errorf("zero pma %v is writable: needCOW=%t effectivePerms=%v maxPerms=%v", ar, pma.needCOW, pma.effectivePerms, pma.maxPerms)
		}
		if pma.private || pma.huge {
			t.Errorf("zero pma %v has private=%t huge=%t, want false", ar, pma.private, pma.huge)
		}
		if ar.Length() > maxZeroPMALength {
			t.Errorf("zero pma %v has length %d, want at most %d", ar, ar.Length(), maxZeroPMALength)
		}
	}
	if mm.curRSS != rss {
		t.Errorf("curRSS is %d, want %d (total length of non-zero pmas)", mm.curRSS, rss)
	}
}

// smapsRSS returns the Rss in kB reported by mm.vmaSmapsEntryLocked() for the
// vma containing addr.
//
// +checklocksexclude:mm.mappingMu
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) smapsRSS(ctx context.Context, t *testing.T, addr hostarch.Addr) uint64 {
	t.Helper()
	var entry string
	mm.mappingMu.RLock()
	if vseg := mm.vmas.FindSegment(addr); vseg.Ok() {
		entry = string(mm.vmaSmapsEntryLocked(ctx, vseg))
	}
	mm.mappingMu.RUnlock()
	for _, line := range strings.Split(entry, "\n") {
		var kb uint64
		if _, err := fmt.Sscanf(line, "Rss: %d kB", &kb); err == nil {
			return kb
		}
	}
	t.Fatalf("no Rss in smaps entry for %#x: %q", addr, entry)
	return 0
}

func isZeroed(b []byte) bool {
	return bytes.Count(b, []byte{0}) == len(b)
}

// TestZeroPMARead tests that reading untouched memory creates zero pmas.
func TestZeroPMARead(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)

	if got := readBytes(ctx, t, mm, addr, hostarch.PageSize); !isZeroed(got) {
		t.Errorf("read non-zero bytes from untouched memory")
	}
	if pi := mm.pmaAt(t, addr); !pi.zero {
		t.Errorf("after read, got pma %+v, want zero pma", pi)
	}
	if rss := mm.ResidentSetSize(); rss != 0 {
		t.Errorf("after read, got RSS %d, want 0", rss)
	}
	mm.checkZeroPMAInvariants(t)
}

// TestZeroPMAWrite tests that reads create zero pmas, and that a write
// replaces only the written page if the write window is a single page.
func TestZeroPMAWrite(t *testing.T) {
	setZeroPageWriteWindow(t, hostarch.PageSize)
	for _, test := range []struct {
		name   string
		access func(ctx context.Context, mm *MemoryManager, addr hostarch.Addr, at hostarch.AccessType) error
	}{
		{
			name: "IO",
			access: func(ctx context.Context, mm *MemoryManager, addr hostarch.Addr, at hostarch.AccessType) error {
				// A zero byte keeps the expected contents the same for both cases.
				buf := []byte{0}
				if at.Write {
					_, err := mm.CopyOut(ctx, addr, buf, usermem.IOOpts{})
					return err
				}
				_, err := mm.CopyIn(ctx, addr, buf, usermem.IOOpts{})
				return err
			},
		},
		{
			name: "UserFault",
			access: func(ctx context.Context, mm *MemoryManager, addr hostarch.Addr, at hostarch.AccessType) error {
				return mm.HandleUserFault(ctx, addr, at, 0 /* sp */)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			mm := zeroTestMemoryManager(ctx, t)
			addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
			ar := hostarch.AddrRange{Start: addr, End: addr + 3*hostarch.PageSize}
			for a := ar.Start; a < ar.End; a += hostarch.PageSize {
				if err := test.access(ctx, mm, a, hostarch.Read); err != nil {
					t.Fatalf("read at %#x got err %v want nil", a, err)
				}
			}
			mm.checkPMAs(t, ar, "zero", func(pi pmaInfo) bool { return pi.zero })

			mid := addr + hostarch.PageSize
			if err := test.access(ctx, mm, mid, hostarch.Write); err != nil {
				t.Fatalf("write at %#x got err %v want nil", mid, err)
			}
			wantAR := hostarch.AddrRange{Start: mid, End: mid + hostarch.PageSize}
			if pi := mm.pmaAt(t, mid); !pi.private || pi.ar != wantAR {
				t.Errorf("after write, got pma %+v, want private pma %v", pi, wantAR)
			}
			for _, a := range []hostarch.Addr{addr, mid + hostarch.PageSize} {
				if pi := mm.pmaAt(t, a); !pi.zero {
					t.Errorf("after write, got pma %+v, want zero pma", pi)
				}
			}
			if rss := mm.ResidentSetSize(); rss != hostarch.PageSize {
				t.Errorf("after write, got RSS %d, want %d", rss, hostarch.PageSize)
			}
			if got := readBytes(ctx, t, mm, addr, int(ar.Length())); !isZeroed(got) {
				t.Errorf("after write, read non-zero bytes")
			}
			mm.checkZeroPMAInvariants(t)
		})
	}
}

// TestZeroPMAWriteWindow tests that writes replace a huge page by default.
func TestZeroPMAWriteWindow(t *testing.T) {
	if got, want := zeroPageWriteWindow.Load(), uint64(hostarch.HugePageSize); got != want {
		t.Fatalf("got default zero page write window %d, want %d", got, want)
	}
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	vmaAR := hostarch.AddrRange{Start: addr, End: addr + zeroTestMappingLength}

	readBytes(ctx, t, mm, addr, zeroTestMappingLength)
	target := addr + hostarch.HugePageSize/2
	writeBytes(ctx, t, mm, target, []byte{1})

	windowStart := target.HugeRoundDown()
	wantAR := hostarch.AddrRange{Start: windowStart, End: windowStart + hostarch.HugePageSize}.Intersect(vmaAR)
	if pi := mm.pmaAt(t, target); !pi.private || pi.ar != wantAR {
		t.Errorf("after write, got pma %+v, want private pma %v", pi, wantAR)
	}
	if rss := mm.ResidentSetSize(); rss != uint64(wantAR.Length()) {
		t.Errorf("after write, got RSS %d, want %d", rss, wantAR.Length())
	}
	mm.checkZeroPMAInvariants(t)
}

// TestSetZeroPageWriteWindow tests SetZeroPageWriteWindow's validation.
func TestSetZeroPageWriteWindow(t *testing.T) {
	t.Cleanup(func() { zeroPageWriteWindow.Store(defaultZeroPageWriteWindow) })
	for _, size := range []uint64{0, 1, hostarch.PageSize - 1, hostarch.PageSize + 1, 3 * hostarch.PageSize} {
		if err := SetZeroPageWriteWindow(size); err == nil {
			t.Errorf("SetZeroPageWriteWindow(%d) got nil error, want non-nil", size)
		}
	}
	for _, size := range []uint64{hostarch.PageSize, 2 * hostarch.PageSize, hostarch.HugePageSize} {
		if err := SetZeroPageWriteWindow(size); err != nil {
			t.Errorf("SetZeroPageWriteWindow(%d) got err %v, want nil", size, err)
		}
		if got := zeroPageWriteWindow.Load(); got != size {
			t.Errorf("after SetZeroPageWriteWindow(%d), got window %d", size, got)
		}
	}
}

// TestZeroPMAFork tests that Fork doesn't copy zero pmas, and that writes
// after Fork are private to each MemoryManager.
func TestZeroPMAFork(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	ar := hostarch.AddrRange{Start: addr, End: addr + hostarch.PageSize}
	readBytes(ctx, t, mm, addr, hostarch.PageSize)

	mm2, err := mm.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork got err %v want nil", err)
	}
	defer mm2.DecUsers(ctx)
	if pis := mm2.pmasIn(ar); len(pis) != 0 {
		t.Errorf("in child after Fork, got pmas %+v, want none", pis)
	}
	if got := readBytes(ctx, t, mm2, addr, hostarch.PageSize); !isZeroed(got) {
		t.Errorf("child read non-zero bytes")
	}
	if pi := mm2.pmaAt(t, addr); !pi.zero {
		t.Errorf("in child after read, got pma %+v, want zero pma", pi)
	}
	if rss := mm2.ResidentSetSize(); rss != 0 {
		t.Errorf("in child, got RSS %d, want 0", rss)
	}

	writeBytes(ctx, t, mm, addr, []byte{'p'})
	writeBytes(ctx, t, mm2, addr+1, []byte{'c'})
	if got, want := readBytes(ctx, t, mm, addr, 2), []byte{'p', 0}; !bytes.Equal(got, want) {
		t.Errorf("parent read %q, want %q", got, want)
	}
	if got, want := readBytes(ctx, t, mm2, addr, 2), []byte{0, 'c'}; !bytes.Equal(got, want) {
		t.Errorf("child read %q, want %q", got, want)
	}
	mm.checkZeroPMAInvariants(t)
	mm2.checkZeroPMAInvariants(t)
}

// TestZeroPMAAccounting tests that zero pmas are excluded from RSS and smaps.
func TestZeroPMAAccounting(t *testing.T) {
	setZeroPageWriteWindow(t, hostarch.PageSize)
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)

	readBytes(ctx, t, mm, addr, zeroTestMappingLength)
	if got := mm.smapsRSS(ctx, t, addr); got != 0 {
		t.Errorf("after read, got smaps Rss %d kB, want 0 kB", got)
	}
	writeBytes(ctx, t, mm, addr, []byte{1})
	if got, want := mm.smapsRSS(ctx, t, addr), uint64(hostarch.PageSize/1024); got != want {
		t.Errorf("after write, got smaps Rss %d kB, want %d kB", got, want)
	}

	if err := mm.Decommit(addr, hostarch.HugePageSize); err != nil {
		t.Fatalf("Decommit got err %v want nil", err)
	}
	if rss := mm.ResidentSetSize(); rss != 0 {
		t.Errorf("after Decommit, got RSS %d, want 0", rss)
	}
	mm.checkZeroPMAInvariants(t)
	if got := readBytes(ctx, t, mm, addr, 1); !isZeroed(got) {
		t.Errorf("after Decommit, read %v, want zeroes", got)
	}

	if err := mm.MUnmap(ctx, addr, zeroTestMappingLength); err != nil {
		t.Fatalf("MUnmap got err %v want nil", err)
	}
	if pis := mm.pmasIn(hostarch.AddrRange{Start: addr, End: addr + zeroTestMappingLength}); len(pis) != 0 {
		t.Errorf("after MUnmap, got pmas %+v, want none", pis)
	}
	mm.checkZeroPMAInvariants(t)
}

// TestZeroPMAPopulate tests that populating allocates memory for writable
// vmas and uses zero pmas for read-only ones.
func TestZeroPMAPopulate(t *testing.T) {
	// Root credentials are required for MLock.
	ctx := contexttest.RootContext(t)
	mm := zeroTestMemoryManager(ctx, t)

	// MMap populates small anonymous mappings eagerly.
	rwSmall := mmapAnon(ctx, t, mm, hostarch.PageSize, hostarch.ReadWrite)
	if pi := mm.pmaAt(t, rwSmall); !pi.private {
		t.Errorf("for small writable mapping, got pma %+v, want private pma", pi)
	}
	roSmall := mmapAnon(ctx, t, mm, hostarch.PageSize, hostarch.Read)
	if pi := mm.pmaAt(t, roSmall); !pi.zero {
		t.Errorf("for small read-only mapping, got pma %+v, want zero pma", pi)
	}

	rw := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	rwAR := hostarch.AddrRange{Start: rw, End: rw + zeroTestMappingLength}
	readBytes(ctx, t, mm, rw, zeroTestMappingLength)
	if err := mm.MLock(ctx, rw, zeroTestMappingLength, memmap.MLockEager); err != nil {
		t.Fatalf("MLock(writable) got err %v want nil", err)
	}
	mm.checkPMAs(t, rwAR, "private", func(pi pmaInfo) bool { return pi.private })

	ro := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.Read)
	roAR := hostarch.AddrRange{Start: ro, End: ro + zeroTestMappingLength}
	rss := mm.ResidentSetSize()
	if err := mm.MLock(ctx, ro, zeroTestMappingLength, memmap.MLockEager); err != nil {
		t.Fatalf("MLock(read-only) got err %v want nil", err)
	}
	mm.checkPMAs(t, roAR, "zero", func(pi pmaInfo) bool { return pi.zero })
	if got := mm.ResidentSetSize(); got != rss {
		t.Errorf("after MLock(read-only), got RSS %d, want %d", got, rss)
	}
	mm.checkZeroPMAInvariants(t)
}

// TestZeroPMAMRemap tests that zero pmas can be moved by MRemap.
func TestZeroPMAMRemap(t *testing.T) {
	setZeroPageWriteWindow(t, hostarch.PageSize)
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	readBytes(ctx, t, mm, addr, zeroTestMappingLength)
	writeBytes(ctx, t, mm, addr+hostarch.PageSize, []byte{'x'})

	// Move the mapping to the location of another mapping, which is replaced.
	dst := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	newAddr, err := mm.MRemap(ctx, addr, zeroTestMappingLength, zeroTestMappingLength, MRemapOpts{
		Move:    MRemapMustMove,
		NewAddr: dst,
	})
	if err != nil {
		t.Fatalf("MRemap got err %v want nil", err)
	}
	if newAddr != dst {
		t.Fatalf("MRemap got address %#x, want %#x", newAddr, dst)
	}
	if pi := mm.pmaAt(t, newAddr); !pi.zero {
		t.Errorf("after MRemap, got pma %+v, want zero pma", pi)
	}
	mm.checkZeroPMAInvariants(t)
	want := make([]byte, 2*hostarch.PageSize)
	want[hostarch.PageSize] = 'x'
	if got := readBytes(ctx, t, mm, newAddr, len(want)); !bytes.Equal(got, want) {
		t.Errorf("after MRemap, read unexpected contents")
	}
}

// TestZeroPMAPin tests that Pin replaces zero pmas, even for reading.
func TestZeroPMAPin(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	readBytes(ctx, t, mm, addr, hostarch.PageSize)

	ar := hostarch.AddrRange{Start: addr, End: addr + hostarch.PageSize}
	prs, err := mm.Pin(ctx, ar, hostarch.Read, false /* ignorePermissions */)
	if err != nil {
		t.Fatalf("Pin got err %v want nil", err)
	}
	defer Unpin(prs)
	if len(prs) != 1 {
		t.Fatalf("Pin got %d PinnedRanges, want 1", len(prs))
	}
	if _, ok := prs[0].File.(*pgalloc.MemoryFile); !ok {
		t.Errorf("Pin got file of type %T, want *pgalloc.MemoryFile", prs[0].File)
	}
	if pi := mm.pmaAt(t, addr); !pi.private {
		t.Errorf("after Pin, got pma %+v, want private pma", pi)
	}

	data := bytes.Repeat([]byte{'p'}, hostarch.PageSize)
	writeBytes(ctx, t, mm, addr, data)
	if got := readPinnedRange(t, prs[0]); !bytes.Equal(got, data) {
		t.Errorf("pinned range contains %q..., want %q...", got[:4], data[:4])
	}
	mm.checkZeroPMAInvariants(t)
}

// TestZeroPMAInvalidateUnsavable tests that InvalidateUnsavable removes only
// zero pmas.
func TestZeroPMAInvalidateUnsavable(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)
	ar := hostarch.AddrRange{Start: addr, End: addr + zeroTestMappingLength}
	readBytes(ctx, t, mm, addr, zeroTestMappingLength)
	writeBytes(ctx, t, mm, addr, []byte{'x'})

	if err := mm.InvalidateUnsavable(ctx); err != nil {
		t.Fatalf("InvalidateUnsavable got err %v want nil", err)
	}
	for _, pi := range mm.pmasIn(ar) {
		if !pi.private {
			t.Errorf("after InvalidateUnsavable, got pma %+v, want only private pmas", pi)
		}
	}
	if pi := mm.pmaAt(t, addr); !pi.private {
		t.Errorf("after InvalidateUnsavable, got pma %+v, want private pma", pi)
	}
	if got, want := readBytes(ctx, t, mm, addr, hostarch.PageSize+1), append([]byte{'x'}, make([]byte, hostarch.PageSize)...); !bytes.Equal(got, want) {
		t.Errorf("after InvalidateUnsavable, read unexpected contents")
	}
	mm.checkZeroPMAInvariants(t)
}

// TestZeroPMALengthLimit tests that zero pmas are no longer than
// maxZeroPMALength, including after merging.
func TestZeroPMALengthLimit(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	const length = maxZeroPMALength + 2*hostarch.HugePageSize
	addr := mmapAnon(ctx, t, mm, length, hostarch.ReadWrite)

	// Read the whole mapping without allocating a buffer for it.
	ar := hostarch.AddrRange{Start: addr, End: addr + length}
	n, err := mm.CopyInTo(ctx, hostarch.AddrRangeSeqOf(ar), safemem.FromIOWriter{Writer: io.Discard}, usermem.IOOpts{})
	if err != nil || n != length {
		t.Fatalf("CopyInTo got (%d, %v), want (%d, nil)", n, err, length)
	}
	mm.checkPMAs(t, ar, "zero", func(pi pmaInfo) bool { return pi.zero })
	mm.checkZeroPMAInvariants(t)

	// MProtect merges pmas after changing permissions.
	for _, perms := range []hostarch.AccessType{hostarch.Read, hostarch.ReadWrite} {
		if err := mm.MProtect(addr, length, perms, false /* growsDown */); err != nil {
			t.Fatalf("MProtect(%v) got err %v want nil", perms, err)
		}
		mm.checkZeroPMAInvariants(t)
	}
}

// TestZeroPMASpanningVMAs tests writes to zero pmas that span multiple vmas.
func TestZeroPMASpanningVMAs(t *testing.T) {
	// A multi-page window can extend beyond the written vma.
	const window = 2 * hostarch.PageSize
	setZeroPageWriteWindow(t, window)
	ctx := contexttest.Context(t)
	mm := zeroTestMemoryManager(ctx, t)
	addr := mmapAnon(ctx, t, mm, zeroTestMappingLength, hostarch.ReadWrite)

	// Make the second part read-only at an address that isn't window-aligned.
	split := addr + hostarch.HugePageSize
	if split%window == 0 {
		split += hostarch.PageSize
	}
	if err := mm.MProtect(split, uint64(addr+zeroTestMappingLength-split), hostarch.Read, false /* growsDown */); err != nil {
		t.Fatalf("MProtect got err %v want nil", err)
	}

	// Zero pmas are never writable, so zero pmas in both vmas merge.
	readBytes(ctx, t, mm, addr, zeroTestMappingLength)
	last := split - hostarch.PageSize
	if pi := mm.pmaAt(t, last); !pi.zero || !pi.ar.Contains(split) {
		t.Fatalf("after read, got pma %+v, want zero pma containing %#x", pi, split)
	}

	// The last page's window extends into the read-only vma; only the part
	// in the writable vma should be replaced.
	writeBytes(ctx, t, mm, last, []byte{'x'})
	wantAR := hostarch.AddrRange{Start: last, End: split}
	if pi := mm.pmaAt(t, last); !pi.private || pi.ar != wantAR {
		t.Errorf("after write, got pma %+v, want private pma %v", pi, wantAR)
	}
	if pi := mm.pmaAt(t, split); !pi.zero {
		t.Errorf("after write, got pma %+v, want zero pma", pi)
	}
	if _, err := mm.CopyOut(ctx, split, []byte{'y'}, usermem.IOOpts{}); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyOut to read-only vma got err %v, want EFAULT", err)
	}
	mm.checkZeroPMAInvariants(t)
}
