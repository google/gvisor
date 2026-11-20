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
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
)

// Zero pmas represent private anonymous memory that has been read but not
// written. They map zeroFile and are installed with
// platform.AddressSpace.MapZero, so they use no MemoryFile memory or RSS.
// Writing a zero pma replaces the written range and allocates memory.

const (
	// zeroRegionLength is the length of zeroRegion.
	zeroRegionLength = min(hostarch.HugePageSize, maxZeroPMALength)

	// maxZeroPMALength bounds the length of a zero pma, and thus the cost of
	// remapping it.
	maxZeroPMALength = 64 << 20
)

// zeroRegion returns the read-only zero-filled mapping that backs internal
// mappings of zero pmas, or nil if it couldn't be created.
var zeroRegion = sync.OnceValue(func() []byte {
	m, err := unix.Mmap(-1, 0, zeroRegionLength, unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		log.Warningf("Failed to map zero region, zero pmas will not be used: %v", err)
		return nil
	}
	// Otherwise reads may allocate a host huge page. Errors only affect
	// memory usage.
	_ = unix.Madvise(m, unix.MADV_NOHUGEPAGE)
	return m
})

// canMapZero returns true if MemoryManagers using p may create zero pmas.
func canMapZero(p platform.Platform) bool {
	return p.SupportsMapZero() && zeroRegion() != nil
}

// zeroFile is the memmap.File mapped by zero pmas. It is never writable and
// needs no references. It must remain comparable for pmaSetFunctions.Merge.
type zeroFile struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback
}

// IncRef implements memmap.File.IncRef.
func (zeroFile) IncRef(fr memmap.FileRange, memCgID uint32) {}

// DecRef implements memmap.File.DecRef.
func (zeroFile) DecRef(fr memmap.FileRange) {}

// MapInternal implements memmap.File.MapInternal.
func (zeroFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Write || at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}
	// zeroRegion() != nil since zero pmas exist. It is never unmapped, so it
	// can't fault and needs no safecopy.
	region := zeroRegion()
	n := fr.Length()
	if n <= zeroRegionLength {
		return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(region[:n])), nil
	}
	blocks := make([]safemem.Block, 0, (n+zeroRegionLength-1)/zeroRegionLength)
	for n > 0 {
		blockLen := min(n, zeroRegionLength)
		blocks = append(blocks, safemem.BlockFromSafeSlice(region[:blockLen]))
		n -= blockLen
	}
	return safemem.BlockSeqFromSlice(blocks), nil
}

// DataFD implements memmap.File.DataFD. Zero pmas are mapped with MapZero.
func (zeroFile) DataFD(fr memmap.FileRange) (int, error) {
	return -1, linuxerr.ENODEV
}

// FD implements memmap.File.FD.
func (zeroFile) FD() int {
	return -1
}

// zeroPageWriteWindow is the alignment of the range of a zero pma replaced when
// part of it is written. Larger windows take fewer faults for dense writes but
// allocate more memory for sparse writes.
var zeroPageWriteWindow = atomicbitops.FromUint64(defaultZeroPageWriteWindow)

// defaultZeroPageWriteWindow matches the alignment of allocations for untouched
// memory, so zero pmas never allocate more memory.
const defaultZeroPageWriteWindow = hostarch.HugePageSize

// SetZeroPageWriteWindow sets zeroPageWriteWindow. size must be a power of 2
// that is at least hostarch.PageSize.
func SetZeroPageWriteWindow(size uint64) error {
	if size < hostarch.PageSize || size&(size-1) != 0 {
		return fmt.Errorf("zero page write window must be a power of 2 that is at least %d bytes, got %d", hostarch.PageSize, size)
	}
	zeroPageWriteWindow.Store(size)
	return nil
}

// zeroPageWriteWindowAR returns ar expanded to zeroPageWriteWindow alignment.
func zeroPageWriteWindowAR(ar hostarch.AddrRange) hostarch.AddrRange {
	mask := hostarch.Addr(zeroPageWriteWindow.Load() - 1)
	windowAR := hostarch.AddrRange{Start: ar.Start &^ mask, End: ar.End}
	// If rounding ar.End up overflows, just keep ar.End.
	if end := (ar.End + mask) &^ mask; end >= ar.End {
		windowAR.End = end
	}
	return windowAR
}

// newZeroPMA returns a zero pma for addresses ar in the given vma.
func newZeroPMA(ar hostarch.AddrRange, vma *vma) pma {
	p := pma{
		file:           zeroFile{},
		off:            uint64(ar.Start),
		translatePerms: hostarch.AnyAccess,
		effectivePerms: vma.effectivePerms,
		maxPerms:       vma.maxPerms,
		needCOW:        true,
		zero:           true,
	}
	p.effectivePerms.Write = false
	p.maxPerms.Write = false
	return p
}

// removeZeroPMAsLocked removes all zero pmas and their AddressSpace mappings.
//
// +checklocks:mm.activeMu
func (mm *MemoryManager) removeZeroPMAsLocked() {
	var unmapAR hostarch.AddrRange
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); {
		if !pseg.ValuePtr().zero {
			pseg = pseg.NextSegment()
			continue
		}
		if ar := pseg.Range(); ar.Start == unmapAR.End {
			unmapAR.End = ar.End
		} else {
			mm.unmapASLocked(unmapAR)
			unmapAR = ar
		}
		// Zero pmas hold no references and are not included in RSS.
		pseg = mm.pmas.Remove(pseg).NextSegment()
	}
	mm.unmapASLocked(unmapAR)
}
