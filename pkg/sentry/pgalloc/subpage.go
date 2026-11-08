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

// Subpage saving.
//
// With large host pages (e.g. 64K on arm64), the sentry's tmpfs stores each
// file in whole host pages, so a small file occupies a full page that is
// mostly zero. This is independent of the host filesystem. It applies to
// overlay upper layers with a filestore (--overlay2 with medium self or
// dir=...), including the root filesystem's, and to tmpfs mounts with a
// filestore, whose pages live in disk-backed MemoryFiles. When subpage saving
// is enabled, SaveTo writes only the subpage-sized blocks of each committed
// page that contain non-zero bytes, and records which blocks were written in
// the MemoryFile's metadata. LoadFrom reads such pages back block by block;
// the blocks that were not saved are left zero, as they are in a newly loaded
// MemoryFile.
//
// Subpage saving is selected by SaveOpts.SubpageSize. It requires async page
// saving (a pages file), and only applies to disk-backed MemoryFiles, whose
// contents are tmpfs data rather than application memory. Memory-backed
// overlays and tmpfs mounts (e.g. --overlay2=root:memory) store their pages in
// the main MemoryFile, which is not disk-backed, so they are still saved with
// whole pages. Subpage saving avoids saving the zero padding of small files
// on hosts whose pages are larger than 4 KiB (see SubpageSize4K). Masks
// describe base pages, including in huge-page chunks. Checkpoints can only be
// restored with the same host page size, as for other checkpoints.

import (
	"bytes"
	"fmt"
	"math/bits"
	"sort"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	pgallocpb "gvisor.dev/gvisor/pkg/sentry/pgalloc/pgalloc_metadata_go_proto"
)

// checkMetadataVersion returns an error if pb's version is not supported or
// does not match whether pb describes a MemoryFile saved with subpage saving.
func checkMetadataVersion(pb *pgallocpb.MemoryFileMetadataProto) error {
	switch pb.Version {
	case metadataVersionWholePages:
		if pb.SubpageSize != 0 || len(pb.SubpageMasks) != 0 {
			return fmt.Errorf("MemoryFileMetadataProto version %d has subpage size %d and %d subpage masks", pb.Version, pb.SubpageSize, len(pb.SubpageMasks))
		}
	case metadataVersionSubpages:
		if pb.SubpageSize == 0 {
			return fmt.Errorf("MemoryFileMetadataProto version %d has no subpage size", pb.Version)
		}
	default:
		return fmt.Errorf("unsupported MemoryFileMetadataProto version %d", pb.Version)
	}
	return nil
}

// SubpageSize4K returns the SaveOpts.SubpageSize that saves 4 KiB blocks, or
// 0 if that is not a valid subpage size because host pages are not larger than
// 4 KiB (or are more than 64 times larger).
func SubpageSize4K() uint64 {
	if ValidSubpageSize(4096) {
		return 4096
	}
	return 0
}

// MinSubpageSize is the smallest valid SaveOpts.SubpageSize. Every MemoryFile
// saved to a pages file starts at an offset that is a multiple of
// MinSubpageSize, since every valid subpage size and hostarch.PageSize are.
const MinSubpageSize = 512

// ValidSubpageSize returns true if size is a valid SaveOpts.SubpageSize other
// than 0: a power of two of at least MinSubpageSize bytes that is smaller than
// hostarch.PageSize and divides it into at most 64 blocks.
func ValidSubpageSize(size uint64) bool {
	return size >= MinSubpageSize && size < hostarch.PageSize && size&(size-1) == 0 && hostarch.PageSize/size <= 64
}

// subpageMask returns a mask with bit i set if the i-th size-byte block of pg
// contains a non-zero byte.
func subpageMask(pg []byte, size uint64, zero []byte) uint64 {
	var mask uint64
	for i := uint64(0); i < uint64(len(pg)); i += size {
		if !bytes.Equal(pg[i:i+size], zero[:size]) {
			mask |= 1 << (i / size)
		}
	}
	return mask
}

// fullSubpageMask returns the mask of all size-byte blocks in a page.
func fullSubpageMask(size uint64) uint64 {
	n := hostarch.PageSize / size
	if n == 64 {
		return ^uint64(0)
	}
	return 1<<n - 1
}

// maxSubpageRuns returns the maximum number of runs of saved blocks in a page,
// for block size size.
func maxSubpageRuns(size uint64) int {
	return int(hostarch.PageSize/size+1) / 2
}

// forEachSubpageRun calls fn with the [first, end) block indexes of each run
// of consecutive set bits in mask, in increasing order.
func forEachSubpageRun(mask uint64, fn func(first, end uint64)) {
	for mask != 0 {
		first := uint64(bits.TrailingZeros64(mask))
		n := uint64(bits.TrailingZeros64(^(mask >> first)))
		fn(first, first+n)
		if first+n >= 64 {
			return
		}
		mask &^= (1<<n - 1) << first
	}
}

// subpageLayout locates the saved blocks of each committed page of a
// MemoryFile saved with subpage saving.
type subpageLayout struct {
	// size is the block size.
	size uint64

	// segs are the committed ranges of the MemoryFile, in offset order, each
	// with the index of its first page in masks and offs.
	segs []subpageSeg

	// masks[i] is the mask of saved blocks of the i-th committed page.
	masks []uint64

	// offs[i] is the pages file offset of the i-th committed page's first
	// saved block.
	offs []uint64
}

type subpageSeg struct {
	memmap.FileRange
	first int
}

// newSubpageLayout returns the layout of the committed pages described by pb,
// whose saved blocks start at pages file offset off, and the pages file offset
// after them.
func newSubpageLayout(pb *pgallocpb.MemoryFileMetadataProto, off uint64) (*subpageLayout, uint64, error) {
	l := &subpageLayout{size: pb.SubpageSize}
	for _, s := range pb.MemAcct {
		if !s.KnownCommitted {
			continue
		}
		var err error
		if off, err = l.addRange(memmap.FileRange{s.Start, s.End}, off, pb.SubpageMasks); err != nil {
			return nil, 0, err
		}
	}
	if len(l.masks) != len(pb.SubpageMasks) {
		return nil, 0, fmt.Errorf("%d subpage masks for %d committed pages", len(pb.SubpageMasks), len(l.masks))
	}
	return l, off, nil
}

// addRange appends the committed range fr, whose saved blocks start at pages
// file offset off, and returns the pages file offset after them.
func (l *subpageLayout) addRange(fr memmap.FileRange, off uint64, masks []uint64) (uint64, error) {
	if !fr.WellFormed() || fr.Start%hostarch.PageSize != 0 || fr.End%hostarch.PageSize != 0 || (len(l.segs) != 0 && l.segs[len(l.segs)-1].End > fr.Start) {
		return 0, fmt.Errorf("invalid committed range %v for subpage saving", fr)
	}
	n := int(fr.Length() / hostarch.PageSize)
	if len(l.masks)+n > len(masks) {
		return 0, fmt.Errorf("%d subpage masks for at least %d committed pages", len(masks), len(l.masks)+n)
	}
	l.segs = append(l.segs, subpageSeg{fr, len(l.masks)})
	full := fullSubpageMask(l.size)
	for _, mask := range masks[len(l.masks) : len(l.masks)+n] {
		if mask == 0 || mask&^full != 0 {
			return 0, fmt.Errorf("invalid subpage mask %#x for block size %d", mask, l.size)
		}
		l.masks = append(l.masks, mask)
		l.offs = append(l.offs, off)
		off += uint64(bits.OnesCount64(mask)) * l.size
	}
	return off, nil
}

// pageIndex returns the index into l.masks and l.offs of the committed page
// at MemoryFile offset off.
func (l *subpageLayout) pageIndex(off uint64) int {
	i := sort.Search(len(l.segs), func(i int) bool { return l.segs[i].End > off })
	if i == len(l.segs) || l.segs[i].Start > off {
		panic(fmt.Sprintf("MemoryFile offset %#x is not in a committed range saved with subpage saving", off))
	}
	return l.segs[i].first + int((off-l.segs[i].Start)/hostarch.PageSize)
}
