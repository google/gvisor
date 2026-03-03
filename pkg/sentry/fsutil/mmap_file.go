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

package fsutil

import (
	"fmt"
	"io"
	"math"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// A MmapFile implements memmap.File by owning a host file descriptor on behalf
// of an implementation of memmap.Mappable.
type MmapFile interface {
	memmap.File
	// File.IncRef may be called on pages without an existing reference as long
	// as MappableRelease has not been called.

	// SetFD sets the file descriptor represented by the MmapFile. It must be
	// called on zero-value (implementations of) MmapFile before first use. If
	// fd >= 0, the MmapFile takes ownership of the file descriptor fd, i.e. fd
	// will be closed when the MmapFile is no longer in use. If fd < 0,
	// MapInternal and DataFD can never succeed, but the MmapFile is
	// nevertheless a valid memmap.File.
	//
	// After save/restore, the file descriptor is reset to -1, and SetFD may be
	// called to set it again before first post-restore use.
	//
	// Preconditions: MappableRelease has never been called.
	SetFD(fd int)

	// MappableRelease is called by the memmap.Mappable that is the nominal
	// owner of the represented file descriptor, to indicate that the Mappable
	// is being destroyed. The MmapFile retains ownership of the file
	// descriptor, and remains a valid memmap.File, until all page references
	// are dropped.
	MappableRelease()
}

// MmapFileRefs provides reference counting for implementations of MmapFile
// that don't unmap pages with zero references, and consequently don't need to
// keep track of per-page reference counts.
//
// +stateify savable
type MmapFileRefs struct {
	// Closer.Close is called when MappableRelease has been called and all page
	// references have been released.
	Closer io.Closer

	// refs is the sum of page reference counts across all pages in the file,
	// plus math.MinInt64 (i.e. with the most significant bit set) if
	// MappableRelease has been called.
	refs atomicbitops.Int64
}

// MappableRelease implements MmapFile.MappableRelease.
func (r *MmapFileRefs) MappableRelease() {
retry:
	refs := r.refs.Load()
	if refs < 0 {
		return // MappableRelease already called
	}
	if !r.refs.CompareAndSwap(refs, refs+math.MinInt64) {
		goto retry
	}
	if refs == 0 {
		r.close()
	}
}

// IncRef implements memmap.File.IncRef.
func (r *MmapFileRefs) IncRef(fr memmap.FileRange, memCgID uint32) {
	n := int64(fr.Length() / hostarch.PageSize)
retry:
	refs := r.refs.Load()
	if refs == math.MinInt64 {
		panic("IncRef called with zero references after MappableRelease")
	}
	if realRefs := refs & math.MaxInt64; realRefs+n < realRefs {
		panic(fmt.Sprintf("fsutil.MmapFileRefs reference count %d (%#x) + %d (%v) overflows", realRefs, refs, n, fr))
	}
	if !r.refs.CompareAndSwap(refs, refs+n) {
		goto retry
	}
}

// DecRef implements memmap.File.DecRef.
func (r *MmapFileRefs) DecRef(fr memmap.FileRange) {
	n := int64(fr.Length() / hostarch.PageSize)
retry:
	refs := r.refs.Load()
	if realRefs := refs & math.MaxInt64; realRefs < n {
		panic(fmt.Sprintf("fsutil.MmapFileRefs reference count %d (%#x) < %d (%v)", realRefs, refs, n, fr))
	}
	newRefs := refs - n
	if !r.refs.CompareAndSwap(refs, newRefs) {
		goto retry
	}
	if newRefs == math.MinInt64 {
		r.close()
	}
}

func (r *MmapFileRefs) close() {
	if err := r.Closer.Close(); err != nil {
		log.Warningf("fsutil.MmapFileRefs: %T.Close failed: %v", r.Closer, err)
	}
}
