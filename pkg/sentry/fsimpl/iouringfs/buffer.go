// Copyright 2022 The gVisor Authors.
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

package iouringfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/safemem"
)

// sharedBuffer represents a memory buffer shared between the sentry and
// userspace. In many cases, this is simply an internal mmap on the underlying
// memory (aka fast mode). However in some cases the mapped region may lie
// across multiple blocks and we need to copy the region into a contiguous
// buffer (aka slow mode). The goal in either case is to present a contiguous
// slice for easy access.
//
// sharedBuffer must be initialized with init before first use.
//
// Example
// =======
/*
var sb sharedBuffer
bs := MapInternal(...)
sb.init(bs)

fetch := true

for !done {
	var err error

	// (Re-)Fetch the view.
	var view []byte
	if fetch {
		view, err = sb.view(128)
	}

	// Use the view slice to access the region, both for read or write.
	someState := dosomething(view[10])
	view[20] = someState & mask

	// Write back the changes.
	fetch, err = sb.writeback(128)
}
*/
// In the above example, in fast mode view returns a slice that points directly
// to the underlying memory and requires no copying. Writeback is a no-op, and
// the view can be reused on subsequent loop iterations (writeback will return
// refetch == false).
//
// In slow mode, view will copy disjoint parts of the region from different
// blocks to a single contiguous slice. Writeback will also required a copy, and
// a new view will have to be fetched on every loop iteration (writeback will
// return refetch == true).
//
// sharedBuffer is *not* thread safe.
type sharedBuffer struct {
	bs safemem.BlockSeq

	// copy is allocated once and reused on subsequent calls to view. We don't
	// use the Task's copy scratch buffer because these buffers may be accessed
	// from a background context.
	copy []byte

	// needsWriteback indicates whether we need to copy out back data from the
	// slice returned by the last view() call.
	needsWriteback bool
}

// init initializes the sharedBuffer, and must be called before first use.
func (b *sharedBuffer) init(bs safemem.BlockSeq) {
	b.bs = bs
}

func (b *sharedBuffer) valid() bool {
	return !b.bs.IsEmpty()
}

// view returns a slice representing the shared buffer. When done, view must be
// released with either writeback{,Window} or drop.
func (b *sharedBuffer) view(n int) ([]byte, error) {
	if uint64(n) > b.bs.NumBytes() {
		// Mapping too short? This is a bug.
		panic(fmt.Sprintf("iouringfs: mapping too short for requested len: mapping length %v, requested %d", b.bs.NumBytes(), n))
	}

	// Fast path: use mapping directly, no copies required.
	h := b.bs.Head()
	if h.Len() <= n && !h.NeedSafecopy() {
		b.needsWriteback = false
		return h.ToSlice()[:n], nil
	}

	// Buffer mapped across multiple blocks, or requires safe copy.
	if len(b.copy) < n {
		b.copy = make([]byte, n)
	}
	dst := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(b.copy[:n]))
	copyN, err := safemem.CopySeq(dst, b.bs)
	if err != nil {
		return nil, err
	}
	if copyN != uint64(n) {
		// Short copy risks exposing stale data from view buffer. This should never happen.
		panic(fmt.Sprintf("iouringfs: short copy for shared buffer view: want %d, got %d", n, copyN))
	}
	b.needsWriteback = true
	return b.copy, nil
}

// writeback writes back the changes to the slice returned by the previous view
// call. On return, writeback indicates if the previous view may be reused, or
// needs to be refetched with a new call to view.
//
// Precondition: Must follow a call to view. n must match the value pased to
// view.
//
// Postcondition: Previous view is invalidated whether writeback is successful
// or not. To attempt another modification, a new view may need to be obtained,
// according to refetch.
func (b *sharedBuffer) writeback(n int) (refetch bool, err error) {
	return b.writebackWindow(0, n)
}

// writebackWindow is like writeback, but only writes back a subregion. Useful
// if the caller knows only a small region has been updated, as it reduces how
// much data need to be copied. writebackWindow still potentially invalidates
// the entire view, caller must check refetch to determine if the view needs to
// be refreshed.
func (b *sharedBuffer) writebackWindow(off, len int) (refetch bool, err error) {
	if uint64(off+len) > b.bs.NumBytes() {
		panic(fmt.Sprintf("iouringfs: requested writeback to shared buffer from offset %d for %d bytes would overflow underlying region of size %d", off, len, b.bs.NumBytes()))
	}

	if !b.needsWriteback {
		return false, nil
	}

	// Existing view invalid after this point.
	b.needsWriteback = false

	src := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(b.copy[off : off+len]))
	dst := b.bs.DropFirst(off)
	copyN, err := safemem.CopySeq(dst, src)
	if err != nil {
		return true, err
	}
	if copyN != uint64(len) {
		panic(fmt.Sprintf("iouringfs: short copy for shared buffer writeback: want %d, got %d", len, copyN))
	}
	return true, nil
}

// drop releases a view without writeback. Returns whether any existing views
// need to be refetched. Useful when caller is done with a view that doesn't
// need to be modified.
func (b *sharedBuffer) drop() bool {
	wb := b.needsWriteback
	b.needsWriteback = false
	return wb
}
