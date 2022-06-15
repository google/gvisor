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

package buffer

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/sync"
)

var viewPool = sync.Pool{
	New: func() interface{} {
		return &View{}
	},
}

// View is a window into a shared chunk. Views are held by Buffers in
// viewLists to represent contiguous memory.
//
// A View must be created with NewView, NewViewWithData, or Clone. Owners are
// responsible for maintaining ownership over their views. When Views need to be
// shared or copied, the owner should create a new View with Clone. Clone must
// only ever be called on a owned View, not a borrowed one.
//
// Users are responsible for calling Release when finished with their View so
// that its resources can be returned to the pool.
//
// Users must not write directly to slices returned by AsSlice. Instead, they
// must use Write/WriteAt/CopyIn to modify the underlying View. This preserves
// the safety guarantees of copy-on-write.
type View struct {
	sync.NoCopy

	viewEntry
	read  int
	write int
	chunk *chunk
}

// NewView creates a new view with capacity at least as big as cap. It is
// analogous to make([]byte, 0, cap).
func NewView(cap int) *View {
	c := newChunk(cap)
	v := viewPool.Get().(*View)
	*v = View{chunk: c}
	return v
}

// NewViewSize creates a new view with capacity at least as big as size and
// length that is exactly size. It is analogous to make([]byte, size).
func NewViewSize(size int) *View {
	v := NewView(size)
	v.Grow(size)
	return v
}

// NewViewWithData creates a new view and initializes it with data. This
// function should be used with caution to avoid unnecessary []byte allocations.
// When in doubt use NewWithView to maximize chunk reuse in production
// environments.
func NewViewWithData(data []byte) *View {
	c := newChunk(len(data))
	v := viewPool.Get().(*View)
	*v = View{chunk: c}
	v.Write(data)
	return v
}

// Clone creates a shallow clone of v where the underlying chunk is shared.
//
// The caller must own the View to call Clone. It is not safe to call Clone
// on a borrowed or shared View because it can race with other View methods.
func (v *View) Clone() *View {
	v.chunk.IncRef()
	newV := viewPool.Get().(*View)
	newV.chunk = v.chunk
	newV.read = v.read
	newV.write = v.write
	return newV
}

// Release releases the chunk held by v and returns v to the pool.
func (v *View) Release() {
	v.chunk.DecRef()
	*v = View{}
	viewPool.Put(v)
}

func (v *View) sharesChunk() bool {
	return v.chunk.refCount.Load() > 1
}

// Full indicates the chunk is full.
//
// This indicates there is no capacity left to write.
func (v *View) Full() bool {
	return v == nil || v.write == len(v.chunk.data)
}

// Capacity returns the total size of this view's chunk.
func (v *View) Capacity() int {
	return len(v.chunk.data)
}

// Size returns the size of data written to the view.
func (v *View) Size() int {
	return v.write - v.read
}

// TrimFront advances the read index by the given amount.
func (v *View) TrimFront(n int) {
	v.read += n
}

// AsSlice returns a slice of the data written to this view.
func (v *View) AsSlice() []byte {
	if v == nil {
		return nil
	}
	return v.chunk.data[v.read:v.write]
}

// AvailableSize returns the number of bytes available for writing.
func (v *View) AvailableSize() int {
	return len(v.chunk.data) - v.write
}

// Read reads v's data into p.
//
// Implements the io.Reader interface.
func (v *View) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if v.Size() == 0 {
		return 0, io.EOF
	}
	n := copy(p, v.AsSlice())
	v.TrimFront(n)
	return n, nil
}

// ReadAt reads data to the p starting at offset.
//
// Implements the io.ReaderAt interface.
func (v *View) ReadAt(p []byte, off int) (int, error) {
	if off < 0 || off > v.Size() {
		return 0, fmt.Errorf("ReadAt(): offset out of bounds: want 0 < off < %d, got off=%d", v.Size(), off)
	}
	n := copy(p, v.AsSlice()[off:])
	return n, nil
}

// Write writes data to the view's chunk starting at the v.write index. If the
// view's chunk has a reference count greater than 1, the chunk is copied first
// and then written to.
//
// Implements the io.Writer interface.
func (v *View) Write(p []byte) (int, error) {
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.chunk.data[v.write:], p)
	v.write += n
	if n < len(p) {
		return n, fmt.Errorf("could not finish write: want len(p) <= v.AvailableSize(), got len(p)=%d, v.AvailableSize()=%d", len(p), v.AvailableSize())
	}
	return n, nil
}

// WriteAt writes data to the views's chunk starting at start. If the
// view's chunk has a reference count greater than 1, the chunk is copied first
// and then written to.
//
// Implements the io.WriterAt interface.
func (v *View) WriteAt(p []byte, off int) (int, error) {
	if off < 0 || off > v.Size() {
		return 0, fmt.Errorf("write offset out of bounds: want 0 < off < %d, got off=%d", v.Size(), off)
	}
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.AsSlice()[off:], p)
	if n < len(p) {
		return n, fmt.Errorf("could not finish write: want off + len(p) < v.Capacity(), got off=%d, len(p)=%d ,v.Size() = %d", off, len(p), v.Size())
	}
	return n, nil
}

// Grow advances the write index by the given amount.
func (v *View) Grow(n int) {
	if n+v.write > v.Capacity() {
		panic("cannot grow view past capacity")
	}
	v.write += n
}

// CapLength caps the length of the view's read slice to n. If n > v.Size(),
// the function is a no-op.
func (v *View) CapLength(n int) {
	if n < 0 {
		panic("n must be >= 0")
	}
	if n > v.Size() {
		n = v.Size()
	}
	v.write = v.read + n
}

func (v *View) availableSlice() []byte {
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		c := v.chunk.Clone()
		v.chunk = c
	}
	return v.chunk.data[v.write:]
}
