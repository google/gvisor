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

package bufferv2

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/sync"
)

// ReadSize is the default amount that a View's size is increased by when an
// io.Reader has more data than a View can hold during calls to ReadFrom.
const ReadSize = 512

var viewPool = sync.Pool{
	New: func() any {
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
//
// +stateify savable
type View struct {
	viewEntry `state:"nosave"`
	read      int
	write     int
	chunk     *chunk
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
	if v == nil {
		panic("cannot clone a nil view")
	}
	v.chunk.IncRef()
	newV := viewPool.Get().(*View)
	newV.chunk = v.chunk
	newV.read = v.read
	newV.write = v.write
	return newV
}

// Release releases the chunk held by v and returns v to the pool.
func (v *View) Release() {
	if v == nil {
		panic("cannot release a nil view")
	}
	v.chunk.DecRef()
	*v = View{}
	viewPool.Put(v)
}

// Reset sets the view's read and write indices back to zero.
func (v *View) Reset() {
	if v == nil {
		panic("cannot reset a nil view")
	}
	v.read = 0
	v.write = 0
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
	if v == nil {
		return 0
	}
	return len(v.chunk.data)
}

// Size returns the size of data written to the view.
func (v *View) Size() int {
	if v == nil {
		return 0
	}
	return v.write - v.read
}

// TrimFront advances the read index by the given amount.
func (v *View) TrimFront(n int) {
	if v.read+n > v.write {
		panic("cannot trim past the end of a view")
	}
	v.read += n
}

// AsSlice returns a slice of the data written to this view.
func (v *View) AsSlice() []byte {
	if v.Size() == 0 {
		return nil
	}
	return v.chunk.data[v.read:v.write]
}

// ToSlice returns an owned copy of the data in this view.
func (v *View) ToSlice() []byte {
	if v.Size() == 0 {
		return nil
	}
	s := make([]byte, v.Size())
	copy(s, v.AsSlice())
	return s
}

// AvailableSize returns the number of bytes available for writing.
func (v *View) AvailableSize() int {
	if v == nil {
		return 0
	}
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

// ReadByte implements the io.ByteReader interface.
func (v *View) ReadByte() (byte, error) {
	if v.Size() == 0 {
		return 0, io.EOF
	}
	b := v.AsSlice()[0]
	v.read++
	return b, nil
}

// WriteTo writes data to w until the view is empty or an error occurs. The
// return value n is the number of bytes written.
//
// WriteTo implements the io.WriterTo interface.
func (v *View) WriteTo(w io.Writer) (n int64, err error) {
	if v.Size() > 0 {
		sz := v.Size()
		m, e := w.Write(v.AsSlice())
		v.TrimFront(m)
		n = int64(m)
		if e != nil {
			return n, e
		}
		if m != sz {
			return n, io.ErrShortWrite
		}
	}
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
	if v == nil {
		panic("cannot write to a nil view")
	}
	if v.AvailableSize() < len(p) {
		v.growCap(len(p) - v.AvailableSize())
	} else if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.chunk.data[v.write:], p)
	v.write += n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// ReadFrom reads data from r until EOF and appends it to the buffer, growing
// the buffer as needed. The return value n is the number of bytes read. Any
// error except io.EOF encountered during the read is also returned.
//
// ReadFrom implements the io.ReaderFrom interface.
func (v *View) ReadFrom(r io.Reader) (n int64, err error) {
	if v == nil {
		panic("cannot write to a nil view")
	}
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	for {
		// Check for EOF to avoid an unnnecesary allocation.
		if _, e := r.Read(nil); e == io.EOF {
			return n, nil
		}
		if v.AvailableSize() == 0 {
			v.growCap(ReadSize)
		}
		m, e := r.Read(v.availableSlice())
		v.write += m
		n += int64(m)

		if e == io.EOF {
			return n, nil
		}
		if e != nil {
			return n, e
		}
	}
}

// WriteAt writes data to the views's chunk starting at start. If the
// view's chunk has a reference count greater than 1, the chunk is copied first
// and then written to.
//
// Implements the io.WriterAt interface.
func (v *View) WriteAt(p []byte, off int) (int, error) {
	if v == nil {
		panic("cannot write to a nil view")
	}
	if off < 0 || off > v.Size() {
		return 0, fmt.Errorf("write offset out of bounds: want 0 < off < %d, got off=%d", v.Size(), off)
	}
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.AsSlice()[off:], p)
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// Grow increases the size of the view. If the new size is greater than the
// view's current capacity, Grow will reallocate the view with an increased
// capacity.
func (v *View) Grow(n int) {
	if v == nil {
		panic("cannot grow a nil view")
	}
	if v.write+n > v.Capacity() {
		v.growCap(n)
	}
	v.write += n
}

// growCap increases the capacity of the view by at least n.
func (v *View) growCap(n int) {
	if v == nil {
		panic("cannot grow a nil view")
	}
	defer v.chunk.DecRef()
	old := v.AsSlice()
	v.chunk = newChunk(v.Capacity() + n)
	copy(v.chunk.data, old)
	v.read = 0
	v.write = len(old)
}

// CapLength caps the length of the view's read slice to n. If n > v.Size(),
// the function is a no-op.
func (v *View) CapLength(n int) {
	if v == nil {
		panic("cannot resize a nil view")
	}
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
