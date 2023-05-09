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

// Package bufferv2 provides the implementation of a non-contiguous buffer that
// is reference counted, pooled, and copy-on-write. It allows O(1) append,
// and prepend operations.
package bufferv2

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// Buffer is a non-linear buffer.
//
// +stateify savable
type Buffer struct {
	data viewList `state:".([]byte)"`
	size int64
}

func (b *Buffer) removeView(v *View) {
	b.data.Remove(v)
	v.Release()
}

// MakeWithData creates a new Buffer initialized with given data. This function
// should be used with caution to avoid unnecessary []byte allocations. When in
// doubt use NewWithView to maximize chunk reuse.
func MakeWithData(b []byte) Buffer {
	buf := Buffer{}
	if len(b) == 0 {
		return buf
	}
	v := NewViewWithData(b)
	buf.Append(v)
	return buf
}

// MakeWithView creates a new Buffer initialized with given view. This function
// takes ownership of v.
func MakeWithView(v *View) Buffer {
	if v == nil {
		return Buffer{}
	}
	b := Buffer{
		size: int64(v.Size()),
	}
	if b.size == 0 {
		v.Release()
		return b
	}
	b.data.PushBack(v)
	return b
}

// Release frees all resources held by b.
func (b *Buffer) Release() {
	for v := b.data.Front(); v != nil; v = b.data.Front() {
		b.removeView(v)
	}
	b.size = 0
}

// TrimFront removes the first count bytes from the buffer.
func (b *Buffer) TrimFront(count int64) {
	if count >= b.size {
		b.advanceRead(b.size)
	} else {
		b.advanceRead(count)
	}
}

// ReadAt implements io.ReaderAt.ReadAt.
func (b *Buffer) ReadAt(p []byte, offset int64) (int, error) {
	var (
		skipped int64
		done    int64
	)
	for v := b.data.Front(); v != nil && done < int64(len(p)); v = v.Next() {
		needToSkip := int(offset - skipped)
		if sz := v.Size(); sz <= needToSkip {
			skipped += int64(sz)
			continue
		}

		// Actually read data.
		n := copy(p[done:], v.AsSlice()[needToSkip:])
		skipped += int64(needToSkip)
		done += int64(n)
	}
	if int(done) < len(p) || offset+done == b.size {
		return int(done), io.EOF
	}
	return int(done), nil
}

// advanceRead advances the Buffer's read index.
//
// Precondition: there must be sufficient bytes in the buffer.
func (b *Buffer) advanceRead(count int64) {
	for v := b.data.Front(); v != nil && count > 0; {
		sz := int64(v.Size())
		if sz > count {
			// There is still data for reading.
			v.TrimFront(int(count))
			b.size -= count
			count = 0
			return
		}

		// Consume the whole view.
		oldView := v
		v = v.Next() // Iterate.
		b.removeView(oldView)

		// Update counts.
		count -= sz
		b.size -= sz
	}
	if count > 0 {
		panic(fmt.Sprintf("advanceRead still has %d bytes remaining", count))
	}
}

// Truncate truncates the Buffer to the given length.
//
// This will not grow the Buffer, only shrink it. If a length is passed that is
// greater than the current size of the Buffer, then nothing will happen.
//
// Precondition: length must be >= 0.
func (b *Buffer) Truncate(length int64) {
	if length < 0 {
		panic("negative length provided")
	}
	if length >= b.size {
		return // Nothing to do.
	}
	for v := b.data.Back(); v != nil && b.size > length; v = b.data.Back() {
		sz := int64(v.Size())
		if after := b.size - sz; after < length {
			// Truncate the buffer locally.
			left := (length - after)
			v.write = v.read + int(left)
			b.size = length
			break
		}

		// Drop the buffer completely; see above.
		b.removeView(v)
		b.size -= sz
	}
}

// GrowTo grows the given Buffer to the number of bytes, which will be appended.
// If zero is true, all these bytes will be zero. If zero is false, then this is
// the caller's responsibility.
//
// Precondition: length must be >= 0.
func (b *Buffer) GrowTo(length int64, zero bool) {
	if length < 0 {
		panic("negative length provided")
	}
	for b.size < length {
		v := b.data.Back()

		// Is there some space in the last buffer?
		if v.Full() {
			v = NewView(int(length - b.size))
			b.data.PushBack(v)
		}

		// Write up to length bytes.
		sz := v.AvailableSize()
		if int64(sz) > length-b.size {
			sz = int(length - b.size)
		}

		// Zero the written section; note that this pattern is
		// specifically recognized and optimized by the compiler.
		if zero {
			for i := v.write; i < v.write+sz; i++ {
				v.chunk.data[i] = 0
			}
		}

		// Advance the index.
		v.Grow(sz)
		b.size += int64(sz)
	}
}

// Prepend prepends the given data. Prepend takes ownership of src.
func (b *Buffer) Prepend(src *View) error {
	if src == nil {
		return nil
	}
	if src.Size() == 0 {
		src.Release()
		return nil
	}
	// If the first buffer does not have room just prepend the view.
	v := b.data.Front()
	if v == nil || v.read == 0 {
		b.prependOwned(src)
		return nil
	}

	// If there's room at the front and we won't incur a copy by writing to this
	// view, fill in the extra room first.
	if !v.sharesChunk() {
		avail := v.read
		vStart := 0
		srcStart := src.Size() - avail
		if avail > src.Size() {
			vStart = avail - src.Size()
			srcStart = 0
		}
		// Save the write index and restore it after.
		old := v.write
		v.read = vStart
		n, err := v.WriteAt(src.AsSlice()[srcStart:], 0)
		if err != nil {
			return fmt.Errorf("could not write to view during append: %w", err)
		}
		b.size += int64(n)
		v.write = old
		src.write = srcStart

		// If there's no more to be written, then we're done.
		if src.Size() == 0 {
			src.Release()
			return nil
		}
	}

	// Otherwise, just prepend the view.
	b.prependOwned(src)
	return nil
}

// Append appends the given data. Append takes ownership of src.
func (b *Buffer) Append(src *View) error {
	if src == nil {
		return nil
	}
	if src.Size() == 0 {
		src.Release()
		return nil
	}
	// If the last buffer is full, just append the view.
	v := b.data.Back()
	if v.Full() {
		b.appendOwned(src)
		return nil
	}

	// If a write won't incur a copy, then fill the back of the existing last
	// chunk.
	if !v.sharesChunk() {
		writeSz := src.Size()
		if src.Size() > v.AvailableSize() {
			writeSz = v.AvailableSize()
		}
		done, err := v.Write(src.AsSlice()[:writeSz])
		if err != nil {
			return fmt.Errorf("could not write to view during append: %w", err)
		}
		src.TrimFront(done)
		b.size += int64(done)
		if src.Size() == 0 {
			src.Release()
			return nil
		}
	}

	// If there is still data left just append the src.
	b.appendOwned(src)
	return nil
}

func (b *Buffer) appendOwned(v *View) {
	b.data.PushBack(v)
	b.size += int64(v.Size())
}

func (b *Buffer) prependOwned(v *View) {
	b.data.PushFront(v)
	b.size += int64(v.Size())
}

// PullUp makes the specified range contiguous and returns the backing memory.
func (b *Buffer) PullUp(offset, length int) (View, bool) {
	if length == 0 {
		return View{}, true
	}
	tgt := Range{begin: offset, end: offset + length}
	if tgt.Intersect(Range{end: int(b.size)}).Len() != length {
		return View{}, false
	}

	curr := Range{}
	v := b.data.Front()
	for ; v != nil; v = v.Next() {
		origLen := v.Size()
		curr.end = curr.begin + origLen

		if x := curr.Intersect(tgt); x.Len() == tgt.Len() {
			// buf covers the whole requested target range.
			sub := x.Offset(-curr.begin)
			// Don't increment the reference count of the underlying chunk. Views
			// returned by PullUp are explicitly unowned and read only
			new := View{
				read:  v.read + sub.begin,
				write: v.read + sub.end,
				chunk: v.chunk,
			}
			return new, true
		} else if x.Len() > 0 {
			// buf is pointing at the starting buffer we want to merge.
			break
		}

		curr.begin += origLen
	}

	// Calculate the total merged length.
	totLen := 0
	for n := v; n != nil; n = n.Next() {
		totLen += n.Size()
		if curr.begin+totLen >= tgt.end {
			break
		}
	}

	// Merge the buffers.
	merged := NewViewSize(totLen)
	off := 0
	for n := v; n != nil && off < totLen; {
		merged.WriteAt(n.AsSlice(), off)
		off += n.Size()

		// Remove buffers except for the first one, which will be reused.
		if n == v {
			n = n.Next()
		} else {
			old := n
			n = n.Next()
			b.removeView(old)
		}
	}
	// Make data the first buffer.
	b.data.InsertBefore(v, merged)
	b.removeView(v)

	r := tgt.Offset(-curr.begin)
	pulled := View{
		read:  r.begin,
		write: r.end,
		chunk: merged.chunk,
	}
	return pulled, true
}

// Flatten returns a flattened copy of this data.
//
// This method should not be used in any performance-sensitive paths. It may
// allocate a fresh byte slice sufficiently large to contain all the data in
// the buffer. This is principally for debugging.
//
// N.B. Tee data still belongs to this Buffer, as if there is a single buffer
// present, then it will be returned directly. This should be used for
// temporary use only, and a reference to the given slice should not be held.
func (b *Buffer) Flatten() []byte {
	if v := b.data.Front(); v == nil {
		return nil // No data at all.
	}
	data := make([]byte, 0, b.size) // Need to flatten.
	for v := b.data.Front(); v != nil; v = v.Next() {
		// Copy to the allocated slice.
		data = append(data, v.AsSlice()...)
	}
	return data
}

// Size indicates the total amount of data available in this Buffer.
func (b *Buffer) Size() int64 {
	return b.size
}

// Clone creates a copy-on-write clone of b. The underlying chunks are shared
// until they are written to.
func (b *Buffer) Clone() Buffer {
	other := Buffer{
		size: b.size,
	}
	for v := b.data.Front(); v != nil; v = v.Next() {
		newView := v.Clone()
		other.data.PushBack(newView)
	}
	return other
}

// Apply applies the given function across all valid data.
func (b *Buffer) Apply(fn func(*View)) {
	for v := b.data.Front(); v != nil; v = v.Next() {
		d := v.Clone()
		fn(d)
		d.Release()
	}
}

// SubApply applies fn to a given range of data in b. Any part of the range
// outside of b is ignored.
func (b *Buffer) SubApply(offset, length int, fn func(*View)) {
	for v := b.data.Front(); length > 0 && v != nil; v = v.Next() {
		if offset >= v.Size() {
			offset -= v.Size()
			continue
		}
		d := v.Clone()
		if offset > 0 {
			d.TrimFront(offset)
			offset = 0
		}
		if length < d.Size() {
			d.write = d.read + length
		}
		fn(d)
		length -= d.Size()
		d.Release()
	}
}

// Checksum calculates a checksum over the buffer's payload starting at offset.
func (b *Buffer) Checksum(offset int) uint16 {
	if offset >= int(b.size) {
		return 0
	}
	var v *View
	for v = b.data.Front(); v != nil && offset >= v.Size(); v = v.Next() {
		offset -= v.Size()
	}

	var cs checksum.Checksumer
	cs.Add(v.AsSlice()[offset:])
	for v = v.Next(); v != nil; v = v.Next() {
		cs.Add(v.AsSlice())
	}
	return cs.Checksum()
}

// Merge merges the provided Buffer with this one.
//
// The other Buffer will be appended to v, and other will be empty after this
// operation completes.
func (b *Buffer) Merge(other *Buffer) {
	// Copy over all buffers.
	for v := other.data.Front(); v != nil; v = other.data.Front() {
		b.Append(v.Clone())
		other.removeView(v)
	}

	// Adjust sizes.
	other.size = 0
}

// WriteFromReader writes to the buffer from an io.Reader. A maximum read size
// of MaxChunkSize is enforced to prevent allocating views from the heap.
func (b *Buffer) WriteFromReader(r io.Reader, count int64) (int64, error) {
	var done int64
	for done < count {
		vsize := count - done
		if vsize > MaxChunkSize {
			vsize = MaxChunkSize
		}
		v := NewView(int(vsize))
		lr := io.LimitedReader{R: r, N: vsize}
		n, err := io.Copy(v, &lr)
		b.Append(v)
		done += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

// ReadToWriter reads from the buffer into an io.Writer.
//
// N.B. This does not consume the bytes read. TrimFront should
// be called appropriately after this call in order to do so.
func (b *Buffer) ReadToWriter(w io.Writer, count int64) (int64, error) {
	bytesLeft := int(count)
	for v := b.data.Front(); v != nil && bytesLeft > 0; v = v.Next() {
		view := v.Clone()
		if view.Size() > bytesLeft {
			view.CapLength(bytesLeft)
		}
		n, err := io.Copy(w, view)
		bytesLeft -= int(n)
		view.Release()
		if err != nil {
			return count - int64(bytesLeft), err
		}
	}
	return count - int64(bytesLeft), nil
}

// read implements the io.Reader interface. This method is used by BufferReader
// to consume its underlying buffer. To perform io operations on buffers
// directly, use ReadToWriter or WriteToReader.
func (b *Buffer) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.Size() == 0 {
		return 0, io.EOF
	}
	done := 0
	v := b.data.Front()
	for v != nil && done < len(p) {
		n, err := v.Read(p[done:])
		done += n
		next := v.Next()
		if v.Size() == 0 {
			b.removeView(v)
		}
		b.size -= int64(n)
		if err != nil && err != io.EOF {
			return done, err
		}
		v = next
	}
	return done, nil
}

// readByte implements the io.ByteReader interface. This method is used by
// BufferReader to consume its underlying buffer. To perform io operations on
// buffers directly, use ReadToWriter or WriteToReader.
func (b *Buffer) readByte() (byte, error) {
	if b.Size() == 0 {
		return 0, io.EOF
	}
	v := b.data.Front()
	bt := v.AsSlice()[0]
	b.TrimFront(1)
	return bt, nil
}

// AsBufferReader returns the Buffer as a BufferReader capabable of io methods.
// The new BufferReader takes ownership of b.
func (b *Buffer) AsBufferReader() BufferReader {
	return BufferReader{b}
}

// BufferReader implements io methods on Buffer. Users must call Close()
// when finished with the buffer to free the underlying memory.
type BufferReader struct {
	b *Buffer
}

// Read implements the io.Reader interface.
func (br *BufferReader) Read(p []byte) (int, error) {
	return br.b.read(p)
}

// ReadByte implements the io.ByteReader interface.
func (br *BufferReader) ReadByte() (byte, error) {
	return br.b.readByte()
}

// Close implements the io.Closer interface.
func (br *BufferReader) Close() {
	br.b.Release()
}

// Len returns the number of bytes in the unread portion of the buffer.
func (br *BufferReader) Len() int {
	return int(br.b.Size())
}

// Range specifies a range of buffer.
type Range struct {
	begin int
	end   int
}

// Intersect returns the intersection of x and y.
func (x Range) Intersect(y Range) Range {
	if x.begin < y.begin {
		x.begin = y.begin
	}
	if x.end > y.end {
		x.end = y.end
	}
	if x.begin >= x.end {
		return Range{}
	}
	return x
}

// Offset returns x offset by off.
func (x Range) Offset(off int) Range {
	x.begin += off
	x.end += off
	return x
}

// Len returns the length of x.
func (x Range) Len() int {
	l := x.end - x.begin
	if l < 0 {
		l = 0
	}
	return l
}
