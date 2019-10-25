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

// Package buffer provides the implementation of a buffer view.
package buffer

import (
	"fmt"
	"io"
)

// View is a non-linear buffer.
//
// No locking is provided.
//
// +stateify savable
type View struct {
	data bufferList
	size int64
}

// TrimFront removes the first count bytes from the buffer.
func (v *View) TrimFront(count int64) {
	if count >= v.size {
		v.advanceRead(v.size)
	} else {
		v.advanceRead(count)
	}
}

// Read implements io.Reader.Read.
//
// Note that reading does not advance the read index. This must be done
// manually using TrimFront or other methods.
func (v *View) Read(p []byte) (int, error) {
	return v.ReadAt(p, 0)
}

// ReadAt implements io.ReaderAt.ReadAt.
func (v *View) ReadAt(p []byte, offset int64) (int, error) {
	var (
		skipped int64
		done    int64
	)
	for buf := v.data.Front(); buf != nil && done < int64(len(p)); buf = buf.Next() {
		if needToSkip := int(offset - skipped); needToSkip > 0 {
			if l := buf.write - buf.read; l <= needToSkip {
				skipped += int64(l)
			} else {
				// There is a partial overlap here. At least
				// one byte will be actually read. We need to
				// do this inline.
				n := copy(p[done:], buf.data[buf.read+needToSkip:buf.read+l])
				skipped += int64(needToSkip)
				done += int64(n)
			}
		} else {
			if l := buf.write - buf.read; l < int(int64(len(p))-done) {
				copy(p[done:], buf.data[buf.read:buf.write])
				done += int64(l)
			} else {
				n := copy(p[done:], buf.data[buf.read:buf.read+l])
				done += int64(n)
			}
		}
	}
	if int(done) < len(p) {
		return int(done), io.EOF
	}
	return int(done), nil
}

// Write implements io.Writer.Write.
func (v *View) Write(p []byte) (int, error) {
	v.Append(p) // Does not fail.
	return len(p), nil
}

// advanceRead advances the view's read index.
//
// Precondition: there must be sufficient bytes in the buffer.
func (v *View) advanceRead(count int64) {
	for buf := v.data.Front(); buf != nil && count > 0; {
		if l := int64(buf.write - buf.read); l <= count {
			buf.read += int(l)
			count -= l
			v.size -= l

			// When all data has been read from a buffer, we push
			// it into the empty buffer pool for reuse.
			oldBuf := buf
			buf = buf.Next() // Iterate.
			oldBuf.Reset()
			v.data.Remove(oldBuf)
			bufferPool.Put(oldBuf)
		} else {
			// There is still data for reading.
			buf.read += int(count)
			v.size -= count
			count = 0
			break
		}
	}
	if count > 0 {
		panic(fmt.Sprintf("advanceRead still has %d bytes remaining", count))
	}
}

// Truncate truncates the view to the given bytes.
func (v *View) Truncate(length int64) {
	if length < 0 || length >= v.size {
		return // Nothing to do.
	}
	for buf := v.data.Back(); buf != nil && v.size > length; buf = v.data.Back() {
		l := int64(buf.write - buf.read) // Local bytes.
		switch {
		case v.size-l >= length:
			// Drop the buffer completely; see above.
			v.data.Remove(buf)
			v.size -= l
			buf.Reset()
			bufferPool.Put(buf)

		case v.size > length && v.size-l < length:
			// Just truncate the buffer locally.
			delta := (length - (v.size - l))
			buf.write = buf.read + int(delta)
			v.size = length

		default:
			// Should never happen.
			panic("invalid buffer during truncation")
		}
	}
	v.size = length // Save the new size.
}

// Grow grows the given view to the number of bytes. If zero
// is true, all these bytes will be zero. If zero is false,
// then this is the caller's responsibility.
//
// Precondition: length must be >= 0.
func (v *View) Grow(length int64, zero bool) {
	if length < 0 {
		panic("negative length provided")
	}
	for v.size < length {
		buf := v.data.Back()

		// Is there at least one buffer?
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*Buffer)
			v.data.PushBack(buf)
		}

		// Write up to length bytes.
		l := len(buf.data) - buf.write
		if int64(l) > length-v.size {
			l = int(length - v.size)
		}

		// Zero the written section; note that this pattern is
		// specifically recognized and optimized by the compiler.
		if zero {
			for i := buf.write; i < buf.write+l; i++ {
				buf.data[i] = 0
			}
		}

		// Advance the index.
		buf.write += l
		v.size += int64(l)
	}
}

// Prepend prepends the given data.
func (v *View) Prepend(data []byte) {
	// Is there any space in the first buffer?
	if buf := v.data.Front(); buf != nil && buf.read > 0 {
		// Fill up before the first write.
		avail := buf.read
		copy(buf.data[0:], data[len(data)-avail:])
		data = data[:len(data)-avail]
		v.size += int64(avail)
	}

	for len(data) > 0 {
		// Do we need an empty buffer?
		buf := bufferPool.Get().(*Buffer)
		v.data.PushFront(buf)

		// The buffer is empty; copy last chunk.
		start := len(data) - len(buf.data)
		if start < 0 {
			start = 0 // Everything.
		}

		// We have to put the data at the end of the current
		// buffer in order to ensure that the next prepend will
		// correctly fill up the beginning of this buffer.
		bStart := len(buf.data) - len(data[start:])
		n := copy(buf.data[bStart:], data[start:])
		buf.read = bStart
		buf.write = len(buf.data)
		data = data[:start]
		v.size += int64(n)
	}
}

// Append appends the given data.
func (v *View) Append(data []byte) {
	for len(data) > 0 {
		buf := v.data.Back()

		// Find the first empty buffer.
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*Buffer)
			v.data.PushBack(buf)
		}

		// Copy in to the given buffer.
		n := copy(buf.data[buf.write:], data)
		data = data[n:]
		buf.write += n
		v.size += int64(n)
	}
}

// Flatten returns a flattened copy of this data.
//
// This method should not be used in any performance-sensitive paths. It is
// guaranteed to allocate a fresh byte slice sufficiently large to contain all
// the data in the buffer.
func (v *View) Flatten() []byte {
	data := make([]byte, 0, v.size)
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		// Copy to the allocated slice.
		data = append(data, buf.data[buf.read:buf.write]...)
	}
	return data
}

// Size indicates the total amount of data available in this view.
func (v *View) Size() (sz int64) {
	sz = v.size // Pre-calculated.
	return sz
}

// Copy makes a strict copy of this view.
func (v *View) Copy() (other View) {
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		other.Append(buf.data[buf.read:buf.write])
	}
	return other
}

// Apply applies the given function across all valid data.
func (v *View) Apply(fn func([]byte)) {
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		if l := int64(buf.write - buf.read); l > 0 {
			fn(buf.data[buf.read:buf.write])
		}
	}
}

// Merge merges the provided View with this one.
//
// The other view will be empty after this operation.
func (v *View) Merge(other *View) {
	// Copy over all buffers.
	for buf := other.data.Front(); buf != nil && !buf.Empty(); buf = other.data.Front() {
		other.data.Remove(buf)
		v.data.PushBack(buf)
	}

	// Adjust sizes.
	v.size += other.size
	other.size = 0
}

// WriteFromReader writes to the buffer from an io.Reader.
func (v *View) WriteFromReader(r io.Reader, count int64) (int64, error) {
	var (
		done int64
		n    int
		err  error
	)
	for done < count {
		buf := v.data.Back()

		// Find the first empty buffer.
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*Buffer)
			v.data.PushBack(buf)
		}

		// Limit the write, if necessary.
		end := len(buf.data)
		if int64(end-buf.read) > count-done {
			end = buf.read + int(count-done)
		}

		// Pass the relevant portion of the buffer.
		n, err = r.Read(buf.data[buf.write:end])
		buf.write += n
		done += int64(n)
		v.size += int64(n)
		if err == io.EOF {
			err = nil // Short write allowed.
			break
		} else if err != nil {
			break
		}
	}
	return done, err
}

// ReadToWriter reads from the buffer into an io.Writer.
func (v *View) ReadToWriter(w io.Writer, count int64) (int64, error) {
	var (
		done int64
		n    int
		err  error
	)
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		if l := buf.write - buf.read; int64(l) < (count - done) {
			n, err = w.Write(buf.data[buf.read:buf.write])
		} else {
			n, err = w.Write(buf.data[buf.read : buf.read+l])
		}
		done += int64(n)
		if err != nil {
			break
		}
	}
	return done, err
}
