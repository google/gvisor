// Copyright 2020 The gVisor Authors.
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
)

// View is a non-linear buffer.
//
// All methods are thread compatible.
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

// ReadAt implements io.ReaderAt.ReadAt.
func (v *View) ReadAt(p []byte, offset int64) (int, error) {
	var (
		skipped int64
		done    int64
	)
	for buf := v.data.Front(); buf != nil && done < int64(len(p)); buf = buf.Next() {
		needToSkip := int(offset - skipped)
		if sz := buf.ReadSize(); sz <= needToSkip {
			skipped += int64(sz)
			continue
		}

		// Actually read data.
		n := copy(p[done:], buf.ReadSlice()[needToSkip:])
		skipped += int64(needToSkip)
		done += int64(n)
	}
	if int(done) < len(p) || offset+done == v.size {
		return int(done), io.EOF
	}
	return int(done), nil
}

// advanceRead advances the view's read index.
//
// Precondition: there must be sufficient bytes in the buffer.
func (v *View) advanceRead(count int64) {
	for buf := v.data.Front(); buf != nil && count > 0; {
		sz := int64(buf.ReadSize())
		if sz > count {
			// There is still data for reading.
			buf.ReadMove(int(count))
			v.size -= count
			count = 0
			break
		}

		// Consume the whole buffer.
		oldBuf := buf
		buf = buf.Next() // Iterate.
		v.data.Remove(oldBuf)
		oldBuf.Reset()
		bufferPool.Put(oldBuf)

		// Update counts.
		count -= sz
		v.size -= sz
	}
	if count > 0 {
		panic(fmt.Sprintf("advanceRead still has %d bytes remaining", count))
	}
}

// Truncate truncates the view to the given bytes.
//
// This will not grow the view, only shrink it. If a length is passed that is
// greater than the current size of the view, then nothing will happen.
//
// Precondition: length must be >= 0.
func (v *View) Truncate(length int64) {
	if length < 0 {
		panic("negative length provided")
	}
	if length >= v.size {
		return // Nothing to do.
	}
	for buf := v.data.Back(); buf != nil && v.size > length; buf = v.data.Back() {
		sz := int64(buf.ReadSize())
		if after := v.size - sz; after < length {
			// Truncate the buffer locally.
			left := (length - after)
			buf.write = buf.read + int(left)
			v.size = length
			break
		}

		// Drop the buffer completely; see above.
		v.data.Remove(buf)
		buf.Reset()
		bufferPool.Put(buf)
		v.size -= sz
	}
}

// Grow grows the given view to the number of bytes, which will be appended. If
// zero is true, all these bytes will be zero. If zero is false, then this is
// the caller's responsibility.
//
// Precondition: length must be >= 0.
func (v *View) Grow(length int64, zero bool) {
	if length < 0 {
		panic("negative length provided")
	}
	for v.size < length {
		buf := v.data.Back()

		// Is there some space in the last buffer?
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*buffer)
			v.data.PushBack(buf)
		}

		// Write up to length bytes.
		sz := buf.WriteSize()
		if int64(sz) > length-v.size {
			sz = int(length - v.size)
		}

		// Zero the written section; note that this pattern is
		// specifically recognized and optimized by the compiler.
		if zero {
			for i := buf.write; i < buf.write+sz; i++ {
				buf.data[i] = 0
			}
		}

		// Advance the index.
		buf.WriteMove(sz)
		v.size += int64(sz)
	}
}

// Prepend prepends the given data.
func (v *View) Prepend(data []byte) {
	// Is there any space in the first buffer?
	if buf := v.data.Front(); buf != nil && buf.read > 0 {
		// Fill up before the first write.
		avail := buf.read
		bStart := 0
		dStart := len(data) - avail
		if avail > len(data) {
			bStart = avail - len(data)
			dStart = 0
		}
		n := copy(buf.data[bStart:], data[dStart:])
		data = data[:dStart]
		v.size += int64(n)
		buf.read -= n
	}

	for len(data) > 0 {
		// Do we need an empty buffer?
		buf := bufferPool.Get().(*buffer)
		v.data.PushFront(buf)

		// The buffer is empty; copy last chunk.
		avail := len(buf.data)
		bStart := 0
		dStart := len(data) - avail
		if avail > len(data) {
			bStart = avail - len(data)
			dStart = 0
		}

		// We have to put the data at the end of the current
		// buffer in order to ensure that the next prepend will
		// correctly fill up the beginning of this buffer.
		n := copy(buf.data[bStart:], data[dStart:])
		data = data[:dStart]
		v.size += int64(n)
		buf.read = len(buf.data) - n
		buf.write = len(buf.data)
	}
}

// Append appends the given data.
func (v *View) Append(data []byte) {
	for done := 0; done < len(data); {
		buf := v.data.Back()

		// Ensure there's a buffer with space.
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*buffer)
			v.data.PushBack(buf)
		}

		// Copy in to the given buffer.
		n := copy(buf.WriteSlice(), data[done:])
		done += n
		buf.WriteMove(n)
		v.size += int64(n)
	}
}

// Flatten returns a flattened copy of this data.
//
// This method should not be used in any performance-sensitive paths. It may
// allocate a fresh byte slice sufficiently large to contain all the data in
// the buffer. This is principally for debugging.
//
// N.B. Tee data still belongs to this view, as if there is a single buffer
// present, then it will be returned directly. This should be used for
// temporary use only, and a reference to the given slice should not be held.
func (v *View) Flatten() []byte {
	if buf := v.data.Front(); buf == nil {
		return nil // No data at all.
	} else if buf.Next() == nil {
		return buf.ReadSlice() // Only one buffer.
	}
	data := make([]byte, 0, v.size) // Need to flatten.
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		// Copy to the allocated slice.
		data = append(data, buf.ReadSlice()...)
	}
	return data
}

// Size indicates the total amount of data available in this view.
func (v *View) Size() int64 {
	return v.size
}

// Copy makes a strict copy of this view.
func (v *View) Copy() (other View) {
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		other.Append(buf.ReadSlice())
	}
	return
}

// Apply applies the given function across all valid data.
func (v *View) Apply(fn func([]byte)) {
	for buf := v.data.Front(); buf != nil; buf = buf.Next() {
		fn(buf.ReadSlice())
	}
}

// Merge merges the provided View with this one.
//
// The other view will be appended to v, and other will be empty after this
// operation completes.
func (v *View) Merge(other *View) {
	// Copy over all buffers.
	for buf := other.data.Front(); buf != nil; buf = other.data.Front() {
		other.data.Remove(buf)
		v.data.PushBack(buf)
	}

	// Adjust sizes.
	v.size += other.size
	other.size = 0
}

// WriteFromReader writes to the buffer from an io.Reader.
//
// A minimum read size equal to unsafe.Sizeof(unintptr) is enforced,
// provided that count is greater than or equal to unsafe.Sizeof(uintptr).
func (v *View) WriteFromReader(r io.Reader, count int64) (int64, error) {
	var (
		done int64
		n    int
		err  error
	)
	for done < count {
		buf := v.data.Back()

		// Ensure we have an empty buffer.
		if buf == nil || buf.Full() {
			buf = bufferPool.Get().(*buffer)
			v.data.PushBack(buf)
		}

		// Is this less than the minimum batch?
		if buf.WriteSize() < minBatch && (count-done) >= int64(minBatch) {
			tmp := make([]byte, minBatch)
			n, err = r.Read(tmp)
			v.Append(tmp[:n])
			done += int64(n)
			if err != nil {
				break
			}
			continue
		}

		// Limit the read, if necessary.
		sz := buf.WriteSize()
		if left := count - done; int64(sz) > left {
			sz = int(left)
		}

		// Pass the relevant portion of the buffer.
		n, err = r.Read(buf.WriteSlice()[:sz])
		buf.WriteMove(n)
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
//
// N.B. This does not consume the bytes read. TrimFront should
// be called appropriately after this call in order to do so.
//
// A minimum write size equal to unsafe.Sizeof(unintptr) is enforced,
// provided that count is greater than or equal to unsafe.Sizeof(uintptr).
func (v *View) ReadToWriter(w io.Writer, count int64) (int64, error) {
	var (
		done int64
		n    int
		err  error
	)
	offset := 0 // Spill-over for batching.
	for buf := v.data.Front(); buf != nil && done < count; buf = buf.Next() {
		// Has this been consumed? Skip it.
		sz := buf.ReadSize()
		if sz <= offset {
			offset -= sz
			continue
		}
		sz -= offset

		// Is this less than the minimum batch?
		left := count - done
		if sz < minBatch && left >= int64(minBatch) && (v.size-done) >= int64(minBatch) {
			tmp := make([]byte, minBatch)
			n, err = v.ReadAt(tmp, done)
			w.Write(tmp[:n])
			done += int64(n)
			offset = n - sz // Reset below.
			if err != nil {
				break
			}
			continue
		}

		// Limit the write if necessary.
		if int64(sz) >= left {
			sz = int(left)
		}

		// Perform the actual write.
		n, err = w.Write(buf.ReadSlice()[offset : offset+sz])
		done += int64(n)
		if err != nil {
			break
		}

		// Reset spill-over.
		offset = 0
	}
	return done, err
}
