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

// Package buffer provides the implementation of a buffer view.
//
// A view is an flexible buffer, backed by a pool, supporting the safecopy
// operations natively as well as the ability to grow via either prepend or
// append, as well as shrink.
package buffer

import (
	"sync"
)

const bufferSize = 8144 // See below.

// buffer encapsulates a queueable byte buffer.
//
// Note that the total size is slightly less than two pages. This is done
// intentionally to ensure that the buffer object aligns with runtime
// internals. We have no hard size or alignment requirements. This two page
// size will effectively minimize internal fragmentation, but still have a
// large enough chunk to limit excessive segmentation.
//
// +stateify savable
type buffer struct {
	data  [bufferSize]byte
	read  int
	write int
	bufferEntry
}

// reset resets internal data.
//
// This must be called before returning the buffer to the pool.
func (b *buffer) Reset() {
	b.read = 0
	b.write = 0
}

// Full indicates the buffer is full.
//
// This indicates there is no capacity left to write.
func (b *buffer) Full() bool {
	return b.write == len(b.data)
}

// ReadSize returns the number of bytes available for reading.
func (b *buffer) ReadSize() int {
	return b.write - b.read
}

// ReadMove advances the read index by the given amount.
func (b *buffer) ReadMove(n int) {
	b.read += n
}

// ReadSlice returns the read slice for this buffer.
func (b *buffer) ReadSlice() []byte {
	return b.data[b.read:b.write]
}

// WriteSize returns the number of bytes available for writing.
func (b *buffer) WriteSize() int {
	return len(b.data) - b.write
}

// WriteMove advances the write index by the given amount.
func (b *buffer) WriteMove(n int) {
	b.write += n
}

// WriteSlice returns the write slice for this buffer.
func (b *buffer) WriteSlice() []byte {
	return b.data[b.write:]
}

// bufferPool is a pool for buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(buffer)
	},
}
