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

package pipe

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/safemem"
)

// buffer encapsulates a queueable byte buffer.
//
// Note that the total size is slightly less than two pages. This
// is done intentionally to ensure that the buffer object aligns
// with runtime internals. We have no hard size or alignment
// requirements. This two page size will effectively minimize
// internal fragmentation, but still have a large enough chunk
// to limit excessive segmentation.
//
// +stateify savable
type buffer struct {
	data  [8144]byte
	read  int
	write int
	bufferEntry
}

// Reset resets internal data.
//
// This must be called before use.
func (b *buffer) Reset() {
	b.read = 0
	b.write = 0
}

// Empty indicates the buffer is empty.
//
// This indicates there is no data left to read.
func (b *buffer) Empty() bool {
	return b.read == b.write
}

// Full indicates the buffer is full.
//
// This indicates there is no capacity left to write.
func (b *buffer) Full() bool {
	return b.write == len(b.data)
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (b *buffer) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	dst := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(b.data[b.write:]))
	n, err := safemem.CopySeq(dst, srcs)
	b.write += int(n)
	return n, err
}

// WriteFromReader writes to the buffer from an io.Reader.
func (b *buffer) WriteFromReader(r io.Reader, count int64) (int64, error) {
	dst := b.data[b.write:]
	if count < int64(len(dst)) {
		dst = b.data[b.write:][:count]
	}
	n, err := r.Read(dst)
	b.write += n
	return int64(n), err
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (b *buffer) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	src := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(b.data[b.read:b.write]))
	n, err := safemem.CopySeq(dsts, src)
	b.read += int(n)
	return n, err
}

// ReadToWriter reads from the buffer into an io.Writer.
func (b *buffer) ReadToWriter(w io.Writer, count int64, dup bool) (int64, error) {
	src := b.data[b.read:b.write]
	if count < int64(len(src)) {
		src = b.data[b.read:][:count]
	}
	n, err := w.Write(src)
	if !dup {
		b.read += n
	}
	return int64(n), err
}

// bufferPool is a pool for buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(buffer)
	},
}

// newBuffer grabs a new buffer from the pool.
func newBuffer() *buffer {
	b := bufferPool.Get().(*buffer)
	b.Reset()
	return b
}
