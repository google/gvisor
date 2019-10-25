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

package buffer

import (
	"gvisor.dev/gvisor/pkg/sentry/safemem"
)

// WriteBlock returns this buffer as a write Block.
func (b *Buffer) WriteBlock() safemem.Block {
	return safemem.BlockFromSafeSlice(b.data[b.write:])
}

// ReadBlock returns this buffer as a read Block.
func (b *Buffer) ReadBlock() safemem.Block {
	return safemem.BlockFromSafeSlice(b.data[b.read:b.write])
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// This will advance the write index.
func (v *View) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	var (
		dst    safemem.BlockSeq
		blocks []safemem.Block
	)

	need := int(srcs.NumBytes())
	buf := v.data.Back()

	// Does the last block have sufficient capacity alone?
	if buf != nil && (len(buf.data)-buf.write) > int(srcs.NumBytes()) {
		dst = safemem.BlockSeqOf(buf.WriteBlock())
	} else if need > 0 {
		// Append blocks until sufficient.
		if buf != nil {
			need -= len(buf.data) - buf.write // Remaining.
			blocks = append(blocks, buf.WriteBlock())
		} else {
			buf = new(Buffer)
			v.data.PushBack(buf)
			need -= len(buf.data) // Full block.
			blocks = append(blocks, buf.WriteBlock())
		}
		for need > 0 {
			emptyBuf := new(Buffer)
			v.data.PushBack(emptyBuf)
			need -= len(emptyBuf.data) // Full block.
			blocks = append(blocks, emptyBuf.WriteBlock())
		}
		dst = safemem.BlockSeqFromSlice(blocks)
	}

	// Perform the copy.
	n, err := safemem.CopySeq(dst, srcs)
	v.size += int64(n)

	// Update all indices.
	for left := int(n); buf != nil && left > 0; {
		if left > len(buf.data)-buf.write {
			buf.write = len(buf.data) // Whole block.
			left -= len(buf.data) - buf.write
		} else {
			buf.write += left // Partial block.
			left = 0
		}
		buf = buf.Next()
	}

	return n, err
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
//
// This will not advance the read index; the caller should follow
// this call with a call to TrimFront in order to remove the read
// data from the buffer. This is done to support pipe sematics.
func (v *View) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	var (
		src    safemem.BlockSeq
		blocks []safemem.Block
	)

	// Is all the data in a single block?
	if buf := v.data.Front(); buf != nil && int64(buf.write-buf.read) == v.size {
		src = safemem.BlockSeqOf(buf.ReadBlock())
	} else {
		// Build a list of all the buffers.
		blocks = append(blocks, buf.ReadBlock())
		for buf != nil {
			blocks = append(blocks, buf.ReadBlock())
			buf = buf.Next()
		}
		src = safemem.BlockSeqFromSlice(blocks)
	}

	// Perform the copy.
	n, err := safemem.CopySeq(dsts, src)

	// See above: we would normally advance the read index here, but we
	// don't do that in order to support pipe semantics. We rely on a
	// separate call to TrimFront() in this case.

	return n, err
}
