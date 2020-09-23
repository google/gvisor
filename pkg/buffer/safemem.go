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
	"gvisor.dev/gvisor/pkg/safemem"
)

// WriteBlock returns this buffer as a write Block.
func (b *buffer) WriteBlock() safemem.Block {
	return safemem.BlockFromSafeSlice(b.WriteSlice())
}

// ReadBlock returns this buffer as a read Block.
func (b *buffer) ReadBlock() safemem.Block {
	return safemem.BlockFromSafeSlice(b.ReadSlice())
}

// WriteFromSafememReader writes up to count bytes from r to v and advances the
// write index by the number of bytes written. It calls r.ReadToBlocks() at
// most once.
func (v *View) WriteFromSafememReader(r safemem.Reader, count uint64) (uint64, error) {
	if count == 0 {
		return 0, nil
	}

	var (
		dst    safemem.BlockSeq
		blocks []safemem.Block
	)

	// Need at least one buffer.
	firstBuf := v.data.Back()
	if firstBuf == nil {
		firstBuf = v.pool.get()
		v.data.PushBack(firstBuf)
	}

	// Does the last block have sufficient capacity alone?
	if l := uint64(firstBuf.WriteSize()); l >= count {
		dst = safemem.BlockSeqOf(firstBuf.WriteBlock().TakeFirst64(count))
	} else {
		// Append blocks until sufficient.
		count -= l
		blocks = append(blocks, firstBuf.WriteBlock())
		for count > 0 {
			emptyBuf := v.pool.get()
			v.data.PushBack(emptyBuf)
			block := emptyBuf.WriteBlock().TakeFirst64(count)
			count -= uint64(block.Len())
			blocks = append(blocks, block)
		}
		dst = safemem.BlockSeqFromSlice(blocks)
	}

	// Perform I/O.
	n, err := r.ReadToBlocks(dst)
	v.size += int64(n)

	// Update all indices.
	for left := n; left > 0; firstBuf = firstBuf.Next() {
		if l := firstBuf.WriteSize(); left >= uint64(l) {
			firstBuf.WriteMove(l) // Whole block.
			left -= uint64(l)
		} else {
			firstBuf.WriteMove(int(left)) // Partial block.
			left = 0
		}
	}

	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks. It advances the
// write index by the number of bytes written.
func (v *View) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	return v.WriteFromSafememReader(&safemem.BlockSeqReader{srcs}, srcs.NumBytes())
}

// ReadToSafememWriter reads up to count bytes from v to w. It does not advance
// the read index. It calls w.WriteFromBlocks() at most once.
func (v *View) ReadToSafememWriter(w safemem.Writer, count uint64) (uint64, error) {
	if count == 0 {
		return 0, nil
	}

	var (
		src    safemem.BlockSeq
		blocks []safemem.Block
	)

	firstBuf := v.data.Front()
	if firstBuf == nil {
		return 0, nil // No EOF.
	}

	// Is all the data in a single block?
	if l := uint64(firstBuf.ReadSize()); l >= count {
		src = safemem.BlockSeqOf(firstBuf.ReadBlock().TakeFirst64(count))
	} else {
		// Build a list of all the buffers.
		count -= l
		blocks = append(blocks, firstBuf.ReadBlock())
		for buf := firstBuf.Next(); buf != nil && count > 0; buf = buf.Next() {
			block := buf.ReadBlock().TakeFirst64(count)
			count -= uint64(block.Len())
			blocks = append(blocks, block)
		}
		src = safemem.BlockSeqFromSlice(blocks)
	}

	// Perform I/O. As documented, we don't advance the read index.
	return w.WriteFromBlocks(src)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks. It does not advance the
// read index by the number of bytes read, such that it's only safe to call if
// the caller guarantees that ReadToBlocks will only be called once.
func (v *View) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	return v.ReadToSafememWriter(&safemem.BlockSeqWriter{dsts}, dsts.NumBytes())
}
