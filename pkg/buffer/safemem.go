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

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// This will advance the write index.
func (v *View) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	need := int(srcs.NumBytes())
	if need == 0 {
		return 0, nil
	}

	var (
		dst    safemem.BlockSeq
		blocks []safemem.Block
	)

	// Need at least one buffer.
	firstBuf := v.data.Back()
	if firstBuf == nil {
		firstBuf = bufferPool.Get().(*buffer)
		v.data.PushBack(firstBuf)
	}

	// Does the last block have sufficient capacity alone?
	if l := firstBuf.WriteSize(); l >= need {
		dst = safemem.BlockSeqOf(firstBuf.WriteBlock())
	} else {
		// Append blocks until sufficient.
		need -= l
		blocks = append(blocks, firstBuf.WriteBlock())
		for need > 0 {
			emptyBuf := bufferPool.Get().(*buffer)
			v.data.PushBack(emptyBuf)
			need -= emptyBuf.WriteSize()
			blocks = append(blocks, emptyBuf.WriteBlock())
		}
		dst = safemem.BlockSeqFromSlice(blocks)
	}

	// Perform the copy.
	n, err := safemem.CopySeq(dst, srcs)
	v.size += int64(n)

	// Update all indices.
	for left := int(n); left > 0; firstBuf = firstBuf.Next() {
		if l := firstBuf.WriteSize(); left >= l {
			firstBuf.WriteMove(l) // Whole block.
			left -= l
		} else {
			firstBuf.WriteMove(left) // Partial block.
			left = 0
		}
	}

	return n, err
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
//
// This will not advance the read index; the caller should follow
// this call with a call to TrimFront in order to remove the read
// data from the buffer. This is done to support pipe sematics.
func (v *View) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	need := int(dsts.NumBytes())
	if need == 0 {
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
	if l := firstBuf.ReadSize(); l >= need {
		src = safemem.BlockSeqOf(firstBuf.ReadBlock())
	} else {
		// Build a list of all the buffers.
		need -= l
		blocks = append(blocks, firstBuf.ReadBlock())
		for buf := firstBuf.Next(); buf != nil && need > 0; buf = buf.Next() {
			need -= buf.ReadSize()
			blocks = append(blocks, buf.ReadBlock())
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
