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

	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// This is log2(baseChunkSize). This number is used to calculate which pool
	// to use for a payload size by right shifting the payload size by this
	// number and passing the result to MostSignificantOne64.
	baseChunkSizeLog2 = 6

	// This is the size of the buffers in the first pool. Each subsequent pool
	// creates payloads 2^(pool index) times larger than the first pool's
	// payloads.
	baseChunkSize = 1 << baseChunkSizeLog2 // 64

	// MaxChunkSize is largest payload size that we pool. Payloads larger than
	// this will be allocated from the heap and garbage collected as normal.
	MaxChunkSize = baseChunkSize << (numPools - 1) // 64k

	// The number of chunk pools we have for use.
	numPools = 11
)

// chunkPools is a collection of pools for payloads of different sizes. The
// size of the payloads doubles in each successive pool.
var chunkPools [numPools]sync.Pool

func init() {
	for i := 0; i < numPools; i++ {
		chunkSize := baseChunkSize * (1 << i)
		chunkPools[i].New = func() any {
			return &chunk{
				data: make([]byte, chunkSize),
			}
		}
	}
}

// Precondition: 0 <= size <= maxChunkSize
func getChunkPool(size int) *sync.Pool {
	idx := 0
	if size > baseChunkSize {
		idx = bits.MostSignificantOne64(uint64(size) >> baseChunkSizeLog2)
		if size > 1<<(idx+baseChunkSizeLog2) {
			idx++
		}
	}
	if idx >= numPools {
		panic(fmt.Sprintf("pool for chunk size %d does not exist", size))
	}
	return &chunkPools[idx]
}

// ExternalStorage owns memory supplied to a View by another package. The caller
// must not otherwise access the memory after transferring ownership to a View.
//
// To support checkpointing, the concrete implementation must be savable and
// own restoration of the backing memory.
type ExternalStorage interface {
	// Bytes returns the same writable, nonempty slice until Release. Its length
	// must not exceed MaxChunkSize, which bounds the heap copy when a shared
	// external chunk detaches on write. Access must not require a fallible
	// operation.
	//
	// Bytes must be usable before restored buffers are accessed. Loading a
	// Buffer does not call Bytes.
	Bytes() []byte

	// Release relinquishes the backing memory. It is called exactly once, when
	// the last chunk reference is released, and must not require calling Bytes.
	Release()
}

// chunk represents reference-counted heap or externally owned memory. It holds
// either heap bytes in data or an owner in external, never both.
//
// +stateify savable
type chunk struct {
	chunkRefs
	data     []byte
	external ExternalStorage
}

func (c *chunk) bytes() []byte {
	if c.external != nil {
		return c.external.Bytes()
	}
	return c.data
}

func newChunk(size int) *chunk {
	var c *chunk
	if size > MaxChunkSize {
		c = &chunk{
			data: make([]byte, size),
		}
	} else {
		pool := getChunkPool(size)
		c = pool.Get().(*chunk)
		clear(c.data)
	}
	c.InitRefs()
	return c
}

func (c *chunk) destroy() {
	if c.external != nil {
		c.external.Release()
		c.external = nil
		return
	}
	if len(c.data) > MaxChunkSize {
		c.data = nil
		return
	}
	pool := getChunkPool(len(c.data))
	pool.Put(c)
}

func (c *chunk) DecRef() {
	c.chunkRefs.DecRef(c.destroy)
}

func (c *chunk) Clone() *chunk {
	data := c.bytes()
	cpy := newChunk(len(data))
	copy(cpy.data, data)
	return cpy
}
