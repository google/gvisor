// Copyright 2021 The gVisor Authors.
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

// Package bitmap provides the implementation of bitmap.
package bitmap

import (
	"fmt"
	"math"
	"math/bits"
)

// MaxBitEntryLimit defines the upper limit on how many bit entries are supported by this Bitmap
// implementation.
const MaxBitEntryLimit uint32 = math.MaxInt32

// Bitmap implements an efficient bitmap.
//
// +stateify savable
type Bitmap struct {
	// numOnes is the number of ones in the bitmap.
	numOnes uint32

	// bitBlock holds the bits. The type of bitBlock is uint64 which means
	// each number in bitBlock contains 64 entries.
	bitBlock []uint64
}

// New create a new empty Bitmap.
func New(size uint32) Bitmap {
	b := Bitmap{}
	bSize := (size + 63) / 64
	b.bitBlock = make([]uint64, bSize)
	return b
}

// IsEmpty verifies whether the Bitmap is empty.
func (b *Bitmap) IsEmpty() bool {
	return b.numOnes == 0
}

// Size returns the total number of bits in the bitmap.
func (b *Bitmap) Size() int {
	return len(b.bitBlock) * 64
}

// Grow grows the bitmap by at least toGrow bits.
func (b *Bitmap) Grow(toGrow uint32) error {
	newbitBlockSize := uint32(len(b.bitBlock)) + ((toGrow + 63) / 64)
	if newbitBlockSize > MaxBitEntryLimit/8 {
		return fmt.Errorf("requested bitmap size %d too large", newbitBlockSize*64)
	}
	bits := make([]uint64, (toGrow+63)/64)
	b.bitBlock = append(b.bitBlock, bits...)
	return nil
}

// Minimum return the smallest value in the Bitmap.
func (b *Bitmap) Minimum() uint32 {
	for i := 0; i < len(b.bitBlock); i++ {
		if w := b.bitBlock[i]; w != 0 {
			r := bits.TrailingZeros64(w)
			return uint32(r + i*64)
		}
	}
	return MaxBitEntryLimit
}

// FirstZero returns the first unset bit from the range [start, ).
func (b *Bitmap) FirstZero(start uint32) (bit uint32, err error) {
	i, nbit := int(start/64), start%64
	n := len(b.bitBlock)
	if i >= n {
		return MaxBitEntryLimit, fmt.Errorf("given start of range exceeds bitmap size")
	}
	w := b.bitBlock[i] | ((1 << nbit) - 1)
	for {
		if w != ^uint64(0) {
			r := bits.TrailingZeros64(^w)
			return uint32(r + i*64), nil
		}
		i++
		if i == n {
			break
		}
		w = b.bitBlock[i]
	}
	return MaxBitEntryLimit, fmt.Errorf("bitmap has no unset bits")
}

// FirstOne returns the first set bit from the range [start, )
func (b *Bitmap) FirstOne(start uint32) (bit uint32, err error) {
	i, nbit := int(start/64), start%64
	n := len(b.bitBlock)
	if i >= n {
		return MaxBitEntryLimit, fmt.Errorf("given start of range exceeds bitmap size")
	}
	w := b.bitBlock[i] & (math.MaxUint64 << nbit)
	for {
		if w != uint64(0) {
			r := bits.TrailingZeros64(w)
			return uint32(r + i*64), nil
		}
		i++
		if i == n {
			break
		}
		w = b.bitBlock[i]
	}
	return MaxBitEntryLimit, fmt.Errorf("bitmap has no set bits")
}

// Maximum return the largest value in the Bitmap.
func (b *Bitmap) Maximum() uint32 {
	for i := len(b.bitBlock) - 1; i >= 0; i-- {
		if w := b.bitBlock[i]; w != 0 {
			r := bits.LeadingZeros64(w)
			return uint32(i*64 + 63 - r)
		}
	}
	return uint32(0)
}

// Add add i to the Bitmap.
func (b *Bitmap) Add(i uint32) {
	blockNum, mask := i/64, uint64(1)<<(i%64)
	// if blockNum is out of range, extend b.bitBlock
	if x, y := int(blockNum), len(b.bitBlock); x >= y {
		b.bitBlock = append(b.bitBlock, make([]uint64, x-y+1)...)
	}
	oldBlock := b.bitBlock[blockNum]
	newBlock := oldBlock | mask
	if oldBlock != newBlock {
		b.bitBlock[blockNum] = newBlock
		b.numOnes++
	}
}

// Remove i from the Bitmap.
func (b *Bitmap) Remove(i uint32) {
	blockNum, mask := i/64, uint64(1)<<(i%64)
	oldBlock := b.bitBlock[blockNum]
	newBlock := oldBlock &^ mask
	if oldBlock != newBlock {
		b.bitBlock[blockNum] = newBlock
		b.numOnes--
	}
}

// Clone the Bitmap.
func (b *Bitmap) Clone() Bitmap {
	bitmap := Bitmap{b.numOnes, make([]uint64, len(b.bitBlock))}
	copy(bitmap.bitBlock, b.bitBlock[:])
	return bitmap
}

// countOnesForBlocks count all 1 bits within b.bitBlock of begin and that of end.
// The begin block and end block are inclusive.
func (b *Bitmap) countOnesForBlocks(begin, end uint32) uint64 {
	ones := uint64(0)
	beginBlock := begin / 64
	endBlock := end / 64
	for i := beginBlock; i <= endBlock; i++ {
		ones += uint64(bits.OnesCount64(b.bitBlock[i]))
	}
	return ones
}

// countOnesForAllBlocks count all 1 bits in b.bitBlock.
func (b *Bitmap) countOnesForAllBlocks() uint64 {
	ones := uint64(0)
	for i := 0; i < len(b.bitBlock); i++ {
		ones += uint64(bits.OnesCount64(b.bitBlock[i]))
	}
	return ones
}

// flipRange flip the bits within range (begin and end). begin is inclusive and end is exclusive.
func (b *Bitmap) flipRange(begin, end uint32) {
	end--
	beginBlock := begin / 64
	endBlock := end / 64
	if beginBlock == endBlock {
		b.bitBlock[endBlock] ^= ((^uint64(0) << uint(begin%64)) & ((uint64(1) << (uint(end)%64 + 1)) - 1))
	} else {
		b.bitBlock[beginBlock] ^= ^(^uint64(0) << uint(begin%64))
		for i := beginBlock; i < endBlock; i++ {
			b.bitBlock[i] = ^b.bitBlock[i]
		}
		b.bitBlock[endBlock] ^= ((uint64(1) << (uint(end)%64 + 1)) - 1)
	}
}

// clearRange clear the bits within range (begin and end). begin is inclusive and end is exclusive.
func (b *Bitmap) clearRange(begin, end uint32) {
	end--
	beginBlock := begin / 64
	endBlock := end / 64
	if beginBlock == endBlock {
		b.bitBlock[beginBlock] &= (((uint64(1) << uint(begin%64)) - 1) | ^((uint64(1) << (uint(end)%64 + 1)) - 1))
	} else {
		b.bitBlock[beginBlock] &= ((uint64(1) << uint(begin%64)) - 1)
		for i := beginBlock + 1; i < endBlock; i++ {
			b.bitBlock[i] &= ^b.bitBlock[i]
		}
		b.bitBlock[endBlock] &= ^((uint64(1) << (uint(end)%64 + 1)) - 1)
	}
}

// ClearRange clear bits within range (begin and end) for the Bitmap. begin is inclusive and end is exclusive.
func (b *Bitmap) ClearRange(begin, end uint32) {
	blockRange := end/64 - begin/64
	// When the number of cleared blocks is larger than half of the length of b.bitBlock,
	// counting 1s for the entire bitmap has better performance.
	if blockRange > uint32(len(b.bitBlock)/2) {
		b.clearRange(begin, end)
		b.numOnes = uint32(b.countOnesForAllBlocks())
	} else {
		oldRangeOnes := b.countOnesForBlocks(begin, end)
		b.clearRange(begin, end)
		newRangeOnes := b.countOnesForBlocks(begin, end)
		b.numOnes += uint32(newRangeOnes - oldRangeOnes)
	}
}

// FlipRange flip bits within range (begin and end) for the Bitmap. begin is inclusive and end is exclusive.
func (b *Bitmap) FlipRange(begin, end uint32) {
	blockRange := end/64 - begin/64
	// When the number of flipped blocks is larger than half of the length of b.bitBlock,
	// counting 1s for the entire bitmap has better performance.
	if blockRange > uint32(len(b.bitBlock)/2) {
		b.flipRange(begin, end)
		b.numOnes = uint32(b.countOnesForAllBlocks())
	} else {
		oldRangeOnes := b.countOnesForBlocks(begin, end)
		b.flipRange(begin, end)
		newRangeOnes := b.countOnesForBlocks(begin, end)
		b.numOnes += uint32(newRangeOnes - oldRangeOnes)
	}
}

// ToSlice transform the Bitmap into slice. For example, a bitmap of [0, 1, 0, 1]
// will return the slice [1, 3].
func (b *Bitmap) ToSlice() []uint32 {
	bitmapSlice := make([]uint32, 0, b.numOnes)
	// base is the start number of a bitBlock
	base := 0
	for i := 0; i < len(b.bitBlock); i++ {
		bitBlock := b.bitBlock[i]
		// Iterate through all the numbers held by this bit block.
		for bitBlock != 0 {
			// Extract the lowest set 1 bit.
			j := bitBlock & -bitBlock
			// Interpret the bit as the in32 number it represents and add it to result.
			bitmapSlice = append(bitmapSlice, uint32((base + int(bits.OnesCount64(j-1)))))
			bitBlock ^= j
		}
		base += 64
	}
	return bitmapSlice
}

// GetNumOnes return the the number of ones in the Bitmap.
func (b *Bitmap) GetNumOnes() uint32 {
	return b.numOnes
}
