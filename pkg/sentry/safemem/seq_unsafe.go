// Copyright 2018 Google LLC
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

package safemem

import (
	"bytes"
	"fmt"
	"reflect"
	"unsafe"
)

// A BlockSeq represents a sequence of Blocks, each of which has non-zero
// length.
//
// BlockSeqs are immutable and may be copied by value. The zero value of
// BlockSeq represents an empty sequence.
type BlockSeq struct {
	// If length is 0, then the BlockSeq is empty. Invariants: data == 0;
	// offset == 0; limit == 0.
	//
	// If length is -1, then the BlockSeq represents the single Block{data,
	// limit, false}. Invariants: offset == 0; limit > 0; limit does not
	// overflow the range of an int.
	//
	// If length is -2, then the BlockSeq represents the single Block{data,
	// limit, true}. Invariants: offset == 0; limit > 0; limit does not
	// overflow the range of an int.
	//
	// Otherwise, length >= 2, and the BlockSeq represents the `length` Blocks
	// in the array of Blocks starting at address `data`, starting at `offset`
	// bytes into the first Block and limited to the following `limit` bytes.
	// Invariants: data != 0; offset < len(data[0]); limit > 0; offset+limit <=
	// the combined length of all Blocks in the array; the first Block in the
	// array has non-zero length.
	//
	// length is never 1; sequences consisting of a single Block are always
	// stored inline (with length < 0).
	data   unsafe.Pointer
	length int
	offset int
	limit  uint64
}

// BlockSeqOf returns a BlockSeq representing the single Block b.
func BlockSeqOf(b Block) BlockSeq {
	bs := BlockSeq{
		data:   b.start,
		length: -1,
		limit:  uint64(b.length),
	}
	if b.needSafecopy {
		bs.length = -2
	}
	return bs
}

// BlockSeqFromSlice returns a BlockSeq representing all Blocks in slice.
// If slice contains Blocks with zero length, BlockSeq will skip them during
// iteration.
//
// Whether the returned BlockSeq shares memory with slice is unspecified;
// clients should avoid mutating slices passed to BlockSeqFromSlice.
//
// Preconditions: The combined length of all Blocks in slice <= math.MaxUint64.
func BlockSeqFromSlice(slice []Block) BlockSeq {
	slice = skipEmpty(slice)
	var limit uint64
	for _, b := range slice {
		sum := limit + uint64(b.Len())
		if sum < limit {
			panic("BlockSeq length overflows uint64")
		}
		limit = sum
	}
	return blockSeqFromSliceLimited(slice, limit)
}

// Preconditions: The combined length of all Blocks in slice <= limit. If
// len(slice) != 0, the first Block in slice has non-zero length, and limit >
// 0.
func blockSeqFromSliceLimited(slice []Block, limit uint64) BlockSeq {
	switch len(slice) {
	case 0:
		return BlockSeq{}
	case 1:
		return BlockSeqOf(slice[0].TakeFirst64(limit))
	default:
		return BlockSeq{
			data:   unsafe.Pointer(&slice[0]),
			length: len(slice),
			limit:  limit,
		}
	}
}

func skipEmpty(slice []Block) []Block {
	for i, b := range slice {
		if b.Len() != 0 {
			return slice[i:]
		}
	}
	return nil
}

// IsEmpty returns true if bs contains no Blocks.
//
// Invariants: bs.IsEmpty() == (bs.NumBlocks() == 0) == (bs.NumBytes() == 0).
// (Of these, prefer to use bs.IsEmpty().)
func (bs BlockSeq) IsEmpty() bool {
	return bs.length == 0
}

// NumBlocks returns the number of Blocks in bs.
func (bs BlockSeq) NumBlocks() int {
	// In general, we have to count: if bs represents a windowed slice then the
	// slice may contain Blocks with zero length, and bs.length may be larger
	// than the actual number of Blocks due to bs.limit.
	var n int
	for !bs.IsEmpty() {
		n++
		bs = bs.Tail()
	}
	return n
}

// NumBytes returns the sum of Block.Len() for all Blocks in bs.
func (bs BlockSeq) NumBytes() uint64 {
	return bs.limit
}

// Head returns the first Block in bs.
//
// Preconditions: !bs.IsEmpty().
func (bs BlockSeq) Head() Block {
	if bs.length == 0 {
		panic("empty BlockSeq")
	}
	if bs.length < 0 {
		return bs.internalBlock()
	}
	return (*Block)(bs.data).DropFirst(bs.offset).TakeFirst64(bs.limit)
}

// Preconditions: bs.length < 0.
func (bs BlockSeq) internalBlock() Block {
	return Block{
		start:        bs.data,
		length:       int(bs.limit),
		needSafecopy: bs.length == -2,
	}
}

// Tail returns a BlockSeq consisting of all Blocks in bs after the first.
//
// Preconditions: !bs.IsEmpty().
func (bs BlockSeq) Tail() BlockSeq {
	if bs.length == 0 {
		panic("empty BlockSeq")
	}
	if bs.length < 0 {
		return BlockSeq{}
	}
	head := (*Block)(bs.data).DropFirst(bs.offset)
	headLen := uint64(head.Len())
	if headLen >= bs.limit {
		// The head Block exhausts the limit, so the tail is empty.
		return BlockSeq{}
	}
	var extSlice []Block
	extSliceHdr := (*reflect.SliceHeader)(unsafe.Pointer(&extSlice))
	extSliceHdr.Data = uintptr(bs.data)
	extSliceHdr.Len = bs.length
	extSliceHdr.Cap = bs.length
	tailSlice := skipEmpty(extSlice[1:])
	tailLimit := bs.limit - headLen
	return blockSeqFromSliceLimited(tailSlice, tailLimit)
}

// DropFirst returns a BlockSeq equivalent to bs, but with the first n bytes
// omitted. If n > bs.NumBytes(), DropFirst returns an empty BlockSeq.
//
// Preconditions: n >= 0.
func (bs BlockSeq) DropFirst(n int) BlockSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return bs.DropFirst64(uint64(n))
}

// DropFirst64 is equivalent to DropFirst but takes an uint64.
func (bs BlockSeq) DropFirst64(n uint64) BlockSeq {
	if n >= bs.limit {
		return BlockSeq{}
	}
	for {
		// Calling bs.Head() here is surprisingly expensive, so inline getting
		// the head's length.
		var headLen uint64
		if bs.length < 0 {
			headLen = bs.limit
		} else {
			headLen = uint64((*Block)(bs.data).Len() - bs.offset)
		}
		if n < headLen {
			// Dropping ends partway through the head Block.
			if bs.length < 0 {
				return BlockSeqOf(bs.internalBlock().DropFirst64(n))
			}
			bs.offset += int(n)
			bs.limit -= n
			return bs
		}
		n -= headLen
		bs = bs.Tail()
	}
}

// TakeFirst returns a BlockSeq equivalent to the first n bytes of bs. If n >
// bs.NumBytes(), TakeFirst returns a BlockSeq equivalent to bs.
//
// Preconditions: n >= 0.
func (bs BlockSeq) TakeFirst(n int) BlockSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return bs.TakeFirst64(uint64(n))
}

// TakeFirst64 is equivalent to TakeFirst but takes a uint64.
func (bs BlockSeq) TakeFirst64(n uint64) BlockSeq {
	if n == 0 {
		return BlockSeq{}
	}
	if bs.limit > n {
		bs.limit = n
	}
	return bs
}

// String implements fmt.Stringer.String.
func (bs BlockSeq) String() string {
	var buf bytes.Buffer
	buf.WriteByte('[')
	var sep string
	for !bs.IsEmpty() {
		buf.WriteString(sep)
		sep = " "
		buf.WriteString(bs.Head().String())
		bs = bs.Tail()
	}
	buf.WriteByte(']')
	return buf.String()
}

// CopySeq copies srcs.NumBytes() or dsts.NumBytes() bytes, whichever is less,
// from srcs to dsts and returns the number of bytes copied.
//
// If srcs and dsts overlap, the data stored in dsts is unspecified.
func CopySeq(dsts, srcs BlockSeq) (uint64, error) {
	var done uint64
	for !dsts.IsEmpty() && !srcs.IsEmpty() {
		dst := dsts.Head()
		src := srcs.Head()
		n, err := Copy(dst, src)
		done += uint64(n)
		if err != nil {
			return done, err
		}
		dsts = dsts.DropFirst(n)
		srcs = srcs.DropFirst(n)
	}
	return done, nil
}

// ZeroSeq sets all bytes in dsts to 0 and returns the number of bytes zeroed.
func ZeroSeq(dsts BlockSeq) (uint64, error) {
	var done uint64
	for !dsts.IsEmpty() {
		n, err := Zero(dsts.Head())
		done += uint64(n)
		if err != nil {
			return done, err
		}
		dsts = dsts.DropFirst(n)
	}
	return done, nil
}
