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

package hostarch

import (
	"bytes"
	"fmt"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// An AddrRangeSeq represents a sequence of AddrRanges.
//
// AddrRangeSeqs are immutable and may be copied by value. The zero value of
// AddrRangeSeq represents an empty sequence.
//
// An AddrRangeSeq may contain AddrRanges with a length of 0. This is necessary
// since zero-length AddrRanges are significant to MM bounds checks.
type AddrRangeSeq struct {
	// If length is 0, then the AddrRangeSeq represents no AddrRanges.
	// Invariants: data == 0; offset == 0; limit == 0.
	//
	// If length is 1, then the AddrRangeSeq represents the single
	// AddrRange{offset, offset+limit}. Invariants: data == 0.
	//
	// Otherwise, length >= 2, and the AddrRangeSeq represents the `length`
	// AddrRanges in the array of AddrRanges starting at address `data`,
	// starting at `offset` bytes into the first AddrRange and limited to the
	// following `limit` bytes. (AddrRanges after `limit` are still iterated,
	// but are truncated to a length of 0.) Invariants: data != 0; offset <=
	// data[0].Length(); limit > 0; offset+limit <= the combined length of all
	// AddrRanges in the array.
	data   unsafe.Pointer
	length int
	offset Addr
	limit  Addr
}

// AddrRangeSeqOf returns an AddrRangeSeq representing the single AddrRange ar.
func AddrRangeSeqOf(ar AddrRange) AddrRangeSeq {
	return AddrRangeSeq{
		length: 1,
		offset: ar.Start,
		limit:  ar.Length(),
	}
}

// AddrRangeSeqFromSlice returns an AddrRangeSeq representing all AddrRanges in
// slice.
//
// Whether the returned AddrRangeSeq shares memory with slice is unspecified;
// clients should avoid mutating slices passed to AddrRangeSeqFromSlice.
//
// Preconditions: The combined length of all AddrRanges in slice <=
// math.MaxInt64.
func AddrRangeSeqFromSlice(slice []AddrRange) AddrRangeSeq {
	var limit int64
	for _, ar := range slice {
		len64 := int64(ar.Length())
		if len64 < 0 {
			panic(fmt.Sprintf("Length of AddrRange %v overflows int64", ar))
		}
		sum := limit + len64
		if sum < limit {
			panic(fmt.Sprintf("Total length of AddrRanges %v overflows int64", slice))
		}
		limit = sum
	}
	return addrRangeSeqFromSliceLimited(slice, limit)
}

// Preconditions:
// * The combined length of all AddrRanges in slice <= limit.
// * limit >= 0.
// * If len(slice) != 0, then limit > 0.
func addrRangeSeqFromSliceLimited(slice []AddrRange, limit int64) AddrRangeSeq {
	switch len(slice) {
	case 0:
		return AddrRangeSeq{}
	case 1:
		return AddrRangeSeq{
			length: 1,
			offset: slice[0].Start,
			limit:  Addr(limit),
		}
	default:
		return AddrRangeSeq{
			data:   unsafe.Pointer(&slice[0]),
			length: len(slice),
			limit:  Addr(limit),
		}
	}
}

// IsEmpty returns true if ars.NumRanges() == 0.
//
// Note that since AddrRangeSeq may contain AddrRanges with a length of zero,
// an AddrRange representing 0 bytes (AddrRangeSeq.NumBytes() == 0) is not
// necessarily empty.
func (ars AddrRangeSeq) IsEmpty() bool {
	return ars.length == 0
}

// NumRanges returns the number of AddrRanges in ars.
func (ars AddrRangeSeq) NumRanges() int {
	return ars.length
}

// NumBytes returns the number of bytes represented by ars.
func (ars AddrRangeSeq) NumBytes() int64 {
	return int64(ars.limit)
}

// Head returns the first AddrRange in ars.
//
// Preconditions: !ars.IsEmpty().
func (ars AddrRangeSeq) Head() AddrRange {
	if ars.length == 0 {
		panic("empty AddrRangeSeq")
	}
	if ars.length == 1 {
		return AddrRange{ars.offset, ars.offset + ars.limit}
	}
	ar := *(*AddrRange)(ars.data)
	ar.Start += ars.offset
	if ar.Length() > ars.limit {
		ar.End = ar.Start + ars.limit
	}
	return ar
}

// Tail returns an AddrRangeSeq consisting of all AddrRanges in ars after the
// first.
//
// Preconditions: !ars.IsEmpty().
func (ars AddrRangeSeq) Tail() AddrRangeSeq {
	if ars.length == 0 {
		panic("empty AddrRangeSeq")
	}
	if ars.length == 1 {
		return AddrRangeSeq{}
	}
	return ars.externalTail()
}

// Preconditions: ars.length >= 2.
func (ars AddrRangeSeq) externalTail() AddrRangeSeq {
	headLen := (*AddrRange)(ars.data).Length() - ars.offset
	var tailLimit int64
	if ars.limit > headLen {
		tailLimit = int64(ars.limit - headLen)
	}
	var extSlice []AddrRange
	extSliceHdr := (*gohacks.SliceHeader)(unsafe.Pointer(&extSlice))
	extSliceHdr.Data = ars.data
	extSliceHdr.Len = ars.length
	extSliceHdr.Cap = ars.length
	return addrRangeSeqFromSliceLimited(extSlice[1:], tailLimit)
}

// DropFirst returns an AddrRangeSeq equivalent to ars, but with the first n
// bytes omitted. If n > ars.NumBytes(), DropFirst returns an empty
// AddrRangeSeq.
//
// If !ars.IsEmpty() and ars.Head().Length() == 0, DropFirst will always omit
// at least ars.Head(), even if n == 0. This guarantees that the basic pattern
// of:
//
//     for !ars.IsEmpty() {
//       n, err = doIOWith(ars.Head())
//       if err != nil {
//         return err
//       }
//       ars = ars.DropFirst(n)
//     }
//
// works even in the presence of zero-length AddrRanges.
//
// Preconditions: n >= 0.
func (ars AddrRangeSeq) DropFirst(n int) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return ars.DropFirst64(int64(n))
}

// DropFirst64 is equivalent to DropFirst but takes an int64.
func (ars AddrRangeSeq) DropFirst64(n int64) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	if Addr(n) > ars.limit {
		return AddrRangeSeq{}
	}
	// Handle initial empty AddrRange.
	switch ars.length {
	case 0:
		return AddrRangeSeq{}
	case 1:
		if ars.limit == 0 {
			return AddrRangeSeq{}
		}
	default:
		if rawHeadLen := (*AddrRange)(ars.data).Length(); ars.offset == rawHeadLen {
			ars = ars.externalTail()
		}
	}
	for n != 0 {
		// Calling ars.Head() here is surprisingly expensive, so inline getting
		// the head's length.
		var headLen Addr
		if ars.length == 1 {
			headLen = ars.limit
		} else {
			headLen = (*AddrRange)(ars.data).Length() - ars.offset
		}
		if Addr(n) < headLen {
			// Dropping ends partway through the head AddrRange.
			ars.offset += Addr(n)
			ars.limit -= Addr(n)
			return ars
		}
		n -= int64(headLen)
		ars = ars.Tail()
	}
	return ars
}

// TakeFirst returns an AddrRangeSeq equivalent to ars, but iterating at most n
// bytes. TakeFirst never removes AddrRanges from ars; AddrRanges beyond the
// first n bytes are reduced to a length of zero, but will still be iterated.
//
// Preconditions: n >= 0.
func (ars AddrRangeSeq) TakeFirst(n int) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return ars.TakeFirst64(int64(n))
}

// TakeFirst64 is equivalent to TakeFirst but takes an int64.
func (ars AddrRangeSeq) TakeFirst64(n int64) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	if ars.limit > Addr(n) {
		ars.limit = Addr(n)
	}
	return ars
}

// String implements fmt.Stringer.String.
func (ars AddrRangeSeq) String() string {
	// This is deliberately chosen to be the same as fmt's automatic stringer
	// for []AddrRange.
	var buf bytes.Buffer
	buf.WriteByte('[')
	var sep string
	for !ars.IsEmpty() {
		buf.WriteString(sep)
		sep = " "
		buf.WriteString(ars.Head().String())
		ars = ars.Tail()
	}
	buf.WriteByte(']')
	return buf.String()
}
