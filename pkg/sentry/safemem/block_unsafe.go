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

package safemem

import (
	"fmt"
	"reflect"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
)

// A Block is a range of contiguous bytes, similar to []byte but with the
// following differences:
//
// - The memory represented by a Block may require the use of safecopy to
// access.
//
// - Block does not carry a capacity and cannot be expanded.
//
// Blocks are immutable and may be copied by value. The zero value of Block
// represents an empty range, analogous to a nil []byte.
type Block struct {
	// [start, start+length) is the represented memory.
	//
	// start is an unsafe.Pointer to ensure that Block prevents the represented
	// memory from being garbage-collected.
	start  unsafe.Pointer
	length int

	// needSafecopy is true if accessing the represented memory requires the
	// use of safecopy.
	needSafecopy bool
}

// BlockFromSafeSlice returns a Block equivalent to slice, which is safe to
// access without safecopy.
func BlockFromSafeSlice(slice []byte) Block {
	return blockFromSlice(slice, false)
}

// BlockFromUnsafeSlice returns a Block equivalent to bs, which is not safe to
// access without safecopy.
func BlockFromUnsafeSlice(slice []byte) Block {
	return blockFromSlice(slice, true)
}

func blockFromSlice(slice []byte, needSafecopy bool) Block {
	if len(slice) == 0 {
		return Block{}
	}
	return Block{
		start:        unsafe.Pointer(&slice[0]),
		length:       len(slice),
		needSafecopy: needSafecopy,
	}
}

// BlockFromSafePointer returns a Block equivalent to [ptr, ptr+len), which is
// safe to access without safecopy.
//
// Preconditions: ptr+len does not overflow.
func BlockFromSafePointer(ptr unsafe.Pointer, len int) Block {
	return blockFromPointer(ptr, len, false)
}

// BlockFromUnsafePointer returns a Block equivalent to [ptr, ptr+len), which
// is not safe to access without safecopy.
//
// Preconditions: ptr+len does not overflow.
func BlockFromUnsafePointer(ptr unsafe.Pointer, len int) Block {
	return blockFromPointer(ptr, len, true)
}

func blockFromPointer(ptr unsafe.Pointer, len int, needSafecopy bool) Block {
	if uptr := uintptr(ptr); uptr+uintptr(len) < uptr {
		panic(fmt.Sprintf("ptr %#x + len %#x overflows", ptr, len))
	}
	return Block{
		start:        ptr,
		length:       len,
		needSafecopy: needSafecopy,
	}
}

// DropFirst returns a Block equivalent to b, but with the first n bytes
// omitted. It is analogous to the [n:] operation on a slice, except that if n
// > b.Len(), DropFirst returns an empty Block instead of panicking.
//
// Preconditions: n >= 0.
func (b Block) DropFirst(n int) Block {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return b.DropFirst64(uint64(n))
}

// DropFirst64 is equivalent to DropFirst but takes a uint64.
func (b Block) DropFirst64(n uint64) Block {
	if n >= uint64(b.length) {
		return Block{}
	}
	return Block{
		start:        unsafe.Pointer(uintptr(b.start) + uintptr(n)),
		length:       b.length - int(n),
		needSafecopy: b.needSafecopy,
	}
}

// TakeFirst returns a Block equivalent to the first n bytes of b. It is
// analogous to the [:n] operation on a slice, except that if n > b.Len(),
// TakeFirst returns a copy of b instead of panicking.
//
// Preconditions: n >= 0.
func (b Block) TakeFirst(n int) Block {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return b.TakeFirst64(uint64(n))
}

// TakeFirst64 is equivalent to TakeFirst but takes a uint64.
func (b Block) TakeFirst64(n uint64) Block {
	if n == 0 {
		return Block{}
	}
	if n >= uint64(b.length) {
		return b
	}
	return Block{
		start:        b.start,
		length:       int(n),
		needSafecopy: b.needSafecopy,
	}
}

// ToSlice returns a []byte equivalent to b.
func (b Block) ToSlice() []byte {
	var bs []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	hdr.Data = uintptr(b.start)
	hdr.Len = b.length
	hdr.Cap = b.length
	return bs
}

// Addr returns b's start address as a uintptr. It returns uintptr instead of
// unsafe.Pointer so that code using safemem cannot obtain unsafe.Pointers
// without importing the unsafe package explicitly.
//
// Note that a uintptr is not recognized as a pointer by the garbage collector,
// such that if there are no uses of b after a call to b.Addr() and the address
// is to Go-managed memory, the returned uintptr does not prevent garbage
// collection of the pointee.
func (b Block) Addr() uintptr {
	return uintptr(b.start)
}

// Len returns b's length in bytes.
func (b Block) Len() int {
	return b.length
}

// NeedSafecopy returns true if accessing b.ToSlice() requires the use of safecopy.
func (b Block) NeedSafecopy() bool {
	return b.needSafecopy
}

// String implements fmt.Stringer.String.
func (b Block) String() string {
	if uintptr(b.start) == 0 && b.length == 0 {
		return "<nil>"
	}
	var suffix string
	if b.needSafecopy {
		suffix = "*"
	}
	return fmt.Sprintf("[%#x-%#x)%s", uintptr(b.start), uintptr(b.start)+uintptr(b.length), suffix)
}

// Copy copies src.Len() or dst.Len() bytes, whichever is less, from src
// to dst and returns the number of bytes copied.
//
// If src and dst overlap, the data stored in dst is unspecified.
func Copy(dst, src Block) (int, error) {
	if !dst.needSafecopy && !src.needSafecopy {
		return copy(dst.ToSlice(), src.ToSlice()), nil
	}

	n := dst.length
	if n > src.length {
		n = src.length
	}
	if n == 0 {
		return 0, nil
	}

	switch {
	case dst.needSafecopy && !src.needSafecopy:
		return safecopy.CopyOut(dst.start, src.TakeFirst(n).ToSlice())
	case !dst.needSafecopy && src.needSafecopy:
		return safecopy.CopyIn(dst.TakeFirst(n).ToSlice(), src.start)
	case dst.needSafecopy && src.needSafecopy:
		n64, err := safecopy.Copy(dst.start, src.start, uintptr(n))
		return int(n64), err
	default:
		panic("unreachable")
	}
}

// Zero sets all bytes in dst to 0 and returns the number of bytes zeroed.
func Zero(dst Block) (int, error) {
	if !dst.needSafecopy {
		bs := dst.ToSlice()
		for i := range bs {
			bs[i] = 0
		}
		return len(bs), nil
	}

	n64, err := safecopy.ZeroOut(dst.start, uintptr(dst.length))
	return int(n64), err
}

// Safecopy atomics are no slower than non-safecopy atomics, so use the former
// even when !b.needSafecopy to get consistent alignment checking.

// SwapUint32 invokes safecopy.SwapUint32 on the first 4 bytes of b.
//
// Preconditions: b.Len() >= 4.
func SwapUint32(b Block, new uint32) (uint32, error) {
	if b.length < 4 {
		panic(fmt.Sprintf("insufficient length: %d", b.length))
	}
	return safecopy.SwapUint32(b.start, new)
}

// SwapUint64 invokes safecopy.SwapUint64 on the first 8 bytes of b.
//
// Preconditions: b.Len() >= 8.
func SwapUint64(b Block, new uint64) (uint64, error) {
	if b.length < 8 {
		panic(fmt.Sprintf("insufficient length: %d", b.length))
	}
	return safecopy.SwapUint64(b.start, new)
}

// CompareAndSwapUint32 invokes safecopy.CompareAndSwapUint32 on the first 4
// bytes of b.
//
// Preconditions: b.Len() >= 4.
func CompareAndSwapUint32(b Block, old, new uint32) (uint32, error) {
	if b.length < 4 {
		panic(fmt.Sprintf("insufficient length: %d", b.length))
	}
	return safecopy.CompareAndSwapUint32(b.start, old, new)
}

// LoadUint32 invokes safecopy.LoadUint32 on the first 4 bytes of b.
//
// Preconditions: b.Len() >= 4.
func LoadUint32(b Block) (uint32, error) {
	if b.length < 4 {
		panic(fmt.Sprintf("insufficient length: %d", b.length))
	}
	return safecopy.LoadUint32(b.start)
}
