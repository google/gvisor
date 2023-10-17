// Copyright 2023 The gVisor Authors.
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

package checksum

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

// Note: odd indicates whether initial is a partial checksum over an odd number
// of bytes.
func calculateChecksum(buf []byte, odd bool, initial uint16) (uint16, bool) {
	// Use a larger-than-uint16 accumulator to benefit from parallel summation
	// as described in RFC 1071 1.2.C.
	acc := uint64(initial)

	// Handle an odd number of previously-summed bytes, and get the return
	// value for odd.
	if odd {
		acc += uint64(buf[0])
		buf = buf[1:]
	}
	odd = len(buf)&1 != 0

	// Aligning &buf[0] below is much simpler if len(buf) >= 8; special-case
	// smaller bufs.
	if len(buf) < 8 {
		if len(buf) >= 4 {
			acc += (uint64(buf[0]) << 8) + uint64(buf[1])
			acc += (uint64(buf[2]) << 8) + uint64(buf[3])
			buf = buf[4:]
		}
		if len(buf) >= 2 {
			acc += (uint64(buf[0]) << 8) + uint64(buf[1])
			buf = buf[2:]
		}
		if len(buf) >= 1 {
			acc += uint64(buf[0]) << 8
			// buf = buf[1:] is skipped because it's unused and nogo will
			// complain.
		}
		return reduce(acc), odd
	}

	// On little-endian architectures, multi-byte loads from buf will load
	// bytes in the wrong order. Rather than byte-swap after each load (slow),
	// we byte-swap the accumulator before summing any bytes and byte-swap it
	// back before returning, which still produces the correct result as
	// described in RFC 1071 1.2.B "Byte Order Independence".
	//
	// acc is at most a uint16 + a uint8, so its upper 32 bits must be 0s. We
	// preserve this property by byte-swapping only the lower 32 bits of acc,
	// so that additions to acc performed during alignment can't overflow.
	acc = uint64(bswapIfLittleEndian32(uint32(acc)))

	// Align &buf[0] to an 8-byte boundary.
	bswapped := false
	if sliceAddr(buf)&1 != 0 {
		// Compute the rest of the partial checksum with bytes swapped, and
		// swap back before returning; see the last paragraph of
		// RFC 1071 1.2.B.
		acc = uint64(bits.ReverseBytes32(uint32(acc)))
		bswapped = true
		// No `<< 8` here due to the byte swap we just did.
		acc += uint64(bswapIfLittleEndian16(uint16(buf[0])))
		buf = buf[1:]
	}
	if sliceAddr(buf)&2 != 0 {
		acc += uint64(*(*uint16)(unsafe.Pointer(&buf[0])))
		buf = buf[2:]
	}
	if sliceAddr(buf)&4 != 0 {
		acc += uint64(*(*uint32)(unsafe.Pointer(&buf[0])))
		buf = buf[4:]
	}

	// Sum 64 bytes at a time. Beyond this point, additions to acc may
	// overflow, so we have to handle carrying.
	for len(buf) >= 64 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[16])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[24])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[32])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[40])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[48])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[56])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[64:]
	}

	// Sum the remaining 0-63 bytes.
	if len(buf) >= 32 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[16])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[24])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[32:]
	}
	if len(buf) >= 16 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[16:]
	}
	if len(buf) >= 8 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[8:]
	}
	if len(buf) >= 4 {
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(*(*uint32)(unsafe.Pointer(&buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[4:]
	}
	if len(buf) >= 2 {
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(*(*uint16)(unsafe.Pointer(&buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[2:]
	}
	if len(buf) >= 1 {
		// bswapIfBigEndian16(buf[0]) == bswapIfLittleEndian16(buf[0]<<8).
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(bswapIfBigEndian16(uint16(buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		// buf = buf[1:] is skipped because it's unused and nogo will complain.
	}

	// Reduce the checksum to 16 bits and undo byte swaps before returning.
	acc16 := bswapIfLittleEndian16(reduce(acc))
	if bswapped {
		acc16 = bits.ReverseBytes16(acc16)
	}
	return acc16, odd
}

func reduce(acc uint64) uint16 {
	// Ideally we would do:
	//   return uint16(acc>>48) +' uint16(acc>>32) +' uint16(acc>>16) +' uint16(acc)
	// for more instruction-level parallelism; however, there is no
	// bits.Add16().
	acc = (acc >> 32) + (acc & 0xffff_ffff)  // at most 0x1_ffff_fffe
	acc32 := uint32(acc>>32 + acc)           // at most 0xffff_ffff
	acc32 = (acc32 >> 16) + (acc32 & 0xffff) // at most 0x1_fffe
	return uint16(acc32>>16 + acc32)         // at most 0xffff
}

func bswapIfLittleEndian32(val uint32) uint32 {
	return binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&val))[:])
}

func bswapIfLittleEndian16(val uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&val))[:])
}

func bswapIfBigEndian16(val uint16) uint16 {
	return binary.LittleEndian.Uint16((*[2]byte)(unsafe.Pointer(&val))[:])
}

func sliceAddr(buf []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
}
