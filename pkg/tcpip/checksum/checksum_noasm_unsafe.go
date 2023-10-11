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
	"math"
	"math/bits"
	"unsafe"
)

// Note: odd indicates whether initial is a partial checksum over an odd number
// of bytes.
func calculateChecksumNoASM(buf []byte, odd bool, initial uint16) (uint16, bool) {
	// Fall back to slower checksum if we're not on a 64 bit machine or if
	// this optimization will result in misaligned accesses. Calculating
	// the checksum starting at an odd address messes up the endianness
	// expected by the below.
	var oddOffset uintptr
	if odd {
		oddOffset = 1
	}
	if bits.UintSize != 64 || (sliceAddr(buf)+oddOffset)%2 != 0 {
		return unrolledCalculateChecksum(buf, odd, initial)
	}

	// Utilize byte order independence and parallel summation as
	// described in RFC 1071 1.2.

	// It doesn't matter what endianness we use, only that it's
	// consistent throughout the calculation. See RFC 1071 1.2.B.
	acc := uint64(((initial & 0xff00) >> 8) | ((initial & 0x00ff) << 8))

	// Account for initial having been calculated over an odd number of
	// bytes.
	if odd {
		acc += uint64(buf[0]) << 8
		buf = buf[1:]
	}

	// See whether we're checksumming an odd number of bytes. If
	// so, the final byte is a big endian most significant byte.
	odd = len(buf)%2 != 0
	if odd {
		acc += uint64(buf[len(buf)-1])
		buf = buf[:len(buf)-1]
	}

	// Deal with unaligned bytes. We're guaranteed at this point that buf
	// points to an even address.
	var carry uint64
	for sliceAddr(buf)%8 != 0 && len(buf) >= 2 {
		acc, carry = bits.Add64(acc, uint64(*(*uint16)(unsafe.Pointer(&buf[0]))), carry)
		buf = buf[2:]
	}

	// Compute the checksum 8 bytes at a time.
	for len(buf) >= 8 {
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), carry)
		buf = buf[8:]
	}

	// Compute the remainder 2 bytes at a time. We are guaranteed that
	// len(buf) is even due to the above handling of odd-length buffers.
	for len(buf) > 0 {
		acc, carry = bits.Add64(acc, uint64(*(*uint16)(unsafe.Pointer(&buf[0]))), carry)
		buf = buf[2:]
	}
	acc += carry

	// Fold the checksum into 16 bits.
	for acc > math.MaxUint16 {
		acc = (acc & 0xffff) + acc>>16
	}

	// Swap the byte order before returning.
	acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8)
	return uint16(acc), odd
}

func sliceAddr(buf []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
}
