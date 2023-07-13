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

//go:build !amd64
// +build !amd64

package checksum

import (
	"math"
	"math/bits"
	"unsafe"
)

// Note: odd indicates whether initial is a partial checksum over an odd number
// of bytes.
func calculateChecksum(buf []byte, odd bool, initial uint16) (uint16, bool) {
	// Note: we can probably remove unrolledCalculateChecksum altogether,
	// but I don't have any 32 bit machines to benchmark on.
	if bits.UintSize != 64 {
		return unrolledCalculateChecksum(buf, odd, initial)
	}

	// Utilize byte order independence and parallel summation as
	// described in RFC 1071 1.2.

	// It doesn't matter what endianness we use, only that it's
	// consistent throughout the calculation. See RFC 1071 1.2.B.
	acc := uint(((initial & 0xff00) >> 8) | ((initial & 0x00ff) << 8))

	// Account for initial having been calculated over an odd number of
	// bytes.
	if odd {
		acc += uint(buf[0]) << 8
		buf = buf[1:]
	}

	// See whether we're checksumming an odd number of bytes. If
	// so, the final byte is a big endian most significant byte.
	odd = len(buf)%2 != 0
	if odd {
		acc += uint(buf[len(buf)-1])
		buf = buf[:len(buf)-1]
	}

	// Compute the checksum 8 bytes at a time.
	var carry uint
	for len(buf) >= 8 {
		acc, carry = bits.Add(acc, *(*uint)(unsafe.Pointer(&buf[0])), carry)
		buf = buf[8:]
	}

	// Compute the remainder 2 bytes at a time. We are guaranteed that
	// len(buf) is even due to the above handling of odd-length buffers.
	for len(buf) > 0 {
		acc, carry = bits.Add(acc, uint(*(*uint16)(unsafe.Pointer(&buf[0]))), carry)
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
