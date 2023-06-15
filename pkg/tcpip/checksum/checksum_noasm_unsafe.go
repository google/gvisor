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

func calculateChecksum(buf []byte, odd bool, initial uint16) (uint16, bool) {
	if bits.UintSize == 64 {
		// Utilize byte order independence and parallel summation as
		// described in RFC 1071 1.2.

		// Initialize the accumulator and account for odd byte input.
		acc := uint(initial)
		if odd {
			acc += uint(buf[0])
			buf = buf[1:]
		}
		// It doesn't matter what endianness we use, only that it's
		// consistent throughout the calculation. See RFC ?.
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8)

		// Compute the checksum.
		remaining := len(buf)
		var carry uint
		for remaining >= 8 {
			acc, carry = bits.Add(acc, *(*uint)(unsafe.Pointer(&buf[0])), carry)
			remaining -= 8
			buf = buf[8:]
		}
		acc += carry

		// Fold the checksum into 16 bits.
		for acc > math.MaxUint16 {
			acc = (acc & 0xffff) + acc>>16
		}

		// Swap back to little endian and let unrolledCalculateChecksum
		// handle the remaining bytes.
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8)
		return unrolledCalculateChecksum(buf, false, uint16(acc))
	}
	return unrolledCalculateChecksum(buf, odd, initial)
}
