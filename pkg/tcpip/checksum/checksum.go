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

// Package checksum provides the implementation of the encoding and decoding of
// network protocol headers.
package checksum

import (
	"encoding/binary"
)

// Size is the size of a checksum.
//
// The checksum is held in a uint16 which is 2 bytes.
const Size = 2

// Put puts the checksum in the provided byte slice.
func Put(b []byte, xsum uint16) {
	binary.BigEndian.PutUint16(b, xsum)
}

// Checksum calculates the checksum (as defined in RFC 1071) of the bytes in the
// given byte array. This function uses an optimized version of the checksum
// algorithm.
//
// The initial checksum must have been computed on an even number of bytes.
func Checksum(buf []byte, initial uint16) uint16 {
	s, _ := calculateChecksum(buf, false, initial)
	return s
}

// Checksumer calculates checksum defined in RFC 1071.
type Checksumer struct {
	sum uint16
	odd bool
}

// Add adds b to checksum.
func (c *Checksumer) Add(b []byte) {
	if len(b) > 0 {
		c.sum, c.odd = calculateChecksum(b, c.odd, c.sum)
	}
}

// Checksum returns the latest checksum value.
func (c *Checksumer) Checksum() uint16 {
	return c.sum
}

// Combine combines the two uint16 to form their checksum. This is done
// by adding them and the carry.
//
// Note that checksum a must have been computed on an even number of bytes.
func Combine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}
