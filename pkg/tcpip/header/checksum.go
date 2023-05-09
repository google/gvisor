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

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package header

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// PseudoHeaderChecksum calculates the pseudo-header checksum for the given
// destination protocol and network address. Pseudo-headers are needed by
// transport layers when calculating their own checksum.
func PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, srcAddr tcpip.Address, dstAddr tcpip.Address, totalLen uint16) uint16 {
	xsum := checksum.Checksum([]byte(srcAddr), 0)
	xsum = checksum.Checksum([]byte(dstAddr), xsum)

	// Add the length portion of the checksum to the pseudo-checksum.
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	xsum = checksum.Checksum(tmp, xsum)

	return checksum.Checksum([]byte{0, uint8(protocol)}, xsum)
}

// checksumUpdate2ByteAlignedUint16 updates a uint16 value in a calculated
// checksum.
//
// The value MUST begin at a 2-byte boundary in the original buffer.
func checksumUpdate2ByteAlignedUint16(xsum, old, new uint16) uint16 {
	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	return checksum.Combine(xsum, checksum.Combine(new, ^old))
}

// checksumUpdate2ByteAlignedAddress updates an address in a calculated
// checksum.
//
// The addresses must have the same length and must contain an even number
// of bytes. The address MUST begin at a 2-byte boundary in the original buffer.
func checksumUpdate2ByteAlignedAddress(xsum uint16, old, new tcpip.Address) uint16 {
	const uint16Bytes = 2

	if len(old) != len(new) {
		panic(fmt.Sprintf("buffer lengths are different; old = %d, new = %d", len(old), len(new)))
	}

	if len(old)%uint16Bytes != 0 {
		panic(fmt.Sprintf("buffer has an odd number of bytes; got = %d", len(old)))
	}

	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	for len(old) != 0 {
		// Convert the 2 byte sequences to uint16 values then apply the increment
		// update.
		xsum = checksumUpdate2ByteAlignedUint16(xsum, (uint16(old[0])<<8)+uint16(old[1]), (uint16(new[0])<<8)+uint16(new[1]))
		old = old[uint16Bytes:]
		new = new[uint16Bytes:]
	}

	return xsum
}
