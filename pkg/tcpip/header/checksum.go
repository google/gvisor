// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package header

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

// Checksum calculates the checksum (as defined in RFC 1071) of the bytes in the
// given byte array.
func Checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)

	l := len(buf)
	if l&1 != 0 {
		l--
		v += uint32(buf[l]) << 8
	}

	for i := 0; i < l; i += 2 {
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
	}

	return ChecksumCombine(uint16(v), uint16(v>>16))
}

// ChecksumCombine combines the two uint16 to form their checksum. This is done
// by adding them and the carry.
func ChecksumCombine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}

// PseudoHeaderChecksum calculates the pseudo-header checksum for the
// given destination protocol and network address, ignoring the length
// field. Pseudo-headers are needed by transport layers when calculating
// their own checksum.
func PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, srcAddr tcpip.Address, dstAddr tcpip.Address) uint16 {
	xsum := Checksum([]byte(srcAddr), 0)
	xsum = Checksum([]byte(dstAddr), xsum)
	return Checksum([]byte{0, uint8(protocol)}, xsum)
}
