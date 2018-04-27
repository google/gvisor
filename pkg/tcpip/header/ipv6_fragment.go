// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

const (
	nextHdrFrag = 0
	fragOff     = 2
	more        = 3
	idV6        = 4
)

// IPv6FragmentFields contains the fields of an IPv6 fragment. It is used to describe the
// fields of a packet that needs to be encoded.
type IPv6FragmentFields struct {
	// NextHeader is the "next header" field of an IPv6 fragment.
	NextHeader uint8

	// FragmentOffset is the "fragment offset" field of an IPv6 fragment.
	FragmentOffset uint16

	// M is the "more" field of an IPv6 fragment.
	M bool

	// Identification is the "identification" field of an IPv6 fragment.
	Identification uint32
}

// IPv6Fragment represents an ipv6 fragment header stored in a byte array.
// Most of the methods of IPv6Fragment access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv6Fragment before using other methods.
type IPv6Fragment []byte

const (
	// IPv6FragmentHeader header is the number used to specify that the next
	// header is a fragment header, per RFC 2460.
	IPv6FragmentHeader = 44

	// IPv6FragmentHeaderSize is the size of the fragment header.
	IPv6FragmentHeaderSize = 8
)

// Encode encodes all the fields of the ipv6 fragment.
func (b IPv6Fragment) Encode(i *IPv6FragmentFields) {
	b[nextHdrFrag] = i.NextHeader
	binary.BigEndian.PutUint16(b[fragOff:], i.FragmentOffset<<3)
	if i.M {
		b[more] |= 1
	}
	binary.BigEndian.PutUint32(b[idV6:], i.Identification)
}

// IsValid performs basic validation on the fragment header.
func (b IPv6Fragment) IsValid() bool {
	return len(b) >= IPv6FragmentHeaderSize
}

// NextHeader returns the value of the "next header" field of the ipv6 fragment.
func (b IPv6Fragment) NextHeader() uint8 {
	return b[nextHdrFrag]
}

// FragmentOffset returns the "fragment offset" field of the ipv6 fragment.
func (b IPv6Fragment) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[fragOff:]) >> 3
}

// More returns the "more" field of the ipv6 fragment.
func (b IPv6Fragment) More() bool {
	return b[more]&1 > 0
}

// Payload implements Network.Payload.
func (b IPv6Fragment) Payload() []byte {
	return b[IPv6FragmentHeaderSize:]
}

// ID returns the value of the identifier field of the ipv6 fragment.
func (b IPv6Fragment) ID() uint32 {
	return binary.BigEndian.Uint32(b[idV6:])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv6Fragment) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}

// The functions below have been added only to satisfy the Network interface.

// Checksum is not supported by IPv6Fragment.
func (b IPv6Fragment) Checksum() uint16 {
	panic("not supported")
}

// SourceAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SourceAddress() tcpip.Address {
	panic("not supported")
}

// DestinationAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) DestinationAddress() tcpip.Address {
	panic("not supported")
}

// SetSourceAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SetSourceAddress(tcpip.Address) {
	panic("not supported")
}

// SetDestinationAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SetDestinationAddress(tcpip.Address) {
	panic("not supported")
}

// SetChecksum is not supported by IPv6Fragment.
func (b IPv6Fragment) SetChecksum(uint16) {
	panic("not supported")
}

// TOS is not supported by IPv6Fragment.
func (b IPv6Fragment) TOS() (uint8, uint32) {
	panic("not supported")
}

// SetTOS is not supported by IPv6Fragment.
func (b IPv6Fragment) SetTOS(t uint8, l uint32) {
	panic("not supported")
}
