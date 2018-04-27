// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

const (
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

// EthernetFields contains the fields of an ethernet frame header. It is used to
// describe the fields of a frame that needs to be encoded.
type EthernetFields struct {
	// SrcAddr is the "MAC source" field of an ethernet frame header.
	SrcAddr tcpip.LinkAddress

	// DstAddr is the "MAC destination" field of an ethernet frame header.
	DstAddr tcpip.LinkAddress

	// Type is the "ethertype" field of an ethernet frame header.
	Type tcpip.NetworkProtocolNumber
}

// Ethernet represents an ethernet frame header stored in a byte array.
type Ethernet []byte

const (
	// EthernetMinimumSize is the minimum size of a valid ethernet frame.
	EthernetMinimumSize = 14

	// EthernetAddressSize is the size, in bytes, of an ethernet address.
	EthernetAddressSize = 6
)

// SourceAddress returns the "MAC source" field of the ethernet frame header.
func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

// DestinationAddress returns the "MAC destination" field of the ethernet frame
// header.
func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

// Type returns the "ethertype" field of the ethernet frame header.
func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

// Encode encodes all the fields of the ethernet frame header.
func (b Ethernet) Encode(e *EthernetFields) {
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)
}
