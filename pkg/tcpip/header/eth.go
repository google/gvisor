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

package header

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip"
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

const (
	// EthernetProtocolAll is a catch-all for all protocols carried inside
	// an ethernet frame. It is mainly used to create packet sockets that
	// capture all traffic.
	EthernetProtocolAll tcpip.NetworkProtocolNumber = 0x0003

	// EthernetProtocolPUP is the PARC Universial Packet protocol ethertype.
	EthernetProtocolPUP tcpip.NetworkProtocolNumber = 0x0200
)

// Ethertypes holds the protocol numbers describing the payload of an ethernet
// frame. These types aren't necessarily supported by netstack, but can be used
// to catch all traffic of a type via packet endpoints.
var Ethertypes = []tcpip.NetworkProtocolNumber{
	EthernetProtocolAll,
	EthernetProtocolPUP,
}

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
