// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

const (
	// MaxIPPacketSize is the maximum supported IP packet size, excluding
	// jumbograms. The maximum IPv4 packet size is 64k-1 (total size must fit
	// in 16 bits). For IPv6, the payload max size (excluding jumbograms) is
	// 64k-1 (also needs to fit in 16 bits). So we use 64k - 1 + 2 * m, where
	// m is the minimum IPv6 header size; we leave room for some potential
	// IP options.
	MaxIPPacketSize = 0xffff + 2*IPv6MinimumSize
)

// Transport offers generic methods to query and/or update the fields of the
// header of a transport protocol buffer.
type Transport interface {
	// SourcePort returns the value of the "source port" field.
	SourcePort() uint16

	// Destination returns the value of the "destination port" field.
	DestinationPort() uint16

	// Checksum returns the value of the "checksum" field.
	Checksum() uint16

	// SetSourcePort sets the value of the "source port" field.
	SetSourcePort(uint16)

	// SetDestinationPort sets the value of the "destination port" field.
	SetDestinationPort(uint16)

	// SetChecksum sets the value of the "checksum" field.
	SetChecksum(uint16)

	// Payload returns the data carried in the transport buffer.
	Payload() []byte
}

// Network offers generic methods to query and/or update the fields of the
// header of a network protocol buffer.
type Network interface {
	// SourceAddress returns the value of the "source address" field.
	SourceAddress() tcpip.Address

	// DestinationAddress returns the value of the "destination address"
	// field.
	DestinationAddress() tcpip.Address

	// Checksum returns the value of the "checksum" field.
	Checksum() uint16

	// SetSourceAddress sets the value of the "source address" field.
	SetSourceAddress(tcpip.Address)

	// SetDestinationAddress sets the value of the "destination address"
	// field.
	SetDestinationAddress(tcpip.Address)

	// SetChecksum sets the value of the "checksum" field.
	SetChecksum(uint16)

	// TransportProtocol returns the number of the transport protocol
	// stored in the payload.
	TransportProtocol() tcpip.TransportProtocolNumber

	// Payload returns a byte slice containing the payload of the network
	// packet.
	Payload() []byte

	// TOS returns the values of the "type of service" and "flow label" fields.
	TOS() (uint8, uint32)

	// SetTOS sets the values of the "type of service" and "flow label" fields.
	SetTOS(t uint8, l uint32)
}
