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

// ICMPv6 represents an ICMPv6 header stored in a byte array.
type ICMPv6 []byte

const (
	// ICMPv6MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv6MinimumSize = 4

	// ICMPv6ProtocolNumber is the ICMP transport protocol number.
	ICMPv6ProtocolNumber tcpip.TransportProtocolNumber = 58

	// ICMPv6NeighborSolicitMinimumSize is the minimum size of a
	// neighbor solicitation packet.
	ICMPv6NeighborSolicitMinimumSize = ICMPv6MinimumSize + 4 + 16

	// ICMPv6NeighborAdvertSize is size of a neighbor advertisement.
	ICMPv6NeighborAdvertSize = 32

	// ICMPv6EchoMinimumSize is the minimum size of a valid ICMP echo packet.
	ICMPv6EchoMinimumSize = 8

	// ICMPv6DstUnreachableMinimumSize is the minimum size of a valid ICMP
	// destination unreachable packet.
	ICMPv6DstUnreachableMinimumSize = ICMPv6MinimumSize + 4

	// ICMPv6PacketTooBigMinimumSize is the minimum size of a valid ICMP
	// packet-too-big packet.
	ICMPv6PacketTooBigMinimumSize = ICMPv6MinimumSize + 4
)

// ICMPv6Type is the ICMP type field described in RFC 4443 and friends.
type ICMPv6Type byte

// Typical values of ICMPv6Type defined in RFC 4443.
const (
	ICMPv6DstUnreachable ICMPv6Type = 1
	ICMPv6PacketTooBig   ICMPv6Type = 2
	ICMPv6TimeExceeded   ICMPv6Type = 3
	ICMPv6ParamProblem   ICMPv6Type = 4
	ICMPv6EchoRequest    ICMPv6Type = 128
	ICMPv6EchoReply      ICMPv6Type = 129

	// Neighbor Discovery Protocol (NDP) messages, see RFC 4861.

	ICMPv6RouterSolicit   ICMPv6Type = 133
	ICMPv6RouterAdvert    ICMPv6Type = 134
	ICMPv6NeighborSolicit ICMPv6Type = 135
	ICMPv6NeighborAdvert  ICMPv6Type = 136
	ICMPv6RedirectMsg     ICMPv6Type = 137
)

// Values for ICMP code as defined in RFC 4443.
const (
	ICMPv6PortUnreachable = 4
)

// Type is the ICMP type field.
func (b ICMPv6) Type() ICMPv6Type { return ICMPv6Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv6) SetType(t ICMPv6Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv6) Code() byte { return b[1] }

// SetCode sets the ICMP code field.
func (b ICMPv6) SetCode(c byte) { b[1] = c }

// Checksum is the ICMP checksum field.
func (b ICMPv6) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[2:])
}

// SetChecksum calculates and sets the ICMP checksum field.
func (b ICMPv6) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[2:], checksum)
}

// SourcePort implements Transport.SourcePort.
func (ICMPv6) SourcePort() uint16 {
	return 0
}

// DestinationPort implements Transport.DestinationPort.
func (ICMPv6) DestinationPort() uint16 {
	return 0
}

// SetSourcePort implements Transport.SetSourcePort.
func (ICMPv6) SetSourcePort(uint16) {
}

// SetDestinationPort implements Transport.SetDestinationPort.
func (ICMPv6) SetDestinationPort(uint16) {
}

// Payload implements Transport.Payload.
func (b ICMPv6) Payload() []byte {
	return b[ICMPv6MinimumSize:]
}
