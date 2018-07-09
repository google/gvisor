// Copyright 2018 Google Inc.
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

import "gvisor.googlesource.com/gvisor/pkg/tcpip"

const (
	// ARPProtocolNumber is the ARP network protocol number.
	ARPProtocolNumber tcpip.NetworkProtocolNumber = 0x0806

	// ARPSize is the size of an IPv4-over-Ethernet ARP packet.
	ARPSize = 2 + 2 + 1 + 1 + 2 + 2*6 + 2*4
)

// ARPOp is an ARP opcode.
type ARPOp uint16

// Typical ARP opcodes defined in RFC 826.
const (
	ARPRequest ARPOp = 1
	ARPReply   ARPOp = 2
)

// ARP is an ARP packet stored in a byte array as described in RFC 826.
type ARP []byte

func (a ARP) hardwareAddressSpace() uint16 { return uint16(a[0])<<8 | uint16(a[1]) }
func (a ARP) protocolAddressSpace() uint16 { return uint16(a[2])<<8 | uint16(a[3]) }
func (a ARP) hardwareAddressSize() int     { return int(a[4]) }
func (a ARP) protocolAddressSize() int     { return int(a[5]) }

// Op is the ARP opcode.
func (a ARP) Op() ARPOp { return ARPOp(a[6])<<8 | ARPOp(a[7]) }

// SetOp sets the ARP opcode.
func (a ARP) SetOp(op ARPOp) {
	a[6] = uint8(op >> 8)
	a[7] = uint8(op)
}

// SetIPv4OverEthernet configures the ARP packet for IPv4-over-Ethernet.
func (a ARP) SetIPv4OverEthernet() {
	a[0], a[1] = 0, 1       // htypeEthernet
	a[2], a[3] = 0x08, 0x00 // IPv4ProtocolNumber
	a[4] = 6                // macSize
	a[5] = uint8(IPv4AddressSize)
}

// HardwareAddressSender is the link address of the sender.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) HardwareAddressSender() []byte {
	const s = 8
	return a[s : s+6]
}

// ProtocolAddressSender is the protocol address of the sender.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) ProtocolAddressSender() []byte {
	const s = 8 + 6
	return a[s : s+4]
}

// HardwareAddressTarget is the link address of the target.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) HardwareAddressTarget() []byte {
	const s = 8 + 6 + 4
	return a[s : s+6]
}

// ProtocolAddressTarget is the protocol address of the target.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) ProtocolAddressTarget() []byte {
	const s = 8 + 6 + 4 + 6
	return a[s : s+4]
}

// IsValid reports whether this is an ARP packet for IPv4 over Ethernet.
func (a ARP) IsValid() bool {
	if len(a) < ARPSize {
		return false
	}
	const htypeEthernet = 1
	const macSize = 6
	return a.hardwareAddressSpace() == htypeEthernet &&
		a.protocolAddressSpace() == uint16(IPv4ProtocolNumber) &&
		a.hardwareAddressSize() == macSize &&
		a.protocolAddressSize() == IPv4AddressSize
}
