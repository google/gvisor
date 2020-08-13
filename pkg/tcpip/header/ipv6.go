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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	versTCFL = 0
	// IPv6PayloadLenOffset is the offset of the PayloadLength field in
	// IPv6 header.
	IPv6PayloadLenOffset = 4
	// IPv6NextHeaderOffset is the offset of the NextHeader field in
	// IPv6 header.
	IPv6NextHeaderOffset = 6
	hopLimit             = 7
	v6SrcAddr            = 8
	v6DstAddr            = v6SrcAddr + IPv6AddressSize
)

// IPv6Fields contains the fields of an IPv6 packet. It is used to describe the
// fields of a packet that needs to be encoded.
type IPv6Fields struct {
	// TrafficClass is the "traffic class" field of an IPv6 packet.
	TrafficClass uint8

	// FlowLabel is the "flow label" field of an IPv6 packet.
	FlowLabel uint32

	// PayloadLength is the "payload length" field of an IPv6 packet.
	PayloadLength uint16

	// NextHeader is the "next header" field of an IPv6 packet.
	NextHeader uint8

	// HopLimit is the "hop limit" field of an IPv6 packet.
	HopLimit uint8

	// SrcAddr is the "source ip address" of an IPv6 packet.
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv6 packet.
	DstAddr tcpip.Address
}

// IPv6 represents an ipv6 header stored in a byte array.
// Most of the methods of IPv6 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv6 before using other methods.
type IPv6 []byte

const (
	// IPv6MinimumSize is the minimum size of a valid IPv6 packet.
	IPv6MinimumSize = 40

	// IPv6AddressSize is the size, in bytes, of an IPv6 address.
	IPv6AddressSize = 16

	// IPv6ProtocolNumber is IPv6's network protocol number.
	IPv6ProtocolNumber tcpip.NetworkProtocolNumber = 0x86dd

	// IPv6Version is the version of the ipv6 protocol.
	IPv6Version = 6

	// IPv6AllNodesMulticastAddress is a link-local multicast group that
	// all IPv6 nodes MUST join, as per RFC 4291, section 2.8. Packets
	// destined to this address will reach all nodes on a link.
	//
	// The address is ff02::1.
	IPv6AllNodesMulticastAddress tcpip.Address = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

	// IPv6AllRoutersMulticastAddress is a link-local multicast group that
	// all IPv6 routers MUST join, as per RFC 4291, section 2.8. Packets
	// destined to this address will reach all routers on a link.
	//
	// The address is ff02::2.
	IPv6AllRoutersMulticastAddress tcpip.Address = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	// IPv6MinimumMTU is the minimum MTU required by IPv6, per RFC 2460,
	// section 5.
	IPv6MinimumMTU = 1280

	// IPv6Any is the non-routable IPv6 "any" meta address. It is also
	// known as the unspecified address.
	IPv6Any tcpip.Address = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	// IIDSize is the size of an interface identifier (IID), in bytes, as
	// defined by RFC 4291 section 2.5.1.
	IIDSize = 8

	// IIDOffsetInIPv6Address is the offset, in bytes, from the start
	// of an IPv6 address to the beginning of the interface identifier
	// (IID) for auto-generated addresses. That is, all bytes before
	// the IIDOffsetInIPv6Address-th byte are the prefix bytes, and all
	// bytes including and after the IIDOffsetInIPv6Address-th byte are
	// for the IID.
	IIDOffsetInIPv6Address = 8

	// OpaqueIIDSecretKeyMinBytes is the recommended minimum number of bytes
	// for the secret key used to generate an opaque interface identifier as
	// outlined by RFC 7217.
	OpaqueIIDSecretKeyMinBytes = 16

	// ipv6MulticastAddressScopeByteIdx is the byte where the scope (scop) field
	// is located within a multicast IPv6 address, as per RFC 4291 section 2.7.
	ipv6MulticastAddressScopeByteIdx = 1

	// ipv6MulticastAddressScopeMask is the mask for the scope (scop) field,
	// within the byte holding the field, as per RFC 4291 section 2.7.
	ipv6MulticastAddressScopeMask = 0xF

	// ipv6LinkLocalMulticastScope is the value of the scope (scop) field within
	// a multicast IPv6 address that indicates the address has link-local scope,
	// as per RFC 4291 section 2.7.
	ipv6LinkLocalMulticastScope = 2
)

// IPv6EmptySubnet is the empty IPv6 subnet. It may also be known as the
// catch-all or wildcard subnet. That is, all IPv6 addresses are considered to
// be contained within this subnet.
var IPv6EmptySubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv6Any, tcpip.AddressMask(IPv6Any))
	if err != nil {
		panic(err)
	}
	return subnet
}()

// IPv6LinkLocalPrefix is the prefix for IPv6 link-local addresses, as defined
// by RFC 4291 section 2.5.6.
//
// The prefix is fe80::/64
var IPv6LinkLocalPrefix = tcpip.AddressWithPrefix{
	Address:   "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	PrefixLen: 64,
}

// PayloadLength returns the value of the "payload length" field of the ipv6
// header.
func (b IPv6) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv6PayloadLenOffset:])
}

// HopLimit returns the value of the "hop limit" field of the ipv6 header.
func (b IPv6) HopLimit() uint8 {
	return b[hopLimit]
}

// NextHeader returns the value of the "next header" field of the ipv6 header.
func (b IPv6) NextHeader() uint8 {
	return b[IPv6NextHeaderOffset]
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv6) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}

// Payload implements Network.Payload.
func (b IPv6) Payload() []byte {
	return b[IPv6MinimumSize:][:b.PayloadLength()]
}

// SourceAddress returns the "source address" field of the ipv6 header.
func (b IPv6) SourceAddress() tcpip.Address {
	return tcpip.Address(b[v6SrcAddr:][:IPv6AddressSize])
}

// DestinationAddress returns the "destination address" field of the ipv6
// header.
func (b IPv6) DestinationAddress() tcpip.Address {
	return tcpip.Address(b[v6DstAddr:][:IPv6AddressSize])
}

// Checksum implements Network.Checksum. Given that IPv6 doesn't have a
// checksum, it just returns 0.
func (IPv6) Checksum() uint16 {
	return 0
}

// TOS returns the "traffic class" and "flow label" fields of the ipv6 header.
func (b IPv6) TOS() (uint8, uint32) {
	v := binary.BigEndian.Uint32(b[versTCFL:])
	return uint8(v >> 20), v & 0xfffff
}

// SetTOS sets the "traffic class" and "flow label" fields of the ipv6 header.
func (b IPv6) SetTOS(t uint8, l uint32) {
	vtf := (6 << 28) | (uint32(t) << 20) | (l & 0xfffff)
	binary.BigEndian.PutUint32(b[versTCFL:], vtf)
}

// SetPayloadLength sets the "payload length" field of the ipv6 header.
func (b IPv6) SetPayloadLength(payloadLength uint16) {
	binary.BigEndian.PutUint16(b[IPv6PayloadLenOffset:], payloadLength)
}

// SetSourceAddress sets the "source address" field of the ipv6 header.
func (b IPv6) SetSourceAddress(addr tcpip.Address) {
	copy(b[v6SrcAddr:][:IPv6AddressSize], addr)
}

// SetDestinationAddress sets the "destination address" field of the ipv6
// header.
func (b IPv6) SetDestinationAddress(addr tcpip.Address) {
	copy(b[v6DstAddr:][:IPv6AddressSize], addr)
}

// SetNextHeader sets the value of the "next header" field of the ipv6 header.
func (b IPv6) SetNextHeader(v uint8) {
	b[IPv6NextHeaderOffset] = v
}

// SetChecksum implements Network.SetChecksum. Given that IPv6 doesn't have a
// checksum, it is empty.
func (IPv6) SetChecksum(uint16) {
}

// Encode encodes all the fields of the ipv6 header.
func (b IPv6) Encode(i *IPv6Fields) {
	b.SetTOS(i.TrafficClass, i.FlowLabel)
	b.SetPayloadLength(i.PayloadLength)
	b[IPv6NextHeaderOffset] = i.NextHeader
	b[hopLimit] = i.HopLimit
	b.SetSourceAddress(i.SrcAddr)
	b.SetDestinationAddress(i.DstAddr)
}

// IsValid performs basic validation on the packet.
func (b IPv6) IsValid(pktSize int) bool {
	if len(b) < IPv6MinimumSize {
		return false
	}

	dlen := int(b.PayloadLength())
	if dlen > pktSize-IPv6MinimumSize {
		return false
	}

	if IPVersion(b) != IPv6Version {
		return false
	}

	return true
}

// IsV4MappedAddress determines if the provided address is an IPv4 mapped
// address by checking if its prefix is 0:0:0:0:0:ffff::/96.
func IsV4MappedAddress(addr tcpip.Address) bool {
	if len(addr) != IPv6AddressSize {
		return false
	}

	return strings.HasPrefix(string(addr), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")
}

// IsV6MulticastAddress determines if the provided address is an IPv6
// multicast address (anything starting with FF).
func IsV6MulticastAddress(addr tcpip.Address) bool {
	if len(addr) != IPv6AddressSize {
		return false
	}
	return addr[0] == 0xff
}

// IsV6UnicastAddress determines if the provided address is a valid IPv6
// unicast (and specified) address. That is, IsV6UnicastAddress returns
// true if addr contains IPv6AddressSize bytes, is not the unspecified
// address and is not a multicast address.
func IsV6UnicastAddress(addr tcpip.Address) bool {
	if len(addr) != IPv6AddressSize {
		return false
	}

	// Must not be unspecified
	if addr == IPv6Any {
		return false
	}

	// Return if not a multicast.
	return addr[0] != 0xff
}

// SolicitedNodeAddr computes the solicited-node multicast address. This is
// used for NDP. Described in RFC 4291. The argument must be a full-length IPv6
// address.
func SolicitedNodeAddr(addr tcpip.Address) tcpip.Address {
	const solicitedNodeMulticastPrefix = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff"
	return solicitedNodeMulticastPrefix + addr[len(addr)-3:]
}

// EthernetAdddressToModifiedEUI64IntoBuf populates buf with a modified EUI-64
// from a 48-bit Ethernet/MAC address, as per RFC 4291 section 2.5.1.
//
// buf MUST be at least 8 bytes.
func EthernetAdddressToModifiedEUI64IntoBuf(linkAddr tcpip.LinkAddress, buf []byte) {
	buf[0] = linkAddr[0] ^ 2
	buf[1] = linkAddr[1]
	buf[2] = linkAddr[2]
	buf[3] = 0xFF
	buf[4] = 0xFE
	buf[5] = linkAddr[3]
	buf[6] = linkAddr[4]
	buf[7] = linkAddr[5]
}

// EthernetAddressToModifiedEUI64 computes a modified EUI-64 from a 48-bit
// Ethernet/MAC address, as per RFC 4291 section 2.5.1.
func EthernetAddressToModifiedEUI64(linkAddr tcpip.LinkAddress) [IIDSize]byte {
	var buf [IIDSize]byte
	EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, buf[:])
	return buf
}

// LinkLocalAddr computes the default IPv6 link-local address from a link-layer
// (MAC) address.
func LinkLocalAddr(linkAddr tcpip.LinkAddress) tcpip.Address {
	// Convert a 48-bit MAC to a modified EUI-64 and then prepend the
	// link-local header, FE80::.
	//
	// The conversion is very nearly:
	//	aa:bb:cc:dd:ee:ff => FE80::Aabb:ccFF:FEdd:eeff
	// Note the capital A. The conversion aa->Aa involves a bit flip.
	lladdrb := [IPv6AddressSize]byte{
		0: 0xFE,
		1: 0x80,
	}
	EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, lladdrb[IIDOffsetInIPv6Address:])
	return tcpip.Address(lladdrb[:])
}

// IsV6LinkLocalAddress determines if the provided address is an IPv6
// link-local address (fe80::/10).
func IsV6LinkLocalAddress(addr tcpip.Address) bool {
	if len(addr) != IPv6AddressSize {
		return false
	}
	return addr[0] == 0xfe && (addr[1]&0xc0) == 0x80
}

// IsV6LinkLocalMulticastAddress determines if the provided address is an IPv6
// link-local multicast address.
func IsV6LinkLocalMulticastAddress(addr tcpip.Address) bool {
	return IsV6MulticastAddress(addr) && addr[ipv6MulticastAddressScopeByteIdx]&ipv6MulticastAddressScopeMask == ipv6LinkLocalMulticastScope
}

// IsV6UniqueLocalAddress determines if the provided address is an IPv6
// unique-local address (within the prefix FC00::/7).
func IsV6UniqueLocalAddress(addr tcpip.Address) bool {
	if len(addr) != IPv6AddressSize {
		return false
	}
	// According to RFC 4193 section 3.1, a unique local address has the prefix
	// FC00::/7.
	return (addr[0] & 0xfe) == 0xfc
}

// AppendOpaqueInterfaceIdentifier appends a 64 bit opaque interface identifier
// (IID) to buf as outlined by RFC 7217 and returns the extended buffer.
//
// The opaque IID is generated from the cryptographic hash of the concatenation
// of the prefix, NIC's name, DAD counter (DAD retry counter) and the secret
// key. The secret key SHOULD be at least OpaqueIIDSecretKeyMinBytes bytes and
// MUST be generated to a pseudo-random number. See RFC 4086 for randomness
// requirements for security.
//
// If buf has enough capacity for the IID (IIDSize bytes), a new underlying
// array for the buffer will not be allocated.
func AppendOpaqueInterfaceIdentifier(buf []byte, prefix tcpip.Subnet, nicName string, dadCounter uint8, secretKey []byte) []byte {
	// As per RFC 7217 section 5, the opaque identifier can be generated as a
	// cryptographic hash of the concatenation of each of the function parameters.
	// Note, we omit the optional Network_ID field.
	h := sha256.New()
	// h.Write never returns an error.
	h.Write([]byte(prefix.ID()[:IIDOffsetInIPv6Address]))
	h.Write([]byte(nicName))
	h.Write([]byte{dadCounter})
	h.Write(secretKey)

	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])

	return append(buf, sum[:IIDSize]...)
}

// LinkLocalAddrWithOpaqueIID computes the default IPv6 link-local address with
// an opaque IID.
func LinkLocalAddrWithOpaqueIID(nicName string, dadCounter uint8, secretKey []byte) tcpip.Address {
	lladdrb := [IPv6AddressSize]byte{
		0: 0xFE,
		1: 0x80,
	}

	return tcpip.Address(AppendOpaqueInterfaceIdentifier(lladdrb[:IIDOffsetInIPv6Address], IPv6LinkLocalPrefix.Subnet(), nicName, dadCounter, secretKey))
}

// IPv6AddressScope is the scope of an IPv6 address.
type IPv6AddressScope int

const (
	// LinkLocalScope indicates a link-local address.
	LinkLocalScope IPv6AddressScope = iota

	// UniqueLocalScope indicates a unique-local address.
	UniqueLocalScope

	// GlobalScope indicates a global address.
	GlobalScope
)

// ScopeForIPv6Address returns the scope for an IPv6 address.
func ScopeForIPv6Address(addr tcpip.Address) (IPv6AddressScope, *tcpip.Error) {
	if len(addr) != IPv6AddressSize {
		return GlobalScope, tcpip.ErrBadAddress
	}

	switch {
	case IsV6LinkLocalMulticastAddress(addr):
		return LinkLocalScope, nil

	case IsV6LinkLocalAddress(addr):
		return LinkLocalScope, nil

	case IsV6UniqueLocalAddress(addr):
		return UniqueLocalScope, nil

	default:
		return GlobalScope, nil
	}
}

// InitialTempIID generates the initial temporary IID history value to generate
// temporary SLAAC addresses with.
//
// Panics if initialTempIIDHistory is not at least IIDSize bytes.
func InitialTempIID(initialTempIIDHistory []byte, seed []byte, nicID tcpip.NICID) {
	h := sha256.New()
	// h.Write never returns an error.
	h.Write(seed)
	var nicIDBuf [4]byte
	binary.BigEndian.PutUint32(nicIDBuf[:], uint32(nicID))
	h.Write(nicIDBuf[:])

	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])

	if n := copy(initialTempIIDHistory, sum[sha256.Size-IIDSize:]); n != IIDSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, IIDSize))
	}
}

// GenerateTempIPv6SLAACAddr generates a temporary SLAAC IPv6 address for an
// associated stable/permanent SLAAC address.
//
// GenerateTempIPv6SLAACAddr will update the temporary IID history value to be
// used when generating a new temporary IID.
//
// Panics if tempIIDHistory is not at least IIDSize bytes.
func GenerateTempIPv6SLAACAddr(tempIIDHistory []byte, stableAddr tcpip.Address) tcpip.AddressWithPrefix {
	addrBytes := []byte(stableAddr)
	h := sha256.New()
	h.Write(tempIIDHistory)
	h.Write(addrBytes[IIDOffsetInIPv6Address:])
	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])

	// The rightmost 64 bits of sum are saved for the next iteration.
	if n := copy(tempIIDHistory, sum[sha256.Size-IIDSize:]); n != IIDSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, IIDSize))
	}

	// The leftmost 64 bits of sum is used as the IID.
	if n := copy(addrBytes[IIDOffsetInIPv6Address:], sum); n != IIDSize {
		panic(fmt.Sprintf("copied %d IID bytes, expected %d bytes", n, IIDSize))
	}

	return tcpip.AddressWithPrefix{
		Address:   tcpip.Address(addrBytes),
		PrefixLen: IIDOffsetInIPv6Address * 8,
	}
}
