// Copyright 2021 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// IPv4Buffer is an IPv4 header that is backed by a buffer.View. It must be
// released with Release() when no longer needed or passed to an object that
// takes ownership of the buffer.View.
//
// Most of the methods of IPv4 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv4 before using other
// methods.
type IPv4Buffer struct {
	buffer.View
}

// Release releases the underlying buffer.View.
func (ip *IPv4Buffer) Release() {
	ip.View.Release()
}

// HeaderLength returns the value of the "header length" field of the IPv4
// header. The length returned is in bytes.
func (ip *IPv4Buffer) HeaderLength() uint8 {
	b := ip.View.AsSlice()
	return (b[versIHL] & ipIHLMask) * IPv4IHLStride
}

// SetHeaderLength sets the value of the "Internet Header Length" field.
func (ip *IPv4Buffer) SetHeaderLength(hdrLen uint8) {
	if hdrLen > IPv4MaximumHeaderSize {
		panic(fmt.Sprintf("got IPv4 Header size = %d, want <= %d", hdrLen, IPv4MaximumHeaderSize))
	}
	ip.View.WriteAt([]byte{(IPv4Version << ipVersionShift) | ((hdrLen / IPv4IHLStride) & ipIHLMask)}, versIHL)
}

// ID returns the value of the identifier field of the IPv4 header.
func (ip *IPv4Buffer) ID() uint16 {
	b := ip.View.AsSlice()
	return binary.BigEndian.Uint16(b[id:])
}

// Protocol returns the value of the protocol field of the IPv4 header.
func (ip *IPv4Buffer) Protocol() uint8 {
	return ip.View.AsSlice()[protocol]
}

// Flags returns the "flags" field of the IPv4 header.
func (ip *IPv4Buffer) Flags() uint8 {
	b := ip.View.AsSlice()
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

// More returns whether the more fragments flag is set.
func (ip *IPv4Buffer) More() bool {
	return ip.Flags()&IPv4FlagMoreFragments != 0
}

// TTL returns the "TTL" field of the IPv4 header.
func (ip *IPv4Buffer) TTL() uint8 {
	b := ip.View.AsSlice()
	return b[ttl]
}

// FragmentOffset returns the "fragment offset" field of the IPv4 header.
func (ip *IPv4Buffer) FragmentOffset() uint16 {
	b := ip.View.AsSlice()
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

// TotalLength returns the "total length" field of the IPv4 header.
func (ip *IPv4Buffer) TotalLength() uint16 {
	b := ip.View.AsSlice()
	return binary.BigEndian.Uint16(b[IPv4TotalLenOffset:])
}

// Checksum returns the checksum field of the IPv4 header.
func (ip *IPv4Buffer) Checksum() uint16 {
	b := ip.View.AsSlice()
	return binary.BigEndian.Uint16(b[xsum:])
}

// SourceAddress returns the "source address" field of the IPv4 header.
func (ip *IPv4Buffer) SourceAddress() tcpip.Address {
	b := ip.View.AsSlice()
	return tcpip.AddrFrom4([4]byte(b[srcAddr : srcAddr+IPv4AddressSize]))
}

// DestinationAddress returns the "destination address" field of the IPv4
// header.
func (ip *IPv4Buffer) DestinationAddress() tcpip.Address {
	b := ip.View.AsSlice()
	return tcpip.AddrFrom4([4]byte(b[dstAddr : dstAddr+IPv4AddressSize]))
}

// SourceAddressSlice returns the "source address" field of the IPv4 header as a
// byte slice.
func (ip *IPv4Buffer) SourceAddressSlice() []byte {
	b := ip.View.AsSlice()
	return []byte(b[srcAddr : srcAddr+IPv4AddressSize])
}

// DestinationAddressSlice returns the "destination address" field of the IPv4
// header as a byte slice.
func (ip *IPv4Buffer) DestinationAddressSlice() []byte {
	b := ip.View.AsSlice()
	return []byte(b[dstAddr : dstAddr+IPv4AddressSize])
}

// SetSourceAddressWithChecksumUpdate implements ChecksummableNetwork.
func (ip *IPv4Buffer) SetSourceAddressWithChecksumUpdate(new tcpip.Address) {
	ip.SetChecksum(^checksumUpdate2ByteAlignedAddress(^ip.Checksum(), ip.SourceAddress(), new))
	ip.SetSourceAddress(new)
}

// SetDestinationAddressWithChecksumUpdate implements ChecksummableNetwork.
func (ip *IPv4Buffer) SetDestinationAddressWithChecksumUpdate(new tcpip.Address) {
	ip.SetChecksum(^checksumUpdate2ByteAlignedAddress(^ip.Checksum(), ip.DestinationAddress(), new))
	ip.SetDestinationAddress(new)
}

// Options returns a buffer holding the options.
func (ip *IPv4Buffer) Options() IPv4Options {
	hdrLen := ip.HeaderLength()
	b := ip.View.AsSlice()
	return IPv4Options(b[options:hdrLen:hdrLen])
}

// TransportProtocol implements Network.TransportProtocol.
func (ip *IPv4Buffer) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(ip.Protocol())
}

// Payload implements Network.Payload.
func (ip *IPv4Buffer) Payload() []byte {
	b := ip.View.AsSlice()
	return b[ip.HeaderLength():][:ip.PayloadLength()]
}

// PayloadLength returns the length of the payload portion of the IPv4 packet.
func (ip *IPv4Buffer) PayloadLength() uint16 {
	return ip.TotalLength() - uint16(ip.HeaderLength())
}

// TOS returns the "type of service" field of the IPv4 header.
func (ip *IPv4Buffer) TOS() (uint8, uint32) {
	b := ip.View.AsSlice()
	return b[tos], 0
}

// SetTOS sets the "type of service" field of the IPv4 header.
func (ip *IPv4Buffer) SetTOS(v uint8, _ uint32) {
	ip.View.WriteAt([]byte{v}, tos)
}

// SetTTL sets the "Time to Live" field of the IPv4 header.
func (ip *IPv4Buffer) SetTTL(v byte) {
	ip.View.WriteAt([]byte{v}, ttl)
}

// SetTotalLength sets the "total length" field of the IPv4 header.
func (ip *IPv4Buffer) SetTotalLength(totalLength uint16) {
	ip.View.WithSlice(func(b []byte) {
		binary.BigEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
	})
}

// SetChecksum sets the checksum field of the IPv4 header.
func (ip *IPv4Buffer) SetChecksum(v uint16) {
	ip.View.WithSlice(func(b []byte) {
		binary.BigEndian.PutUint16(b[xsum:], v)
	})
}

// SetFlagsFragmentOffset sets the "flags" and "fragment offset" fields of the
// IPv4 header.
func (ip *IPv4Buffer) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	ip.View.WithSlice(func(b []byte) {
		v := (uint16(flags) << 13) | (offset >> 3)
		binary.BigEndian.PutUint16(b[flagsFO:], v)
	})
}

// SetID sets the identification field.
func (ip *IPv4Buffer) SetID(v uint16) {
	ip.View.WithSlice(func(b []byte) {
		binary.BigEndian.PutUint16(b[id:], v)
	})
}

// SetSourceAddress sets the "source address" field of the IPv4 header.
func (ip *IPv4Buffer) SetSourceAddress(addr tcpip.Address) {
	ip.View.WriteAt(addr.AsSlice(), srcAddr)
}

// SetDestinationAddress sets the "destination address" field of the IPv4
// header.
func (ip *IPv4Buffer) SetDestinationAddress(addr tcpip.Address) {
	ip.View.WriteAt(addr.AsSlice(), dstAddr)
}

// CalculateChecksum calculates the checksum of the IPv4 header.
func (ip *IPv4Buffer) CalculateChecksum() uint16 {
	b := ip.View.AsSlice()
	return checksum.Checksum(b[:ip.HeaderLength()], 0)
}

// Encode encodes all the fields of the IPv4 header.
func (ip *IPv4Buffer) Encode(i *IPv4Fields) {
	// The size of the options defines the size of the whole header and thus the
	// IHL field. Options are rare and this is a heavily used function so it is
	// worth a bit of optimisation here to keep the serializer out of the fast
	// path.
	ip.View.WithSlice(func(b []byte) {
		hdrLen := uint8(IPv4MinimumSize)
		if len(i.Options) != 0 {
			hdrLen += i.Options.Serialize(b[options:])
		}
		if hdrLen > IPv4MaximumHeaderSize {
			panic(fmt.Sprintf("%d is larger than maximum IPv4 header size of %d", hdrLen, IPv4MaximumHeaderSize))
		}
		ip.SetHeaderLength(hdrLen)
		b[tos] = i.TOS
		ip.SetTotalLength(i.TotalLength)
		binary.BigEndian.PutUint16(b[id:], i.ID)
		ip.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
		b[ttl] = i.TTL
		b[protocol] = i.Protocol
		ip.SetChecksum(i.Checksum)
		copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr.AsSlice())
		copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr.AsSlice())
	})
}

// EncodePartial updates the total length and checksum fields of IPv4 header,
// taking in the partial checksum, which is the checksum of the header without
// the total length and checksum fields. It is useful in cases when similar
// packets are produced.
func (ip *IPv4Buffer) EncodePartial(partialChecksum, totalLength uint16) {
	ip.SetTotalLength(totalLength)
	b := ip.View.AsSlice()
	xsum := checksum.Checksum(b[IPv4TotalLenOffset:IPv4TotalLenOffset+2], partialChecksum)
	ip.SetChecksum(^xsum)
}

// IsValid performs basic validation on the packet.
func (ip *IPv4Buffer) IsValid(pktSize int) bool {
	b := ip.View.AsSlice()
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(ip.HeaderLength())
	tlen := int(ip.TotalLength())
	if hlen < IPv4MinimumSize || hlen > tlen || tlen > pktSize {
		return false
	}

	if IPVersion(b) != IPv4Version {
		return false
	}

	return true
}

// IsChecksumValid returns true iff the IPv4 header's checksum is valid.
func (ip *IPv4Buffer) IsChecksumValid() bool {
	// There has been some confusion regarding verifying checksums. We need
	// just look for negative 0 (0xffff) as the checksum, as it's not possible to
	// get positive 0 (0) for the checksum. Some bad implementations could get it
	// when doing entry replacement in the early days of the Internet,
	// however the lore that one needs to check for both persists.
	//
	// RFC 1624 section 1 describes the source of this confusion as:
	//     [the partial recalculation method described in RFC 1071] computes a
	//     result for certain cases that differs from the one obtained from
	//     scratch (one's complement of one's complement sum of the original
	//     fields).
	//
	// However RFC 1624 section 5 clarifies that if using the verification method
	// "recommended by RFC 1071, it does not matter if an intermediate system
	// generated a -0 instead of +0".
	//
	// RFC1071 page 1 specifies the verification method as:
	//	  (3)  To check a checksum, the 1's complement sum is computed over the
	//        same set of octets, including the checksum field.  If the result
	//        is all 1 bits (-0 in 1's complement arithmetic), the check
	//        succeeds.
	return ip.CalculateChecksum() == 0xffff
}
