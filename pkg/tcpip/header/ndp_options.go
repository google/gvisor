// Copyright 2019 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// NDPTargetLinkLayerAddressOptionType is the type of the Target
	// Link-Layer Address option, as per RFC 4861 section 4.6.1.
	NDPTargetLinkLayerAddressOptionType = 2

	// ndpTargetEthernetLinkLayerAddressSize is the size of a Target
	// Link Layer Option for an Ethernet address.
	ndpTargetEthernetLinkLayerAddressSize = 8

	// ndpPrefixInformationType is the type of the Prefix Information
	// option, as per RFC 4861 section 4.6.2.
	ndpPrefixInformationType = 3

	// ndpPrefixInformationLength is the expected length, in bytes, of the
	// body of an NDP Prefix Information option, as per RFC 4861 section
	// 4.6.2 which specifies that the Length field is 4. Given this, the
	// expected length, in bytes, is 30 becuase 4 * lengthByteUnits (8) - 2
	// (Type & Length) = 30.
	ndpPrefixInformationLength = 30

	// ndpPrefixInformationPrefixLengthOffset is the offset of the Prefix
	// Length field within an NDPPrefixInformation.
	ndpPrefixInformationPrefixLengthOffset = 0

	// ndpPrefixInformationFlagsOffset is the offset of the flags byte
	// within an NDPPrefixInformation.
	ndpPrefixInformationFlagsOffset = 1

	// ndpPrefixInformationOnLinkFlagMask is the mask of the On-Link Flag
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationOnLinkFlagMask = (1 << 7)

	// ndpPrefixInformationAutoAddrConfFlagMask is the mask of the
	// Autonomous Address-Configuration flag field in the flags byte within
	// an NDPPrefixInformation.
	ndpPrefixInformationAutoAddrConfFlagMask = (1 << 6)

	// ndpPrefixInformationReserved1FlagsMask is the mask of the Reserved1
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationReserved1FlagsMask = 63

	// ndpPrefixInformationValidLifetimeOffset is the start of the 4-byte
	// Valid Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationValidLifetimeOffset = 2

	// ndpPrefixInformationPreferredLifetimeOffset is the start of the
	// 4-byte Preferred Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationPreferredLifetimeOffset = 6

	// ndpPrefixInformationReserved2Offset is the start of the 4-byte
	// Reserved2 field within an NDPPrefixInformation.
	ndpPrefixInformationReserved2Offset = 10

	// ndpPrefixInformationReserved2Length is the length of the Reserved2
	// field.
	//
	// It is 4 bytes.
	ndpPrefixInformationReserved2Length = 4

	// ndpPrefixInformationPrefixOffset is the start of the Prefix field
	// within an NDPPrefixInformation.
	ndpPrefixInformationPrefixOffset = 14

	// NDPPrefixInformationInfiniteLifetime is a value that represents
	// infinity for the Valid and Preferred Lifetime fields in a NDP Prefix
	// Information option. Its value is (2^32 - 1)s = 4294967295s
	NDPPrefixInformationInfiniteLifetime = time.Second * 4294967295

	// lengthByteUnits is the multiplier factor for the Length field of an
	// NDP option. That is, the length field for NDP options is in units of
	// 8 octets, as per RFC 4861 section 4.6.
	lengthByteUnits = 8
)

// NDPOptions is a buffer of NDP options as defined by RFC 4861 section 4.6.
type NDPOptions []byte

// Serialize serializes the provided list of NDP options into o.
//
// Note, b must be of sufficient size to hold all the options in s. See
// NDPOptionsSerializer.Length for details on the getting the total size
// of a serialized NDPOptionsSerializer.
//
// Serialize may panic if b is not of sufficient size to hold all the options
// in s.
func (b NDPOptions) Serialize(s NDPOptionsSerializer) int {
	done := 0

	for _, o := range s {
		l := paddedLength(o)

		if l == 0 {
			continue
		}

		b[0] = o.Type()

		// We know this safe because paddedLength would have returned
		// 0 if o had an invalid length (> 255 * lengthByteUnits).
		b[1] = uint8(l / lengthByteUnits)

		// Serialize NDP option body.
		used := o.serializeInto(b[2:])

		// Zero out remaining (padding) bytes, if any exists.
		for i := used + 2; i < l; i++ {
			b[i] = 0
		}

		b = b[l:]
		done += l
	}

	return done
}

// ndpOption is the set of functions to be implemented by all NDP option types.
type ndpOption interface {
	// Type returns the type of this ndpOption.
	Type() uint8

	// Length returns the length of the body of this ndpOption, in bytes.
	Length() int

	// serializeInto serializes this ndpOption into the provided byte
	// buffer.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// Length. Implementers of this function may assume that the byte buffer
	// is of sufficient size. serializeInto MAY panic if the provided byte
	// buffer is not of sufficient size.
	//
	// serializeInto will return the number of bytes that was used to
	// serialize this ndpOption. Implementers must only use the number of
	// bytes required to serialize this ndpOption. Callers MAY provide a
	// larger buffer than required to serialize into.
	serializeInto([]byte) int
}

// paddedLength returns the length of o, in bytes, with any padding bytes, if
// required.
func paddedLength(o ndpOption) int {
	l := o.Length()

	if l == 0 {
		return 0
	}

	// Length excludes the 2 Type and Length bytes.
	l += 2

	// Add extra bytes if needed to make sure the option is
	// lengthByteUnits-byte aligned. We do this by adding lengthByteUnits-1
	// to l and then stripping off the last few LSBits from l. This will
	// make sure that l is rounded up to the nearest unit of
	// lengthByteUnits. This works since lengthByteUnits is a power of 2
	// (= 8).
	mask := lengthByteUnits - 1
	l += mask
	l &^= mask

	if l/lengthByteUnits > 255 {
		// Should never happen because an option can only have a max
		// value of 255 for its Length field, so just return 0 so this
		// option does not get serialized.
		//
		// Returning 0 here will make sure that this option does not get
		// serialized when NDPOptions.Serialize is called with the
		// NDPOptionsSerializer that holds this option, effectively
		// skipping this option during serialization. Also note that
		// a value of zero for the Length field in an NDP option is
		// invalid so this is another sign to the caller that this NDP
		// option is malformed, as per RFC 4861 section 4.6.
		return 0
	}

	return l
}

// NDPOptionsSerializer is a serializer for NDP options.
type NDPOptionsSerializer []ndpOption

// Length returns the total number of bytes required to serialize.
func (b NDPOptionsSerializer) Length() int {
	l := 0

	for _, o := range b {
		l += paddedLength(o)
	}

	return l
}

// NDPTargetLinkLayerAddressOption is the NDP Target Link Layer Option
// as defined by RFC 4861 section 4.6.1.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits - 2 bytes.
type NDPTargetLinkLayerAddressOption tcpip.LinkAddress

// Type implements ndpOption.Type.
func (o NDPTargetLinkLayerAddressOption) Type() uint8 {
	return NDPTargetLinkLayerAddressOptionType
}

// Length implements ndpOption.Length.
func (o NDPTargetLinkLayerAddressOption) Length() int {
	return len(o)
}

// serializeInto implements ndpOption.serializeInto.
func (o NDPTargetLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

// NDPPrefixInformation is the NDP Prefix Information option as defined by
// RFC 4861 section 4.6.2.
//
// The length, in bytes, of a valid NDP Prefix Information option body MUST be
// ndpPrefixInformationLength bytes.
type NDPPrefixInformation []byte

// Type implements ndpOption.Type.
func (o NDPPrefixInformation) Type() uint8 {
	return ndpPrefixInformationType
}

// Length implements ndpOption.Length.
func (o NDPPrefixInformation) Length() int {
	return ndpPrefixInformationLength
}

// serializeInto implements ndpOption.serializeInto.
func (o NDPPrefixInformation) serializeInto(b []byte) int {
	used := copy(b, o)

	// Zero out the Reserved1 field.
	b[ndpPrefixInformationFlagsOffset] &^= ndpPrefixInformationReserved1FlagsMask

	// Zero out the Reserved2 field.
	reserved2 := b[ndpPrefixInformationReserved2Offset:][:ndpPrefixInformationReserved2Length]
	for i := range reserved2 {
		reserved2[i] = 0
	}

	return used
}

// PrefixLength returns the value in the number of leading bits in the Prefix
// that are valid.
//
// Valid values are in the range [0, 128], but o may not always contain valid
// values. It is up to the caller to valdiate the Prefix Information option.
func (o NDPPrefixInformation) PrefixLength() uint8 {
	return o[ndpPrefixInformationPrefixLengthOffset]
}

// OnLinkFlag returns true of the prefix is considered on-link. On-link means
// that a forwarding node is not needed to send packets to other nodes on the
// same prefix.
//
// Note, when this function returns false, no statement is made about the
// on-link property of a prefix. That is, if OnLinkFlag returns false, the
// caller MUST NOT conclude that the prefix is off-link and MUST NOT update any
// previously stored state for this prefix about its on-link status.
func (o NDPPrefixInformation) OnLinkFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationOnLinkFlagMask != 0
}

// AutonomousAddressConfigurationFlag returns true if the prefix can be used for
// Stateless Address Auto-Configuration (as specified in RFC 4862).
func (o NDPPrefixInformation) AutonomousAddressConfigurationFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationAutoAddrConfFlagMask != 0
}

// ValidLifetime returns the length of time that the prefix is valid for the
// purpose of on-link determination. This value is relative to the send time of
// the packet that the Prefix Information option was present in.
//
// Note, a value of 0 implies the prefix should not be considered as on-link,
// and a value of infinity/forever is represented by
// NDPPrefixInformationInfiniteLifetime.
func (o NDPPrefixInformation) ValidLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationValidLifetimeOffset:]))
}

// PreferredLifetime returns the length of time that an address generated from
// the prefix via Stateless Address Auto-Configuration remains preferred. This
// value is relative to the send time of the packet that the Prefix Information
// option was present in.
//
// Note, a value of 0 implies that addresses generated from the prefix should
// no longer remain preferred, and a value of infinity is represented by
// NDPPrefixInformationInfiniteLifetime.
//
// Also note that the value of this field MUST NOT exceed the Valid Lifetime
// field to avoid preferring addresses that are no longer valid, for the
// purpose of Stateless Address Auto-Configuration.
func (o NDPPrefixInformation) PreferredLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationPreferredLifetimeOffset:]))
}

// Prefix returns an IPv6 address or a prefix of an IPv6 address. The Prefix
// Length field (see NDPPrefixInformation.PrefixLength) contains the number
// of valid leading bits in the prefix.
//
// Hosts SHOULD ignore an NDP Prefix Information option where the Prefix field
// holds the link-local prefix (fe80::).
func (o NDPPrefixInformation) Prefix() tcpip.Address {
	return tcpip.Address(o[ndpPrefixInformationPrefixOffset:][:IPv6AddressSize])
}
