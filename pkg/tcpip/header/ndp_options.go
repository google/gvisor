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
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// NDPTargetLinkLayerAddressOptionType is the type of the Target
	// Link-Layer Address option, as per RFC 4861 section 4.6.1.
	NDPTargetLinkLayerAddressOptionType = 2

	// ndpTargetEthernetLinkLayerAddressSize is the size of a Target
	// Link Layer Option for an Ethernet address.
	ndpTargetEthernetLinkLayerAddressSize = 8

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
