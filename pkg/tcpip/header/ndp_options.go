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
	"errors"
	"strings"
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

	// NDPPrefixInformationType is the type of the Prefix Information
	// option, as per RFC 4861 section 4.6.2.
	NDPPrefixInformationType = 3

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

	// NDPDNSSearchListOptionType is the type of the DNS Search List option,
	// as per RFC 8106 section 5.2.
	NDPDNSSearchListOptionType = 31

	// ndpDNSSearchListLifetimeOffset is the start of the 4-byte
	// Lifetime field within an NDPDNSSearchList.
	ndpDNSSearchListLifetimeOffset = 2

	// ndpDNSSearchListDomainNamesOffset is the start of the DNS search list
	// domain names within an NDPDNSSearchList.
	ndpDNSSearchListDomainNamesOffset = 6

	// minNDPDNSSearchListLength is the minimum NDP DNS Search List option's
	// length field value when it contains at least one domain name.
	minNDPDNSSearchListLength = 2

	// maxDomainNameLabelLength is the maximum length of a domain name
	// label, as per RFC 1035 section 3.1.
	maxDomainNameLabelLength = 63

	// maxDomainNameLength is the maximum length of a domain name, including
	// label AND label length octet (which we substitute as a period), as
	// per RFC 1035 section 3.1.
	maxDomainNameLength = 255

	// lengthByteUnits is the multiplier factor for the Length field of an
	// NDP option. That is, the length field for NDP options is in units of
	// 8 octets, as per RFC 4861 section 4.6.
	lengthByteUnits = 8
)

var (
	// NDPInfiniteLifetime is a value that represents
	// infinity for the Valid and Preferred Lifetime fields in a NDP Prefix
	// Information option. Its value is (2^32 - 1)s = 4294967295s
	//
	// This is a variable instead of a constant so that tests can change
	// this value to a smaller value. It should only be modified by tests.
	NDPInfiniteLifetime = time.Second * 4294967295
)

// NDPOptionIterator is an iterator of NDPOption.
//
// Note, between when an NDPOptionIterator is obtained and last used, no changes
// to the NDPOptions may happen. Doing so may cause undefined and unexpected
// behaviour. It is fine to obtain an NDPOptionIterator, iterate over the first
// few NDPOption then modify the backing NDPOptions so long as the
// NDPOptionIterator obtained before modification is no longer used.
type NDPOptionIterator struct {
	// The NDPOptions this NDPOptionIterator is iterating over.
	opts NDPOptions
}

// Potential errors when iterating over an NDPOptions.
var (
	ErrNDPOptBufExhausted  = errors.New("Buffer unexpectedly exhausted")
	ErrNDPOptZeroLength    = errors.New("NDP option has zero-valued Length field")
	ErrNDPOptMalformedBody = errors.New("NDP option has a malformed body")
	ErrNDPInvalidLength    = errors.New("NDP option's Length value is invalid as per relevant RFC")
)

// Next returns the next element in the backing NDPOptions, or true if we are
// done, or false if an error occured.
//
// The return can be read as option, done, error. Note, option should only be
// used if done is false and error is nil.
func (i *NDPOptionIterator) Next() (NDPOption, bool, error) {
	for {
		// Do we still have elements to look at?
		if len(i.opts) == 0 {
			return nil, true, nil
		}

		// Do we have enough bytes for an NDP option that has a Length
		// field of at least 1? Note, 0 in the Length field is invalid.
		if len(i.opts) < lengthByteUnits {
			return nil, true, ErrNDPOptBufExhausted
		}

		// Get the Type field.
		t := i.opts[0]

		// Get the Length field.
		l := i.opts[1]

		// This would indicate an erroneous NDP option as the Length
		// field should never be 0.
		if l == 0 {
			return nil, true, ErrNDPOptZeroLength
		}

		// How many bytes are in the option body?
		numBytes := int(l) * lengthByteUnits
		numBodyBytes := numBytes - 2

		potentialBody := i.opts[2:]

		// This would indicate an erroenous NDPOptions buffer as we ran
		// out of the buffer in the middle of an NDP option.
		if left := len(potentialBody); left < numBodyBytes {
			return nil, true, ErrNDPOptBufExhausted
		}

		// Get only the options body, leaving the rest of the options
		// buffer alone.
		body := potentialBody[:numBodyBytes]

		// Update opts with the remaining options body.
		i.opts = i.opts[numBytes:]

		switch t {
		case NDPTargetLinkLayerAddressOptionType:
			return NDPTargetLinkLayerAddressOption(body), false, nil

		case NDPPrefixInformationType:
			// Make sure the length of a Prefix Information option
			// body is ndpPrefixInformationLength, as per RFC 4861
			// section 4.6.2.
			if numBodyBytes != ndpPrefixInformationLength {
				return nil, true, ErrNDPOptMalformedBody
			}

			return NDPPrefixInformation(body), false, nil

		case NDPDNSSearchListOptionType:
			// RFC 8106 section 5.3.1 outlines that the DNSSL option
			// must have a minimum length of 2 so it contains at
			// least one domain name.
			if l < minNDPDNSSearchListLength {
				return nil, true, ErrNDPInvalidLength
			}

			opt := NDPDNSSearchList(body)
			if len(opt.DomainNames()) == 0 {
				return nil, true, ErrNDPOptMalformedBody
			}

			return opt, false, nil

		default:
			// We do not yet recognize the option, just skip for
			// now. This is okay because RFC 4861 allows us to
			// skip/ignore any unrecognized options. However,
			// we MUST recognized all the options in RFC 4861.
			//
			// TODO(b/141487990): Handle all NDP options as defined
			//                    by RFC 4861.
		}
	}
}

// NDPOptions is a buffer of NDP options as defined by RFC 4861 section 4.6.
type NDPOptions []byte

// Iter returns an iterator of NDPOption.
//
// If check is true, Iter will do an integrity check on the options by iterating
// over it and returning an error if detected.
//
// See NDPOptionIterator for more information.
func (b NDPOptions) Iter(check bool) (NDPOptionIterator, error) {
	it := NDPOptionIterator{opts: b}

	if check {
		for it2 := it; true; {
			if _, done, err := it2.Next(); err != nil || done {
				return it, err
			}
		}
	}

	return it, nil
}

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

// NDPOption is the set of functions to be implemented by all NDP option types.
type NDPOption interface {
	// Type returns the type of the receiver.
	Type() uint8

	// Length returns the length of the body of the receiver, in bytes.
	Length() int

	// serializeInto serializes the receiver into the provided byte
	// buffer.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// Length. Implementers of this function may assume that the byte buffer
	// is of sufficient size. serializeInto MAY panic if the provided byte
	// buffer is not of sufficient size.
	//
	// serializeInto will return the number of bytes that was used to
	// serialize the receiver. Implementers must only use the number of
	// bytes required to serialize the receiver. Callers MAY provide a
	// larger buffer than required to serialize into.
	serializeInto([]byte) int
}

// paddedLength returns the length of o, in bytes, with any padding bytes, if
// required.
func paddedLength(o NDPOption) int {
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
type NDPOptionsSerializer []NDPOption

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

// Type implements NDPOption.Type.
func (o NDPTargetLinkLayerAddressOption) Type() uint8 {
	return NDPTargetLinkLayerAddressOptionType
}

// Length implements NDPOption.Length.
func (o NDPTargetLinkLayerAddressOption) Length() int {
	return len(o)
}

// serializeInto implements NDPOption.serializeInto.
func (o NDPTargetLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

// EthernetAddress will return an ethernet (MAC) address if the
// NDPTargetLinkLayerAddressOption's body has at minimum EthernetAddressSize
// bytes. If the body has more than EthernetAddressSize bytes, only the first
// EthernetAddressSize bytes are returned as that is all that is needed for an
// Ethernet address.
func (o NDPTargetLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
}

// NDPPrefixInformation is the NDP Prefix Information option as defined by
// RFC 4861 section 4.6.2.
//
// The length, in bytes, of a valid NDP Prefix Information option body MUST be
// ndpPrefixInformationLength bytes.
type NDPPrefixInformation []byte

// Type implements NDPOption.Type.
func (o NDPPrefixInformation) Type() uint8 {
	return NDPPrefixInformationType
}

// Length implements NDPOption.Length.
func (o NDPPrefixInformation) Length() int {
	return ndpPrefixInformationLength
}

// serializeInto implements NDPOption.serializeInto.
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
// NDPInfiniteLifetime.
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
// NDPInfiniteLifetime.
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

// Subnet returns the Prefix field and Prefix Length field represented in a
// tcpip.Subnet.
func (o NDPPrefixInformation) Subnet() tcpip.Subnet {
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   o.Prefix(),
		PrefixLen: int(o.PrefixLength()),
	}
	return addrWithPrefix.Subnet()
}

// NDPDNSSearchList is the NDP DNS Search List option, as defined by
// RFC 8106 section 5.2.
type NDPDNSSearchList []byte

// Type implements NDPOption.Type.
func (o NDPDNSSearchList) Type() uint8 {
	return NDPDNSSearchListOptionType
}

// Length implements NDPOption.Length.
func (o NDPDNSSearchList) Length() int {
	return len(o)
}

// serializeInto implements NDPOption.serializeInto.
func (o NDPDNSSearchList) serializeInto(b []byte) int {
	return copy(b, o)
}

// Lifetime returns the length of time that the DNS search list of domain names
// in this option may be used for name resolution.
//
// Note, a value of 0 implies the domain names should no longer be used,
// and a value of infinity/forever is represented by NDPInfiniteLifetime.
func (o NDPDNSSearchList) Lifetime() time.Duration {
	// The field is the time in seconds, as per RFC 8106 section 5.1.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpDNSSearchListLifetimeOffset:]))
}

// DomainNames returns a DNS search list of domain names.
//
// DomainNames will parse the backing buffer as outlined by RFC 1035 section
// 3.1 and return a list of strings, with all domain names in lower case.
func (o NDPDNSSearchList) DomainNames() []string {
	buf := o[ndpDNSSearchListDomainNamesOffset:]

	var domainNames []string
	domainNameBuf := [maxDomainNameLength]byte{}

	// Parse the domain names, as per RFC 1035 section 3.1.
	for len(buf) > 0 {
		dn := domainNameBuf[:]

		for {
			// If we are done, we should have ended with a NULL
			// byte, not an empty array in the middle of a domain
			// name.
			if len(buf) == 0 {
				return nil
			}

			labelLen := int(buf[0])
			buf = buf[1:]

			// A length of 0 implies the end of a domain name.
			if labelLen == 0 {
				// If dn's length is still maxDomainNameLength,
				// then we know that we have not reached a new
				// label for this domain name yet, so we don't
				// need to add it to the list of domain names.
				if len(dn) != maxDomainNameLength {
					// When we copy the domain name into
					// the list of domain names, ignore the
					// trailing period.
					name := strings.ToLower(string(domainNameBuf[:maxDomainNameLength-len(dn)-1]))
					domainNames = append(domainNames, name)
				}

				break
			}

			// The buf should have enough bytes for the label.
			if len(buf) < labelLen {
				return nil
			}

			// Each label is limited to maxDomainNameLabelLength
			// bytes.
			if labelLen > maxDomainNameLabelLength {
				return nil
			}

			// The label should not make the domain name too large.
			// We do a less than OR equal comparision because the
			// max total length of a domain name includes the label
			// and label length octet.
			if len(dn) <= labelLen {
				return nil
			}

			// Copy the label and add a trailing period.
			copy(dn, buf[:labelLen])
			dn[labelLen] = '.'
			dn = dn[labelLen+1:]

			buf = buf[labelLen:]
		}
	}

	return domainNames
}
