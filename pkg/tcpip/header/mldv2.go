// Copyright 2022 The gVisor Authors.
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
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// MLDv2QueryMinimumSize is the minimum size for an MLDv2 message.
	MLDv2QueryMinimumSize = 24

	mldv2QueryMaximumResponseCodeOffset = 0
	mldv2QueryResvSQRVOffset            = 20
	mldv2QueryQRVMask                   = 0b111
	mldv2QueryQQICOffset                = 21
	// mldv2QueryNumberOfSourcesOffset is the offset to the Number of Sources
	// field within MLDv2Query.
	mldv2QueryNumberOfSourcesOffset = 22

	// MLDv2ReportMinimumSize is the minimum size of an MLDv2 report.
	MLDv2ReportMinimumSize = 24

	// mldv2QuerySourcesOffset is the offset to the Sources field within
	// MLDv2Query.
	mldv2QuerySourcesOffset = 24
)

var (
	// MLDv2RoutersAddress is the address to send MLDv2 reports to.
	//
	// As per RFC 3810 section 5.2.14,
	//
	//   Version 2 Multicast Listener Reports are sent with an IP destination
	//   address of FF02:0:0:0:0:0:0:16, to which all MLDv2-capable multicast
	//   routers listen (see section 11 for IANA considerations related to
	//   this special destination address).
	MLDv2RoutersAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16})
)

// MLDv2Query is a Multicast Listener Discovery Version 2 Query message in an
// ICMPv6 packet.
//
// MLDv2Query will only contain the body of an ICMPv6 packet.
//
// As per RFC 3810 section 5.1, MLDv2 Query messages have the following format
// (MLDv2Query only holds the bytes after the first four bytes in the diagram
// below):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Type = 130   |      Code     |           Checksum            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    Maximum Response Code      |           Reserved            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Multicast Address                       *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [1]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [2]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                              .                              -+
//	.                               .                               .
//	.                               .                               .
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [N]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2Query MLD

// MaximumResponseCode returns the Maximum Response Code
func (m MLDv2Query) MaximumResponseCode() uint16 {
	return binary.BigEndian.Uint16(m[mldv2QueryMaximumResponseCodeOffset:])
}

// MLDv2MaximumResponseDelay returns the Maximum Response Delay in an MLDv2
// Maximum Response Code.
//
// As per RFC 3810 section 5.1.3,
//
//	The Maximum Response Code field specifies the maximum time allowed
//	before sending a responding Report.  The actual time allowed, called
//	the Maximum Response Delay, is represented in units of milliseconds,
//	and is derived from the Maximum Response Code as follows:
//
//	If Maximum Response Code < 32768,
//	   Maximum Response Delay = Maximum Response Code
//
//	If Maximum Response Code >=32768, Maximum Response Code represents a
//	floating-point value as follows:
//
//	    0 1 2 3 4 5 6 7 8 9 A B C D E F
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	   |1| exp |          mant         |
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	Maximum Response Delay = (mant | 0x1000) << (exp+3)
//
//	Small values of Maximum Response Delay allow MLDv2 routers to tune
//	the "leave latency" (the time between the moment the last node on a
//	link ceases to listen to a specific multicast address and the moment
//	the routing protocol is notified that there are no more listeners for
//	that address).  Larger values, especially in the exponential range,
//	allow the tuning of the burstiness of MLD traffic on a link.
func MLDv2MaximumResponseDelay(codeRaw uint16) time.Duration {
	code := time.Duration(codeRaw)
	if code < 32768 {
		return code * time.Millisecond
	}

	const mantBits = 12
	const expMask = 0b111
	exp := (code >> mantBits) & expMask
	mant := code & ((1 << mantBits) - 1)
	return (mant | 0x1000) << (exp + 3) * time.Millisecond
}

// MulticastAddress returns the Multicast Address.
func (m MLDv2Query) MulticastAddress() tcpip.Address {
	// As per RFC 2710 section 3.5:
	//
	//   In a Query message, the Multicast Address field is set to zero when
	//   sending a General Query, and set to a specific IPv6 multicast address
	//   when sending a Multicast-Address-Specific Query.
	//
	//   In a Report or Done message, the Multicast Address field holds a
	//   specific IPv6 multicast address to which the message sender is
	//   listening or is ceasing to listen, respectively.
	return tcpip.AddrFrom16([16]byte(m[mldMulticastAddressOffset:][:IPv6AddressSize]))
}

// QuerierRobustnessVariable returns the querier's robustness variable.
func (m MLDv2Query) QuerierRobustnessVariable() uint8 {
	return m[mldv2QueryResvSQRVOffset] & mldv2QueryQRVMask
}

// QuerierQueryInterval returns the querier's query interval.
func (m MLDv2Query) QuerierQueryInterval() time.Duration {
	return mldv2AndIGMPv3QuerierQueryCodeToInterval(m[mldv2QueryQQICOffset])
}

// Sources returns an iterator over source addresses in the query.
//
// Returns false if the message cannot hold the expected number of sources.
func (m MLDv2Query) Sources() (AddressIterator, bool) {
	return makeAddressIterator(
		m[mldv2QuerySourcesOffset:],
		binary.BigEndian.Uint16(m[mldv2QueryNumberOfSourcesOffset:]),
		IPv6AddressSize,
	)
}

// MLDv2ReportRecordType is the type of an MLDv2 multicast address record
// found in an MLDv2 report, as per RFC 3810 section 5.2.12.
type MLDv2ReportRecordType int

// MLDv2 multicast address record types, as per RFC 3810 section 5.2.12.
const (
	MLDv2ReportRecordModeIsInclude       MLDv2ReportRecordType = 1
	MLDv2ReportRecordModeIsExclude       MLDv2ReportRecordType = 2
	MLDv2ReportRecordChangeToIncludeMode MLDv2ReportRecordType = 3
	MLDv2ReportRecordChangeToExcludeMode MLDv2ReportRecordType = 4
	MLDv2ReportRecordAllowNewSources     MLDv2ReportRecordType = 5
	MLDv2ReportRecordBlockOldSources     MLDv2ReportRecordType = 6
)

const (
	mldv2ReportMulticastAddressRecordMinimumSize            = 20
	mldv2ReportMulticastAddressRecordTypeOffset             = 0
	mldv2ReportMulticastAddressRecordAuxDataLenOffset       = 1
	mldv2ReportMulticastAddressRecordAuxDataLenUnits        = 4
	mldv2ReportMulticastAddressRecordNumberOfSourcesOffset  = 2
	mldv2ReportMulticastAddressRecordMulticastAddressOffset = 4
	mldv2ReportMulticastAddressRecordSourcesOffset          = 20
)

// MLDv2ReportMulticastAddressRecordSerializer is an MLDv2 Multicast Address
// Record serializer.
//
// As per RFC 3810 section 5.2, a Multicast Address Record has the following
// internal format:
//
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Record Type  |  Aux Data Len |     Number of Sources (N)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Multicast Address                       *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [1]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [2]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                                                             -+
//	.                               .                               .
//	.                               .                               .
//	.                               .                               .
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [N]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                         Auxiliary Data                        .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2ReportMulticastAddressRecordSerializer struct {
	RecordType       MLDv2ReportRecordType
	MulticastAddress tcpip.Address
	Sources          []tcpip.Address
}

// Length returns the number of bytes this serializer would occupy.
func (s *MLDv2ReportMulticastAddressRecordSerializer) Length() int {
	return mldv2ReportMulticastAddressRecordSourcesOffset + len(s.Sources)*IPv6AddressSize
}

func copyIPv6Address(dst []byte, src tcpip.Address) {
	if n := copy(dst, src.AsSlice()); n != IPv6AddressSize {
		panic(fmt.Sprintf("got copy(...) = %d, want = %d", n, IPv6AddressSize))
	}
}

// SerializeInto serializes the record into the buffer.
//
// Panics if the buffer does not have enough space to fit the record.
func (s *MLDv2ReportMulticastAddressRecordSerializer) SerializeInto(b []byte) {
	b[mldv2ReportMulticastAddressRecordTypeOffset] = byte(s.RecordType)
	b[mldv2ReportMulticastAddressRecordAuxDataLenOffset] = 0
	binary.BigEndian.PutUint16(b[mldv2ReportMulticastAddressRecordNumberOfSourcesOffset:], uint16(len(s.Sources)))
	copyIPv6Address(b[mldv2ReportMulticastAddressRecordMulticastAddressOffset:], s.MulticastAddress)
	b = b[mldv2ReportMulticastAddressRecordSourcesOffset:]
	for _, source := range s.Sources {
		copyIPv6Address(b, source)
		b = b[IPv6AddressSize:]
	}
}

const (
	mldv2ReportReservedOffset                        = 0
	mldv2ReportNumberOfMulticastAddressRecordsOffset = 2
	mldv2ReportMulticastAddressRecordsOffset         = 4
)

// MLDv2ReportSerializer is an MLD Version 2 Report serializer.
//
// As per RFC 3810 section 5.2,
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Type = 143   |    Reserved   |           Checksum            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Reserved            |Nr of Mcast Address Records (M)|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [1]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [2]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               .                               |
//	.                               .                               .
//	|                               .                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [M]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2ReportSerializer struct {
	Records []MLDv2ReportMulticastAddressRecordSerializer
}

// Length returns the number of bytes this serializer would occupy.
func (s *MLDv2ReportSerializer) Length() int {
	ret := mldv2ReportMulticastAddressRecordsOffset
	for _, record := range s.Records {
		ret += record.Length()
	}
	return ret
}

// SerializeInto serializes the report into the buffer.
//
// Panics if the buffer does not have enough space to fit the report.
func (s *MLDv2ReportSerializer) SerializeInto(b []byte) {
	binary.BigEndian.PutUint16(b[mldv2ReportReservedOffset:], 0)
	binary.BigEndian.PutUint16(b[mldv2ReportNumberOfMulticastAddressRecordsOffset:], uint16(len(s.Records)))
	b = b[mldv2ReportMulticastAddressRecordsOffset:]
	for _, record := range s.Records {
		len := record.Length()
		record.SerializeInto(b[:len])
		b = b[len:]
	}
}

// MLDv2ReportMulticastAddressRecord is an MLDv2 record.
//
// As per RFC 3810 section 5.2, a Multicast Address Record has the following
// internal format:
//
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Record Type  |  Aux Data Len |     Number of Sources (N)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Multicast Address                       *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [1]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [2]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-                                                             -+
//	.                               .                               .
//	.                               .                               .
//	.                               .                               .
//	+-                                                             -+
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	*                       Source Address [N]                      *
//	|                                                               |
//	*                                                               *
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                         Auxiliary Data                        .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2ReportMulticastAddressRecord []byte

// RecordType returns the type of this record.
func (r MLDv2ReportMulticastAddressRecord) RecordType() MLDv2ReportRecordType {
	return MLDv2ReportRecordType(r[mldv2ReportMulticastAddressRecordTypeOffset])
}

// AuxDataLen returns the length of the auxillary data in this record.
func (r MLDv2ReportMulticastAddressRecord) AuxDataLen() int {
	return int(r[mldv2ReportMulticastAddressRecordAuxDataLenOffset]) * mldv2ReportMulticastAddressRecordAuxDataLenUnits
}

// numberOfSources returns the number of sources in this record.
func (r MLDv2ReportMulticastAddressRecord) numberOfSources() uint16 {
	return binary.BigEndian.Uint16(r[mldv2ReportMulticastAddressRecordNumberOfSourcesOffset:])
}

// MulticastAddress returns the multicast address this record targets.
func (r MLDv2ReportMulticastAddressRecord) MulticastAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(r[mldv2ReportMulticastAddressRecordMulticastAddressOffset:][:IPv6AddressSize]))
}

// Sources returns an iterator over source addresses in the query.
//
// Returns false if the message cannot hold the expected number of sources.
func (r MLDv2ReportMulticastAddressRecord) Sources() (AddressIterator, bool) {
	expectedLen := int(r.numberOfSources()) * IPv6AddressSize
	b := r[mldv2ReportMulticastAddressRecordSourcesOffset:]
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return AddressIterator{addressSize: IPv6AddressSize, buf: bytes.NewBuffer(b[:expectedLen])}, true
}

// MLDv2Report is an MLDv2 Report.
//
// As per RFC 3810 section 5.2,
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Type = 143   |    Reserved   |           Checksum            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Reserved            |Nr of Mcast Address Records (M)|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [1]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [2]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               .                               |
//	.                               .                               .
//	|                               .                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	.                                                               .
//	.                  Multicast Address Record [M]                 .
//	.                                                               .
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2Report []byte

// MLDv2ReportMulticastAddressRecordIterator is an iterator over MLDv2 Multicast
// Address Records.
type MLDv2ReportMulticastAddressRecordIterator struct {
	recordsLeft uint16
	buf         *bytes.Buffer
}

// MLDv2ReportMulticastAddressRecordIteratorNextDisposition is the possible
// return values from MLDv2ReportMulticastAddressRecordIterator.Next.
type MLDv2ReportMulticastAddressRecordIteratorNextDisposition int

const (
	// MLDv2ReportMulticastAddressRecordIteratorNextOk indicates that a multicast
	// address record was yielded.
	MLDv2ReportMulticastAddressRecordIteratorNextOk MLDv2ReportMulticastAddressRecordIteratorNextDisposition = iota

	// MLDv2ReportMulticastAddressRecordIteratorNextDone indicates that the iterator
	// has been exhausted.
	MLDv2ReportMulticastAddressRecordIteratorNextDone

	// MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort indicates
	// that the iterator expected another record, but the buffer ended
	// prematurely.
	MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
)

// Next returns the next MLDv2 Multicast Address Record.
func (it *MLDv2ReportMulticastAddressRecordIterator) Next() (MLDv2ReportMulticastAddressRecord, MLDv2ReportMulticastAddressRecordIteratorNextDisposition) {
	if it.recordsLeft == 0 {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextDone
	}
	if it.buf.Len() < mldv2ReportMulticastAddressRecordMinimumSize {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
	}

	hdr := MLDv2ReportMulticastAddressRecord(it.buf.Bytes())
	expectedLen := mldv2ReportMulticastAddressRecordMinimumSize +
		int(hdr.AuxDataLen()) + int(hdr.numberOfSources())*IPv6AddressSize

	bytes := it.buf.Next(expectedLen)
	if len(bytes) < expectedLen {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
	}
	it.recordsLeft--
	return MLDv2ReportMulticastAddressRecord(bytes), MLDv2ReportMulticastAddressRecordIteratorNextOk
}

// MulticastAddressRecords returns an iterator of MLDv2 Multicast Address
// Records.
func (m MLDv2Report) MulticastAddressRecords() MLDv2ReportMulticastAddressRecordIterator {
	return MLDv2ReportMulticastAddressRecordIterator{
		recordsLeft: binary.BigEndian.Uint16(m[mldv2ReportNumberOfMulticastAddressRecordsOffset:]),
		buf:         bytes.NewBuffer(m[mldv2ReportMulticastAddressRecordsOffset:]),
	}
}
