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

var (
	// IGMPv3RoutersAddress is the address to send IGMPv3 reports to.
	//
	// As per RFC 3376 section 4.2.14,
	//
	//   Version 3 Reports are sent with an IP destination address of
	//   224.0.0.22, to which all IGMPv3-capable multicast routers listen.
	IGMPv3RoutersAddress = tcpip.AddrFrom4([4]byte{0xe0, 0x00, 0x00, 0x16})
)

const (
	// IGMPv3QueryMinimumSize is the mimum size of a valid IGMPv3 query,
	// as per RFC 3376 section 4.1.
	IGMPv3QueryMinimumSize = 12

	igmpv3QueryMaxRespCodeOffset     = 1
	igmpv3QueryGroupAddressOffset    = 4
	igmpv3QueryResvSQRVOffset        = 8
	igmpv3QueryQRVMask               = 0b111
	igmpv3QueryQQICOffset            = 9
	igmpv3QueryNumberOfSourcesOffset = 10
	igmpv3QuerySourcesOffset         = 12
)

// IGMPv3Query is an IGMPv3 query message.
//
// As per RFC 3376 section 4.1,
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Type = 0x11  | Max Resp Code |           Checksum            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Group Address                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       Source Address [1]                      |
//	+-                                                             -+
//	|                       Source Address [2]                      |
//	+-                              .                              -+
//	.                               .                               .
//	.                               .                               .
//	+-                                                             -+
//	|                       Source Address [N]                      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv3Query IGMP

// MaximumResponseCode returns the Maximum Response Code.
func (i IGMPv3Query) MaximumResponseCode() uint8 {
	return i[igmpv3QueryMaxRespCodeOffset]
}

// IGMPv3MaximumResponseDelay returns the Maximum Response Delay in an IGMPv3
// Maximum Response Code.
//
// As per RFC 3376 section 4.1.1,
//
//	The Max Resp Code field specifies the maximum time allowed before
//	sending a responding report.  The actual time allowed, called the Max
//	Resp Time, is represented in units of 1/10 second and is derived from
//	the Max Resp Code as follows:
//
//	If Max Resp Code < 128, Max Resp Time = Max Resp Code
//
//	If Max Resp Code >= 128, Max Resp Code represents a floating-point
//	value as follows:
//
//	    0 1 2 3 4 5 6 7
//	  +-+-+-+-+-+-+-+-+
//	   |1| exp | mant  |
//	   +-+-+-+-+-+-+-+-+
//
//	Max Resp Time = (mant | 0x10) << (exp + 3)
//
//	Small values of Max Resp Time allow IGMPv3 routers to tune the "leave
//	latency" (the time between the moment the last host leaves a group
//	and the moment the routing protocol is notified that there are no
//	more members).  Larger values, especially in the exponential range,
//	allow tuning of the burstiness of IGMP traffic on a network.
func IGMPv3MaximumResponseDelay(codeRaw uint8) time.Duration {
	code := uint16(codeRaw)
	if code < 128 {
		return DecisecondToDuration(code)
	}

	const mantBits = 4
	const expMask = 0b111
	exp := (code >> mantBits) & expMask
	mant := code & ((1 << mantBits) - 1)
	return DecisecondToDuration((mant | 0x10) << (exp + 3))
}

// GroupAddress returns the group address.
func (i IGMPv3Query) GroupAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(i[igmpv3QueryGroupAddressOffset:][:IPv4AddressSize]))
}

// QuerierRobustnessVariable returns the querier's robustness variable.
func (i IGMPv3Query) QuerierRobustnessVariable() uint8 {
	return i[igmpv3QueryResvSQRVOffset] & igmpv3QueryQRVMask
}

// QuerierQueryInterval returns the querier's query interval.
func (i IGMPv3Query) QuerierQueryInterval() time.Duration {
	return mldv2AndIGMPv3QuerierQueryCodeToInterval(i[igmpv3QueryQQICOffset])
}

// Sources returns an iterator over source addresses in the query.
//
// Returns false if the message cannot hold the expected number of sources.
func (i IGMPv3Query) Sources() (AddressIterator, bool) {
	return makeAddressIterator(
		i[igmpv3QuerySourcesOffset:],
		binary.BigEndian.Uint16(i[igmpv3QueryNumberOfSourcesOffset:]),
		IPv4AddressSize,
	)
}

// IGMPv3ReportRecordType is the type of an IGMPv3 multicast address record
// found in an IGMPv3 report, as per RFC 3810 section 5.2.12.
type IGMPv3ReportRecordType int

// IGMPv3 multicast address record types, as per RFC 3810 section 5.2.12.
const (
	IGMPv3ReportRecordModeIsInclude       IGMPv3ReportRecordType = 1
	IGMPv3ReportRecordModeIsExclude       IGMPv3ReportRecordType = 2
	IGMPv3ReportRecordChangeToIncludeMode IGMPv3ReportRecordType = 3
	IGMPv3ReportRecordChangeToExcludeMode IGMPv3ReportRecordType = 4
	IGMPv3ReportRecordAllowNewSources     IGMPv3ReportRecordType = 5
	IGMPv3ReportRecordBlockOldSources     IGMPv3ReportRecordType = 6
)

const (
	igmpv3ReportGroupAddressRecordMinimumSize           = 8
	igmpv3ReportGroupAddressRecordTypeOffset            = 0
	igmpv3ReportGroupAddressRecordAuxDataLenOffset      = 1
	igmpv3ReportGroupAddressRecordAuxDataLenUnits       = 4
	igmpv3ReportGroupAddressRecordNumberOfSourcesOffset = 2
	igmpv3ReportGroupAddressRecordGroupAddressOffset    = 4
	igmpv3ReportGroupAddressRecordSourcesOffset         = 8
)

// IGMPv3ReportGroupAddressRecordSerializer is an IGMPv3 Multicast Address
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
type IGMPv3ReportGroupAddressRecordSerializer struct {
	RecordType   IGMPv3ReportRecordType
	GroupAddress tcpip.Address
	Sources      []tcpip.Address
}

// Length returns the number of bytes this serializer would occupy.
func (s *IGMPv3ReportGroupAddressRecordSerializer) Length() int {
	return igmpv3ReportGroupAddressRecordSourcesOffset + len(s.Sources)*IPv4AddressSize
}

func copyIPv4Address(dst []byte, src tcpip.Address) {
	srcBytes := src.As4()
	if n := copy(dst, srcBytes[:]); n != IPv4AddressSize {
		panic(fmt.Sprintf("got copy(...) = %d, want = %d", n, IPv4AddressSize))
	}
}

// SerializeInto serializes the record into the buffer.
//
// Panics if the buffer does not have enough space to fit the record.
func (s *IGMPv3ReportGroupAddressRecordSerializer) SerializeInto(b []byte) {
	b[igmpv3ReportGroupAddressRecordTypeOffset] = byte(s.RecordType)
	b[igmpv3ReportGroupAddressRecordAuxDataLenOffset] = 0
	binary.BigEndian.PutUint16(b[igmpv3ReportGroupAddressRecordNumberOfSourcesOffset:], uint16(len(s.Sources)))
	copyIPv4Address(b[igmpv3ReportGroupAddressRecordGroupAddressOffset:], s.GroupAddress)
	b = b[igmpv3ReportGroupAddressRecordSourcesOffset:]
	for _, source := range s.Sources {
		copyIPv4Address(b, source)
		b = b[IPv4AddressSize:]
	}
}

const (
	igmpv3ReportTypeOffset                        = 0
	igmpv3ReportReserved1Offset                   = 1
	igmpv3ReportReserved2Offset                   = 4
	igmpv3ReportNumberOfGroupAddressRecordsOffset = 6
	igmpv3ReportGroupAddressRecordsOffset         = 8
)

// IGMPv3ReportSerializer is an MLD Version 2 Report serializer.
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
type IGMPv3ReportSerializer struct {
	Records []IGMPv3ReportGroupAddressRecordSerializer
}

// Length returns the number of bytes this serializer would occupy.
func (s *IGMPv3ReportSerializer) Length() int {
	ret := igmpv3ReportGroupAddressRecordsOffset
	for _, record := range s.Records {
		ret += record.Length()
	}
	return ret
}

// SerializeInto serializes the report into the buffer.
//
// Panics if the buffer does not have enough space to fit the report.
func (s *IGMPv3ReportSerializer) SerializeInto(b []byte) {
	b[igmpv3ReportTypeOffset] = byte(IGMPv3MembershipReport)
	b[igmpv3ReportReserved1Offset] = 0
	binary.BigEndian.PutUint16(b[igmpv3ReportReserved2Offset:], 0)
	binary.BigEndian.PutUint16(b[igmpv3ReportNumberOfGroupAddressRecordsOffset:], uint16(len(s.Records)))
	recordsBytes := b[igmpv3ReportGroupAddressRecordsOffset:]
	for _, record := range s.Records {
		len := record.Length()
		record.SerializeInto(recordsBytes[:len])
		recordsBytes = recordsBytes[len:]
	}
	binary.BigEndian.PutUint16(b[igmpChecksumOffset:], IGMPCalculateChecksum(b))
}

// IGMPv3ReportGroupAddressRecord is an IGMPv3 record.
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
type IGMPv3ReportGroupAddressRecord []byte

// RecordType returns the type of this record.
func (r IGMPv3ReportGroupAddressRecord) RecordType() IGMPv3ReportRecordType {
	return IGMPv3ReportRecordType(r[igmpv3ReportGroupAddressRecordTypeOffset])
}

// AuxDataLen returns the length of the auxillary data in this record.
func (r IGMPv3ReportGroupAddressRecord) AuxDataLen() int {
	return int(r[igmpv3ReportGroupAddressRecordAuxDataLenOffset]) * igmpv3ReportGroupAddressRecordAuxDataLenUnits
}

// numberOfSources returns the number of sources in this record.
func (r IGMPv3ReportGroupAddressRecord) numberOfSources() uint16 {
	return binary.BigEndian.Uint16(r[igmpv3ReportGroupAddressRecordNumberOfSourcesOffset:])
}

// GroupAddress returns the multicast address this record targets.
func (r IGMPv3ReportGroupAddressRecord) GroupAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(r[igmpv3ReportGroupAddressRecordGroupAddressOffset:][:IPv4AddressSize]))
}

// Sources returns an iterator over source addresses in the query.
//
// Returns false if the message cannot hold the expected number of sources.
func (r IGMPv3ReportGroupAddressRecord) Sources() (AddressIterator, bool) {
	expectedLen := int(r.numberOfSources()) * IPv4AddressSize
	b := r[igmpv3ReportGroupAddressRecordSourcesOffset:]
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return AddressIterator{addressSize: IPv4AddressSize, buf: bytes.NewBuffer(b[:expectedLen])}, true
}

// IGMPv3Report is an IGMPv3 Report.
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
type IGMPv3Report []byte

// Checksum returns the checksum.
func (i IGMPv3Report) Checksum() uint16 {
	return binary.BigEndian.Uint16(i[igmpChecksumOffset:])
}

// IGMPv3ReportGroupAddressRecordIterator is an iterator over IGMPv3 Multicast
// Address Records.
type IGMPv3ReportGroupAddressRecordIterator struct {
	recordsLeft uint16
	buf         *bytes.Buffer
}

// IGMPv3ReportGroupAddressRecordIteratorNextDisposition is the possible
// return values from IGMPv3ReportGroupAddressRecordIterator.Next.
type IGMPv3ReportGroupAddressRecordIteratorNextDisposition int

const (
	// IGMPv3ReportGroupAddressRecordIteratorNextOk indicates that a multicast
	// address record was yielded.
	IGMPv3ReportGroupAddressRecordIteratorNextOk IGMPv3ReportGroupAddressRecordIteratorNextDisposition = iota

	// IGMPv3ReportGroupAddressRecordIteratorNextDone indicates that the iterator
	// has been exhausted.
	IGMPv3ReportGroupAddressRecordIteratorNextDone

	// IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort indicates
	// that the iterator expected another record, but the buffer ended
	// prematurely.
	IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
)

// Next returns the next IGMPv3 Multicast Address Record.
func (it *IGMPv3ReportGroupAddressRecordIterator) Next() (IGMPv3ReportGroupAddressRecord, IGMPv3ReportGroupAddressRecordIteratorNextDisposition) {
	if it.recordsLeft == 0 {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextDone
	}
	if it.buf.Len() < igmpv3ReportGroupAddressRecordMinimumSize {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
	}

	hdr := IGMPv3ReportGroupAddressRecord(it.buf.Bytes())
	expectedLen := igmpv3ReportGroupAddressRecordMinimumSize +
		int(hdr.AuxDataLen()) + int(hdr.numberOfSources())*IPv4AddressSize

	bytes := it.buf.Next(expectedLen)
	if len(bytes) < expectedLen {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
	}
	it.recordsLeft--
	return IGMPv3ReportGroupAddressRecord(bytes), IGMPv3ReportGroupAddressRecordIteratorNextOk
}

// GroupAddressRecords returns an iterator of IGMPv3 Multicast Address
// Records.
func (i IGMPv3Report) GroupAddressRecords() IGMPv3ReportGroupAddressRecordIterator {
	return IGMPv3ReportGroupAddressRecordIterator{
		recordsLeft: binary.BigEndian.Uint16(i[igmpv3ReportNumberOfGroupAddressRecordsOffset:]),
		buf:         bytes.NewBuffer(i[igmpv3ReportGroupAddressRecordsOffset:]),
	}
}
