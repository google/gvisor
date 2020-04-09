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

// Package pcap impliments the libpcap file format.
//
// Spec: https://wiki.wireshark.org/Development/LibpcapFileFormat
package pcap

import (
	"time"
)

// HeaderLen is the binary size of a Header struct.
const HeaderLen = 24

// A Header is the top-level header in a pcap file.
type Header struct {
	// MagicNumber is the file magic number.
	MagicNumber uint32

	// VersionMajor is the major version number.
	VersionMajor uint16

	// VersionMinor is the minor version number.
	VersionMinor uint16

	// Thiszone is the GMT to local correction.
	Thiszone int32

	// Sigfigs is the accuracy of timestamps.
	Sigfigs uint32

	// Snaplen is the max length of captured packets, in octets.
	Snaplen uint32

	// Network is the data link type.
	Network uint32
}

// MaxSnaplen is the maximum value of Header.Snaplen.
const MaxSnaplen = 262144

const (
	// LINKTYPE_ETHERNET is the data link type for ethernet packets.
	//
	// This is the default in Linux and can optionally be emitted by
	// netstack.
	LINKTYPE_ETHERNET = 1

	// LINKTYPE_RAW is the data link type for raw IP packets.
	//
	// This is the default in netstack.
	LINKTYPE_RAW = 101
)

func zoneOffset() (int32, error) {
	loc, err := time.LoadLocation("Local")
	if err != nil {
		return 0, err
	}
	date := time.Date(0, 0, 0, 0, 0, 0, 0, loc)
	_, offset := date.Zone()
	return int32(offset), nil
}

// MakeHeader initializes a Header.
func MakeHeader(maxLen uint32) (Header, error) {
	offset, err := zoneOffset()
	if err != nil {
		return Header{}, err
	}

	return Header{
		// From https://wiki.wireshark.org/Development/LibpcapFileFormat
		MagicNumber: 0xa1b2c3d4,

		VersionMajor: 2,
		VersionMinor: 4,
		Thiszone:     offset,
		Sigfigs:      0,
		Snaplen:      maxLen,
		Network:      LINKTYPE_RAW,
	}, nil
}

// PacketHeaderLen is the binary size of a PacketHeader struct.
const PacketHeaderLen = 16

// A PacketHeader is the per-packet header in a pcap file.
type PacketHeader struct {
	// Seconds is the timestamp seconds.
	Seconds uint32

	// Microseconds is the timestamp microseconds.
	Microseconds uint32

	// IncludedLength is the number of octets of packet saved in file.
	IncludedLength uint32

	// OriginalLength is the actual length of packet.
	OriginalLength uint32
}

// MakePacketHeader initializes a PacketHeadern with the current time.
func MakePacketHeader(incLen, orgLen uint32) PacketHeader {
	now := time.Now()
	return PacketHeader{
		Seconds:        uint32(now.Unix()),
		Microseconds:   uint32(now.Nanosecond() / 1000),
		IncludedLength: incLen,
		OriginalLength: orgLen,
	}
}
