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

package sniffer

import "time"

type pcapHeader struct {
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

const pcapPacketHeaderLen = 16

type pcapPacketHeader struct {
	// Seconds is the timestamp seconds.
	Seconds uint32

	// Microseconds is the timestamp microseconds.
	Microseconds uint32

	// IncludedLength is the number of octets of packet saved in file.
	IncludedLength uint32

	// OriginalLength is the actual length of packet.
	OriginalLength uint32
}

func newPCAPPacketHeader(now time.Time, incLen, orgLen uint32) pcapPacketHeader {
	return pcapPacketHeader{
		Seconds:        uint32(now.Unix()),
		Microseconds:   uint32(now.Nanosecond() / 1000),
		IncludedLength: incLen,
		OriginalLength: orgLen,
	}
}
