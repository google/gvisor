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

func newPCAPPacketHeader(incLen, orgLen uint32) pcapPacketHeader {
	now := time.Now()
	return pcapPacketHeader{
		Seconds:        uint32(now.Unix()),
		Microseconds:   uint32(now.Nanosecond() / 1000),
		IncludedLength: incLen,
		OriginalLength: orgLen,
	}
}
