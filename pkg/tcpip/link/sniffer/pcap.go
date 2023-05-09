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

import (
	"encoding"
	"encoding/binary"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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

var _ encoding.BinaryMarshaler = (*pcapPacket)(nil)

type pcapPacket struct {
	timestamp     time.Time
	packet        stack.PacketBufferPtr
	maxCaptureLen int
}

func (p *pcapPacket) MarshalBinary() ([]byte, error) {
	pkt := trimmedClone(p.packet)
	defer pkt.DecRef()
	packetSize := pkt.Size()
	captureLen := p.maxCaptureLen
	if packetSize < captureLen {
		captureLen = packetSize
	}
	b := make([]byte, 16+captureLen)
	binary.LittleEndian.PutUint32(b[0:4], uint32(p.timestamp.Unix()))
	binary.LittleEndian.PutUint32(b[4:8], uint32(p.timestamp.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(b[8:12], uint32(captureLen))
	binary.LittleEndian.PutUint32(b[12:16], uint32(packetSize))
	w := tcpip.SliceWriter(b[16:])
	for _, v := range pkt.AsSlices() {
		if captureLen == 0 {
			break
		}
		if len(v) > captureLen {
			v = v[:captureLen]
		}
		n, err := w.Write(v)
		if err != nil {
			panic(err)
		}
		captureLen -= n
	}
	return b, nil
}
