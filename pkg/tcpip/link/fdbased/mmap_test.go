// Copyright 2026 The gVisor Authors.
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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package fdbased

import (
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestPacketMMapHostGRO(t *testing.T) {
	// A ring with one packet that the host coalesced from 1448-byte TCPv4
	// segments, preceded by its virtioNetHdr.
	ring := make([]byte, 2*tpFrameSize)
	frame := tPacketHdr(ring)
	const mac = 64
	payload := []byte{1, 2, 3, 4}
	copy(frame[mac-virtioNetHdrSize:], (&virtioNetHdr{gsoType: _VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 1448}).marshal())
	copy(frame[mac:], payload)
	binary.LittleEndian.PutUint16(frame[tpMacOffset:], mac)
	binary.LittleEndian.PutUint32(frame[tpSnapLenOffset:], uint32(len(payload)))
	frame.setTPStatus(tpStatusUser)

	d := &packetMMapDispatcher{
		e:          &endpoint{gsoKind: stack.HostGSOSupported},
		ringBuffer: ring,
	}
	pkts, _, err := d.readMMappedPackets()
	if err != nil {
		t.Fatalf("readMMappedPackets: %s", err)
	}
	defer pkts.DecRef()
	if got := pkts.Len(); got != 1 {
		t.Fatalf("got %d packets, want 1", got)
	}
	pkt := pkts.AsSlice()[0]
	if got := pkt.Data().Size(); got != len(payload) {
		t.Errorf("pkt.Data().Size() = %d, want %d", got, len(payload))
	}
	if got := pkt.GROSegmentSize; got != 1448 {
		t.Errorf("pkt.GROSegmentSize = %d, want 1448", got)
	}
}
