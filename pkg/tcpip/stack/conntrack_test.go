// Copyright 2021 The gVisor Authors.
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

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

func TestReap(t *testing.T) {
	// Initialize conntrack.
	clock := faketime.NewManualClock()
	ct := ConnTrack{
		clock: clock,
	}
	ct.init()
	ct.checkNumTuples(t, 0)

	// Simulate sending a SYN. This will get the connection into conntrack, but
	// the connection won't be considered established. Thus the timeout for
	// reaping is unestablishedTimeout.
	pkt1 := genTCPPacket()
	pkt1.tuple = ct.getConnAndUpdate(pkt1)
	// We set rt.routeInfo.Loop to avoid a panic when handlePacket calls
	// rt.RequiresTXTransportChecksum.
	var rt Route
	rt.routeInfo.Loop = PacketLoop
	if pkt1.tuple.conn.handlePacket(pkt1, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 1)

	// Travel a little into the future and send the same SYN. This should update
	// lastUsed, but per #6748 didn't.
	clock.Advance(unestablishedTimeout / 2)
	pkt2 := genTCPPacket()
	pkt2.tuple = ct.getConnAndUpdate(pkt2)
	if pkt2.tuple.conn.handlePacket(pkt2, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 1)

	// Travel farther into the future - enough that failing to update lastUsed
	// would cause a reaping - and reap the whole table. Make sure the connection
	// hasn't been reaped.
	clock.Advance(unestablishedTimeout * 3 / 4)
	ct.reapEverything()
	ct.checkNumTuples(t, 1)

	// Travel past unestablishedTimeout to confirm the tuple is gone.
	clock.Advance(unestablishedTimeout / 2)
	ct.reapEverything()
	ct.checkNumTuples(t, 0)
}

// genTCPPacket returns an initialized IPv4 TCP packet.
func genTCPPacket() *PacketBuffer {
	const packetLen = header.IPv4MinimumSize + header.TCPMinimumSize
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: packetLen,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	tcpHdr := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    5555,
		DstPort:    6666,
		SeqNum:     7777,
		AckNum:     8888,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
		Checksum:   0, // Conntrack doesn't verify the checksum.
	})
	ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: packetLen,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     testutil.MustParse4("1.0.0.1"),
		DstAddr:     testutil.MustParse4("1.0.0.2"),
		Checksum:    0, // Conntrack doesn't verify the checksum.
	})

	return pkt
}

// checkNumTuples checks that there are exactly want tuples tracked by
// conntrack.
func (ct *ConnTrack) checkNumTuples(t *testing.T, want int) {
	t.Helper()
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var total int
	for idx := range ct.buckets {
		ct.buckets[idx].mu.RLock()
		total += ct.buckets[idx].tuples.Len()
		ct.buckets[idx].mu.RUnlock()
	}

	if total != want {
		t.Fatalf("checkNumTuples: got %d, wanted %d", total, want)
	}
}

func (ct *ConnTrack) reapEverything() {
	var bucket int
	for {
		newBucket, _ := ct.reapUnused(bucket, 0 /* ignored */)
		// We started reaping at bucket 0. If the next bucket isn't after our
		// current bucket, we've gone through them all.
		if newBucket <= bucket {
			break
		}
		bucket = newBucket
	}
}
