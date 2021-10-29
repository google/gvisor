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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestNATedConnectionReap tests that NATed connections are properly reaped.
func TestNATedConnectionReap(t *testing.T) {
	// Note that the network protocol used for this test doesn't matter as this
	// test focuses on reaping, not anything related to a specific network
	// protocol.

	const (
		nattedDstPort = 1
		srcPort       = 2
		dstPort       = 3

		nattedDstAddr = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
		srcAddr       = tcpip.Address("\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
		dstAddr       = tcpip.Address("\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
	)

	clock := faketime.NewManualClock()
	iptables := DefaultTables(0 /* seed */, clock)

	table := Table{
		Rules: []Rule{
			// Prerouting
			{
				Target: &DNATTarget{NetworkProtocol: header.IPv6ProtocolNumber, Addr: nattedDstAddr, Port: nattedDstPort},
			},
			{
				Target: &AcceptTarget{},
			},

			// Input
			{
				Target: &AcceptTarget{},
			},

			// Forward
			{
				Target: &AcceptTarget{},
			},

			// Output
			{
				Target: &AcceptTarget{},
			},

			// Postrouting
			{
				Target: &AcceptTarget{},
			},
		},
		BuiltinChains: [NumHooks]int{
			Prerouting:  0,
			Input:       2,
			Forward:     3,
			Output:      4,
			Postrouting: 5,
		},
	}
	if err := iptables.ReplaceTable(NATID, table, true /* ipv6 */); err != nil {
		t.Fatalf("ipt.ReplaceTable(%d, _, true): %s", NATID, err)
	}

	// Stop the reaper if it is running so we can reap manually as it gets started
	// on the first change to IPTables.
	iptables.reaperDone <- struct{}{}

	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + header.UDPMinimumSize,
	})
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.SetSourcePort(srcPort)
	udp.SetDestinationPort(dstPort)
	udp.SetChecksum(0)
	udp.SetChecksum(^udp.CalculateChecksum(header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		srcAddr,
		dstAddr,
		uint16(len(udp)),
	)))
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(udp)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber

	originalTID, _, ok := getTupleID(pkt)
	if !ok {
		t.Fatal("failed to get original tuple ID")
	}

	if !iptables.CheckPrerouting(pkt, nil /* addressEP */, "" /* inNicName */) {
		t.Fatal("got ipt.CheckPrerouting(...) = false, want = true")
	}
	if !iptables.CheckInput(pkt, "" /* inNicName */) {
		t.Fatal("got ipt.CheckInput(...) = false, want = true")
	}

	invertedReplyTID, _, ok := getTupleID(pkt)
	if !ok {
		t.Fatal("failed to get NATed packet's tuple ID")
	}
	if originalTID == invertedReplyTID {
		t.Fatalf("NAT not performed; got invertedTID = %#v", invertedReplyTID)
	}
	replyTID := invertedReplyTID.reply()

	originalBktID := iptables.connections.bucket(originalTID)
	replyBktID := iptables.connections.bucket(replyTID)

	// This test depends on the original and reply tuples mapping to different
	// buckets.
	if originalBktID == replyBktID {
		t.Fatalf("expected bucket IDs to be different; got = %d", originalBktID)
	}

	lowerBktID := originalBktID
	if lowerBktID > replyBktID {
		lowerBktID = replyBktID
	}

	runReaper := func() {
		// Reaping the bucket with the lower ID should reap both tuples of the
		// connection if it has timed out.
		//
		// We will manually pick the next start bucket ID and don't use the
		// interval so we ignore the return values.
		_, _ = iptables.connections.reapUnused(lowerBktID, 0 /* prevInterval */)
	}

	iptables.connections.mu.RLock()
	buckets := iptables.connections.buckets
	iptables.connections.mu.RUnlock()

	originalBkt := &buckets[originalBktID]
	replyBkt := &buckets[replyBktID]

	// Run the reaper and make sure the tuples were not reaped.
	reapAndCheckForConnections := func() {
		t.Helper()

		runReaper()

		now := clock.NowMonotonic()
		if originalTuple := originalBkt.connForTID(originalTID, now); originalTuple == nil {
			t.Error("expected to get original tuple")
		}

		if replyTuple := replyBkt.connForTID(replyTID, now); replyTuple == nil {
			t.Error("expected to get reply tuple")
		}

		if t.Failed() {
			t.FailNow()
		}
	}

	// Connection was just added and no time has passed - it should not be reaped.
	reapAndCheckForConnections()

	// Time must advance past the unestablished timeout for a connection to be
	// reaped.
	clock.Advance(unestablishedTimeout)
	reapAndCheckForConnections()

	// Connection should now be reaped.
	clock.Advance(1)
	runReaper()
	now := clock.NowMonotonic()
	if originalTuple := originalBkt.connForTID(originalTID, now); originalTuple != nil {
		t.Errorf("got originalBkt.connForTID(%#v, %#v) = %#v, want = nil", originalTID, now, originalTuple)
	}
	if replyTuple := replyBkt.connForTID(replyTID, now); replyTuple != nil {
		t.Errorf("got replyBkt.connForTID(%#v, %#v) = %#v, want = nil", replyTID, now, replyTuple)
	}
	// Make sure we don't have stale tuples just lying around.
	//
	// We manually check the buckets as connForTID will skip over tuples that
	// have timed out.
	checkNoTupleInBucket := func(bkt *bucket, tid tupleID, reply bool) {
		t.Helper()

		bkt.mu.RLock()
		defer bkt.mu.RUnlock()
		for tuple := bkt.tuples.Front(); tuple != nil; tuple = tuple.Next() {
			if tuple.id == originalTID {
				t.Errorf("unexpectedly found tuple with ID = %#v; reply = %t", tid, reply)
			}
		}
	}
	checkNoTupleInBucket(originalBkt, originalTID, false /* reply */)
	checkNoTupleInBucket(replyBkt, replyTID, true /* reply */)
}
