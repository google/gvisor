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
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	nattedPort = 1
	srcPort    = 2
	dstPort    = 3

	// The network protocol used for these tests doesn't matter as the tests are
	// not targetting anything protocol specific.
	ipv6     = true
	netProto = header.IPv6ProtocolNumber
)

var (
	nattedAddr = testutil.MustParse6("a::1")
	srcAddr    = testutil.MustParse6("b::2")
	dstAddr    = testutil.MustParse6("c::3")
)

func v6PacketBufferWithSrcAddr(srcAddr tcpip.Address) PacketBufferPtr {
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + header.UDPMinimumSize,
	})
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.SetSourcePort(srcPort)
	udp.SetDestinationPort(dstPort)
	udp.SetLength(uint16(len(udp)))
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
	return pkt
}

func v6PacketBuffer() PacketBufferPtr {
	return v6PacketBufferWithSrcAddr(srcAddr)
}

// TestNATedConnectionReap tests that NATed connections are properly reaped.
func TestNATedConnectionReap(t *testing.T) {
	clock := faketime.NewManualClock()
	iptables := DefaultTables(clock, rand.New(rand.NewSource(0 /* seed */)))

	table := Table{
		Rules: []Rule{
			// Prerouting
			{
				Target: &DNATTarget{NetworkProtocol: netProto, Addr: nattedAddr, Port: nattedPort},
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
	iptables.ReplaceTable(NATID, table, ipv6)

	// Stop the reaper if it is running so we can reap manually as it is started
	// on the first change to IPTables.
	if !iptables.reaper.Stop() {
		t.Fatal("failed to stop reaper")
	}

	pkt := v6PacketBuffer()

	originalTID, res := getTupleID(pkt)
	if res != getTupleIDOKAndAllowNewConn {
		t.Fatalf("got getTupleID(...) = (%#v, %d), want = (_, %d)", originalTID, res, getTupleIDOKAndAllowNewConn)
	}

	if !iptables.CheckPrerouting(pkt, nil /* addressEP */, "" /* inNicName */) {
		t.Fatal("got ipt.CheckPrerouting(...) = false, want = true")
	}
	if !iptables.CheckInput(pkt, "" /* inNicName */) {
		t.Fatal("got ipt.CheckInput(...) = false, want = true")
	}

	invertedReplyTID, res := getTupleID(pkt)
	if res != getTupleIDOKAndAllowNewConn {
		t.Fatalf("got getTupleID(...) = (%#v, %d), want = (_, %d)", invertedReplyTID, res, getTupleIDOKAndAllowNewConn)
	}
	if invertedReplyTID == originalTID {
		t.Fatalf("NAT not performed; got invertedReplyTID = %#v", invertedReplyTID)
	}
	replyTID := invertedReplyTID.reply()

	iptables.connections.mu.RLock()
	originalBktID := iptables.connections.bucket(originalTID)
	replyBktID := iptables.connections.bucket(replyTID)
	iptables.connections.mu.RUnlock()

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
			if tuple.tupleID == tid {
				t.Errorf("unexpectedly found tuple with ID = %#v; reply = %t", tid, reply)
			}
		}
	}
	checkNoTupleInBucket(originalBkt, originalTID, false /* reply */)
	checkNoTupleInBucket(replyBkt, replyTID, true /* reply */)
}

// TestNATAlwaysPerformed tests that a connection will have a noop-NAT
// performed on it when no rule matches its associated packet.
func TestNATAlwaysPerformed(t *testing.T) {
	tests := []struct {
		name     string
		dnatHook func(*testing.T, *IPTables, PacketBufferPtr)
		snatHook func(*testing.T, *IPTables, PacketBufferPtr)
	}{
		{
			name: "Prerouting and Input",
			dnatHook: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr) {
				t.Helper()

				if !iptables.CheckPrerouting(pkt, nil /* addressEP */, "" /* inNicName */) {
					t.Fatal("got iptables.CheckPrerouting(...) = false, want = true")
				}
			},
			snatHook: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr) {
				t.Helper()

				if !iptables.CheckInput(pkt, "" /* inNicName */) {
					t.Fatal("got iptables.CheckInput(...) = false, want = true")
				}
			},
		},
		{
			name: "Output and Postrouting",
			dnatHook: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr) {
				t.Helper()

				// Output hook depends on a route but if the route is local, we don't
				// need anything else from it.
				r := Route{
					routeInfo: routeInfo{
						Loop: PacketLoop,
					},
				}
				if !iptables.CheckOutput(pkt, &r, "" /* outNicName */) {
					t.Fatal("got iptables.CheckOutput(...) = false, want = true")
				}
			},
			snatHook: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr) {
				t.Helper()

				// Postrouting hook depends on a route but if the route is local, we
				// don't need anything else from it.
				r := Route{
					routeInfo: routeInfo{
						Loop: PacketLoop,
					},
				}
				if !iptables.CheckPostrouting(pkt, &r, nil /* addressEP */, "" /* outNicName */) {
					t.Fatal("got iptables.CheckPostrouting(...) = false, want = true")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			iptables := DefaultTables(clock, rand.New(rand.NewSource(0 /* seed */)))

			// Just to make sure the iptables is not short circuited.
			iptables.ReplaceTable(NATID, iptables.GetTable(NATID, ipv6), ipv6)

			pkt := v6PacketBuffer()

			test.dnatHook(t, iptables, pkt)
			conn := pkt.tuple.conn
			conn.mu.RLock()
			destManip := conn.destinationManip
			conn.mu.RUnlock()
			if destManip != manipPerformedNoop {
				t.Errorf("got destManip = %d, want = %d", destManip, manipPerformedNoop)
			}

			test.snatHook(t, iptables, pkt)
			conn.mu.RLock()
			srcManip := conn.sourceManip
			conn.mu.RUnlock()
			if srcManip != manipPerformedNoop {
				t.Errorf("got destManip = %d, want = %d", destManip, manipPerformedNoop)
			}
		})
	}
}

func TestNATConflict(t *testing.T) {
	otherSrcAddr := testutil.MustParse6("d::4")

	tests := []struct {
		name          string
		checkIPTables func(*testing.T, *IPTables, PacketBufferPtr, bool)
	}{
		{
			name: "Prerouting and Input",
			checkIPTables: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr, lastHookOK bool) {
				t.Helper()

				if !iptables.CheckPrerouting(pkt, nil /* addressEP */, "" /* inNicName */) {
					t.Fatal("got ipt.CheckPrerouting(...) = false, want = true")
				}
				if got := iptables.CheckInput(pkt, "" /* inNicName */); got != lastHookOK {
					t.Fatalf("got ipt.CheckInput(...) = %t, want = %t", got, lastHookOK)
				}
			},
		},
		{
			name: "Output and Postrouting",
			checkIPTables: func(t *testing.T, iptables *IPTables, pkt PacketBufferPtr, lastHookOK bool) {
				t.Helper()

				// Output and Postrouting hooks depends on a route but if the route is
				// local, we don't need anything else from it.
				r := Route{
					routeInfo: routeInfo{
						Loop: PacketLoop,
					},
				}
				if !iptables.CheckOutput(pkt, &r, "" /* outNicName */) {
					t.Fatal("got iptables.CheckOutput(...) = false, want = true")
				}
				if got := iptables.CheckPostrouting(pkt, &r, nil /* addressEP */, "" /* outNicName */); got != lastHookOK {
					t.Fatalf("got iptables.CheckPostrouting(...) = %t, want = %t", got, lastHookOK)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			clock := faketime.NewManualClock()
			iptables := DefaultTables(clock, rand.New(rand.NewSource(0 /* seed */)))

			table := Table{
				Rules: []Rule{
					// Prerouting
					{
						Target: &AcceptTarget{},
					},

					// Input
					{
						Target: &SNATTarget{NetworkProtocol: header.IPv6ProtocolNumber, Addr: nattedAddr, Port: nattedPort},
					},
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
						Target: &SNATTarget{NetworkProtocol: header.IPv6ProtocolNumber, Addr: nattedAddr, Port: nattedPort},
					},
					{
						Target: &AcceptTarget{},
					},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     3,
					Output:      4,
					Postrouting: 5,
				},
			}
			iptables.ReplaceTable(NATID, table, ipv6)

			// Create and finalize the connection.
			test.checkIPTables(t, iptables, v6PacketBufferWithSrcAddr(srcAddr), true /* lastHookOK */)

			// A packet from a different source that get NATed to the same tuple as
			// the connection created above should be dropped when finalizing.
			test.checkIPTables(t, iptables, v6PacketBufferWithSrcAddr(otherSrcAddr), false /* lastHookOK */)

			// A packet from the original source should be NATed as normal.
			test.checkIPTables(t, iptables, v6PacketBufferWithSrcAddr(srcAddr), true /* lastHookOK */)
		})
	}
}
