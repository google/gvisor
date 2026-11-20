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

package tcp_sack_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	maxPayload   = 10
	tsOptionSize = 12
	mtu          = header.TCPMinimumSize + header.IPv4MinimumSize + e2e.MaxTCPOptionSize + maxPayload
)

func TestReceiverDSACK(t *testing.T) {
	for _, sackPermitted := range []bool{true, false} {
		t.Run(fmt.Sprintf("SACK=%t", sackPermitted), func(t *testing.T) {
			c := context.New(t, e2e.DefaultMTU)
			defer c.Cleanup()
			e2e.SetStackSACKPermitted(t, c, true)
			rep := c.CreateConnectedWithOptionsNoDelay(header.TCPSynOptions{SACKPermitted: sackPermitted})
			first := rep.NextSeqNum
			send := func(seq seqnum.Value, payload string, wantAck seqnum.Value, blocks ...header.SACKBlock) {
				t.Helper()
				rep.NextSeqNum = seq
				rep.SendPacket([]byte(payload), nil)
				rep.NextSeqNum = wantAck
				if !sackPermitted {
					blocks = nil
				}
				rep.VerifyACKHasSACK(blocks)
			}

			// An empty keepalive and data beyond the window report no
			// duplicate payload.
			send(first-1, "", first)
			send(first+(1<<30), "x", first)
			send(first, "abcd", first+4)

			// A queued range remains in the ACK after the duplicate block.
			queued := header.SACKBlock{Start: first + 7, End: first + 9}
			send(first+7, "hi", first+4, queued)
			send(first, "abc", first+4, header.SACKBlock{Start: first, End: first + 3}, queued)

			// Only "cd" is duplicate. The new bytes fill the gap and advance
			// the cumulative ACK through the queued range.
			send(first+2, "cdefg", first+9, header.SACKBlock{Start: first + 2, End: first + 4})
			send(first+9, "j", first+10)

			// Queue the final data and FIN. Filling the gap with an overlapping
			// segment must report its duplicate byte in the FIN ACK.
			rep.Flags |= header.TCPFlagFin
			send(first+12, "mn", first+10, header.SACKBlock{Start: first + 12, End: first + 14})
			rep.Flags &^= header.TCPFlagFin
			send(first+9, "jkl", first+15, header.SACKBlock{Start: first + 9, End: first + 10})

			// A retransmission in CLOSE-WAIT includes the FIN sequence number.
			rep.Flags |= header.TCPFlagFin
			send(first+12, "mn", first+15, header.SACKBlock{Start: first + 12, End: first + 15})
			if sackPermitted {
				send(first+14, "", first+15, header.SACKBlock{Start: first + 14, End: first + 15})
			}
		})
	}
}

// TestSackPermittedConnect establishes a connection with the SACK option
// enabled.
func TestSackPermittedConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("stack.sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, e2e.DefaultMTU)
			defer c.Cleanup()

			e2e.SetStackSACKPermitted(t, c, sackEnabled)
			e2e.SetStackTCPRecovery(t, c, 0)
			rep := e2e.CreateConnectedWithSACKPermittedOption(c)
			data := []byte{1, 2, 3}

			rep.SendPacket(data, nil)
			savedSeqNum := rep.NextSeqNum
			rep.VerifyACKNoSACK()

			// Make an out of order packet and send it.
			rep.NextSeqNum += 3
			sackBlocks := []header.SACKBlock{
				{rep.NextSeqNum, rep.NextSeqNum.Add(seqnum.Size(len(data)))},
			}
			rep.SendPacket(data, nil)

			// Restore the saved sequence number so that the
			// VerifyXXX calls use the right sequence number for
			// checking ACK numbers.
			rep.NextSeqNum = savedSeqNum
			if sackEnabled {
				rep.VerifyACKHasSACK(sackBlocks)
			} else {
				rep.VerifyACKNoSACK()
			}

			// Send the missing segment.
			rep.SendPacket(data, nil)
			// The ACK should contain the cumulative ACK for all 9
			// bytes sent and no SACK blocks.
			rep.NextSeqNum += 3
			// Check that no SACK block is returned in the ACK.
			rep.VerifyACKNoSACK()
		})
	}
}

// TestSackDisabledConnect establishes a connection with the SACK option
// disabled and verifies that no SACKs are sent for out of order segments.
func TestSackDisabledConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, e2e.DefaultMTU)
			defer c.Cleanup()

			e2e.SetStackSACKPermitted(t, c, sackEnabled)
			e2e.SetStackTCPRecovery(t, c, 0)

			rep := c.CreateConnectedWithOptionsNoDelay(header.TCPSynOptions{})

			data := []byte{1, 2, 3}

			rep.SendPacket(data, nil)
			savedSeqNum := rep.NextSeqNum
			rep.VerifyACKNoSACK()

			// Make an out of order packet and send it.
			rep.NextSeqNum += 3
			rep.SendPacket(data, nil)

			// The ACK should contain the older sequence number and
			// no SACK blocks.
			rep.NextSeqNum = savedSeqNum
			rep.VerifyACKNoSACK()

			// Send the missing segment.
			rep.SendPacket(data, nil)
			// The ACK should contain the cumulative ACK for all 9
			// bytes sent and no SACK blocks.
			rep.NextSeqNum += 3
			// Check that no SACK block is returned in the ACK.
			rep.VerifyACKNoSACK()
		})
	}
}

// TestSackPermittedAccept accepts and establishes a connection with the
// SACKPermitted option enabled if the connection request specifies the
// SACKPermitted option. A SYN cookie can preserve SACK negotiation when the
// peer uses TCP timestamps.
func TestSackPermittedAccept(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cookieEnabled bool
		wndScale      int
		noPeerSACK    bool
		noTimestamp   bool
		wantSACK      bool
	}{
		{name: "ordinary", wndScale: 5, wantSACK: true},
		{name: "cookie", cookieEnabled: true, wndScale: -1, wantSACK: true},
		{name: "cookie_no_peer_sack", cookieEnabled: true, wndScale: -1, noPeerSACK: true},
		{name: "cookie_no_timestamp", cookieEnabled: true, wndScale: -1, noTimestamp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("sack=%t", sackEnabled), func(t *testing.T) {
					c := context.New(t, e2e.DefaultMTU)
					defer c.Cleanup()

					if tc.cookieEnabled {
						opt := tcpip.TCPAlwaysUseSynCookies(true)
						if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
							t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
						}
					}
					e2e.SetStackSACKPermitted(t, c, sackEnabled)
					e2e.SetStackTCPRecovery(t, c, 0)

					rep := c.AcceptWithOptionsNoDelay(tc.wndScale, header.TCPSynOptions{
						MSS: e2e.DefaultIPv4MSS, TS: !tc.noTimestamp, SACKPermitted: !tc.noPeerSACK,
					})
					wantSACK := sackEnabled && tc.wantSACK
					if got := rep.SACKPermitted; got != wantSACK {
						t.Fatalf("SYN-ACK SACK-permitted option = %t, want %t", got, wantSACK)
					}
					data := []byte{1, 2, 3}
					sendData := func() {
						if tc.noTimestamp {
							rep.SendPacket(data, nil)
						} else {
							rep.SendPacketWithTS(data, rep.TSVal+1)
						}
					}
					sendData()
					rep.VerifyACKNoSACK()

					savedSeqNum := rep.NextSeqNum

					// Leave a hole for the receiver to report.
					rep.NextSeqNum += 3
					sackBlocks := []header.SACKBlock{
						{rep.NextSeqNum, rep.NextSeqNum.Add(seqnum.Size(len(data)))},
					}
					sendData()

					rep.NextSeqNum = savedSeqNum
					if wantSACK {
						rep.VerifyACKHasSACK(sackBlocks)
					} else {
						rep.VerifyACKNoSACK()
					}

					// Send the missing segment.
					sendData()
					rep.NextSeqNum += 3
					rep.VerifyACKNoSACK()
				})
			}
		})
	}
}

// TestSackDisabledAccept accepts and establishes a connection with
// the SACKPermitted option disabled and verifies that no SACKs are
// sent for out of order packets.
func TestSackDisabledAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, 5, 0x8000}, // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test: sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, e2e.DefaultMTU)
					defer c.Cleanup()

					if tc.cookieEnabled {
						opt := tcpip.TCPAlwaysUseSynCookies(true)
						if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
							t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
						}
					}

					e2e.SetStackSACKPermitted(t, c, sackEnabled)
					e2e.SetStackTCPRecovery(t, c, 0)

					rep := c.AcceptWithOptionsNoDelay(tc.wndScale, header.TCPSynOptions{MSS: e2e.DefaultIPv4MSS})

					//  Now verify no SACK blocks are
					//  received when sack is disabled.
					data := []byte{1, 2, 3}
					rep.SendPacket(data, nil)
					rep.VerifyACKNoSACK()
					savedSeqNum := rep.NextSeqNum

					// Make an out of order packet and send
					// it.
					rep.NextSeqNum += 3
					rep.SendPacket(data, nil)

					// The ACK should contain the older
					// sequence number and no SACK blocks.
					rep.NextSeqNum = savedSeqNum
					rep.VerifyACKNoSACK()

					// Send the missing segment.
					rep.SendPacket(data, nil)
					// The ACK should contain the cumulative
					// ACK for all 9 bytes sent and no SACK
					// blocks.
					rep.NextSeqNum += 3
					// Check that no SACK block is returned
					// in the ACK.
					rep.VerifyACKNoSACK()
				})
			}
		})
	}
}

func TestUpdateSACKBlocks(t *testing.T) {
	testCases := []struct {
		segStart   seqnum.Value
		segEnd     seqnum.Value
		rcvNxt     seqnum.Value
		sackBlocks []header.SACKBlock
		updated    []header.SACKBlock
	}{
		// Trivial cases where current SACK block list is empty and we
		// have an out of order delivery.
		{10, 11, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 11}}},
		{10, 12, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 12}}},
		{10, 20, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 20}}},

		// Cases where current SACK block list is not empty and we have
		// an out of order delivery. Tests that the updated SACK block
		// list has the first block as the one that contains the new
		// SACK block representing the segment that was just delivered.
		{10, 11, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 11}, {12, 20}}},
		{24, 30, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{24, 30}, {12, 20}}},
		{24, 30, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{24, 30}, {12, 20}, {32, 40}}},

		// Ensure that we only retain header.MaxSACKBlocks and drop the
		// oldest one if adding a new block exceeds
		// header.MaxSACKBlocks.
		{24, 30, 9,
			[]header.SACKBlock{{12, 20}, {32, 40}, {42, 50}, {52, 60}, {62, 70}, {72, 80}},
			[]header.SACKBlock{{24, 30}, {12, 20}, {32, 40}, {42, 50}, {52, 60}, {62, 70}}},

		// Cases where segment extends an existing SACK block.
		{10, 12, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 20}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 22}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 22}}},
		{15, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{12, 22}}},
		{15, 25, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{12, 25}}},
		{11, 25, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{11, 25}}},
		{10, 12, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 20}, {32, 40}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 22}, {32, 40}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 22}, {32, 40}}},
		{15, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{12, 22}, {32, 40}}},
		{15, 25, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{12, 25}, {32, 40}}},
		{11, 25, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{11, 25}, {32, 40}}},

		// Cases where segment contains rcvNxt.
		{10, 20, 15, []header.SACKBlock{{20, 30}, {40, 50}}, []header.SACKBlock{{40, 50}}},
	}

	for _, tc := range testCases {
		var sack tcp.SACKInfo
		copy(sack.Blocks[:], tc.sackBlocks)
		sack.NumBlocks = len(tc.sackBlocks)
		tcp.UpdateSACKBlocks(&sack, tc.segStart, tc.segEnd, tc.rcvNxt)
		if got, want := sack.Blocks[:sack.NumBlocks], tc.updated; !slices.Equal(got, want) {
			t.Errorf("UpdateSACKBlocks(%v, %v, %v, %v), got: %v, want: %v", tc.sackBlocks, tc.segStart, tc.segEnd, tc.rcvNxt, got, want)
		}

	}
}

func TestTrimSackBlockList(t *testing.T) {
	testCases := []struct {
		rcvNxt     seqnum.Value
		sackBlocks []header.SACKBlock
		trimmed    []header.SACKBlock
	}{
		// Simple cases where we trim whole entries.
		{2, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}},
		{21, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{22, 30}, {32, 40}}},
		{31, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{32, 40}}},
		{40, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{}},
		// Cases where we need to update a block.
		{12, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{12, 20}, {22, 30}, {32, 40}}},
		{23, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{23, 30}, {32, 40}}},
		{33, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{33, 40}}},
		{41, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{}},
	}
	for _, tc := range testCases {
		var sack tcp.SACKInfo
		copy(sack.Blocks[:], tc.sackBlocks)
		sack.NumBlocks = len(tc.sackBlocks)
		tcp.TrimSACKBlockList(&sack, tc.rcvNxt)
		if got, want := sack.Blocks[:sack.NumBlocks], tc.trimmed; !slices.Equal(got, want) {
			t.Errorf("TrimSackBlockList(%v, %v), got: %v, want: %v", tc.sackBlocks, tc.rcvNxt, got, want)
		}
	}
}

func TestSACKRecovery(t *testing.T) {
	probe := func(s *tcp.TCPEndpointState) {
		// We use log.Printf instead of t.Logf here because this probe
		// can fire even when the test function has finished. This is
		// because closing the endpoint in cleanup() does not mean the
		// actual worker loop terminates immediately as it still has to
		// do a full TCP shutdown. But this test can finish running
		// before the shutdown is done. Using t.Logf in such a case
		// causes the test to panic due to logging after test finished.
		log.Printf("state: %+v\n", s)
	}
	const maxPayload = 10
	// See: tcp.makeOptions for why tsOptionSize is set to 12 here.
	const tsOptionSize = 12
	// Enabling SACK means the payload size is reduced to account
	// for the extra space required for the TCP options.
	//
	// We increase the MTU by e2e.MaxTCPOptionSize bytes to account for SACK
	// and Timestamp options.
	c := context.NewWithProbe(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+e2e.MaxTCPOptionSize+maxPayload), probe)
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	e2e.SetStackTCPRecovery(t, c, 0)
	e2e.CreateConnectedWithSACKAndTS(c)

	const iterations = 3
	data := make([]byte, 2*maxPayload*(tcp.InitialCwnd<<(iterations+1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Do slow start for a few iterations.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = tcp.InitialCwnd << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.SendAck(seq, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Send 3 duplicate acks. This should force an immediate retransmit of
	// the pending packet and put the sender into fast recovery.
	rtxOffset := bytesRead - maxPayload*expected
	start := c.IRS.Add(seqnum.Size(rtxOffset) + 30 + 1)
	end := start.Add(10)
	for i := 0; i < 3; i++ {
		c.SendAckWithSACK(seq, rtxOffset, []header.SACKBlock{{start, end}})
		end = end.Add(10)
	}

	// Receive the retransmitted packet.
	c.ReceiveAndCheckPacketWithOptions(data, rtxOffset, maxPayload, tsOptionSize)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
			{tcpStats.Retransmits, "stats.TCP.Retransmits", 1},
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
			{tcpStats.FastRecovery, "stats.TCP.FastRecovery", 0},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}

	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}

	// Now send 7 mode duplicate ACKs. In SACK TCP dupAcks do not cause
	// window inflation and sending of packets is completely handled by the
	// SACK Recovery algorithm. We should see no packets being released, as
	// the cwnd at this point after entering recovery should be half of the
	// outstanding number of packets in flight.
	for i := 0; i < 7; i++ {
		c.SendAckWithSACK(seq, rtxOffset, []header.SACKBlock{{start, end}})
		end = end.Add(10)
	}

	recover := bytesRead

	// Ensure no new packets arrive.
	c.CheckNoPacketTimeout("More packets received than expected during recovery after dupacks for this cwnd.",
		50*time.Millisecond)

	// Acknowledge half of the pending data. This along with the 10 sacked
	// segments above should reduce the outstanding below the current
	// congestion window allowing the sender to transmit data.
	rtxOffset = bytesRead - expected*maxPayload/2

	// Now send a partial ACK w/ a SACK block that indicates that the next 3
	// segments are lost and we have received 6 segments after the lost
	// segments. This should cause the sender to immediately transmit all 3
	// segments in response to this ACK unlike in FastRecovery where only 1
	// segment is retransmitted per ACK.
	start = c.IRS.Add(seqnum.Size(rtxOffset) + 30 + 1)
	end = start.Add(60)
	c.SendAckWithSACK(seq, rtxOffset, []header.SACKBlock{{start, end}})

	// At this point, we acked expected/2 packets and we SACKED 6 packets and
	// 3 segments were considered lost due to the SACK block we sent.
	//
	// So total packets outstanding can be calculated as follows after 7
	// iterations of slow start -> 10/20/40/80/160/320/640. So expected
	// should be 640 at start, then we went to recover at which point the
	// cwnd should be set to 320 + 3 (for the 3 dupAcks which have left the
	// network).
	// Outstanding at this point after acking half the window
	// (320 packets) will be:
	//    outstanding = 640-320-6(due to SACK block)-3 = 311
	//
	// The last 3 is due to the fact that the first 3 packets after
	// rtxOffset will be considered lost due to the SACK blocks sent.
	// Receive the retransmit due to partial ack.

	c.ReceiveAndCheckPacketWithOptions(data, rtxOffset, maxPayload, tsOptionSize)
	// Receive the 2 extra packets that should have been retransmitted as
	// those should be considered lost and immediately retransmitted based
	// on the SACK information in the previous ACK sent above.
	for i := 0; i < 2; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, rtxOffset+maxPayload*(i+1), maxPayload, tsOptionSize)
	}

	// Now we should get 9 more new unsent packets as the cwnd is 323 and
	// outstanding is 311.
	for i := 0; i < 9; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
		bytesRead += maxPayload
	}

	metricPollFn = func() error {
		// In SACK recovery only the first segment is fast retransmitted when
		// entering recovery.
		if got, want := c.Stack().Stats().TCP.FastRetransmit.Value(), uint64(1); got != want {
			return fmt.Errorf("got stats.TCP.FastRetransmit.Value = %d, want = %d", got, want)
		}

		if got, want := c.EP.Stats().(*tcp.Stats).SendErrors.FastRetransmit.Value(), uint64(1); got != want {
			return fmt.Errorf("got EP stats SendErrors.FastRetransmit = %d, want = %d", got, want)
		}

		if got, want := c.Stack().Stats().TCP.Retransmits.Value(), uint64(4); got != want {
			return fmt.Errorf("got stats.TCP.Retransmits.Value = %d, want = %d", got, want)
		}

		if got, want := c.EP.Stats().(*tcp.Stats).SendErrors.Retransmits.Value(), uint64(4); got != want {
			return fmt.Errorf("got EP stats Stats.SendErrors.Retransmits = %d, want = %d", got, want)
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}

	c.CheckNoPacketTimeout("More packets received than expected during recovery after partial ack for this cwnd.", 50*time.Millisecond)

	// Acknowledge all pending data to recover point.
	c.SendAck(seq, recover)

	// At this point, the cwnd should reset to expected/2 and there are 9
	// packets outstanding.
	//
	// Now in the first iteration since there are 9 packets outstanding.
	// We would expect to get expected/2  - 9 packets. But subsequent
	// iterations will send us expected/2  + 1 (per iteration).
	expected = expected/2 - 9
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
			bytesRead += maxPayload
		}
		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout(fmt.Sprintf("More packets received(after deflation) than expected %d for this cwnd and iteration: %d.", expected, i), 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.SendAck(seq, bytesRead)

		// In cogestion avoidance, the packets trains increase by 1 in
		// each iteration.
		if i == 0 {
			// After the first iteration we expect to get the full
			// congestion window worth of packets in every
			// iteration.
			expected += 9
		}
		expected++
	}
}

// TestRecoveryEntry tests the following two properties of entering recovery:
//   - Fast SACK recovery is entered when SND.UNA is considered lost by the SACK
//     scoreboard but dupack count is still below threshold.
//   - Only enter recovery when at least one more byte of data beyond the highest
//     byte that was outstanding when fast retransmit was last entered is acked.
func TestRecoveryEntry(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic"} {
		t.Run(algorithm, func(t *testing.T) {
			c := context.New(t, uint32(mtu))
			defer c.Cleanup()

			cc := tcpip.CongestionControlOption(algorithm)
			if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
				t.Fatalf("SetTransportProtocolOption(%s): %s", algorithm, err)
			}

			numPackets := 5
			data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, false /* enableRACK */)

			// Ack #1 packet.
			seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
			c.SendAck(seq, maxPayload)

			// Now SACK #3, #4 and #5 packets. This will simulate a situation where
			// SND.UNA should be considered lost and the sender should enter fast recovery
			// (even though dupack count is still below threshold).
			p3Start := c.IRS.Add(1 + seqnum.Size(2*maxPayload))
			p3End := p3Start.Add(maxPayload)
			p4Start := p3End
			p4End := p4Start.Add(maxPayload)
			p5Start := p4End
			p5End := p5Start.Add(maxPayload)
			c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{p3Start, p3End}, {p4Start, p4End}, {p5Start, p5End}})

			// Expect #2 to be retransmitted.
			c.ReceiveAndCheckPacketWithOptions(data, maxPayload, maxPayload, tsOptionSize)

			metricPollFn := func() error {
				tcpStats := c.Stack().Stats().TCP
				stats := []struct {
					stat *tcpip.StatCounter
					name string
					want uint64
				}{
					// SACK recovery must have happened.
					{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
					{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
					// #2 was retransmitted.
					{tcpStats.Retransmits, "stats.TCP.Retransmits", 1},
					// No RTOs should have fired yet.
					{tcpStats.Timeouts, "stats.TCP.Timeouts", 0},
				}
				for _, s := range stats {
					if got, want := s.stat.Value(), s.want; got != want {
						return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
					}
				}
				return nil
			}
			if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
				t.Error(err)
			}

			// Send 4 more packets.
			var r bytes.Reader
			data = append(data, data...)
			r.Reset(data[5*maxPayload : 9*maxPayload])
			if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
				t.Fatalf("Write failed: %s", err)
			}

			var sackBlocks []header.SACKBlock
			bytesRead := numPackets * maxPayload
			for i := 0; i < 4; i++ {
				c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
				if i > 0 {
					pStart := c.IRS.Add(1 + seqnum.Size(bytesRead))
					sackBlocks = append(sackBlocks, header.SACKBlock{pStart, pStart.Add(maxPayload)})
					c.SendAckWithSACK(seq, 5*maxPayload, sackBlocks)
				}
				bytesRead += maxPayload
			}

			// #6 should be retransmitted after RTO. The sender should NOT enter fast
			// recovery because the highest byte that was outstanding when fast recovery
			// was last entered is #5 packet's end. And the sender requires at least one
			// more byte beyond that (#6 packet start) to be acked to enter recovery.
			c.ReceiveAndCheckPacketWithOptions(data, 5*maxPayload, maxPayload, tsOptionSize)
			c.SendAck(seq, bytesRead)

			metricPollFn = func() error {
				tcpStats := c.Stack().Stats().TCP
				stats := []struct {
					stat *tcpip.StatCounter
					name string
					want uint64
				}{
					// Only 1 SACK recovery must have happened.
					{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
					{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
					// #2 and #6 were retransmitted.
					{tcpStats.Retransmits, "stats.TCP.Retransmits", 2},
					// RTO should have fired once.
					{tcpStats.Timeouts, "stats.TCP.Timeouts", 1},
				}
				for _, s := range stats {
					if got, want := s.stat.Value(), s.want; got != want {
						return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
					}
				}
				return nil
			}
			if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
				t.Error(err)
			}

			// A completed recovery must allow new data to leave the sender.
			r.Reset(data[bytesRead:])
			if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
				t.Fatalf("Write after recovery: %s", err)
			}
			c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
			c.SendAck(seq, len(data))
		})
	}
}

func verifySpuriousRecoveryMetric(t *testing.T, c *context.Context, numSpuriousRecovery, numSpuriousRTO uint64) {
	t.Helper()

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			{tcpStats.SpuriousRecovery, "stats.TCP.SpuriousRecovery", numSpuriousRecovery},
			{tcpStats.SpuriousRTORecovery, "stats.TCP.SpuriousRTORecovery", numSpuriousRTO},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}

	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

func checkReceivedPacket(t *testing.T, c *context.Context, tcpHdr header.TCP, bytesRead uint32, b *buffer.View, data []byte) {
	payloadLen := uint32(len(tcpHdr.Payload()))
	checker.IPv4(t, b,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1+bytesRead),
			checker.TCPAckNum(context.TestInitialSequenceNumber+1),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	pdata := data[bytesRead : bytesRead+payloadLen]
	if p := tcpHdr.Payload(); !bytes.Equal(pdata, p) {
		t.Fatalf("got data = %v, want = %v", p, pdata)
	}
}

func buildTSOptionFromHeader(tcpHdr header.TCP) []byte {
	opts := tcpHdr.ParsedOptions()
	return timestampOption(opts.TSEcr+1, opts.TSVal)
}

func timestampOption(tsVal, tsEcr uint32) []byte {
	opt := [tsOptionSize]byte{header.TCPOptionNOP, header.TCPOptionNOP}
	header.EncodeTSOption(tsVal, tsEcr, opt[2:])
	return opt[:]
}

func TestDetectSpuriousRecoveryWithRTO(t *testing.T) {
	zeroEcho := func(h header.TCP) []byte {
		return timestampOption(h.ParsedOptions().TSEcr+1, 0)
	}
	for _, tc := range []struct {
		name         string
		negotiateTS  bool
		ackOptions   func(header.TCP) []byte
		wantSpurious bool
	}{
		{name: "timestamps", negotiateTS: true, ackOptions: buildTSOptionFromHeader, wantSpurious: true},
		{name: "no_timestamps"},
		{name: "missing_timestamp", negotiateTS: true},
		{name: "zero_echo", negotiateTS: true, ackOptions: zeroEcho},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testSpuriousRecoveryWithRTO(t, tc.negotiateTS, tc.ackOptions, tc.wantSpurious)
		})
	}
}

func testSpuriousRecoveryWithRTO(t *testing.T, timestamps bool, ackOptions func(header.TCP) []byte, wantSpurious bool) {
	// Only one data ACK is injected. The probe runs after the sender processes it.
	observed := make(chan *tcp.TCPEndpointState, 1)
	probe := func(s *tcp.TCPEndpointState) {
		select {
		case observed <- s:
		default:
		}
	}
	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	c.CreateConnectedWithOptionsNoDelay(header.TCPSynOptions{SACKPermitted: true, TS: timestamps})
	c.EP.SocketOptions().SetDelayOption(false)

	const numPackets = 5
	data := make([]byte, numPackets*maxPayload)
	for i := range data {
		data[i] = byte(i)
	}
	var options []byte
	for i := range numPackets {
		// Without timestamp options a single large write would produce larger segments.
		offset := i * maxPayload
		piece := data[offset : offset+maxPayload]
		if n, err := c.EP.Write(bytes.NewReader(piece), tcpip.WriteOptions{}); err != nil || n != int64(len(piece)) {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(piece))
		}
		b := c.GetPacket()
		defer b.Release()
		tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
		if got := len(tcpHdr.Payload()); got != len(piece) {
			t.Fatalf("segment payload = %d bytes, want %d", got, len(piece))
		}
		checkReceivedPacket(t, c, tcpHdr, uint32(offset), b, data)
		if got := tcpHdr.ParsedOptions().TS; got != timestamps {
			t.Fatalf("segment timestamp option = %t, want %t", got, timestamps)
		}
		if i == 0 && ackOptions != nil {
			options = ackOptions(tcpHdr)
		}
	}

	// Expect segment 5 as a tail loss probe, then segment 1 on RTO.
	optlen := 0
	if timestamps {
		optlen = tsOptionSize
	}
	c.ReceiveAndCheckPacketWithOptions(data, 4*maxPayload, maxPayload, optlen)
	c.ReceiveAndCheckPacketWithOptions(data, 0, maxPayload, optlen)
	info := tcpip.TCPInfoOption{}
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("c.EP.GetSockOpt(&%T) = %s", info, err)
	}
	if info.CcState != tcpip.RTORecovery {
		t.Fatalf("Loss recovery did not happen, got: %v want: %v", info.CcState, tcpip.RTORecovery)
	}

	ack := c.IRS.Add(1 + maxPayload)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(context.TestInitialSequenceNumber).Add(1),
		AckNum:  ack,
		RcvWnd:  30000,
		TCPOpts: options,
	})
	select {
	case s := <-observed:
		if got := s.Sender.SndUna; got != ack {
			t.Fatalf("probe SndUna = %d, want ACK %d", got, ack)
		}
		if wantSpurious && s.Sender.RetransmitTS == 0 {
			t.Error("RetransmitTS was not recorded")
		}
		if got := s.Sender.SpuriousRecovery; got != wantSpurious {
			t.Errorf("SpuriousRecovery = %t, want %t", got, wantSpurious)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the ACK probe")
	}
	want := uint64(0)
	if wantSpurious {
		want = 1
	}
	stats := c.Stack().Stats().TCP
	if got := stats.SpuriousRecovery.Value(); got != want {
		t.Errorf("SpuriousRecovery counter = %d, want %d", got, want)
	}
	if got := stats.SpuriousRTORecovery.Value(); got != want {
		t.Errorf("SpuriousRTORecovery counter = %d, want %d", got, want)
	}
}

func TestEifelRetransmissionTimestamps(t *testing.T) {
	// The first retransmission wraps the timestamp. Neither transmission uses
	// zero, which denotes a missing echo.
	const nearWrap = ^uint32(0) - 5

	// A timestamp above 2^31 precedes zero in TCP serial order. If the
	// second timeout clears retransmitTS, an ACK echoing the first repair
	// would incorrectly count the timeout as spurious.
	const highTimestamp = 3 << 30
	for _, tc := range []struct {
		name        string
		start       uint32
		timeouts    int
		ackOriginal bool
	}{
		{"wrap/original", nearWrap, 1, true},
		{"wrap/repair", nearWrap, 1, false},
		{"two_timeouts/original", highTimestamp, 2, true},
		{"two_timeouts/repair", highTimestamp, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			c := context.NewWithOpts(t, context.Options{MTU: mtu, EnableV4: true, Clock: clock})
			defer c.Cleanup()
			e2e.SetStackSACKPermitted(t, c, true)
			e2e.SetStackTCPRecovery(t, c, 0)
			peer := e2e.CreateConnectedWithSACKAndTS(c)
			// Account for the connection's random timestamp offset.
			clock.Advance(time.Duration(tc.start-peer.RecentTS) * time.Millisecond)

			data := make([]byte, 2*maxPayload)
			if n, err := c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(len(data)) {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(data))
			}
			readTS := func(offset uint32) uint32 {
				t.Helper()
				v := c.GetPacket()
				defer v.Release()
				h := header.TCP(header.IPv4(v.AsSlice()).Payload())
				checkReceivedPacket(t, c, h, offset, v, data)
				opts := h.ParsedOptions()
				if !opts.TS || len(h.Payload()) != maxPayload {
					t.Fatalf("segment at %d: TS = %t, size = %d", offset, opts.TS, len(h.Payload()))
				}
				return opts.TSVal
			}
			original := readTS(0)
			readTS(maxPayload)
			if original != tc.start {
				t.Fatalf("original TS = %d, want %d", original, tc.start)
			}
			var repair uint32
			for range tc.timeouts {
				var info tcpip.TCPInfoOption
				if err := c.EP.GetSockOpt(&info); err != nil {
					t.Fatal(err)
				}
				clock.Advance(info.RTO + time.Millisecond)
				repair = readTS(0)
			}
			if (repair < original) != (tc.start == nearWrap) {
				t.Fatalf("unexpected timestamp order: original %d, repair %d", original, repair)
			}

			// The first advancing ACK covers only the first segment. Echo the
			// timestamp of the copy the peer accepted.
			echo, want := repair, uint64(0)
			if tc.ackOriginal {
				echo, want = original, 1
			}
			peer.Flags = header.TCPFlagAck
			peer.AckNum = peer.AckNum.Add(maxPayload)
			peer.SendPacket(nil, timestampOption(peer.TSVal+1, echo))
			// Drain the ACK before reading the counter, whether or not TCP sends
			// another packet in response.
			c.Stack().Pause()
			c.Stack().Resume()
			if got := c.Stack().Stats().TCP.SpuriousRTORecovery.Value(); got != want {
				t.Errorf("original %d, repair %d, echo %d: spurious RTOs = %d, want %d", original, repair, echo, got, want)
			}
		})
	}
}

func TestSACKDetectSpuriousRecoveryWithDupACK(t *testing.T) {
	numAck := 0
	probeDone := make(chan struct{})
	probe := func(s *tcp.TCPEndpointState) {
		if numAck < 3 {
			numAck++
			return
		}

		if s.Sender.RetransmitTS == 0 {
			t.Fatalf("RetransmitTS did not get updated, got: 0 want > 0")
		}
		if !s.Sender.SpuriousRecovery {
			t.Fatalf("Spurious recovery was not detected")
		}
		close(probeDone)
	}

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	e2e.CreateConnectedWithSACKAndTS(c)
	numPackets := 5
	data := make([]byte, numPackets*maxPayload)
	for i := range data {
		data[i] = byte(i)
	}
	// Write the data.
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	var options []byte
	var bytesRead uint32
	for i := 0; i < numPackets; i++ {
		b := c.GetPacket()
		defer b.Release()
		tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
		checkReceivedPacket(t, c, tcpHdr, bytesRead, b, data)

		// Get options only for the first packet. This will be sent with
		// the ACK to indicate the acknowledgement is for the original
		// packet.
		if i == 0 && c.TimeStampEnabled {
			options = buildTSOptionFromHeader(tcpHdr)
		}
		bytesRead += uint32(len(tcpHdr.Payload()))
	}

	// Receive the retransmitted packet after TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 4*maxPayload, maxPayload, tsOptionSize)

	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	// Send ACK for #3 and #4 segments to avoid entering TLP.
	start := c.IRS.Add(3*maxPayload + 1)
	end := start.Add(2 * maxPayload)
	c.SendAckWithSACK(seq, 0, []header.SACKBlock{{start, end}})

	c.SendAck(seq, 0 /* bytesReceived */)
	c.SendAck(seq, 0 /* bytesReceived */)

	// Receive the retransmitted packet after three duplicate ACKs.
	c.ReceiveAndCheckPacketWithOptions(data, 0, maxPayload, tsOptionSize)

	info := tcpip.TCPInfoOption{}
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("c.EP.GetSockOpt(&%T) = %s", info, err)
	}

	if info.CcState != tcpip.SACKRecovery {
		t.Fatalf("Loss recovery did not happen, got: %v want: %v", info.CcState, tcpip.SACKRecovery)
	}

	// Acknowledge the data.
	rcvWnd := seqnum.Size(30000)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seq,
		AckNum:  c.IRS.Add(1 + seqnum.Size(maxPayload)),
		RcvWnd:  rcvWnd,
		TCPOpts: options,
	})

	// Wait for the probe function to finish processing the
	// ACK before the test completes.
	<-probeDone

	verifySpuriousRecoveryMetric(t, c, 1 /* numSpuriousRecovery */, 0 /* numSpuriousRTO */)
}

func TestNoSpuriousRecoveryWithDSACK(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()
	e2e.SetStackSACKPermitted(t, c, true)
	e2e.CreateConnectedWithSACKAndTS(c)
	numPackets := 5
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Receive the retransmitted packet after TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 4*maxPayload, maxPayload, tsOptionSize)

	// Send ACK for #3 and #4 segments to avoid entering TLP.
	start := c.IRS.Add(3*maxPayload + 1)
	end := start.Add(2 * maxPayload)
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAckWithSACK(seq, 0, []header.SACKBlock{{start, end}})

	c.SendAck(seq, 0 /* bytesReceived */)
	c.SendAck(seq, 0 /* bytesReceived */)

	// Receive the retransmitted packet after three duplicate ACKs.
	c.ReceiveAndCheckPacketWithOptions(data, 0, maxPayload, tsOptionSize)

	// Acknowledge the data with DSACK for #1 segment.
	start = c.IRS.Add(maxPayload + 1)
	end = start.Add(2 * maxPayload)
	seq = seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAckWithSACK(seq, 6*maxPayload, []header.SACKBlock{{start, end}})

	verifySpuriousRecoveryMetric(t, c, 0 /* numSpuriousRecovery */, 0 /* numSpuriousRTO */)
}

func TestSACKRetransmissionTimer(t *testing.T) {
	clock := faketime.NewManualClock()
	c := context.NewWithOpts(t, context.Options{EnableV4: true, MTU: 1500, Clock: clock})
	defer c.Cleanup()
	e2e.SetStackSACKPermitted(t, c, true)
	e2e.SetStackTCPRecovery(t, c, 0) // Use duplicate ACKs, not RACK or TLP.
	peer := e2e.CreateConnectedWithSACKPermittedOption(c)
	info := func() tcpip.TCPInfoOption {
		t.Helper()
		var v tcpip.TCPInfoOption
		if err := c.EP.GetSockOpt(&v); err != nil {
			t.Fatalf("TCP_INFO: %v", err)
		}
		return v
	}
	mss := int(info().SndMss)
	data := make([]byte, 9*mss)
	for i := range data {
		data[i] = byte(i / mss)
	}
	if n, err := c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(len(data)) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(data))
	}
	for i := 0; i < len(data); i += mss {
		c.ReceiveAndCheckPacket(data, i, mss)
	}
	ack := func(blocks ...header.SACKBlock) {
		c.SendAckWithSACK(peer.NextSeqNum, mss, blocks)
		c.Stack().Pause()
		c.Stack().Resume()
	}
	block := func(start, end int) header.SACKBlock {
		return header.SACKBlock{
			Start: peer.AckNum.Add(seqnum.Size(start * mss)),
			End:   peer.AckNum.Add(seqnum.Size(end * mss)),
		}
	}

	// Cumulatively ACK packet 1. Half an RTO later, report packets 3–5
	// to trigger retransmission of packet 2, the oldest outstanding data.
	clock.Advance(100 * time.Millisecond)
	ack()
	rto := info().RTO
	clock.Advance(rto / 2)
	for end := 3; end <= 5; end++ {
		ack(block(2, end))
	}
	c.ReceiveAndCheckPacket(data, mss, mss)

	// Report packets 7–9 with the same cumulative ACK. Retransmitting
	// packet 6 must not postpone the deadline for packet 2.
	clock.Advance(rto / 4)
	ack(block(6, 9), block(2, 5))
	c.ReceiveAndCheckPacket(data, 5*mss, mss)
	if v := info(); v.RTO != rto || v.CcState != tcpip.SACKRecovery {
		t.Fatalf("after retransmitting packet 6: RTO=%s, state=%v; want %s, SACKRecovery", v.RTO, v.CcState, rto)
	}

	timeouts := c.Stack().Stats().TCP.Timeouts
	clock.Advance(rto - rto/4 - time.Nanosecond)
	if got := timeouts.Value(); got != 0 {
		t.Fatalf("before packet 2's retransmission deadline: got %d timeouts, want 0", got)
	}
	clock.Advance(time.Nanosecond)
	if got := timeouts.Value(); got != 1 {
		t.Fatalf("at packet 2's retransmission deadline: got %d timeouts, want 1", got)
	}
	c.ReceiveAndCheckPacket(data, mss, mss)
}

// outstandingTest is a connection in which the test is the peer of a sender
// with SACK and a manual clock. Packet numbers start at 1. The seq, ack and
// checkOutstanding methods count data in units of the MSS at the time of
// the connection, so they are correct only for packets that have that much
// data.
type outstandingTest struct {
	t     *testing.T
	c     *context.Context
	clock *faketime.ManualClock
	peer  *context.RawEndpoint
	mss   int

	// sender is the state of the sender after the last segment that it
	// received.
	sender atomic.Pointer[tcp.TCPSenderState]
}

// outstandingTestRecoveries are the loss detection configurations with
// SACK: duplicate ACK counting and RACK.
var outstandingTestRecoveries = []struct {
	name     string
	recovery tcpip.TCPRecovery
}{
	{name: "DupACK", recovery: 0},
	{name: "RACK", recovery: tcpip.TCPRACKLossDetection},
}

// newOutstandingTest connects an endpoint with SACK and the given loss
// detection configuration. If numPackets is not zero, it writes numPackets
// packets of data to the endpoint and drops the packets that the sender
// sends. The caller must call Cleanup on the c field of the result.
func newOutstandingTest(t *testing.T, recovery tcpip.TCPRecovery, numPackets int) *outstandingTest {
	t.Helper()
	o := &outstandingTest{t: t, clock: faketime.NewManualClock()}
	o.c = context.NewWithOpts(t, context.Options{
		EnableV4: true,
		MTU:      1500,
		Clock:    o.clock,
		Probe: func(s *tcp.TCPEndpointState) {
			snd := s.Sender
			o.sender.Store(&snd)
		},
	})
	e2e.SetStackSACKPermitted(t, o.c, true)
	e2e.SetStackTCPRecovery(t, o.c, int(recovery))
	o.peer = e2e.CreateConnectedWithSACKPermittedOption(o.c)

	var info tcpip.TCPInfoOption
	if err := o.c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("c.EP.GetSockOpt(&%T) = %s", info, err)
	}
	o.mss = int(info.SndMss)
	if numPackets > 0 {
		data := make([]byte, numPackets*o.mss)
		if n, err := o.c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(len(data)) {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(data))
		}
		o.sync()
	}
	return o
}

// sync waits until the sender has processed all the segments from the peer
// and drops the packets that the sender sent.
func (o *outstandingTest) sync() {
	o.c.Stack().Pause()
	o.c.Stack().Resume()
	for p := o.c.GetPacketNonBlocking(); p != nil; p = o.c.GetPacketNonBlocking() {
		p.Release()
	}
}

// seq returns the sequence number of the first byte after packet n.
func (o *outstandingTest) seq(n int) seqnum.Value {
	return o.peer.AckNum.Add(seqnum.Size(n * o.mss))
}

// ack sends a cumulative ACK for packets 1 to acked. If sackEnd is greater
// than sackStart, the ACK has a SACK block for packets sackStart+1 to
// sackEnd. It returns the state of the sender after the sender has
// processed the ACK.
func (o *outstandingTest) ack(acked, sackStart, sackEnd int) *tcp.TCPSenderState {
	var blocks []header.SACKBlock
	if sackStart < sackEnd {
		blocks = []header.SACKBlock{{Start: o.seq(sackStart), End: o.seq(sackEnd)}}
	}
	o.c.SendAckWithSACK(o.peer.NextSeqNum, acked*o.mss, blocks)
	o.sync()
	return o.sender.Load()
}

// decreasePathMTU tells the sender that quoted, a packet that the sender
// sent, was too large for the path. The new path MTU gives a maximum payload
// size that is between a half and the whole of the MSS, so a packet with one
// MSS of data becomes two packets. The sender does not examine the sequence
// number of quoted, so quoted can be a packet that the peer acknowledged.
// decreasePathMTU does not drop the packets that the sender sends.
func (o *outstandingTest) decreasePathMTU(quoted *buffer.View) {
	newMTU := header.IPv4MinimumSize + header.TCPMinimumSize + header.TCPOptionsMaximumSize + o.mss/2 + 1
	mtu := buffer.NewViewWithData([]byte{0, 0, byte(newMTU / 256), byte(newMTU % 256)})
	defer mtu.Release()
	o.c.SendICMPPacket(header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, mtu, quoted, newMTU)
	o.c.Stack().Pause()
	o.c.Stack().Resume()
}

// checkOutstanding checks that the peer has acknowledged packets 1 to
// acked, that the sender is out of recovery and has data in flight, and
// that Outstanding is the number of packets that the sender sent and that
// are not cumulatively acknowledged.
func (o *outstandingTest) checkOutstanding(snd *tcp.TCPSenderState, acked int) {
	o.t.Helper()
	if got, want := snd.SndUna, o.seq(acked); got != want {
		o.t.Fatalf("got SndUna = %d, want = %d", got, want)
	}
	if snd.FastRecovery.Active {
		o.t.Fatal("sender is in recovery")
	}
	want := int(snd.SndUna.Size(snd.SndNxt)) / o.mss
	if want == 0 {
		o.t.Fatal("sender has no data in flight")
	}
	if got := snd.Outstanding; got != want {
		o.t.Errorf("got Outstanding = %d, want = %d", got, want)
	}
}

// TestSACKOutstandingAfterCumulativeACK tests that a segment which the peer
// selectively acknowledges when the sender is not in recovery does not stay in
// the count of outstanding packets after a cumulative ACK covers it.
func TestSACKOutstandingAfterCumulativeACK(t *testing.T) {
	for _, tc := range outstandingTestRecoveries {
		t.Run(tc.name, func(t *testing.T) {
			// The initial congestion window lets the sender send all the
			// packets.
			const numPackets = 8
			o := newOutstandingTest(t, tc.recovery, numPackets)
			defer o.c.Cleanup()

			// Cumulatively ACK packet 1 to give the sender an RTT sample. With
			// RACK, the reorder window is then a quarter of this RTT, and the clock
			// does not advance again, so RACK does not mark a packet as lost.
			o.clock.Advance(100 * time.Millisecond)
			o.ack(1, 0, 0)

			// SACK packet 4. One duplicate ACK does not start recovery.
			o.ack(1, 3, 4)

			// Cumulatively ACK packets 2 to 4. Packets 5 to 8 stay in flight.
			snd := o.ack(4, 0, 0)
			o.checkOutstanding(snd, 4)
			if got, want := snd.SndNxt, o.seq(numPackets); got != want {
				t.Errorf("got SndNxt = %d, want = %d", got, want)
			}
			// In slow start, the congestion window grows by one packet for each
			// packet that a cumulative ACK covers.
			if got, want := snd.SndCwnd, tcp.InitialCwnd+4; got != want {
				t.Errorf("got SndCwnd = %d, want = %d", got, want)
			}

			tcpStats := o.c.Stack().Stats().TCP
			for _, s := range []struct {
				stat *tcpip.StatCounter
				name string
			}{
				{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery"},
				{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit"},
				{tcpStats.Retransmits, "stats.TCP.Retransmits"},
				{tcpStats.Timeouts, "stats.TCP.Timeouts"},
			} {
				if got := s.stat.Value(); got != 0 {
					t.Errorf("got %s = %d, want = 0", s.name, got)
				}
			}
		})
	}
}

// TestSACKOutstandingAfterRecovery tests that, when SACK recovery ends and
// when a later cumulative ACK covers segments that the peer selectively
// acknowledged during recovery, the count of outstanding packets is the
// number of sent packets that are not cumulatively acknowledged.
func TestSACKOutstandingAfterRecovery(t *testing.T) {
	for _, tc := range outstandingTestRecoveries {
		t.Run(tc.name, func(t *testing.T) {
			o := newOutstandingTest(t, tc.recovery, 30 /* numPackets */)
			defer o.c.Cleanup()

			// Cumulatively ACK packet 1, then send three duplicate ACKs that SACK
			// packets 3 to 5. The sender starts recovery.
			o.clock.Advance(100 * time.Millisecond)
			o.ack(1, 0, 0)
			for end := 3; end <= 5; end++ {
				o.ack(1, 2, end)
			}
			if snd := o.sender.Load(); !snd.FastRecovery.Active {
				t.Fatal("sender did not start recovery")
			}
			// The sender sent packets 1 to 12 before recovery started.
			if got, want := o.sender.Load().FastRecovery.Last, o.seq(12)-1; got != want {
				t.Fatalf("got FastRecovery.Last = %d, want = %d", got, want)
			}

			// SACK packets 6 to 10. The sender now has congestion window to send
			// new data during recovery.
			if snd := o.ack(1, 2, 10); snd.SndNxt.LessThan(o.seq(15)) {
				t.Fatalf("got SndNxt = %d, want >= %d", snd.SndNxt, o.seq(15))
			}

			// Cumulatively ACK packets 2 to 12 and SACK packets 14 and 15, which
			// the sender sent during recovery. Recovery ends with SACKed packets
			// above the cumulative ACK. With RACK, the clock advances first so
			// that the RTT sample of these packets is not zero. The reorder
			// window is then not zero, and RACK does not immediately mark
			// packet 13 as lost.
			o.clock.Advance(50 * time.Millisecond)
			o.checkOutstanding(o.ack(12, 13, 15), 12)

			// The cumulative ACK now covers packets that were SACKed during
			// recovery.
			snd := o.ack(15, 0, 0)
			o.checkOutstanding(snd, 15)
			// The sender is in congestion avoidance. The cumulative ACK for
			// packets 13 to 15 completes one congestion window of acknowledged
			// packets, so the window grows by one packet.
			if got, want := snd.SndCwnd, snd.Ssthresh+1; got != want {
				t.Errorf("got SndCwnd = %d, want = %d", got, want)
			}
			if got, want := snd.SndCAAckCount, 1; got != want {
				t.Errorf("got SndCAAckCount = %d, want = %d", got, want)
			}

			if got := o.c.Stack().Stats().TCP.SACKRecovery.Value(); got != 1 {
				t.Errorf("got stats.TCP.SACKRecovery = %d, want = 1", got)
			}
		})
	}
}

// TestSACKOutstandingAfterPathMTUDecrease tests the count of outstanding
// packets when a path MTU decrease makes a selectively acknowledged segment
// larger than one packet. A later cumulative ACK for the segment must
// subtract the number of packets that the count has for the segment.
func TestSACKOutstandingAfterPathMTUDecrease(t *testing.T) {
	for _, tc := range outstandingTestRecoveries {
		t.Run(tc.name, func(t *testing.T) {
			o := newOutstandingTest(t, tc.recovery, 0 /* numPackets */)
			defer o.c.Cleanup()

			// Send two small packets, a packet with one MSS of data, and a
			// small packet.
			const (
				small = 100
				large = 2 // Index in sizes.
			)
			sizes := []int{small, small, o.mss, small}
			first := o.peer.AckNum
			var largePacket *buffer.View
			for i, size := range sizes {
				if n, err := o.c.EP.Write(bytes.NewReader(make([]byte, size)), tcpip.WriteOptions{}); err != nil || n != int64(size) {
					t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, size)
				}
				o.c.Stack().Pause()
				o.c.Stack().Resume()
				p := o.c.GetPacketNonBlocking()
				if p == nil {
					t.Fatalf("sender did not send packet %d", i+1)
				}
				if i == large {
					largePacket = p
					defer largePacket.Release()
				} else {
					p.Release()
				}
			}

			// Cumulatively ACK packet 1 to give the sender an RTT sample. With
			// RACK, the reorder window is then a quarter of this RTT, and the clock
			// does not advance again, so RACK does not mark a packet as lost.
			o.clock.Advance(100 * time.Millisecond)
			o.c.SendAckWithSACK(o.peer.NextSeqNum, small, nil)
			o.sync()

			// SACK the large packet. One duplicate ACK does not start recovery.
			o.c.SendAckWithSACK(o.peer.NextSeqNum, small, []header.SACKBlock{{
				Start: first.Add(2 * small),
				End:   first.Add(seqnum.Size(2*small + o.mss)),
			}})
			o.sync()

			// Decrease the path MTU. The large packet is now two packets. The
			// sender does not send it again. The sender decreases the count of
			// outstanding packets by one for the packet that was too large, and
			// sends the last packet again, which increases the count by one.
			o.decreasePathMTU(largePacket)

			// Cumulatively ACK packets 2 and 3. The last packet stays in flight.
			o.c.SendAckWithSACK(o.peer.NextSeqNum, 2*small+o.mss, nil)
			o.sync()
			snd := o.sender.Load()
			if got, want := snd.SndUna, first.Add(seqnum.Size(2*small+o.mss)); got != want {
				t.Fatalf("got SndUna = %d, want = %d", got, want)
			}
			if got, want := snd.SndNxt, snd.SndUna.Add(small); got != want {
				t.Fatalf("got SndNxt = %d, want = %d", got, want)
			}
			if snd.FastRecovery.Active {
				t.Fatal("sender is in recovery")
			}
			if got := snd.MaxPayloadSize; got >= o.mss || 2*got < o.mss {
				t.Fatalf("got MaxPayloadSize = %d, want in [%d, %d)", got, (o.mss+1)/2, o.mss)
			}
			if got, want := snd.Outstanding, 1; got != want {
				t.Errorf("got Outstanding = %d, want = %d", got, want)
			}
			tcpStats := o.c.Stack().Stats().TCP
			if got := tcpStats.Retransmits.Value(); got != 1 {
				t.Errorf("got stats.TCP.Retransmits = %d, want = 1", got)
			}
			if got := tcpStats.Timeouts.Value(); got != 0 {
				t.Errorf("got stats.TCP.Timeouts = %d, want = 0", got)
			}
		})
	}
}

// TestSACKPathMTUDecreaseWithFullWindow tests that, when the peer has
// selectively acknowledged segments and the congestion window is full or
// almost full, a path MTU decrease lets the sender immediately send one
// packet: the first part of the first segment that is too large.
func TestSACKPathMTUDecreaseWithFullWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		// numPackets is the number of packets of data that the test
		// writes. After the ACK for packet 1, the congestion window is
		// 11 packets and packets 2 to numPackets are in flight, to a
		// maximum of 11 packets.
		numPackets int
		// sackEnd is the last packet that the peer selectively
		// acknowledges. The first is packet 3.
		sackEnd int
	}{
		{name: "FullWindow", numPackets: 14, sackEnd: 3},
		{name: "OnePacketOfWindow", numPackets: 11, sackEnd: 4},
	} {
		for _, rc := range outstandingTestRecoveries {
			t.Run(tc.name+"/"+rc.name, func(t *testing.T) {
				o := newOutstandingTest(t, rc.recovery, 0 /* numPackets */)
				defer o.c.Cleanup()

				data := make([]byte, tc.numPackets*o.mss)
				if n, err := o.c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(len(data)) {
					t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(data))
				}
				o.c.Stack().Pause()
				o.c.Stack().Resume()
				packet := o.c.GetPacketNonBlocking()
				if packet == nil {
					t.Fatal("sender did not send packet 1")
				}
				defer packet.Release()
				o.sync()

				// Cumulatively ACK packet 1 to give the sender an RTT sample. With
				// RACK, the reorder window is then a quarter of this RTT, and the clock
				// does not advance again, so RACK does not mark a packet as lost.
				o.clock.Advance(100 * time.Millisecond)
				o.ack(1, 0, 0)

				// SACK packets 3 to sackEnd. One duplicate ACK does not start
				// recovery. Packet 2 is not acknowledged.
				snd := o.ack(1, 2, tc.sackEnd)
				if snd.FastRecovery.Active {
					t.Fatal("sender is in recovery")
				}
				if got, want := snd.Outstanding, min(tc.numPackets-1, snd.SndCwnd); got != want {
					t.Fatalf("got Outstanding = %d, want = %d", got, want)
				}

				// Decrease the path MTU. Each SACKed packet is now two packets.
				// The sender has congestion window for one packet, and sends the
				// first part of packet 2.
				o.decreasePathMTU(packet)
				p := o.c.GetPacketNonBlocking()
				if p == nil {
					t.Fatal("sender did not send a packet after the path MTU decrease")
				}
				defer p.Release()
				tcpHdr := header.TCP(header.IPv4(p.AsSlice()).Payload())
				if got, want := seqnum.Value(tcpHdr.SequenceNumber()), o.seq(1); got != want {
					t.Errorf("got sequence number = %d, want = %d", got, want)
				}
				if got := len(tcpHdr.Payload()); got >= o.mss || 2*got < o.mss {
					t.Errorf("got payload size = %d, want in [%d, %d)", got, (o.mss+1)/2, o.mss)
				}
				if next := o.c.GetPacketNonBlocking(); next != nil {
					next.Release()
					t.Error("sender sent more than one packet after the path MTU decrease")
				}

				if got := o.c.Stack().Stats().TCP.Timeouts.Value(); got != 0 {
					t.Errorf("got stats.TCP.Timeouts = %d, want = 0", got)
				}
				if rc.recovery != 0 {
					// With RACK, one more ACK can start recovery, because the
					// number of SACKed packets is larger after the path MTU
					// decrease.
					return
				}

				// Send the last ACK again to get the state of the sender. The
				// congestion window is full.
				snd = o.ack(1, 2, tc.sackEnd)
				if snd.FastRecovery.Active {
					t.Fatal("sender is in recovery")
				}
				if got, want := snd.Outstanding, snd.SndCwnd; got != want {
					t.Errorf("got Outstanding = %d, want = %d", got, want)
				}
			})
		}
	}
}

// TestSACKOutstandingAfterRTO tests that, after a retransmit timeout, the
// count of outstanding packets includes only the packets sent after the
// timeout, and that it stays correct when a cumulative ACK covers segments
// that were sent before the timeout and selectively acknowledged after it.
func TestSACKOutstandingAfterRTO(t *testing.T) {
	// The initial congestion window lets the sender send packets 1 to 10.
	// RACK is off: with RACK, the retransmit timer does not expire after one
	// RTO, because the sender first sends a tail loss probe.
	o := newOutstandingTest(t, 0 /* recovery */, 14 /* numPackets */)
	defer o.c.Cleanup()

	var info tcpip.TCPInfoOption
	if err := o.c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("c.EP.GetSockOpt(&%T) = %s", info, err)
	}
	o.clock.Advance(info.RTO)
	o.sync()
	if got := o.c.Stack().Stats().TCP.Timeouts.Value(); got != 1 {
		t.Fatalf("got stats.TCP.Timeouts = %d, want = 1", got)
	}

	// Cumulatively ACK packet 1 and SACK packets 3 to 10. The sender sends
	// packet 2 again, does not send packets 3 to 10 again, and sends packet 11.
	snd := o.ack(1, 2, 10)
	if got, want := snd.SndNxt, o.seq(11); got != want {
		t.Fatalf("got SndNxt = %d, want = %d", got, want)
	}
	if got, want := snd.Outstanding, 2; got != want {
		t.Errorf("got Outstanding = %d, want = %d", got, want)
	}

	// Cumulatively ACK packets 2 to 10. The congestion window grows by one
	// packet, for packet 2.
	snd = o.ack(10, 0, 0)
	o.checkOutstanding(snd, 10)
	if got, want := snd.SndCwnd, 3; got != want {
		t.Errorf("got SndCwnd = %d, want = %d", got, want)
	}
}

// TestSACKOutstandingAfterRTOAndPathMTUDecrease tests that a path MTU
// decrease after a retransmit timeout does not add the segments that the peer
// selectively acknowledged after the timeout to the count of outstanding
// packets.
func TestSACKOutstandingAfterRTOAndPathMTUDecrease(t *testing.T) {
	// The initial congestion window lets the sender send all the packets.
	// RACK is off for the same reason as in TestSACKOutstandingAfterRTO.
	o := newOutstandingTest(t, 0 /* recovery */, 10 /* numPackets */)
	defer o.c.Cleanup()

	var info tcpip.TCPInfoOption
	if err := o.c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("c.EP.GetSockOpt(&%T) = %s", info, err)
	}
	o.clock.Advance(info.RTO)
	o.c.Stack().Pause()
	o.c.Stack().Resume()
	// The sender sends packet 1 again.
	packet := o.c.GetPacketNonBlocking()
	if packet == nil {
		t.Fatal("sender did not send a packet after the retransmit timeout")
	}
	defer packet.Release()
	o.sync()

	// Cumulatively ACK packet 1 and SACK packets 3 to 10. The sender sends
	// packet 2 again and does not send packets 3 to 10 again. The congestion
	// window is two packets.
	snd := o.ack(1, 2, 10)
	if got, want := snd.Outstanding, 1; got != want {
		t.Fatalf("got Outstanding = %d, want = %d", got, want)
	}
	if got, want := snd.SndCwnd, 2; got != want {
		t.Fatalf("got SndCwnd = %d, want = %d", got, want)
	}

	// Decrease the path MTU. The sender decreases the count of outstanding
	// packets by one, to zero, and the congestion window lets it send the two
	// parts of packet 2.
	o.decreasePathMTU(packet)
	sent := 0
	for p := o.c.GetPacketNonBlocking(); p != nil; p = o.c.GetPacketNonBlocking() {
		p.Release()
		sent++
	}
	if got, want := sent, 2; got != want {
		t.Errorf("sender sent %d packets after the path MTU decrease, want = %d", got, want)
	}

	// Send the last ACK again to get the state of the sender.
	snd = o.ack(1, 2, 10)
	if got := snd.MaxPayloadSize; got >= o.mss || 2*got < o.mss {
		t.Fatalf("got MaxPayloadSize = %d, want in [%d, %d)", got, (o.mss+1)/2, o.mss)
	}
	if got, want := snd.Outstanding, 2; got != want {
		t.Errorf("got Outstanding = %d, want = %d", got, want)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	// Allow TCP async work to complete to avoid false reports of leaks.
	// TODO(gvisor.dev/issue/5940): Use fake clock in tests.
	time.Sleep(1 * time.Second)
	refs.DoLeakCheck()
	os.Exit(code)
}
