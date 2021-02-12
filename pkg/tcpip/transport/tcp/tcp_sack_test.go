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

package tcp_test

import (
	"bytes"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// createConnectedWithSACKPermittedOption creates and connects c.ep with the
// SACKPermitted option enabled if the stack in the context has the SACK support
// enabled.
func createConnectedWithSACKPermittedOption(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled()})
}

// createConnectedWithSACKAndTS creates and connects c.ep with the SACK & TS
// option enabled if the stack in the context has SACK and TS enabled.
func createConnectedWithSACKAndTS(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled(), TS: true})
}

func setStackSACKPermitted(t *testing.T, c *context.Context, enable bool) {
	t.Helper()
	opt := tcpip.TCPSACKEnabled(enable)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}
}

// TestSackPermittedConnect establishes a connection with the SACK option
// enabled.
func TestSackPermittedConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("stack.sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)
			rep := createConnectedWithSACKPermittedOption(c)
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
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)

			rep := c.CreateConnectedWithOptions(header.TCPSynOptions{})

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
// SACKPermitted option. In case of SYN cookies SACK should be disabled as we
// don't encode the SACK information in the cookie.
func TestSackPermittedAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		sackPermitted bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, false, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, true, 5, 0x8000},  // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test stack.sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, defaultMTU)
					defer c.Cleanup()

					if tc.cookieEnabled {
						// Set the SynRcvd threshold to
						// zero to force a syn cookie
						// based accept to happen.
						var opt tcpip.TCPSynRcvdCountThresholdOption
						if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
							t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
						}
					}
					setStackSACKPermitted(t, c, sackEnabled)

					rep := c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS, SACKPermitted: tc.sackPermitted})
					//  Now verify no SACK blocks are
					//  received when sack is disabled.
					data := []byte{1, 2, 3}
					rep.SendPacket(data, nil)
					rep.VerifyACKNoSACK()

					savedSeqNum := rep.NextSeqNum

					// Make an out of order packet and send
					// it.
					rep.NextSeqNum += 3
					sackBlocks := []header.SACKBlock{
						{rep.NextSeqNum, rep.NextSeqNum.Add(seqnum.Size(len(data)))},
					}
					rep.SendPacket(data, nil)

					// The ACK should contain the older
					// sequence number.
					rep.NextSeqNum = savedSeqNum
					if sackEnabled && tc.sackPermitted {
						rep.VerifyACKHasSACK(sackBlocks)
					} else {
						rep.VerifyACKNoSACK()
					}

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
					c := context.New(t, defaultMTU)
					defer c.Cleanup()

					if tc.cookieEnabled {
						// Set the SynRcvd threshold to
						// zero to force a syn cookie
						// based accept to happen.
						var opt tcpip.TCPSynRcvdCountThresholdOption
						if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
							t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
						}
					}

					setStackSACKPermitted(t, c, sackEnabled)

					rep := c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS})

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
		if got, want := sack.Blocks[:sack.NumBlocks], tc.updated; !reflect.DeepEqual(got, want) {
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
		if got, want := sack.Blocks[:sack.NumBlocks], tc.trimmed; !reflect.DeepEqual(got, want) {
			t.Errorf("TrimSackBlockList(%v, %v), got: %v, want: %v", tc.sackBlocks, tc.rcvNxt, got, want)
		}
	}
}

func TestSACKRecovery(t *testing.T) {
	const maxPayload = 10
	// See: tcp.makeOptions for why tsOptionSize is set to 12 here.
	const tsOptionSize = 12
	// Enabling SACK means the payload size is reduced to account
	// for the extra space required for the TCP options.
	//
	// We increase the MTU by 40 bytes to account for SACK and Timestamp
	// options.
	const maxTCPOptionSize = 40

	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxTCPOptionSize+maxPayload))
	defer c.Cleanup()

	c.Stack().AddTCPProbe(func(s stack.TCPEndpointState) {
		// We use log.Printf instead of t.Logf here because this probe
		// can fire even when the test function has finished. This is
		// because closing the endpoint in cleanup() does not mean the
		// actual worker loop terminates immediately as it still has to
		// do a full TCP shutdown. But this test can finish running
		// before the shutdown is done. Using t.Logf in such a case
		// causes the test to panic due to logging after test finished.
		log.Printf("state: %+v\n", s)
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

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
// - Fast SACK recovery is entered when SND.UNA is considered lost by the SACK
//   scoreboard but dupack count is still below threshold.
// - Only enter recovery when at least one more byte of data beyond the highest
//   byte that was outstanding when fast retransmit was last entered is acked.
func TestRecoveryEntry(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	numPackets := 5
	data := sendAndReceiveWithSACK(t, c, numPackets, false /* enableRACK */)

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
	c.SendAck(seq, 9*maxPayload)

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
}
