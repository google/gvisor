// Copyright 2020 The gVisor Authors.
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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

// TestRACKUpdate tests the RACK related fields are updated when an ACK is
// received on a SACK enabled connection.
func TestRACKUpdate(t *testing.T) {
	const maxPayload = 10
	const tsOptionSize = 12
	const maxTCPOptionSize = 40

	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxTCPOptionSize+maxPayload))
	defer c.Cleanup()

	var xmitTime time.Time
	ch := make(chan int)
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
		// Validate that the endpoint Sender.RACKState is what we expect.
		if state.Sender.RACKState.XmitTime.Before(xmitTime) {
			t.Fatalf("RACK transmit time failed to update when an ACK is received")
		}

		gotSeq := state.Sender.RACKState.EndSequence
		wantSeq := state.Sender.SndNxt
		if !gotSeq.LessThanEq(wantSeq) || gotSeq.LessThan(wantSeq) {
			t.Fatalf("RACK sequence number failed to update, got: %v, but want: %v", gotSeq, wantSeq)
		}

		if state.Sender.RACKState.RTT == 0 {
			t.Fatalf("RACK RTT failed to update when an ACK is received")
		}
		close(ch)
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

	data := buffer.NewView(maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	xmitTime = time.Now()
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
	bytesRead += maxPayload
	c.SendAck(seqnum.Value(context.TestInitialSequenceNumber).Add(1), bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-ch
}

// TestRACKDetectReorder tests that RACK detects packet reordering.
func TestRACKDetectReorder(t *testing.T) {
	const maxPayload = 10
	const tsOptionSize = 12
	const maxTCPOptionSize = 40

	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxTCPOptionSize+maxPayload))
	defer c.Cleanup()

	ackNum := 1
	ch := make(chan int)
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
		// Validate that RACK detects packet reordering for the
		// endpoint.
		gotSeq := state.Sender.RACKState.FACK
		wantSeq := state.Sender.SndNxt
		if !gotSeq.LessThanEq(wantSeq) || gotSeq.LessThan(wantSeq) {
			t.Fatalf("RACK FACK failed to update, got: %v, but want: %v", gotSeq, wantSeq)
		}

		if ackNum == 2 {
			if state.Sender.RACKState.Reord == false {
				t.Fatalf("RACK reorder detection failed")
			}
			close(ch)
		}
		ackNum++
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

	data := buffer.NewView(2 * maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	for i := 0; i < 2; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
		bytesRead += maxPayload
	}

	start := c.IRS.Add(maxPayload + 1)
	end := start.Add(maxPayload)
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAckWithSACK(seq, 0, []header.SACKBlock{{start, end}})
	c.SendAck(seq, bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-ch
}

// TestRACKUpdateAfterDSACK tests that RACK updates after receiving DSACK.
func TestRACKUpdateAfterDSACK(t *testing.T) {
	const maxPayload = 10
	const tsOptionSize = 12
	const maxTCPOptionSize = 40

	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxTCPOptionSize+maxPayload))
	defer c.Cleanup()

	ackNum := 1
	ch := make(chan int)
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
		// Validate that RACK detects DSACK.
		if ackNum == 1 && state.Sender.RACKState.DSACK {
			t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
		}

		if ackNum == 2 {
			if state.Sender.RACKState.ReoWnd == 0 || state.Sender.RACKState.ReoWnd > state.Sender.SRTT {
				t.Fatalf("RACK failed to update reorder window after receiving duplicate SACK")
			}

			if state.Sender.RACKState.ReoWndIncr != 1 || state.Sender.RACKState.ReoWndPersist != 16 {
				t.Fatalf("RACK failed to update reorder window after receiving duplicate SACK")
			}

			if state.Sender.RACKState.RTTSeq != state.Sender.SndNxt {
				t.Fatalf("RACK failed to update sequence number after receiving duplicate SACK")
			}

			close(ch)
		}
		ackNum++
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

	data := buffer.NewView(2 * maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	for i := 0; i < 2; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
		bytesRead += maxPayload
	}

	// ACK all the packets.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAck(seq, bytesRead)

	// Send DSACK.
	start := c.IRS.Add(maxPayload + 1)
	end := start.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-ch
}
