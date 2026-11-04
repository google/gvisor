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

// Package tcp_delayed_ack_test tests delayed acknowledgments, enabled by
// tcpip.TCPDelayedACKOption.
package tcp_delayed_ack_test

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

const (
	// delayedACKTimeout is the maximum acknowledgment delay.
	delayedACKTimeout = 40 * time.Millisecond

	// payloadSize is below the MSS (536 bytes, the peer advertises no MSS
	// option), so that a single segment is not acknowledged immediately
	// while two are.
	payloadSize = 500

	// responseSize is the size of the endpoint responses.
	responseSize = 3

	// noPacketWait is how long the tests wait to verify that no packet was
	// sent, independently of the stack (fake) clock.
	noPacketWait = 50 * time.Millisecond
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.NoLeakChecking)
	m.Run()
}

// newConnected returns a connected endpoint, with delayed acknowledgments
// enabled as requested, and the stack clock.
func newConnected(t *testing.T, delayedACK bool) (*context.Context, *faketime.ManualClock) {
	t.Helper()

	clock := faketime.NewManualClock()
	c := context.NewWithOpts(t, context.Options{
		EnableV4: true,
		EnableV6: true,
		MTU:      e2e.DefaultMTU,
		Clock:    clock,
	})

	opt := tcpip.TCPDelayedACKOption(delayedACK)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	return c, clock
}

// sendData sends a data segment of payloadSize bytes at the argument offset
// from the initial peer sequence number, acknowledging the argument number of
// bytes sent by the endpoint.
func sendData(c *context.Context, offset int, acked int) {
	sendBytes(c, offset, payloadSize, acked)
}

// sendBytes is like sendData with the argument payload size.
func sendBytes(c *context.Context, offset int, size int, acked int) {
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1).Add(seqnum.Size(offset))

	c.SendPacket(make([]byte, size), &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seq,
		AckNum:  c.IRS.Add(1).Add(seqnum.Size(acked)),
		RcvWnd:  30000,
	})
}

// respond reads the received data and writes a response of responseSize
// bytes, it checks that the response acknowledges the argument number of
// bytes.
func respond(t *testing.T, c *context.Context, received int, sent int) {
	t.Helper()

	var buf bytes.Buffer
	if _, err := c.EP.Read(&buf, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("Read: %s", err)
	}

	var r bytes.Reader
	r.Reset(make([]byte, responseSize))

	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write: %s", err)
	}

	checkSegment(t, c, sent, received, responseSize, header.TCPFlagAck|header.TCPFlagPsh)
}

// newInteractive returns a connected endpoint with delayed acknowledgments
// enabled, after a request/response exchange, which makes the connection
// interactive (acknowledgments are only delayed for interactive traffic).
func newInteractive(t *testing.T) (*context.Context, *faketime.ManualClock) {
	t.Helper()

	c, clock := newConnected(t, true)

	// not interactive yet, the request is acknowledged immediately
	sendData(c, 0, 0)
	checkACK(t, c, payloadSize, 0, header.TCPFlagAck)
	respond(t, c, payloadSize, 0)

	return c, clock
}

// checkACK checks that the next packet, with no data sent before, acknowledges
// the argument number of bytes, with the argument payload size and flags.
func checkACK(t *testing.T, c *context.Context, received int, size int, flags header.TCPFlags) {
	t.Helper()
	checkSegment(t, c, 0, received, size, flags)
}

// checkSegment checks that the next packet follows the argument number of
// bytes sent and acknowledges the argument number of bytes received, with the
// argument payload size and flags.
func checkSegment(t *testing.T, c *context.Context, sent int, received int, size int, flags header.TCPFlags) {
	t.Helper()

	b := c.GetPacket()
	defer b.Release()

	checker.IPv4(t, b,
		checker.PayloadLen(header.TCPMinimumSize+size),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1+uint32(sent)),
			checker.TCPAckNum(uint32(context.TestInitialSequenceNumber)+1+uint32(received)),
			checker.TCPFlags(flags),
		),
	)
}

func TestDelayedACKDisabledByDefault(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	var opt tcpip.TCPDelayedACKOption
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("TransportProtocolOption(%d, &%T): %s", tcp.ProtocolNumber, opt, err)
	}

	if opt {
		t.Fatalf("got %T = %t, want = false", opt, opt)
	}
}

func TestImmediateACKWhenDisabled(t *testing.T) {
	c, _ := newConnected(t, false)
	defer c.Cleanup()

	sendData(c, 0, 0)
	checkACK(t, c, payloadSize, 0, header.TCPFlagAck)
	respond(t, c, payloadSize, 0)

	// still immediate after a request/response exchange
	sendData(c, payloadSize, responseSize)
	checkSegment(t, c, responseSize, 2*payloadSize, 0, header.TCPFlagAck)
}

func TestImmediateACKWhenNotInteractive(t *testing.T) {
	c, _ := newConnected(t, true)
	defer c.Cleanup()

	// no data sent, as by a bulk transfer receiver
	sendData(c, 0, 0)
	checkACK(t, c, payloadSize, 0, header.TCPFlagAck)
}

func TestDelayedACKTimeout(t *testing.T) {
	c, clock := newInteractive(t)
	defer c.Cleanup()

	sendData(c, payloadSize, responseSize)
	c.CheckNoPacketTimeout("acknowledgment not delayed", noPacketWait)

	clock.Advance(delayedACKTimeout - time.Millisecond)
	c.CheckNoPacketTimeout("acknowledgment sent before the delay", noPacketWait)

	clock.Advance(time.Millisecond)
	checkSegment(t, c, responseSize, 2*payloadSize, 0, header.TCPFlagAck)

	// the acknowledgment had to be sent alone, the connection is no longer
	// interactive
	sendData(c, 2*payloadSize, responseSize)
	checkSegment(t, c, responseSize, 3*payloadSize, 0, header.TCPFlagAck)
}

func TestDelayedACKSentWithData(t *testing.T) {
	c, clock := newInteractive(t)
	defer c.Cleanup()

	sendData(c, payloadSize, responseSize)
	c.CheckNoPacketTimeout("acknowledgment not delayed", noPacketWait)

	// the response carries the acknowledgment
	respond(t, c, 2*payloadSize, responseSize)

	clock.Advance(delayedACKTimeout)
	c.CheckNoPacketTimeout("acknowledgment sent again after the delay", noPacketWait)
}

func TestDelayedACKSecondSegment(t *testing.T) {
	c, _ := newInteractive(t)
	defer c.Cleanup()

	sendData(c, payloadSize, responseSize)
	c.CheckNoPacketTimeout("acknowledgment not delayed", noPacketWait)

	// more than one full-sized segment unacknowledged
	sendData(c, 2*payloadSize, responseSize)
	checkSegment(t, c, responseSize, 3*payloadSize, 0, header.TCPFlagAck)
}

func TestDelayedACKOutOfOrder(t *testing.T) {
	c, _ := newInteractive(t)
	defer c.Cleanup()

	sendData(c, payloadSize, responseSize)
	c.CheckNoPacketTimeout("acknowledgment not delayed", noPacketWait)

	// out of order segment, after a missing byte
	sendData(c, 2*payloadSize+1, responseSize)
	checkSegment(t, c, responseSize, 2*payloadSize, 0, header.TCPFlagAck)

	// the missing byte fills the gap, less than a full-sized segment is
	// unacknowledged (RFC 5681, section 4.2)
	sendBytes(c, 2*payloadSize, 1, responseSize)
	checkSegment(t, c, responseSize, 3*payloadSize+1, 0, header.TCPFlagAck)
}
