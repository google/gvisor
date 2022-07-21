// Copyright 2022 The gVisor Authors.
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

// Package e2e contains definitions common to all e2e tcp tests.
package e2e

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// DefaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	DefaultMTU = 65535

	// DefaultIPv4MSS is the MSS sent by the network stack in SYN/SYN-ACK for an
	// IPv4 endpoint when the MTU is set to defaultMTU in the test.
	DefaultIPv4MSS = DefaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize

	// TSOptionSize is the size in bytes of the TCP timestamp option.
	TSOptionSize = 12

	// MaxTCPOptionSize is the maximum size TCP Options in a TCP header.
	MaxTCPOptionSize = 40
)

// CheckBrokenUpWrite does a large write > than the specified maxPayload and
// verifies that the received packets carry the expected payload and
// that the large write was broken up into > 1 packet.
func CheckBrokenUpWrite(t *testing.T, c *context.Context, maxPayload int) {
	payloadMultiplier := 10
	dataLen := payloadMultiplier * maxPayload
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(i)
	}

	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received in chunks.
	bytesReceived := 0
	numPackets := 0
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for bytesReceived != dataLen {
		v := c.GetPacket()
		defer v.Release()
		numPackets++
		tcpHdr := header.TCP(header.IPv4(v.AsSlice()).Payload())
		payloadLen := len(tcpHdr.Payload())
		checker.IPv4(t, v,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1+uint32(bytesReceived)),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			),
		)

		pdata := data[bytesReceived : bytesReceived+payloadLen]
		if p := tcpHdr.Payload(); !bytes.Equal(pdata, p) {
			t.Fatalf("got data = %v, want = %v", p, pdata)
		}
		bytesReceived += payloadLen
		var options []byte
		if c.TimeStampEnabled {
			// If timestamp option is enabled, echo back the timestamp and increment
			// the TSEcr value included in the packet and send that back as the TSVal.
			parsedOpts := tcpHdr.ParsedOptions()
			tsOpt := [12]byte{header.TCPOptionNOP, header.TCPOptionNOP}
			header.EncodeTSOption(parsedOpts.TSEcr+1, parsedOpts.TSVal, tsOpt[2:])
			options = tsOpt[:]
		}
		// Acknowledge the data.
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss,
			AckNum:  c.IRS.Add(1 + seqnum.Size(bytesReceived)),
			RcvWnd:  30000,
			TCPOpts: options,
		})
	}
	if numPackets == 1 {
		t.Fatalf("expected write to be broken up into multiple packets, but got 1 packet")
	}
}

// CreateConnectedWithSACKPermittedOption creates and connects c.ep with the
// SACKPermitted option enabled if the stack in the context has the SACK support
// enabled.
func CreateConnectedWithSACKPermittedOption(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptionsNoDelay(header.TCPSynOptions{SACKPermitted: c.SACKEnabled()})
}

// CreateConnectedWithSACKAndTS creates and connects c.ep with the SACK & TS
// option enabled if the stack in the context has SACK and TS enabled.
func CreateConnectedWithSACKAndTS(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptionsNoDelay(header.TCPSynOptions{SACKPermitted: c.SACKEnabled(), TS: true})
}

// SetStackSACKPermitted sets the tcpip.TCPSACKEnabled option of the context stack to
// enabled value.
func SetStackSACKPermitted(t *testing.T, c *context.Context, enable bool) {
	t.Helper()
	opt := tcpip.TCPSACKEnabled(enable)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}
}

// SetStackTCPRecovery sets the tcpip.TCPRecovery option of the context stack to
// the specified recovery value.
func SetStackTCPRecovery(t *testing.T, c *context.Context, recovery int) {
	t.Helper()
	opt := tcpip.TCPRecovery(recovery)
	if err := c.Stack().SetTransportProtocolOption(header.TCPProtocolNumber, &opt); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(%d, &%v(%v)): %s", header.TCPProtocolNumber, opt, opt, err)
	}
}

// SendAndReceiveWithSACK creates a SACK enabled connection w/ RACK enabled if
// enableRACK is true. It then proceeds to write a large payload and verifies
// that numPackets were received.
func SendAndReceiveWithSACK(t *testing.T, c *context.Context, maxPayload int, numPackets int, enableRACK bool) []byte {
	SetStackSACKPermitted(t, c, true)
	if !enableRACK {
		SetStackTCPRecovery(t, c, 0)
	}
	// The delay should be below initial RTO (1s) otherwise retransimission
	// will start. Choose a relatively large value so that estimated RTT
	// keeps high even after a few rounds of undelayed RTT samples.
	c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled(), TS: true}, 800*time.Millisecond /* delay */)

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

	bytesRead := 0
	for i := 0; i < numPackets; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, TSOptionSize)
		bytesRead += maxPayload
	}

	return data
}

// EnableCUBIC sets the CUBIC congestion control as the default congestion
// control algorithm for all newly created endpoints in the context stack.
func EnableCUBIC(t *testing.T, c *context.Context) {
	t.Helper()
	opt := tcpip.CongestionControlOption("cubic")
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%s)) %s", tcp.ProtocolNumber, opt, opt, err)
	}
}

// TestV4Connect establishes an IPv4 Connection with the context stack.
func TestV4Connect(t *testing.T, c *context.Context, checkers ...checker.NetworkChecker) {
	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)

	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV4MappedAddr, Port: context.TestPort})
	if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
		t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
	}

	// Receive SYN packet.
	v := c.GetPacket()
	defer v.Release()
	synCheckers := append(checkers, checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn),
	))
	checker.IPv4(t, v, synCheckers...)

	tcp := header.TCP(header.IPv4(v.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: tcp.DestinationPort(),
		DstPort: tcp.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK packet.
	ackCheckers := append(checkers, checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(c.IRS)+1),
		checker.TCPAckNum(uint32(iss)+1),
	))

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, ackCheckers...)

	// Wait for connection to be established.
	select {
	case <-ch:
		if err := c.EP.LastError(); err != nil {
			t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
}

// TestV6Connect establishes an IPv6 Connection with the context stack.
func TestV6Connect(t *testing.T, c *context.Context, checkers ...checker.NetworkChecker) {
	// Start connection attempt to IPv6 address.
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	c.WQ.EventRegister(&we)
	defer c.WQ.EventUnregister(&we)

	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestV6Addr, Port: context.TestPort})
	if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
		t.Fatalf("Connect(...) mismatch (-want +got):\n%s", d)
	}

	// Receive SYN packet.
	v := c.GetV6Packet()
	defer v.Release()
	synCheckers := append(checkers, checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn),
	))
	checker.IPv6(t, v, synCheckers...)

	tcp := header.TCP(header.IPv6(v.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: tcp.DestinationPort(),
		DstPort: tcp.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK packet.
	ackCheckers := append(checkers, checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(c.IRS)+1),
		checker.TCPAckNum(uint32(iss)+1),
	))
	v = c.GetV6Packet()
	defer v.Release()
	checker.IPv6(t, v, ackCheckers...)

	// Wait for connection to be established.
	select {
	case <-ch:
		if err := c.EP.LastError(); err != nil {
			t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
}
