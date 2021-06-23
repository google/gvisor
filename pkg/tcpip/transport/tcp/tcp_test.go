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
	"io/ioutil"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	tcpiptestutil "gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/waiter"
)

// endpointTester provides helper functions to test a tcpip.Endpoint.
type endpointTester struct {
	ep tcpip.Endpoint
}

// CheckReadError issues a read to the endpoint and checking for an error.
func (e *endpointTester) CheckReadError(t *testing.T, want tcpip.Error) {
	t.Helper()
	res, got := e.ep.Read(ioutil.Discard, tcpip.ReadOptions{})
	if got != want {
		t.Fatalf("ep.Read = %s, want %s", got, want)
	}
	if diff := cmp.Diff(tcpip.ReadResult{}, res); diff != "" {
		t.Errorf("ep.Read: unexpected non-zero result (-want +got):\n%s", diff)
	}
}

// CheckRead issues a read to the endpoint and checking for a success, returning
// the data read.
func (e *endpointTester) CheckRead(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	res, err := e.ep.Read(&buf, tcpip.ReadOptions{})
	if err != nil {
		t.Fatalf("ep.Read = _, %s; want _, nil", err)
	}
	if diff := cmp.Diff(tcpip.ReadResult{
		Count: buf.Len(),
		Total: buf.Len(),
	}, res, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
		t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
	}
	return buf.Bytes()
}

// CheckReadFull reads from the endpoint for exactly count bytes.
func (e *endpointTester) CheckReadFull(t *testing.T, count int, notifyRead <-chan struct{}, timeout time.Duration) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tcpip.LimitedWriter{
		W: &buf,
		N: int64(count),
	}
	for w.N != 0 {
		_, err := e.ep.Read(&w, tcpip.ReadOptions{})
		if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
			// Wait for receive to be notified.
			select {
			case <-notifyRead:
			case <-time.After(timeout):
				t.Fatalf("Timed out waiting for data to arrive")
			}
			continue
		} else if err != nil {
			t.Fatalf("ep.Read = _, %s; want _, nil", err)
		}
	}
	return buf.Bytes()
}

const (
	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65535

	// defaultIPv4MSS is the MSS sent by the network stack in SYN/SYN-ACK for an
	// IPv4 endpoint when the MTU is set to defaultMTU in the test.
	defaultIPv4MSS = defaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize
)

func TestGiveUpConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	var wq waiter.Queue
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Register for notification, then start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventHUp)
	defer wq.EventUnregister(&waitEntry)

	{
		err := ep.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
			t.Fatalf("ep.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	// Close the connection, wait for completion.
	ep.Close()

	// Wait for ep to become writable.
	<-notifyCh

	// Call Connect again to retreive the handshake failure status
	// and stats updates.
	{
		err := ep.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrAborted{}, err); d != "" {
			t.Fatalf("ep.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	if got := c.Stack().Stats().TCP.FailedConnectionAttempts.Value(); got != 1 {
		t.Errorf("got stats.TCP.FailedConnectionAttempts.Value() = %d, want = 1", got)
	}

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}
}

// Test for ICMP error handling without completing handshake.
func TestConnectICMPError(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	var wq waiter.Queue
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventHUp)
	defer wq.EventUnregister(&waitEntry)

	{
		err := ep.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
			t.Fatalf("ep.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	syn := c.GetPacket()
	checker.IPv4(t, syn, checker.TCP(checker.TCPFlags(header.TCPFlagSyn)))

	wep := ep.(interface {
		StopWork()
		ResumeWork()
		LastErrorLocked() tcpip.Error
	})

	// Stop the protocol loop, ensure that the ICMP error is processed and
	// the last ICMP error is read before the loop is resumed. This sanity
	// tests the handshake completion logic on ICMP errors.
	wep.StopWork()

	c.SendICMPPacket(header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable, nil, syn, defaultMTU)

	for {
		if err := wep.LastErrorLocked(); err != nil {
			if d := cmp.Diff(&tcpip.ErrNoRoute{}, err); d != "" {
				t.Errorf("ep.LastErrorLocked() mismatch (-want +got):\n%s", d)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}

	wep.ResumeWork()

	<-notifyCh

	// The stack would have unregistered the endpoint because of the ICMP error.
	// Expect a RST for any subsequent packets sent to the endpoint.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(context.TestInitialSequenceNumber) + 1,
		AckNum:  c.IRS + 1,
	})

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(0),
		checker.TCPFlags(header.TCPFlagRst)))
}

func TestConnectIncrementActiveConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.ActiveConnectionOpenings.Value() + 1

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	if got := stats.TCP.ActiveConnectionOpenings.Value(); got != want {
		t.Errorf("got stats.TCP.ActtiveConnectionOpenings.Value() = %d, want = %d", got, want)
	}
}

func TestConnectDoesNotIncrementFailedConnectionAttempts(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.FailedConnectionAttempts.Value()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	if got := stats.TCP.FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got stats.TCP.FailedConnectionAttempts.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got EP stats.FailedConnectionAttempts = %d, want = %d", got, want)
	}
}

func TestActiveFailedConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	c.EP = ep
	want := stats.TCP.FailedConnectionAttempts.Value() + 1

	{
		err := c.EP.Connect(tcpip.FullAddress{NIC: 2, Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrNoRoute{}, err); d != "" {
			t.Errorf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	if got := stats.TCP.FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got stats.TCP.FailedConnectionAttempts.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got EP stats FailedConnectionAttempts = %d, want = %d", got, want)
	}
}

func TestCloseWithoutConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	c.EP.Close()

	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

func TestTCPSegmentsSentIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	// SYN and ACK
	want := stats.TCP.SegmentsSent.Value() + 2
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	if got := stats.TCP.SegmentsSent.Value(); got != want {
		t.Errorf("got stats.TCP.SegmentsSent.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).SegmentsSent.Value(); got != want {
		t.Errorf("got EP stats SegmentsSent.Value() = %d, want = %d", got, want)
	}
}

func TestTCPResetsSentIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	stats := c.Stack().Stats()
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	want := stats.TCP.SegmentsSent.Value() + 1

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		// If the AckNum is not the increment of the last sequence number, a RST
		// segment is sent back in response.
		AckNum: c.IRS + 2,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	c.GetPacket()

	metricPollFn := func() error {
		if got := stats.TCP.ResetsSent.Value(); got != want {
			return fmt.Errorf("got stats.TCP.ResetsSent.Value() = %d, want = %d", got, want)
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestTCPResetsSentNoICMP confirms that we don't get an ICMP
// DstUnreachable packet when we try send a packet which is not part
// of an active session.
func TestTCPResetsSentNoICMP(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	stats := c.Stack().Stats()

	// Send a SYN request for a closed port. This should elicit an RST
	// but NOT an ICMPv4 DstUnreachable packet.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
	})

	// Receive whatever comes back.
	b := c.GetPacket()
	ipHdr := header.IPv4(b)
	if got, want := ipHdr.Protocol(), uint8(header.TCPProtocolNumber); got != want {
		t.Errorf("unexpected protocol, got = %d, want = %d", got, want)
	}

	// Read outgoing ICMP stats and check no ICMP DstUnreachable was recorded.
	sent := stats.ICMP.V4.PacketsSent
	if got, want := sent.DstUnreachable.Value(), uint64(0); got != want {
		t.Errorf("got ICMP DstUnreachable.Value() = %d, want = %d", got, want)
	}
}

// TestTCPResetSentForACKWhenNotUsingSynCookies checks that the stack generates
// a RST if an ACK is received on the listening socket for which there is no
// active handshake in progress and we are not using SYN cookies.
func TestTCPResetSentForACKWhenNotUsingSynCookies(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPLingerTimeout to 5 seconds so that sockets are marked closed
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Lower stackwide TIME_WAIT timeout so that the reservations
	// are released instantly on Close.
	tcpTW := tcpip.TCPTimeWaitTimeoutOption(1 * time.Millisecond)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTW); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, tcpTW, tcpTW, err)
	}

	c.EP.Close()
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))
	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	c.GetPacket()

	// Since an active close was done we need to wait for a little more than
	// tcpLingerTimeout for the port reservations to be released and the
	// socket to move to a CLOSED state.
	time.Sleep(20 * time.Millisecond)

	// Now resend the same ACK, this ACK should generate a RST as there
	// should be no endpoint in SYN-RCVD state and we are not using
	// syn-cookies yet. The reason we send the same ACK is we need a valid
	// cookie(IRS) generated by the netstack without which the ACK will be
	// rejected.
	c.SendPacket(nil, ackHeaders)

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(0),
		checker.TCPFlags(header.TCPFlagRst)))
}

func TestTCPResetsReceivedIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.ResetsReceived.Value() + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	rcvWnd := seqnum.Size(30000)
	c.CreateConnected(iss, rcvWnd, -1 /* epRcvBuf */)

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		SeqNum:  iss.Add(1),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  rcvWnd,
		Flags:   header.TCPFlagRst,
	})

	if got := stats.TCP.ResetsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.ResetsReceived.Value() = %d, want = %d", got, want)
	}
}

func TestTCPResetsDoNotGenerateResets(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.ResetsReceived.Value() + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	rcvWnd := seqnum.Size(30000)
	c.CreateConnected(iss, rcvWnd, -1 /* epRcvBuf */)

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		SeqNum:  iss.Add(1),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  rcvWnd,
		Flags:   header.TCPFlagRst,
	})

	if got := stats.TCP.ResetsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.ResetsReceived.Value() = %d, want = %d", got, want)
	}
	c.CheckNoPacketTimeout("got an unexpected packet", 100*time.Millisecond)
}

func TestActiveHandshake(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
}

func TestNonBlockingClose(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	ep := c.EP
	c.EP = nil

	// Close the endpoint and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		t.Fatalf("Took too long to close: %s", diff)
	}
}

func TestConnectResetAfterClose(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPLinger to 3 seconds so that sockets are marked closed
	// after 3 second in FIN_WAIT2 state.
	tcpLingerTimeout := 3 * time.Second
	opt := tcpip.TCPLingerTimeoutOption(tcpLingerTimeout)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	ep := c.EP
	c.EP = nil

	// Close the endpoint, make sure we get a FIN segment, then acknowledge
	// to complete closure of sender, but don't send our own FIN.
	ep.Close()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Wait for the ep to give up waiting for a FIN.
	time.Sleep(tcpLingerTimeout + 1*time.Second)

	// Now send an ACK and it should trigger a RST as the endpoint should
	// not exist anymore.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	for {
		b := c.GetPacket()
		tcpHdr := header.TCP(header.IPv4(b).Payload())
		if tcpHdr.Flags() == header.TCPFlagAck|header.TCPFlagFin {
			// This is a retransmit of the FIN, ignore it.
			continue
		}

		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				// RST is always generated with sndNxt which if the FIN
				// has been sent will be 1 higher than the sequence number
				// of the FIN itself.
				checker.TCPSeqNum(uint32(c.IRS)+2),
				checker.TCPAckNum(0),
				checker.TCPFlags(header.TCPFlagRst),
			),
		)
		break
	}
}

// TestCurrentConnectedIncrement tests increment of the current
// established and connected counters.
func TestCurrentConnectedIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPTimeWaitTimeout to 1 seconds so that sockets are marked closed
	// after 1 second in TIME_WAIT state.
	tcpTimeWaitTimeout := 1 * time.Second
	opt := tcpip.TCPTimeWaitTimeoutOption(tcpTimeWaitTimeout)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	ep := c.EP
	c.EP = nil

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 1 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 1", got)
	}
	gotConnected := c.Stack().Stats().TCP.CurrentConnected.Value()
	if gotConnected != 1 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 1", gotConnected)
	}

	ep.Close()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != gotConnected {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = %d", got, gotConnected)
	}

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+2),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Wait for a little more than the TIME-WAIT duration for the socket to
	// transition to CLOSED state.
	time.Sleep(1200 * time.Millisecond)

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

// TestClosingWithEnqueuedSegments tests handling of still enqueued segments
// when the endpoint transitions to StateClose. The in-flight segments would be
// re-enqueued to a any listening endpoint.
func TestClosingWithEnqueuedSegments(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	ep := c.EP
	c.EP = nil

	if got, want := tcp.EndpointState(ep.State()), tcp.StateEstablished; got != want {
		t.Errorf("unexpected endpoint state: want %d, got %d", want, got)
	}

	// Send a FIN for ESTABLISHED --> CLOSED-WAIT
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagFin | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Get the ACK for the FIN we sent.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Give the stack a few ms to transition the endpoint out of ESTABLISHED
	// state.
	time.Sleep(10 * time.Millisecond)

	if got, want := tcp.EndpointState(ep.State()), tcp.StateCloseWait; got != want {
		t.Errorf("unexpected endpoint state: want %d, got %d", want, got)
	}

	// Close the application endpoint for CLOSE_WAIT --> LAST_ACK
	ep.Close()

	// Get the FIN
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	if got, want := tcp.EndpointState(ep.State()), tcp.StateLastAck; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// Pause the endpoint`s protocolMainLoop.
	ep.(interface{ StopWork() }).StopWork()

	// Enqueue last ACK followed by an ACK matching the endpoint
	//
	// Send Last ACK for LAST_ACK --> CLOSED
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(1),
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Send a packet with ACK set, this would generate RST when
	// not using SYN cookies as in this test.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss.Add(2),
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Unpause endpoint`s protocolMainLoop.
	ep.(interface{ ResumeWork() }).ResumeWork()

	// Wait for the protocolMainLoop to resume and update state.
	time.Sleep(10 * time.Millisecond)

	// Expect the endpoint to be closed.
	if got, want := tcp.EndpointState(ep.State()), tcp.StateClose; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	if got := c.Stack().Stats().TCP.EstablishedClosed.Value(); got != 1 {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedClosed = %d, want = 1", got)
	}

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}

	// Check if the endpoint was moved to CLOSED and netstack a reset in
	// response to the ACK packet that we sent after last-ACK.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+2),
			checker.TCPAckNum(0),
			checker.TCPFlags(header.TCPFlagRst),
		),
	)
}

func TestSimpleReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}

	data := []byte{1, 2, 3}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Receive data.
	v := ept.CheckRead(t)
	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	// Check that ACK is received.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

// TestUserSuppliedMSSOnConnect tests that the user supplied MSS is used when
// creating a new active TCP socket. It should be present in the sent TCP
// SYN segment.
func TestUserSuppliedMSSOnConnect(t *testing.T) {
	const mtu = 5000

	ips := []struct {
		name        string
		createEP    func(*context.Context)
		connectAddr tcpip.Address
		checker     func(*testing.T, *context.Context, uint16, int)
		maxMSS      uint16
	}{
		{
			name: "IPv4",
			createEP: func(c *context.Context) {
				c.Create(-1)
			},
			connectAddr: context.TestAddr,
			checker: func(t *testing.T, c *context.Context, mss uint16, ws int) {
				checker.IPv4(t, c.GetPacket(), checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagSyn),
					checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: ws})))
			},
			maxMSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize,
		},
		{
			name: "IPv6",
			createEP: func(c *context.Context) {
				c.CreateV6Endpoint(true)
			},
			connectAddr: context.TestV6Addr,
			checker: func(t *testing.T, c *context.Context, mss uint16, ws int) {
				checker.IPv6(t, c.GetV6Packet(), checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagSyn),
					checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: ws})))
			},
			maxMSS: mtu - header.IPv6MinimumSize - header.TCPMinimumSize,
		},
	}

	for _, ip := range ips {
		t.Run(ip.name, func(t *testing.T) {
			tests := []struct {
				name   string
				setMSS uint16
				expMSS uint16
			}{
				{
					name:   "EqualToMaxMSS",
					setMSS: ip.maxMSS,
					expMSS: ip.maxMSS,
				},
				{
					name:   "LessThanMaxMSS",
					setMSS: ip.maxMSS - 1,
					expMSS: ip.maxMSS - 1,
				},
				{
					name:   "GreaterThanMaxMSS",
					setMSS: ip.maxMSS + 1,
					expMSS: ip.maxMSS,
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					c := context.New(t, mtu)
					defer c.Cleanup()

					ip.createEP(c)

					// Set the MSS socket option.
					if err := c.EP.SetSockOptInt(tcpip.MaxSegOption, int(test.setMSS)); err != nil {
						t.Fatalf("SetSockOptInt(MaxSegOption, %d): %s", test.setMSS, err)
					}

					// Get expected window size.
					rcvBufSize := c.EP.SocketOptions().GetReceiveBufferSize()
					ws := tcp.FindWndScale(seqnum.Size(rcvBufSize))

					connectAddr := tcpip.FullAddress{Addr: ip.connectAddr, Port: context.TestPort}
					{
						err := c.EP.Connect(connectAddr)
						if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
							t.Fatalf("Connect(%+v) mismatch (-want +got):\n%s", connectAddr, d)
						}
					}

					// Receive SYN packet with our user supplied MSS.
					ip.checker(t, c, test.expMSS, ws)
				})
			}
		})
	}
}

// TestUserSuppliedMSSOnListenAccept tests that the user supplied MSS is used
// when completing the handshake for a new TCP connection from a TCP
// listening socket. It should be present in the sent TCP SYN-ACK segment.
func TestUserSuppliedMSSOnListenAccept(t *testing.T) {
	const mtu = 5000

	ips := []struct {
		name     string
		createEP func(*context.Context)
		sendPkt  func(*context.Context, *context.Headers)
		checker  func(*testing.T, *context.Context, uint16, uint16)
		maxMSS   uint16
	}{
		{
			name: "IPv4",
			createEP: func(c *context.Context) {
				c.Create(-1)
			},
			sendPkt: func(c *context.Context, h *context.Headers) {
				c.SendPacket(nil, h)
			},
			checker: func(t *testing.T, c *context.Context, srcPort, mss uint16) {
				checker.IPv4(t, c.GetPacket(), checker.TCP(
					checker.DstPort(srcPort),
					checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
					checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: -1})))
			},
			maxMSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize,
		},
		{
			name: "IPv6",
			createEP: func(c *context.Context) {
				c.CreateV6Endpoint(false)
			},
			sendPkt: func(c *context.Context, h *context.Headers) {
				c.SendV6Packet(nil, h)
			},
			checker: func(t *testing.T, c *context.Context, srcPort, mss uint16) {
				checker.IPv6(t, c.GetV6Packet(), checker.TCP(
					checker.DstPort(srcPort),
					checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
					checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: -1})))
			},
			maxMSS: mtu - header.IPv6MinimumSize - header.TCPMinimumSize,
		},
	}

	for _, ip := range ips {
		t.Run(ip.name, func(t *testing.T) {
			tests := []struct {
				name   string
				setMSS uint16
				expMSS uint16
			}{
				{
					name:   "EqualToMaxMSS",
					setMSS: ip.maxMSS,
					expMSS: ip.maxMSS,
				},
				{
					name:   "LessThanMaxMSS",
					setMSS: ip.maxMSS - 1,
					expMSS: ip.maxMSS - 1,
				},
				{
					name:   "GreaterThanMaxMSS",
					setMSS: ip.maxMSS + 1,
					expMSS: ip.maxMSS,
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					c := context.New(t, mtu)
					defer c.Cleanup()

					ip.createEP(c)

					if err := c.EP.SetSockOptInt(tcpip.MaxSegOption, int(test.setMSS)); err != nil {
						t.Fatalf("SetSockOptInt(MaxSegOption, %d): %s", test.setMSS, err)
					}

					bindAddr := tcpip.FullAddress{Port: context.StackPort}
					if err := c.EP.Bind(bindAddr); err != nil {
						t.Fatalf("Bind(%+v): %s:", bindAddr, err)
					}

					backlog := 5
					// Keep the number of client requests twice to the backlog
					// such that half of the connections do not use syncookies
					// and the other half does.
					clientConnects := backlog * 2

					if err := c.EP.Listen(backlog); err != nil {
						t.Fatalf("Listen(%d): %s:", backlog, err)
					}

					for i := 0; i < clientConnects; i++ {
						// Send a SYN requests.
						iss := seqnum.Value(i)
						srcPort := context.TestPort + uint16(i)
						ip.sendPkt(c, &context.Headers{
							SrcPort: srcPort,
							DstPort: context.StackPort,
							Flags:   header.TCPFlagSyn,
							SeqNum:  iss,
						})

						// Receive the SYN-ACK reply.
						ip.checker(t, c, srcPort, test.expMSS)
					}
				})
			}
		})
	}
}
func TestSendRstOnListenerRxSynAckV4(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  100,
		AckNum:  200,
	})

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst),
		checker.TCPSeqNum(200)))
}

func TestSendRstOnListenerRxSynAckV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	c.SendV6Packet(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  100,
		AckNum:  200,
	})

	checker.IPv6(t, c.GetV6Packet(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst),
		checker.TCPSeqNum(200)))
}

// TestTCPAckBeforeAcceptV4 tests that once the 3-way handshake is complete,
// peers can send data and expect a response within a reasonable ammount of time
// without calling Accept on the listening endpoint first.
//
// This test uses IPv4.
func TestTCPAckBeforeAcceptV4(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	irs, iss := executeHandshake(t, c, context.TestPort, false /* synCookiesInUse */)

	// Send data before accepting the connection.
	c.SendPacket([]byte{1, 2, 3, 4}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
	})

	// Receive ACK for the data we sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))
}

// TestTCPAckBeforeAcceptV6 tests that once the 3-way handshake is complete,
// peers can send data and expect a response within a reasonable ammount of time
// without calling Accept on the listening endpoint first.
//
// This test uses IPv6.
func TestTCPAckBeforeAcceptV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	irs, iss := executeV6Handshake(t, c, context.TestPort, false /* synCookiesInUse */)

	// Send data before accepting the connection.
	c.SendV6Packet([]byte{1, 2, 3, 4}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
	})

	// Receive ACK for the data we sent.
	checker.IPv6(t, c.GetV6Packet(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))
}

func TestSendRstOnListenerRxAckV4(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1 /* epRcvBuf */)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10 /* backlog */); err != nil {
		t.Fatal("Listen failed:", err)
	}

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagFin | header.TCPFlagAck,
		SeqNum:  100,
		AckNum:  200,
	})

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst),
		checker.TCPSeqNum(200)))
}

func TestSendRstOnListenerRxAckV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(true /* v6Only */)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10 /* backlog */); err != nil {
		t.Fatal("Listen failed:", err)
	}

	c.SendV6Packet(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagFin | header.TCPFlagAck,
		SeqNum:  100,
		AckNum:  200,
	})

	checker.IPv6(t, c.GetV6Packet(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst),
		checker.TCPSeqNum(200)))
}

// TestListenShutdown tests for the listening endpoint replying with RST
// on read shutdown.
func TestListenShutdown(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1 /* epRcvBuf */)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(1 /* backlog */); err != nil {
		t.Fatal("Listen failed:", err)
	}

	if err := c.EP.Shutdown(tcpip.ShutdownRead); err != nil {
		t.Fatal("Shutdown failed:", err)
	}

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  100,
		AckNum:  200,
	})

	// Expect the listening endpoint to reset the connection.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
		))
}

var _ waiter.EntryCallback = (callback)(nil)

type callback func(*waiter.Entry, waiter.EventMask)

func (cb callback) Callback(entry *waiter.Entry, mask waiter.EventMask) {
	cb(entry, mask)
}

func TestListenerReadinessOnEvent(t *testing.T) {
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	{
		ep := loopback.New()
		if testing.Verbose() {
			ep = sniffer.New(ep)
		}
		const id = 1
		if err := s.CreateNIC(id, ep); err != nil {
			t.Fatalf("CreateNIC(%d, %T): %s", id, ep, err)
		}
		if err := s.AddAddress(id, ipv4.ProtocolNumber, context.StackAddr); err != nil {
			t.Fatalf("AddAddress(%d, ipv4.ProtocolNumber, %s): %s", id, context.StackAddr, err)
		}
		s.SetRouteTable([]tcpip.Route{
			{Destination: header.IPv4EmptySubnet, NIC: id},
		})
	}

	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, _): %s", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Addr: context.StackAddr}); err != nil {
		t.Fatalf("Bind(%s): %s", context.StackAddr, err)
	}
	const backlog = 1
	if err := ep.Listen(backlog); err != nil {
		t.Fatalf("Listen(%d): %s", backlog, err)
	}

	address, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("GetLocalAddress(): %s", err)
	}

	conn, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, _): %s", err)
	}
	defer conn.Close()

	events := make(chan waiter.EventMask)
	// Scope `entry` to allow a binding of the same name below.
	{
		entry := waiter.Entry{Callback: callback(func(_ *waiter.Entry, mask waiter.EventMask) {
			events <- ep.Readiness(mask)
		})}
		wq.EventRegister(&entry, waiter.EventIn)
		defer wq.EventUnregister(&entry)
	}

	entry, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&entry, waiter.EventOut)
	defer wq.EventUnregister(&entry)

	switch err := conn.Connect(address).(type) {
	case *tcpip.ErrConnectStarted:
	default:
		t.Fatalf("Connect(%#v): %v", address, err)
	}

	// Read at least one event.
	got := <-events
	for {
		select {
		case event := <-events:
			got |= event
			continue
		case <-ch:
			if want := waiter.ReadableEvents; got != want {
				t.Errorf("observed events = %b, want %b", got, want)
			}
		}
		break
	}
}

// TestListenCloseWhileConnect tests for the listening endpoint to
// drain the accept-queue when closed. This should reset all of the
// pending connections that are waiting to be accepted.
func TestListenCloseWhileConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1 /* epRcvBuf */)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(1 /* backlog */); err != nil {
		t.Fatal("Listen failed:", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&waitEntry)

	executeHandshake(t, c, context.TestPort, false /* synCookiesInUse */)
	// Wait for the new endpoint created because of handshake to be delivered
	// to the listening endpoint's accept queue.
	<-notifyCh

	// Close the listening endpoint.
	c.EP.Close()

	// Expect the listening endpoint to reset the connection.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
		))
}

func TestTOSV4(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	c.EP = ep

	const tos = 0xC0
	if err := c.EP.SetSockOptInt(tcpip.IPv4TOSOption, tos); err != nil {
		t.Errorf("SetSockOptInt(IPv4TOSOption, %d) failed: %s", tos, err)
	}

	v, err := c.EP.GetSockOptInt(tcpip.IPv4TOSOption)
	if err != nil {
		t.Errorf("GetSockoptInt(IPv4TOSOption) failed: %s", err)
	}

	if v != tos {
		t.Errorf("got GetSockOptInt(IPv4TOSOption) = %d, want = %d", v, tos)
	}

	testV4Connect(t, c, checker.TOS(tos, 0))

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)), // Acknum is initial sequence number + 1
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
		checker.TOS(tos, 0),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(data, p) {
		t.Errorf("got data = %x, want = %x", p, data)
	}
}

func TestTrafficClassV6(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateV6Endpoint(false)

	const tos = 0xC0
	if err := c.EP.SetSockOptInt(tcpip.IPv6TrafficClassOption, tos); err != nil {
		t.Errorf("SetSockOpInt(IPv6TrafficClassOption, %d) failed: %s", tos, err)
	}

	v, err := c.EP.GetSockOptInt(tcpip.IPv6TrafficClassOption)
	if err != nil {
		t.Fatalf("GetSockoptInt(IPv6TrafficClassOption) failed: %s", err)
	}

	if v != tos {
		t.Errorf("got GetSockOptInt(IPv6TrafficClassOption) = %d, want = %d", v, tos)
	}

	// Test the connection request.
	testV6Connect(t, c, checker.TOS(tos, 0))

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received.
	b := c.GetV6Packet()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv6(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
		checker.TOS(tos, 0),
	)

	if p := b[header.IPv6MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(data, p) {
		t.Errorf("got data = %x, want = %x", p, data)
	}
}

func TestConnectBindToDevice(t *testing.T) {
	for _, test := range []struct {
		name   string
		device tcpip.NICID
		want   tcp.EndpointState
	}{
		{"RightDevice", 1, tcp.StateEstablished},
		{"WrongDevice", 2, tcp.StateSynSent},
		{"AnyDevice", 0, tcp.StateEstablished},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.Create(-1)
			if err := c.EP.SocketOptions().SetBindToDevice(int32(test.device)); err != nil {
				t.Fatalf("c.EP.SetSockOpt(&%T(%d)): %s", test.device, test.device, err)
			}
			// Start connection attempt.
			waitEntry, _ := waiter.NewChannelEntry(nil)
			c.WQ.EventRegister(&waitEntry, waiter.WritableEvents)
			defer c.WQ.EventUnregister(&waitEntry)

			err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
			if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
				t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
			}

			// Receive SYN packet.
			b := c.GetPacket()
			checker.IPv4(t, b,
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagSyn),
				),
			)
			if got, want := tcp.EndpointState(c.EP.State()), tcp.StateSynSent; got != want {
				t.Fatalf("unexpected endpoint state: want %s, got %s", want, got)
			}
			tcpHdr := header.TCP(header.IPv4(b).Payload())
			c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

			iss := seqnum.Value(context.TestInitialSequenceNumber)
			rcvWnd := seqnum.Size(30000)
			c.SendPacket(nil, &context.Headers{
				SrcPort: tcpHdr.DestinationPort(),
				DstPort: tcpHdr.SourcePort(),
				Flags:   header.TCPFlagSyn | header.TCPFlagAck,
				SeqNum:  iss,
				AckNum:  c.IRS.Add(1),
				RcvWnd:  rcvWnd,
				TCPOpts: nil,
			})

			c.GetPacket()
			if got, want := tcp.EndpointState(c.EP.State()), test.want; got != want {
				t.Fatalf("unexpected endpoint state: want %s, got %s", want, got)
			}
		})
	}
}

func TestSynSent(t *testing.T) {
	for _, test := range []struct {
		name  string
		reset bool
	}{
		{"RstOnSynSent", true},
		{"CloseOnSynSent", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			// Create an endpoint, don't handshake because we want to interfere with the
			// handshake process.
			c.Create(-1)

			// Start connection attempt.
			waitEntry, ch := waiter.NewChannelEntry(nil)
			c.WQ.EventRegister(&waitEntry, waiter.EventHUp)
			defer c.WQ.EventUnregister(&waitEntry)

			addr := tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort}
			err := c.EP.Connect(addr)
			if d := cmp.Diff(err, &tcpip.ErrConnectStarted{}); d != "" {
				t.Fatalf("Connect(...) mismatch (-want +got):\n%s", d)
			}

			// Receive SYN packet.
			b := c.GetPacket()
			checker.IPv4(t, b,
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagSyn),
				),
			)

			if got, want := tcp.EndpointState(c.EP.State()), tcp.StateSynSent; got != want {
				t.Fatalf("got State() = %s, want %s", got, want)
			}
			tcpHdr := header.TCP(header.IPv4(b).Payload())
			c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

			if test.reset {
				// Send a packet with a proper ACK and a RST flag to cause the socket
				// to error and close out.
				iss := seqnum.Value(context.TestInitialSequenceNumber)
				rcvWnd := seqnum.Size(30000)
				c.SendPacket(nil, &context.Headers{
					SrcPort: tcpHdr.DestinationPort(),
					DstPort: tcpHdr.SourcePort(),
					Flags:   header.TCPFlagRst | header.TCPFlagAck,
					SeqNum:  iss,
					AckNum:  c.IRS.Add(1),
					RcvWnd:  rcvWnd,
					TCPOpts: nil,
				})
			} else {
				c.EP.Close()
			}

			// Wait for receive to be notified.
			select {
			case <-ch:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for packet to arrive")
			}

			ept := endpointTester{c.EP}
			if test.reset {
				ept.CheckReadError(t, &tcpip.ErrConnectionRefused{})
			} else {
				ept.CheckReadError(t, &tcpip.ErrAborted{})
			}

			if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
				t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
			}

			// Due to the RST the endpoint should be in an error state.
			if got, want := tcp.EndpointState(c.EP.State()), tcp.StateError; got != want {
				t.Fatalf("got State() = %s, want %s", got, want)
			}
		})
	}
}

func TestOutOfOrderReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Send second half of data first, with seqnum 3 ahead of expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data[3:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(3),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that we get an ACK specifying which seqnum is expected.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Wait 200ms and check that no data has been received.
	time.Sleep(200 * time.Millisecond)
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Send the first 3 bytes now.
	c.SendPacket(data[:3], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive data.
	read := ept.CheckReadFull(t, 6, ch, 5*time.Second)

	// Check that we received the data in proper order.
	if !bytes.Equal(data, read) {
		t.Fatalf("got data = %v, want = %v", read, data)
	}

	// Check that the whole data is acknowledged.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestOutOfOrderFlood(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	rcvBufSz := math.MaxUint16
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, rcvBufSz)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Send 100 packets before the actual one that is expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for i := 0; i < 100; i++ {
		c.SendPacket(data[3:], &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(6),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})

		checker.IPv4(t, c.GetPacket(),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Send packet with seqnum as initial + 3. It must be discarded because the
	// out-of-order buffer was filled by the previous packets.
	c.SendPacket(data[3:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(3),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Now send the expected packet with initial sequence number.
	c.SendPacket(data[:3], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that only packet with initial sequence number is acknowledged.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+3),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestRstOnCloseWithUnreadData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	data := []byte{1, 2, 3}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that ACK is received, this happens regardless of the read.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Now that we know we have unread data, let's just close the connection
	// and verify that netstack sends an RST rather than a FIN.
	c.EP.Close()

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
			// We shouldn't consume a sequence number on RST.
			checker.TCPSeqNum(uint32(c.IRS)+1),
		))
	// The RST puts the endpoint into an error state.
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateError; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// This final ACK should be ignored because an ACK on a reset doesn't mean
	// anything.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(seqnum.Size(len(data))),
		AckNum:  c.IRS.Add(seqnum.Size(2)),
		RcvWnd:  30000,
	})
}

func TestRstOnCloseWithUnreadDataFinConvertRst(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	data := []byte{1, 2, 3}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that ACK is received, this happens regardless of the read.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Cause a FIN to be generated.
	c.EP.Shutdown(tcpip.ShutdownWrite)

	// Make sure we get the FIN but DON't ACK IT.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
			checker.TCPSeqNum(uint32(c.IRS)+1),
		))

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateFinWait1; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// Cause a RST to be generated by closing the read end now since we have
	// unread data.
	c.EP.Shutdown(tcpip.ShutdownRead)

	// Make sure we get the RST
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
			// RST is always generated with sndNxt which if the FIN
			// has been sent will be 1 higher than the sequence
			// number of the FIN itself.
			checker.TCPSeqNum(uint32(c.IRS)+2),
		))
	// The RST puts the endpoint into an error state.
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateError; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// The ACK to the FIN should now be rejected since the connection has been
	// closed by a RST.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(seqnum.Size(len(data))),
		AckNum:  c.IRS.Add(seqnum.Size(2)),
		RcvWnd:  30000,
	})
}

func TestShutdownRead(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	if err := c.EP.Shutdown(tcpip.ShutdownRead); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	ept.CheckReadError(t, &tcpip.ErrClosedForReceive{})
	var want uint64 = 1
	if got := c.EP.Stats().(*tcp.Stats).ReadErrors.ReadClosed.Value(); got != want {
		t.Fatalf("got EP stats Stats.ReadErrors.ReadClosed got %d want %d", got, want)
	}
}

func TestFullWindowReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	const rcvBufSz = 10
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, rcvBufSz)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Fill up the window w/ tcp.SegOverheadFactor*rcvBufSz as netstack multiplies
	// the provided buffer value by tcp.SegOverheadFactor to calculate the actual
	// receive buffer size.
	data := make([]byte, tcp.SegOverheadFactor*rcvBufSz)
	for i := range data {
		data[i] = byte(i % 255)
	}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that data is acknowledged, and window goes to zero.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPWindow(0),
		),
	)

	// Receive data and check it.
	v := ept.CheckRead(t)
	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	var want uint64 = 1
	if got := c.EP.Stats().(*tcp.Stats).ReceiveErrors.ZeroRcvWindowState.Value(); got != want {
		t.Fatalf("got EP stats ReceiveErrors.ZeroRcvWindowState got %d want %d", got, want)
	}

	// Check that we get an ACK for the newly non-zero window.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPWindow(10),
		),
	)
}

// Test the stack receive window advertisement on receiving segments smaller than
// segment overhead. It tests for the right edge of the window to not grow when
// the endpoint is not being read from.
func TestSmallSegReceiveWindowAdvertisement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	opt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: tcp.DefaultReceiveBufferSize,
		Max:     tcp.DefaultReceiveBufferSize << tcp.FindWndScale(seqnum.Size(tcp.DefaultReceiveBufferSize)),
	}
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
	}

	c.AcceptWithOptions(tcp.FindWndScale(seqnum.Size(opt.Default)), header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Bump up the receive buffer size such that, when the receive window grows,
	// the scaled window exceeds maxUint16.
	c.EP.SocketOptions().SetReceiveBufferSize(int64(opt.Max), true)

	// Keep the payload size < segment overhead and such that it is a multiple
	// of the window scaled value. This enables the test to perform equality
	// checks on the incoming receive window.
	payloadSize := 1 << c.RcvdWindowScale
	if payloadSize >= tcp.SegSize {
		t.Fatalf("payload size of %d is not less than the segment overhead of %d", payloadSize, tcp.SegSize)
	}
	payload := generateRandomPayload(t, payloadSize)
	payloadLen := seqnum.Size(len(payload))
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)

	// Send payload to the endpoint and return the advertised receive window
	// from the endpoint.
	getIncomingRcvWnd := func() uint32 {
		c.SendPacket(payload, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			SeqNum:  iss,
			AckNum:  c.IRS.Add(1),
			Flags:   header.TCPFlagAck,
			RcvWnd:  30000,
		})
		iss = iss.Add(payloadLen)

		pkt := c.GetPacket()
		return uint32(header.TCP(header.IPv4(pkt).Payload()).WindowSize()) << c.RcvdWindowScale
	}

	// Read the advertised receive window with the ACK for payload.
	rcvWnd := getIncomingRcvWnd()

	// Check if the subsequent ACK to our send has not grown the right edge of
	// the window.
	if got, want := getIncomingRcvWnd(), rcvWnd-uint32(len(payload)); got != want {
		t.Fatalf("got incomingRcvwnd %d want %d", got, want)
	}

	// Read the data so that the subsequent ACK from the endpoint
	// grows the right edge of the window.
	var buf bytes.Buffer
	if _, err := c.EP.Read(&buf, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("c.EP.Read: %s", err)
	}

	// Check if we have received max uint16 as our advertised
	// scaled window now after a read above.
	maxRcv := uint32(math.MaxUint16 << c.RcvdWindowScale)
	if got, want := getIncomingRcvWnd(), maxRcv; got != want {
		t.Fatalf("got incomingRcvwnd %d want %d", got, want)
	}

	// Check if the subsequent ACK to our send has not grown the right edge of
	// the window.
	if got, want := getIncomingRcvWnd(), maxRcv-uint32(len(payload)); got != want {
		t.Fatalf("got incomingRcvwnd %d want %d", got, want)
	}
}

func TestNoWindowShrinking(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Start off with a certain receive buffer then cut it in half and verify that
	// the right edge of the window does not shrink.
	// NOTE: Netstack doubles the value specified here.
	rcvBufSize := 65536
	// Enable window scaling with a scale of zero from our end.
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, rcvBufSize, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Send a 1 byte payload so that we can record the current receive window.
	// Send a payload of half the size of rcvBufSize.
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	payload := []byte{1}
	c.SendPacket(payload, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Read the 1 byte payload we just sent.
	if got, want := payload, ept.CheckRead(t); !bytes.Equal(got, want) {
		t.Fatalf("got data: %v, want: %v", got, want)
	}

	// Verify that the ACK does not shrink the window.
	pkt := c.GetPacket()
	iss = iss.Add(1)
	checker.IPv4(t, pkt,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
	// Stash the initial window.
	initialWnd := header.TCP(header.IPv4(pkt).Payload()).WindowSize() << c.RcvdWindowScale
	initialLastAcceptableSeq := iss.Add(seqnum.Size(initialWnd))
	// Now shrink the receive buffer to half its original size.
	c.EP.SocketOptions().SetReceiveBufferSize(int64(rcvBufSize/2), true)

	data := generateRandomPayload(t, rcvBufSize)
	// Send a payload of half the size of rcvBufSize.
	c.SendPacket(data[:rcvBufSize/2], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	iss = iss.Add(seqnum.Size(rcvBufSize / 2))

	// Verify that the ACK does not shrink the window.
	pkt = c.GetPacket()
	checker.IPv4(t, pkt,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
	newWnd := header.TCP(header.IPv4(pkt).Payload()).WindowSize() << c.RcvdWindowScale
	newLastAcceptableSeq := iss.Add(seqnum.Size(newWnd))
	if newLastAcceptableSeq.LessThan(initialLastAcceptableSeq) {
		t.Fatalf("receive window shrunk unexpectedly got: %d, want >= %d", newLastAcceptableSeq, initialLastAcceptableSeq)
	}

	// Send another payload of half the size of rcvBufSize. This should fill up the
	// socket receive buffer and we should see a zero window.
	c.SendPacket(data[rcvBufSize/2:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	iss = iss.Add(seqnum.Size(rcvBufSize / 2))

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPWindow(0),
		),
	)

	// Receive data and check it.
	read := ept.CheckReadFull(t, len(data), ch, 5*time.Second)
	if !bytes.Equal(data, read) {
		t.Fatalf("got data = %v, want = %v", read, data)
	}

	// Check that we get an ACK for the newly non-zero window, which is the new
	// receive buffer size we set after the connection was established.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPWindow(uint16(rcvBufSize/2)>>c.RcvdWindowScale),
		),
	)
}

func TestSimpleSend(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(data, p) {
		t.Fatalf("got data = %v, want = %v", p, data)
	}

	// Acknowledge the data.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1 + seqnum.Size(len(data))),
		RcvWnd:  30000,
	})
}

func TestZeroWindowSend(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 0 /* rcvWnd */, -1 /* epRcvBuf */)

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check if we got a zero-window probe.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Open up the window. Data should be received now.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that data is received.
	b = c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(data, p) {
		t.Fatalf("got data = %v, want = %v", p, data)
	}

	// Acknowledge the data.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1 + seqnum.Size(len(data))),
		RcvWnd:  30000,
	})
}

func TestScaledWindowConnect(t *testing.T) {
	// This test ensures that window scaling is used when the peer
	// does advertise it and connection is established with Connect().
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set the window size greater than the maximum non-scaled window.
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, 65535*3, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received, and that advertised window is 0x5fff,
	// that is, that it is scaled.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPWindow(0x5fff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
}

func TestNonScaledWindowConnect(t *testing.T) {
	// This test ensures that window scaling is not used when the peer
	// doesn't advertise it and connection is established with Connect().
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set the window size greater than the maximum non-scaled window.
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, 65535*3)

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPWindow(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
}

func TestScaledWindowAccept(t *testing.T) {
	// This test ensures that window scaling is used when the peer
	// does advertise it and connection is established with Accept().
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	ep.SocketOptions().SetReceiveBufferSize(65535*3, true)

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Do 3-way handshake.
	// wndScale expected is 3 as 65535 * 3 * 2 < 65535 * 2^3 but > 65535 *2 *2
	c.PassiveConnectWithOptions(100, 3 /* wndScale */, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received, and that advertised window is 0x5fff,
	// that is, that it is scaled.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPWindow(0x5fff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
}

func TestNonScaledWindowAccept(t *testing.T) {
	// This test ensures that window scaling is not used when the peer
	// doesn't advertise it and connection is established with Accept().
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	ep.SocketOptions().SetReceiveBufferSize(65535*3, true)

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Do 3-way handshake w/ window scaling disabled. The SYN-ACK to the SYN
	// should not carry the window scaling option.
	c.PassiveConnect(100, -1, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPWindow(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
}

func TestZeroScaledWindowReceive(t *testing.T) {
	// This test ensures that the endpoint sends a non-zero window size
	// advertisement when the scaled window transitions from 0 to non-zero,
	// but the actual window (not scaled) hasn't gotten to zero.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set the buffer size such that a window scale of 5 will be used.
	const bufSz = 65535 * 10
	const ws = uint32(5)
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, bufSz, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	// Write chunks of 50000 bytes.
	remain := 0
	sent := 0
	data := make([]byte, 50000)
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	// Keep writing till the window drops below len(data).
	for {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(seqnum.Size(sent)),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		pkt := c.GetPacket()
		checker.IPv4(t, pkt,
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPAckNum(uint32(iss)+uint32(sent)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
		// Don't reduce window to zero here.
		if wnd := int(header.TCP(header.IPv4(pkt).Payload()).WindowSize()); wnd<<ws < len(data) {
			remain = wnd << ws
			break
		}
	}

	// Make the window non-zero, but the scaled window zero.
	for remain >= 16 {
		data = data[:remain-15]
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(seqnum.Size(sent)),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		pkt := c.GetPacket()
		checker.IPv4(t, pkt,
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPAckNum(uint32(iss)+uint32(sent)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
		// Since the receive buffer is split between window advertisement and
		// application data buffer the window does not always reflect the space
		// available and actual space available can be a bit more than what is
		// advertised in the window.
		wnd := int(header.TCP(header.IPv4(pkt).Payload()).WindowSize())
		if wnd == 0 {
			break
		}
		remain = wnd << ws
	}

	// Read at least 2MSS of data. An ack should be sent in response to that.
	// Since buffer space is now split in half between window and application
	// data we need to read more than 1 MSS(65536) of data for a non-zero window
	// update to be sent. For 1MSS worth of window to be available we need to
	// read at least 128KB. Since our segments above were 50KB each it means
	// we need to read at 3 packets.
	w := tcpip.LimitedWriter{
		W: ioutil.Discard,
		N: defaultMTU * 2,
	}
	for w.N != 0 {
		res, err := c.EP.Read(&w, tcpip.ReadOptions{})
		t.Logf("err=%v res=%#v", err, res)
		if err != nil {
			t.Fatalf("Read failed: %s", err)
		}
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(sent)),
			checker.TCPWindowGreaterThanEq(uint16(defaultMTU>>ws)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestSegmentMerging(t *testing.T) {
	tests := []struct {
		name   string
		stop   func(tcpip.Endpoint)
		resume func(tcpip.Endpoint)
	}{
		{
			"stop work",
			func(ep tcpip.Endpoint) {
				ep.(interface{ StopWork() }).StopWork()
			},
			func(ep tcpip.Endpoint) {
				ep.(interface{ ResumeWork() }).ResumeWork()
			},
		},
		{
			"cork",
			func(ep tcpip.Endpoint) {
				ep.SocketOptions().SetCorkOption(true)
			},
			func(ep tcpip.Endpoint) {
				ep.SocketOptions().SetCorkOption(false)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

			// Send tcp.InitialCwnd number of segments to fill up
			// InitialWindow but don't ACK. That should prevent
			// anymore packets from going out.
			var r bytes.Reader
			for i := 0; i < tcp.InitialCwnd; i++ {
				r.Reset([]byte{0})
				if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write #%d failed: %s", i+1, err)
				}
			}

			// Now send the segments that should get merged as the congestion
			// window is full and we won't be able to send any more packets.
			var allData []byte
			for i, data := range [][]byte{{1, 2, 3, 4}, {5, 6, 7}, {8, 9}, {10}, {11}} {
				allData = append(allData, data...)
				r.Reset(data)
				if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write #%d failed: %s", i+1, err)
				}
			}

			// Check that we get tcp.InitialCwnd packets.
			iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
			for i := 0; i < tcp.InitialCwnd; i++ {
				b := c.GetPacket()
				checker.IPv4(t, b,
					checker.PayloadLen(header.TCPMinimumSize+1),
					checker.TCP(
						checker.DstPort(context.TestPort),
						checker.TCPSeqNum(uint32(c.IRS)+uint32(i)+1),
						checker.TCPAckNum(uint32(iss)),
						checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
					),
				)
			}

			// Acknowledge the data.
			c.SendPacket(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: c.Port,
				Flags:   header.TCPFlagAck,
				SeqNum:  iss,
				AckNum:  c.IRS.Add(1 + 10), // 10 for the 10 bytes of payload.
				RcvWnd:  30000,
			})

			// Check that data is received.
			b := c.GetPacket()
			checker.IPv4(t, b,
				checker.PayloadLen(len(allData)+header.TCPMinimumSize),
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPSeqNum(uint32(c.IRS)+11),
					checker.TCPAckNum(uint32(iss)),
					checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
				),
			)

			if got := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(got, allData) {
				t.Fatalf("got data = %v, want = %v", got, allData)
			}

			// Acknowledge the data.
			c.SendPacket(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: c.Port,
				Flags:   header.TCPFlagAck,
				SeqNum:  iss,
				AckNum:  c.IRS.Add(11 + seqnum.Size(len(allData))),
				RcvWnd:  30000,
			})
		})
	}
}

func TestDelay(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	c.EP.SocketOptions().SetDelayOption(true)

	var allData []byte
	for i, data := range [][]byte{{0}, {1, 2, 3, 4}, {5, 6, 7}, {8, 9}, {10}, {11}} {
		allData = append(allData, data...)
		var r bytes.Reader
		r.Reset(data)
		if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write #%d failed: %s", i+1, err)
		}
	}

	seq := c.IRS.Add(1)
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for _, want := range [][]byte{allData[:1], allData[1:]} {
		// Check that data is received.
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.PayloadLen(len(want)+header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(seq)),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			),
		)

		if got := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(got, want) {
			t.Fatalf("got data = %v, want = %v", got, want)
		}

		seq = seq.Add(seqnum.Size(len(want)))
		// Acknowledge the data.
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss,
			AckNum:  seq,
			RcvWnd:  30000,
		})
	}
}

func TestUndelay(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	c.EP.SocketOptions().SetDelayOption(true)

	allData := [][]byte{{0}, {1, 2, 3}}
	for i, data := range allData {
		var r bytes.Reader
		r.Reset(data)
		if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write #%d failed: %s", i+1, err)
		}
	}

	seq := c.IRS.Add(1)
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	// Check that data is received.
	first := c.GetPacket()
	checker.IPv4(t, first,
		checker.PayloadLen(len(allData[0])+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(seq)),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	if got, want := first[header.IPv4MinimumSize+header.TCPMinimumSize:], allData[0]; !bytes.Equal(got, want) {
		t.Fatalf("got first packet's data = %v, want = %v", got, want)
	}

	seq = seq.Add(seqnum.Size(len(allData[0])))

	// Check that we don't get the second packet yet.
	c.CheckNoPacketTimeout("delayed second packet transmitted", 100*time.Millisecond)

	c.EP.SocketOptions().SetDelayOption(false)

	// Check that data is received.
	second := c.GetPacket()
	checker.IPv4(t, second,
		checker.PayloadLen(len(allData[1])+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(seq)),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	if got, want := second[header.IPv4MinimumSize+header.TCPMinimumSize:], allData[1]; !bytes.Equal(got, want) {
		t.Fatalf("got second packet's data = %v, want = %v", got, want)
	}

	seq = seq.Add(seqnum.Size(len(allData[1])))

	// Acknowledge the data.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seq,
		RcvWnd:  30000,
	})
}

func TestMSSNotDelayed(t *testing.T) {
	tests := []struct {
		name string
		fn   func(tcpip.Endpoint)
	}{
		{"no-op", func(tcpip.Endpoint) {}},
		{"delay", func(ep tcpip.Endpoint) { ep.SocketOptions().SetDelayOption(true) }},
		{"cork", func(ep tcpip.Endpoint) { ep.SocketOptions().SetCorkOption(true) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const maxPayload = 100
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */, []byte{
				header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
			})

			test.fn(c.EP)

			allData := [][]byte{{0}, make([]byte, maxPayload), make([]byte, maxPayload)}
			for i, data := range allData {
				var r bytes.Reader
				r.Reset(data)
				if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write #%d failed: %s", i+1, err)
				}
			}

			seq := c.IRS.Add(1)
			iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
			for i, data := range allData {
				// Check that data is received.
				packet := c.GetPacket()
				checker.IPv4(t, packet,
					checker.PayloadLen(len(data)+header.TCPMinimumSize),
					checker.TCP(
						checker.DstPort(context.TestPort),
						checker.TCPSeqNum(uint32(seq)),
						checker.TCPAckNum(uint32(iss)),
						checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
					),
				)

				if got, want := packet[header.IPv4MinimumSize+header.TCPMinimumSize:], data; !bytes.Equal(got, want) {
					t.Fatalf("got packet #%d's data = %v, want = %v", i+1, got, want)
				}

				seq = seq.Add(seqnum.Size(len(data)))
			}

			// Acknowledge the data.
			c.SendPacket(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: c.Port,
				Flags:   header.TCPFlagAck,
				SeqNum:  iss,
				AckNum:  seq,
				RcvWnd:  30000,
			})
		})
	}
}

func testBrokenUpWrite(t *testing.T, c *context.Context, maxPayload int) {
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
		b := c.GetPacket()
		numPackets++
		tcpHdr := header.TCP(header.IPv4(b).Payload())
		payloadLen := len(tcpHdr.Payload())
		checker.IPv4(t, b,
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

func TestSendGreaterThanMTU(t *testing.T) {
	const maxPayload = 100
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	testBrokenUpWrite(t, c, maxPayload)
}

func TestSetTTL(t *testing.T) {
	for _, wantTTL := range []uint8{1, 2, 50, 64, 128, 254, 255} {
		t.Run(fmt.Sprintf("TTL:%d", wantTTL), func(t *testing.T) {
			c := context.New(t, 65535)
			defer c.Cleanup()

			var err tcpip.Error
			c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
			if err != nil {
				t.Fatalf("NewEndpoint failed: %s", err)
			}

			if err := c.EP.SetSockOptInt(tcpip.TTLOption, int(wantTTL)); err != nil {
				t.Fatalf("SetSockOptInt(TTLOption, %d) failed: %s", wantTTL, err)
			}

			{
				err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
				if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
					t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
				}
			}

			// Receive SYN packet.
			b := c.GetPacket()

			checker.IPv4(t, b, checker.TTL(wantTTL))
		})
	}
}

func TestActiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	c := context.New(t, 65535)
	defer c.Cleanup()

	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	})
	testBrokenUpWrite(t, c, maxPayload)
}

func TestPassiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	defer ep.Close()

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	ep.SocketOptions().SetReceiveBufferSize(rcvBufferSize, true)

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(t, c, maxPayload)
}

func TestSynCookiePassiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 536
	const mtu = 2000
	c := context.New(t, mtu)
	defer c.Cleanup()

	opt := tcpip.TCPAlwaysUseSynCookies(true)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(t, c, maxPayload)
}

func TestForwarderSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Wait for connection to be available.
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(t, c, maxPayload)
}

func TestSynOptionsOnActiveConnect(t *testing.T) {
	const mtu = 1400
	c := context.New(t, mtu)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	const wndScale = 3
	c.EP.SocketOptions().SetReceiveBufferSize(rcvBufferSize, true)

	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.WritableEvents)
	defer c.WQ.EventUnregister(&we)

	{
		err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
			t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	// Receive SYN packet.
	b := c.GetPacket()
	mss := uint16(mtu - header.IPv4MinimumSize - header.TCPMinimumSize)
	checker.IPv4(t, b,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: wndScale}),
		),
	)

	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	// Wait for retransmit.
	time.Sleep(1 * time.Second)
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.SrcPort(tcpHdr.SourcePort()),
			checker.TCPSeqNum(tcpHdr.SequenceNumber()),
			checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: wndScale}),
		),
	)

	// Send SYN-ACK.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: tcpHdr.DestinationPort(),
		DstPort: tcpHdr.SourcePort(),
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK packet.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		if err := c.EP.LastError(); err != nil {
			t.Fatalf("Connect failed: %s", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
}

func TestCloseListener(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create listener.
	var wq waiter.Queue
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Close the listener and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		t.Fatalf("Took too long to close: %s", diff)
	}
}

func TestReceiveOnResetConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	// Send RST segment.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Try to read.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

loop:
	for {
		switch _, err := c.EP.Read(ioutil.Discard, tcpip.ReadOptions{}); err.(type) {
		case *tcpip.ErrWouldBlock:
			<-ch
			// Expect the state to be StateError and subsequent Reads to fail with HardError.
			_, err := c.EP.Read(ioutil.Discard, tcpip.ReadOptions{})
			if d := cmp.Diff(&tcpip.ErrConnectionReset{}, err); d != "" {
				t.Fatalf("c.EP.Read() mismatch (-want +got):\n%s", d)
			}
			break loop
		case *tcpip.ErrConnectionReset:
			break loop
		default:
			t.Fatalf("got c.EP.Read(nil) = %v, want = %s", err, &tcpip.ErrConnectionReset{})
		}
	}

	if tcp.EndpointState(c.EP.State()) != tcp.StateError {
		t.Fatalf("got EP state is not StateError")
	}

	checkValid := func() []error {
		var errors []error
		if got := c.Stack().Stats().TCP.EstablishedResets.Value(); got != 1 {
			errors = append(errors, fmt.Errorf("got stats.TCP.EstablishedResets.Value() = %d, want = 1", got))
		}
		if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
			errors = append(errors, fmt.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got))
		}
		if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
			errors = append(errors, fmt.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got))
		}
		return errors
	}

	start := time.Now()
	for time.Since(start) < time.Minute && len(checkValid()) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	for _, err := range checkValid() {
		t.Error(err)
	}
}

func TestSendOnResetConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Send RST segment.
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Wait for the RST to be received.
	time.Sleep(1 * time.Second)

	// Try to write.
	var r bytes.Reader
	r.Reset(make([]byte, 10))
	_, err := c.EP.Write(&r, tcpip.WriteOptions{})
	if d := cmp.Diff(&tcpip.ErrConnectionReset{}, err); d != "" {
		t.Fatalf("c.EP.Write(...) mismatch (-want +got):\n%s", d)
	}
}

// TestMaxRetransmitsTimeout tests if the connection is timed out after
// a segment has been retransmitted MaxRetries times.
func TestMaxRetransmitsTimeout(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	const numRetries = 2
	opt := tcpip.TCPMaxRetriesOption(numRetries)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000 /* rcvWnd */, -1 /* epRcvBuf */)

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.EventHUp)
	defer c.WQ.EventUnregister(&waitEntry)

	var r bytes.Reader
	r.Reset(make([]byte, 1))
	_, err := c.EP.Write(&r, tcpip.WriteOptions{})
	if err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Expect first transmit and MaxRetries retransmits.
	for i := 0; i < numRetries+1; i++ {
		checker.IPv4(t, c.GetPacket(),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPFlags(header.TCPFlagAck|header.TCPFlagPsh),
			),
		)
	}
	// Wait for the connection to timeout after MaxRetries retransmits.
	initRTO := 1 * time.Second
	select {
	case <-notifyCh:
	case <-time.After((2 << numRetries) * initRTO):
		t.Fatalf("connection still alive after maximum retransmits.\n")
	}

	// Send an ACK and expect a RST as the connection would have been closed.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagRst),
		),
	)

	if got := c.Stack().Stats().TCP.EstablishedTimedout.Value(); got != 1 {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedTimedout.Value() = %d, want = 1", got)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

// TestMaxRTO tests if the retransmit interval caps to MaxRTO.
func TestMaxRTO(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	rto := 1 * time.Second
	opt := tcpip.TCPMaxRTOOption(rto)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000 /* rcvWnd */, -1 /* epRcvBuf */)

	var r bytes.Reader
	r.Reset(make([]byte, 1))
	_, err := c.EP.Write(&r, tcpip.WriteOptions{})
	if err != nil {
		t.Fatalf("Write failed: %s", err)
	}
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	const numRetransmits = 2
	for i := 0; i < numRetransmits; i++ {
		start := time.Now()
		checker.IPv4(t, c.GetPacket(),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			),
		)
		if time.Since(start).Round(time.Second).Seconds() != rto.Seconds() {
			t.Errorf("Retransmit interval not capped to MaxRTO.\n")
		}
	}
}

// TestRetransmitIPv4IDUniqueness tests that the IPv4 Identification field is
// unique on retransmits.
func TestRetransmitIPv4IDUniqueness(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"1Byte", 1},
		{"512Bytes", 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateConnected(context.TestInitialSequenceNumber, 30000 /* rcvWnd */, -1 /* epRcvBuf */)

			// Disabling PMTU discovery causes all packets sent from this socket to
			// have DF=0. This needs to be done because the IPv4 ID uniqueness
			// applies only to non-atomic IPv4 datagrams as defined in RFC 6864
			// Section 4, and datagrams with DF=0 are non-atomic.
			if err := c.EP.SetSockOptInt(tcpip.MTUDiscoverOption, tcpip.PMTUDiscoveryDont); err != nil {
				t.Fatalf("disabling PMTU discovery via sockopt to force DF=0 failed: %s", err)
			}

			var r bytes.Reader
			r.Reset(make([]byte, tc.size))
			if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
				t.Fatalf("Write failed: %s", err)
			}
			pkt := c.GetPacket()
			checker.IPv4(t, pkt,
				checker.FragmentFlags(0),
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
				),
			)
			idSet := map[uint16]struct{}{header.IPv4(pkt).ID(): {}}
			// Expect two retransmitted packets, and that all packets received have
			// unique IPv4 ID values.
			for i := 0; i <= 2; i++ {
				pkt := c.GetPacket()
				checker.IPv4(t, pkt,
					checker.FragmentFlags(0),
					checker.TCP(
						checker.DstPort(context.TestPort),
						checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
					),
				)
				id := header.IPv4(pkt).ID()
				if _, exists := idSet[id]; exists {
					t.Fatalf("duplicate IPv4 ID=%d found in retransmitted packet", id)
				}
				idSet[id] = struct{}{}
			}
		})
	}
}

func TestFinImmediately(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Shutdown immediately, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+2),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinRetransmit(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Shutdown immediately, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Don't acknowledge yet. We should get a retransmit of the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+2),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithNoPendingData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Write something out, and have it acknowledged.
	view := make([]byte, 10)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	next := uint32(c.IRS) + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Shutdown, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingDataCwndFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Write enough segments to fill the congestion window before ACK'ing
	// any of them.
	view := make([]byte, 10)
	var r bytes.Reader
	for i := tcp.InitialCwnd; i > 0; i-- {
		r.Reset(view)
		if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write failed: %s", err)
		}
	}

	next := uint32(c.IRS) + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for i := tcp.InitialCwnd; i > 0; i-- {
		checker.IPv4(t, c.GetPacket(),
			checker.PayloadLen(len(view)+header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(next),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			),
		)
		next += uint32(len(view))
	}

	// Shutdown the connection, check that the FIN segment isn't sent
	// because the congestion window doesn't allow it. Wait until a
	// retransmit is received.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Send the ACK that will allow the FIN to be sent as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Write something out, and acknowledge it to get cwnd to 2.
	view := make([]byte, 10)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	next := uint32(c.IRS) + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Write new data, but don't acknowledge it.
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPartialAck(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Write something out, and acknowledge it to get cwnd to 2. Also send
	// FIN from the test side.
	view := make([]byte, 10)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	next := uint32(c.IRS) + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Check that we get an ACK for the fin.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Write new data, but don't acknowledge it.
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)+1),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send an ACK for the data, but not for the FIN yet.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss.Add(1),
		AckNum:  seqnum.Value(next - 1),
		RcvWnd:  30000,
	})

	// Check that we don't get a retransmit of the FIN.
	c.CheckNoPacketTimeout("FIN retransmitted when data was ack'd", 100*time.Millisecond)

	// Ack the FIN.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss.Add(1),
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})
}

func TestUpdateListenBacklog(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create listener.
	var wq waiter.Queue
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Update the backlog with another Listen() on the same endpoint.
	if err := ep.Listen(20); err != nil {
		t.Fatalf("Listen failed to update backlog: %s", err)
	}

	ep.Close()
}

func scaledSendWindow(t *testing.T, scale uint8) {
	// This test ensures that the endpoint is using the right scaling by
	// sending a buffer that is larger than the window size, and ensuring
	// that the endpoint doesn't send more than allowed.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	maxPayload := defaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 0, -1 /* epRcvBuf */, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
		header.TCPOptionWS, 3, scale, header.TCPOptionNOP,
	})

	// Open up the window with a scaled value.
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  1,
	})

	// Send some data. Check that it's capped by the window size.
	view := make([]byte, 65535)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that only data that fits in the scaled window is sent.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen((1<<scale)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Reset the connection to free resources.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss,
	})
}

func TestScaledSendWindow(t *testing.T) {
	for scale := uint8(0); scale <= 14; scale++ {
		scaledSendWindow(t, scale)
	}
}

func TestReceivedValidSegmentCountIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	stats := c.Stack().Stats()
	want := stats.TCP.ValidSegmentsReceived.Value() + 1

	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	if got := stats.TCP.ValidSegmentsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.ValidSegmentsReceived.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).SegmentsReceived.Value(); got != want {
		t.Errorf("got EP stats Stats.SegmentsReceived = %d, want = %d", got, want)
	}
	// Ensure there were no errors during handshake. If these stats have
	// incremented, then the connection should not have been established.
	if got := c.EP.Stats().(*tcp.Stats).SendErrors.NoRoute.Value(); got != 0 {
		t.Errorf("got EP stats Stats.SendErrors.NoRoute = %d, want = %d", got, 0)
	}
}

func TestReceivedInvalidSegmentCountIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	stats := c.Stack().Stats()
	want := stats.TCP.InvalidSegmentsReceived.Value() + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	vv := c.BuildSegment(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	tcpbuf := vv.ToView()[header.IPv4MinimumSize:]
	tcpbuf[header.TCPDataOffset] = ((header.TCPMinimumSize - 1) / 4) << 4

	c.SendSegment(vv)

	if got := stats.TCP.InvalidSegmentsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.InvalidSegmentsReceived.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).ReceiveErrors.MalformedPacketsReceived.Value(); got != want {
		t.Errorf("got EP Stats.ReceiveErrors.MalformedPacketsReceived stats = %d, want = %d", got, want)
	}
}

func TestReceivedIncorrectChecksumIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	stats := c.Stack().Stats()
	want := stats.TCP.ChecksumErrors.Value() + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	vv := c.BuildSegment([]byte{0x1, 0x2, 0x3}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	tcpbuf := vv.ToView()[header.IPv4MinimumSize:]
	// Overwrite a byte in the payload which should cause checksum
	// verification to fail.
	tcpbuf[(tcpbuf[header.TCPDataOffset]>>4)*4] = 0x4

	c.SendSegment(vv)

	if got := stats.TCP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.TCP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
	if got := c.EP.Stats().(*tcp.Stats).ReceiveErrors.ChecksumErrors.Value(); got != want {
		t.Errorf("got EP stats Stats.ReceiveErrors.ChecksumErrors = %d, want = %d", got, want)
	}
}

func TestReceivedSegmentQueuing(t *testing.T) {
	// This test sends 200 segments containing a few bytes each to an
	// endpoint and checks that they're all received and acknowledged by
	// the endpoint, that is, that none of the segments are dropped by
	// internal queues.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// Send 200 segments.
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	data := []byte{1, 2, 3}
	for i := 0; i < 200; i++ {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(seqnum.Size(i * len(data))),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
	}

	// Receive ACKs for all segments.
	last := iss.Add(seqnum.Size(200 * len(data)))
	for {
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
		tcpHdr := header.TCP(header.IPv4(b).Payload())
		ack := seqnum.Value(tcpHdr.AckNumber())
		if ack == last {
			break
		}

		if last.LessThan(ack) {
			t.Fatalf("Acknowledge (%v) beyond the expected (%v)", ack, last)
		}
	}
}

func TestReadAfterClosedState(t *testing.T) {
	// This test ensures that calling Read() or Peek() after the endpoint
	// has transitioned to closedState still works if there is pending
	// data. To transition to stateClosed without calling Close(), we must
	// shutdown the send path and the peer must send its own FIN.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPTimeWaitTimeout to 1 seconds so that sockets are marked closed
	// after 1 second in TIME_WAIT state.
	tcpTimeWaitTimeout := 1 * time.Second
	opt := tcpip.TCPTimeWaitTimeoutOption(tcpTimeWaitTimeout)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%d)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Shutdown immediately for write, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %s", err)
	}

	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateFinWait1; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// Send some data and acknowledge the FIN.
	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that ACK is received.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+2),
			checker.TCPAckNum(uint32(iss)+uint32(len(data))+1),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Give the stack the chance to transition to closed state from
	// TIME_WAIT.
	time.Sleep(tcpTimeWaitTimeout * 2)

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateClose; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that peek works.
	var peekBuf bytes.Buffer
	res, err := c.EP.Read(&peekBuf, tcpip.ReadOptions{Peek: true})
	if err != nil {
		t.Fatalf("Peek failed: %s", err)
	}

	if got, want := res.Count, len(data); got != want {
		t.Fatalf("res.Count = %d, want %d", got, want)
	}
	if !bytes.Equal(data, peekBuf.Bytes()) {
		t.Fatalf("got data = %v, want = %v", peekBuf.Bytes(), data)
	}

	// Receive data.
	v := ept.CheckRead(t)
	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	// Now that we drained the queue, check that functions fail with the
	// right error code.
	ept.CheckReadError(t, &tcpip.ErrClosedForReceive{})
	var buf bytes.Buffer
	{
		_, err := c.EP.Read(&buf, tcpip.ReadOptions{Peek: true})
		if d := cmp.Diff(&tcpip.ErrClosedForReceive{}, err); d != "" {
			t.Fatalf("c.EP.Read(_, {Peek: true}) mismatch (-want +got):\n%s", d)
		}
	}
}

func TestReusePort(t *testing.T) {
	// This test ensures that ports are immediately available for reuse
	// after Close on the endpoints using them returns.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// First case, just an endpoint that was bound.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	c.EP.Close()
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	c.EP.Close()

	// Second case, an endpoint that was bound and is connecting..
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	{
		err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
			t.Fatalf("c.EP.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}
	c.EP.Close()

	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	c.EP.Close()

	// Third case, an endpoint that was bound and is listening.
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	c.EP.Close()

	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	c.EP.SocketOptions().SetReuseAddress(true)
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
}

func checkRecvBufferSize(t *testing.T, ep tcpip.Endpoint, v int) {
	t.Helper()

	s := ep.SocketOptions().GetReceiveBufferSize()
	if int(s) != v {
		t.Fatalf("got receive buffer size = %d, want = %d", s, v)
	}
}

func checkSendBufferSize(t *testing.T, ep tcpip.Endpoint, v int) {
	t.Helper()

	if s := ep.SocketOptions().GetSendBufferSize(); int(s) != v {
		t.Fatalf("got send buffer size = %d, want = %d", s, v)
	}
}

func TestDefaultBufferSizes(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// Check the default values.
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	defer func() {
		if ep != nil {
			ep.Close()
		}
	}()

	checkSendBufferSize(t, ep, tcp.DefaultSendBufferSize)
	checkRecvBufferSize(t, ep, tcp.DefaultReceiveBufferSize)

	// Change the default send buffer size.
	{
		opt := tcpip.TCPSendBufferSizeRangeOption{
			Min:     1,
			Default: tcp.DefaultSendBufferSize * 2,
			Max:     tcp.DefaultSendBufferSize * 20,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	ep.Close()
	ep, err = s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}

	checkSendBufferSize(t, ep, tcp.DefaultSendBufferSize*2)
	checkRecvBufferSize(t, ep, tcp.DefaultReceiveBufferSize)

	// Change the default receive buffer size.
	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     1,
			Default: tcp.DefaultReceiveBufferSize * 3,
			Max:     tcp.DefaultReceiveBufferSize * 30,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	ep.Close()
	ep, err = s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}

	checkSendBufferSize(t, ep, tcp.DefaultSendBufferSize*2)
	checkRecvBufferSize(t, ep, tcp.DefaultReceiveBufferSize*3)
}

func TestMinMaxBufferSizes(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// Check the default values.
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	defer ep.Close()

	// Change the min/max values for send/receive
	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 200, Default: tcp.DefaultReceiveBufferSize * 2, Max: tcp.DefaultReceiveBufferSize * 20}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	{
		opt := tcpip.TCPSendBufferSizeRangeOption{Min: 300, Default: tcp.DefaultSendBufferSize * 3, Max: tcp.DefaultSendBufferSize * 30}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	// Set values below the min/2.
	ep.SocketOptions().SetReceiveBufferSize(99, true)
	checkRecvBufferSize(t, ep, 200)

	ep.SocketOptions().SetSendBufferSize(149, true)

	checkSendBufferSize(t, ep, 300)

	// Set values above the max.
	ep.SocketOptions().SetReceiveBufferSize(1+tcp.DefaultReceiveBufferSize*20, true)
	// Values above max are capped at max and then doubled.
	checkRecvBufferSize(t, ep, tcp.DefaultReceiveBufferSize*20*2)

	ep.SocketOptions().SetSendBufferSize(1+tcp.DefaultSendBufferSize*30, true)
	// Values above max are capped at max and then doubled.
	checkSendBufferSize(t, ep, tcp.DefaultSendBufferSize*30*2)
}

func TestBindToDeviceOption(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})

	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %s", err)
	}
	defer ep.Close()

	if err := s.CreateNIC(321, loopback.New()); err != nil {
		t.Errorf("CreateNIC failed: %s", err)
	}

	// nicIDPtr is used instead of taking the address of NICID literals, which is
	// a compiler error.
	nicIDPtr := func(s tcpip.NICID) *tcpip.NICID {
		return &s
	}

	testActions := []struct {
		name                 string
		setBindToDevice      *tcpip.NICID
		setBindToDeviceError tcpip.Error
		getBindToDevice      int32
	}{
		{"GetDefaultValue", nil, nil, 0},
		{"BindToNonExistent", nicIDPtr(999), &tcpip.ErrUnknownDevice{}, 0},
		{"BindToExistent", nicIDPtr(321), nil, 321},
		{"UnbindToDevice", nicIDPtr(0), nil, 0},
	}
	for _, testAction := range testActions {
		t.Run(testAction.name, func(t *testing.T) {
			if testAction.setBindToDevice != nil {
				bindToDevice := int32(*testAction.setBindToDevice)
				if gotErr, wantErr := ep.SocketOptions().SetBindToDevice(bindToDevice), testAction.setBindToDeviceError; gotErr != wantErr {
					t.Errorf("got SetSockOpt(&%T(%d)) = %s, want = %s", bindToDevice, bindToDevice, gotErr, wantErr)
				}
			}
			bindToDevice := ep.SocketOptions().GetBindToDevice()
			if bindToDevice != testAction.getBindToDevice {
				t.Errorf("got bindToDevice = %d, want %d", bindToDevice, testAction.getBindToDevice)
			}
		})
	}
}

func makeStack() (*stack.Stack, tcpip.Error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	id := loopback.New()
	if testing.Verbose() {
		id = sniffer.New(id)
	}

	if err := s.CreateNIC(1, id); err != nil {
		return nil, err
	}

	for _, ct := range []struct {
		number  tcpip.NetworkProtocolNumber
		address tcpip.Address
	}{
		{ipv4.ProtocolNumber, context.StackAddr},
		{ipv6.ProtocolNumber, context.StackV6Addr},
	} {
		if err := s.AddAddress(1, ct.number, ct.address); err != nil {
			return nil, err
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	return s, nil
}

func TestSelfConnect(t *testing.T) {
	// This test ensures that intentional self-connects work. In particular,
	// it checks that if an endpoint binds to say 127.0.0.1:1000 then
	// connects to 127.0.0.1:1000, then it will be connected to itself, and
	// is able to send and receive data through the same endpoint.
	s, err := makeStack()
	if err != nil {
		t.Fatal(err)
	}

	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Register for notification, then start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.WritableEvents)
	defer wq.EventUnregister(&waitEntry)

	{
		err := ep.Connect(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort})
		if d := cmp.Diff(&tcpip.ErrConnectStarted{}, err); d != "" {
			t.Fatalf("ep.Connect(...) mismatch (-want +got):\n%s", d)
		}
	}

	<-notifyCh
	if err := ep.LastError(); err != nil {
		t.Fatalf("Connect failed: %s", err)
	}

	// Write something.
	data := []byte{1, 2, 3}
	var r bytes.Reader
	r.Reset(data)
	if _, err := ep.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Read back what was written.
	wq.EventUnregister(&waitEntry)
	wq.EventRegister(&waitEntry, waiter.ReadableEvents)
	ept := endpointTester{ep}
	rd := ept.CheckReadFull(t, len(data), notifyCh, 5*time.Second)

	if !bytes.Equal(data, rd) {
		t.Fatalf("got data = %v, want = %v", rd, data)
	}
}

func TestConnectAvoidsBoundPorts(t *testing.T) {
	addressTypes := func(t *testing.T, network string) []string {
		switch network {
		case "ipv4":
			return []string{"v4"}
		case "ipv6":
			return []string{"v6"}
		case "dual":
			return []string{"v6", "mapped"}
		default:
			t.Fatalf("unknown network: '%s'", network)
		}

		panic("unreachable")
	}

	address := func(t *testing.T, addressType string, isAny bool) tcpip.Address {
		switch addressType {
		case "v4":
			if isAny {
				return ""
			}
			return context.StackAddr
		case "v6":
			if isAny {
				return ""
			}
			return context.StackV6Addr
		case "mapped":
			if isAny {
				return context.V4MappedWildcardAddr
			}
			return context.StackV4MappedAddr
		default:
			t.Fatalf("unknown address type: '%s'", addressType)
		}

		panic("unreachable")
	}
	// This test ensures that Endpoint.Connect doesn't select already-bound ports.
	networks := []string{"ipv4", "ipv6", "dual"}
	for _, exhaustedNetwork := range networks {
		t.Run(fmt.Sprintf("exhaustedNetwork=%s", exhaustedNetwork), func(t *testing.T) {
			for _, exhaustedAddressType := range addressTypes(t, exhaustedNetwork) {
				t.Run(fmt.Sprintf("exhaustedAddressType=%s", exhaustedAddressType), func(t *testing.T) {
					for _, isAny := range []bool{false, true} {
						t.Run(fmt.Sprintf("isAny=%t", isAny), func(t *testing.T) {
							for _, candidateNetwork := range networks {
								t.Run(fmt.Sprintf("candidateNetwork=%s", candidateNetwork), func(t *testing.T) {
									for _, candidateAddressType := range addressTypes(t, candidateNetwork) {
										t.Run(fmt.Sprintf("candidateAddressType=%s", candidateAddressType), func(t *testing.T) {
											s, err := makeStack()
											if err != nil {
												t.Fatal(err)
											}

											var wq waiter.Queue
											var eps []tcpip.Endpoint
											defer func() {
												for _, ep := range eps {
													ep.Close()
												}
											}()
											makeEP := func(network string) tcpip.Endpoint {
												var networkProtocolNumber tcpip.NetworkProtocolNumber
												switch network {
												case "ipv4":
													networkProtocolNumber = ipv4.ProtocolNumber
												case "ipv6", "dual":
													networkProtocolNumber = ipv6.ProtocolNumber
												default:
													t.Fatalf("unknown network: '%s'", network)
												}
												ep, err := s.NewEndpoint(tcp.ProtocolNumber, networkProtocolNumber, &wq)
												if err != nil {
													t.Fatalf("NewEndpoint failed: %s", err)
												}
												eps = append(eps, ep)
												switch network {
												case "ipv4":
												case "ipv6":
													ep.SocketOptions().SetV6Only(true)
												case "dual":
													ep.SocketOptions().SetV6Only(false)
												default:
													t.Fatalf("unknown network: '%s'", network)
												}
												return ep
											}

											var v4reserved, v6reserved bool
											switch exhaustedAddressType {
											case "v4", "mapped":
												v4reserved = true
											case "v6":
												v6reserved = true
												// Dual stack sockets bound to v6 any reserve on v4 as
												// well.
												if isAny {
													switch exhaustedNetwork {
													case "ipv6":
													case "dual":
														v4reserved = true
													default:
														t.Fatalf("unknown address type: '%s'", exhaustedNetwork)
													}
												}
											default:
												t.Fatalf("unknown address type: '%s'", exhaustedAddressType)
											}
											var collides bool
											switch candidateAddressType {
											case "v4", "mapped":
												collides = v4reserved
											case "v6":
												collides = v6reserved
											default:
												t.Fatalf("unknown address type: '%s'", candidateAddressType)
											}

											const (
												start = 16000
												end   = 16050
											)
											if err := s.SetPortRange(start, end); err != nil {
												t.Fatalf("got s.SetPortRange(%d, %d) = %s, want = nil", start, end, err)
											}
											for i := start; i <= end; i++ {
												if makeEP(exhaustedNetwork).Bind(tcpip.FullAddress{Addr: address(t, exhaustedAddressType, isAny), Port: uint16(i)}); err != nil {
													t.Fatalf("Bind(%d) failed: %s", i, err)
												}
											}
											var want tcpip.Error = &tcpip.ErrConnectStarted{}
											if collides {
												want = &tcpip.ErrNoPortAvailable{}
											}
											if err := makeEP(candidateNetwork).Connect(tcpip.FullAddress{Addr: address(t, candidateAddressType, false), Port: 31337}); err != want {
												t.Fatalf("got ep.Connect(..) = %s, want = %s", err, want)
											}
										})
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func TestPathMTUDiscovery(t *testing.T) {
	// This test verifies the stack retransmits packets after it receives an
	// ICMP packet indicating that the path MTU has been exceeded.
	c := context.New(t, 1500)
	defer c.Cleanup()

	// Create new connection with MSS of 1460.
	const maxPayload = 1500 - header.TCPMinimumSize - header.IPv4MinimumSize
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	})

	// Send 3200 bytes of data.
	const writeSize = 3200
	data := make([]byte, writeSize)
	for i := range data {
		data[i] = byte(i)
	}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	receivePackets := func(c *context.Context, sizes []int, which int, seqNum uint32) []byte {
		var ret []byte
		iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
		for i, size := range sizes {
			p := c.GetPacket()
			if i == which {
				ret = p
			}
			checker.IPv4(t, p,
				checker.PayloadLen(size+header.TCPMinimumSize),
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.TCPSeqNum(seqNum),
					checker.TCPAckNum(uint32(iss)),
					checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
				),
			)
			seqNum += uint32(size)
		}
		return ret
	}

	// Receive three packets.
	sizes := []int{maxPayload, maxPayload, writeSize - 2*maxPayload}
	first := receivePackets(c, sizes, 0, uint32(c.IRS)+1)

	// Send "packet too big" messages back to netstack.
	const newMTU = 1200
	const newMaxPayload = newMTU - header.IPv4MinimumSize - header.TCPMinimumSize
	mtu := []byte{0, 0, newMTU / 256, newMTU % 256}
	c.SendICMPPacket(header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, mtu, first, newMTU)

	// See retransmitted packets. None exceeding the new max.
	sizes = []int{newMaxPayload, maxPayload - newMaxPayload, newMaxPayload, maxPayload - newMaxPayload, writeSize - 2*maxPayload}
	receivePackets(c, sizes, -1, uint32(c.IRS)+1)
}

func TestTCPEndpointProbe(t *testing.T) {
	c := context.New(t, 1500)
	defer c.Cleanup()

	invoked := make(chan struct{})
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
		// Validate that the endpoint ID is what we expect.
		//
		// We don't do an extensive validation of every field but a
		// basic sanity test.
		if got, want := state.ID.LocalAddress, tcpip.Address(context.StackAddr); got != want {
			t.Fatalf("got LocalAddress: %q, want: %q", got, want)
		}
		if got, want := state.ID.LocalPort, c.Port; got != want {
			t.Fatalf("got LocalPort: %d, want: %d", got, want)
		}
		if got, want := state.ID.RemoteAddress, tcpip.Address(context.TestAddr); got != want {
			t.Fatalf("got RemoteAddress: %q, want: %q", got, want)
		}
		if got, want := state.ID.RemotePort, uint16(context.TestPort); got != want {
			t.Fatalf("got RemotePort: %d, want: %d", got, want)
		}

		invoked <- struct{}{}
	})

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	data := []byte{1, 2, 3}
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	select {
	case <-invoked:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("TCP Probe function was not called")
	}
}

func TestStackSetCongestionControl(t *testing.T) {
	testCases := []struct {
		cc  tcpip.CongestionControlOption
		err tcpip.Error
	}{
		{"reno", nil},
		{"cubic", nil},
		{"blahblah", &tcpip.ErrNoSuchFile{}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("SetTransportProtocolOption(.., %v)", tc.cc), func(t *testing.T) {
			c := context.New(t, 1500)
			defer c.Cleanup()

			s := c.Stack()

			var oldCC tcpip.CongestionControlOption
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &oldCC); err != nil {
				t.Fatalf("s.TransportProtocolOption(%v, %v) = %s", tcp.ProtocolNumber, &oldCC, err)
			}

			if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tc.cc); err != tc.err {
				t.Fatalf("s.SetTransportProtocolOption(%d, &%T(%s)) = %s, want = %s", tcp.ProtocolNumber, tc.cc, tc.cc, err, tc.err)
			}

			var cc tcpip.CongestionControlOption
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
				t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &cc, err)
			}

			got, want := cc, oldCC
			// If SetTransportProtocolOption is expected to succeed
			// then the returned value for congestion control should
			// match the one specified in the
			// SetTransportProtocolOption call above, else it should
			// be what it was before the call to
			// SetTransportProtocolOption.
			if tc.err == nil {
				want = tc.cc
			}
			if got != want {
				t.Fatalf("got congestion control: %v, want: %v", got, want)
			}
		})
	}
}

func TestStackAvailableCongestionControl(t *testing.T) {
	c := context.New(t, 1500)
	defer c.Cleanup()

	s := c.Stack()

	// Query permitted congestion control algorithms.
	var aCC tcpip.TCPAvailableCongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &aCC); err != nil {
		t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &aCC, err)
	}
	if got, want := aCC, tcpip.TCPAvailableCongestionControlOption("reno cubic"); got != want {
		t.Fatalf("got tcpip.TCPAvailableCongestionControlOption: %v, want: %v", got, want)
	}
}

func TestStackSetAvailableCongestionControl(t *testing.T) {
	c := context.New(t, 1500)
	defer c.Cleanup()

	s := c.Stack()

	// Setting AvailableCongestionControlOption should fail.
	aCC := tcpip.TCPAvailableCongestionControlOption("xyz")
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &aCC); err == nil {
		t.Fatalf("s.SetTransportProtocolOption(%d, &%T(%s)) = nil, want non-nil", tcp.ProtocolNumber, aCC, aCC)
	}

	// Verify that we still get the expected list of congestion control options.
	var cc tcpip.TCPAvailableCongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
		t.Fatalf("s.TransportProtocolOptio(%d, &%T(%s)): %s", tcp.ProtocolNumber, cc, cc, err)
	}
	if got, want := cc, tcpip.TCPAvailableCongestionControlOption("reno cubic"); got != want {
		t.Fatalf("got tcpip.TCPAvailableCongestionControlOption = %s, want = %s", got, want)
	}
}

func TestEndpointSetCongestionControl(t *testing.T) {
	testCases := []struct {
		cc  tcpip.CongestionControlOption
		err tcpip.Error
	}{
		{"reno", nil},
		{"cubic", nil},
		{"blahblah", &tcpip.ErrNoSuchFile{}},
	}

	for _, connected := range []bool{false, true} {
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("SetSockOpt(.., %v) w/ connected = %v", tc.cc, connected), func(t *testing.T) {
				c := context.New(t, 1500)
				defer c.Cleanup()

				// Create TCP endpoint.
				var err tcpip.Error
				c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
				if err != nil {
					t.Fatalf("NewEndpoint failed: %s", err)
				}

				var oldCC tcpip.CongestionControlOption
				if err := c.EP.GetSockOpt(&oldCC); err != nil {
					t.Fatalf("c.EP.GetSockOpt(&%T) = %s", oldCC, err)
				}

				if connected {
					c.Connect(context.TestInitialSequenceNumber, 32768 /* rcvWnd */, nil)
				}

				if err := c.EP.SetSockOpt(&tc.cc); err != tc.err {
					t.Fatalf("got c.EP.SetSockOpt(&%#v) = %s, want %s", tc.cc, err, tc.err)
				}

				var cc tcpip.CongestionControlOption
				if err := c.EP.GetSockOpt(&cc); err != nil {
					t.Fatalf("c.EP.GetSockOpt(&%T): %s", cc, err)
				}

				got, want := cc, oldCC
				// If SetSockOpt is expected to succeed then the
				// returned value for congestion control should match
				// the one specified in the SetSockOpt above, else it
				// should be what it was before the call to SetSockOpt.
				if tc.err == nil {
					want = tc.cc
				}
				if got != want {
					t.Fatalf("got congestion control = %+v, want = %+v", got, want)
				}
			})
		}
	}
}

func enableCUBIC(t *testing.T, c *context.Context) {
	t.Helper()
	opt := tcpip.CongestionControlOption("cubic")
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%s)) %s", tcp.ProtocolNumber, opt, opt, err)
	}
}

func TestKeepalive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	const keepAliveIdle = 100 * time.Millisecond
	const keepAliveInterval = 3 * time.Second
	keepAliveIdleOpt := tcpip.KeepaliveIdleOption(keepAliveIdle)
	if err := c.EP.SetSockOpt(&keepAliveIdleOpt); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", keepAliveIdleOpt, keepAliveIdle, err)
	}
	keepAliveIntervalOpt := tcpip.KeepaliveIntervalOption(keepAliveInterval)
	if err := c.EP.SetSockOpt(&keepAliveIntervalOpt); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", keepAliveIntervalOpt, keepAliveInterval, err)
	}
	c.EP.SetSockOptInt(tcpip.KeepaliveCountOption, 5)
	if err := c.EP.SetSockOptInt(tcpip.KeepaliveCountOption, 5); err != nil {
		t.Fatalf("c.EP.SetSockOptInt(tcpip.KeepaliveCountOption, 5): %s", err)
	}
	c.EP.SocketOptions().SetKeepAlive(true)

	// 5 unacked keepalives are sent. ACK each one, and check that the
	// connection stays alive after 5.
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for i := 0; i < 10; i++ {
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)

		// Acknowledge the keepalive.
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss,
			AckNum:  c.IRS,
			RcvWnd:  30000,
		})
	}

	// Check that the connection is still alive.
	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Send some data and wait before ACKing it. Keepalives should be disabled
	// during this period.
	view := make([]byte, 3)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	next := uint32(c.IRS) + 1
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Wait for the packet to be retransmitted. Verify that no keepalives
	// were sent.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagPsh),
		),
	)
	c.CheckNoPacket("Keepalive packet received while unACKed data is pending")

	next += uint32(len(view))

	// Send ACK. Keepalives should start sending again.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Now receive 5 keepalives, but don't ACK them. The connection
	// should be reset after 5.
	for i := 0; i < 5; i++ {
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(next-1),
				checker.TCPAckNum(uint32(iss)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Sleep for a litte over the KeepAlive interval to make sure
	// the timer has time to fire after the last ACK and close the
	// close the socket.
	time.Sleep(keepAliveInterval + keepAliveInterval/2)

	// The connection should be terminated after 5 unacked keepalives.
	// Send an ACK to trigger a RST from the stack as the endpoint should
	// be dead.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(checker.DstPort(context.TestPort), checker.TCPSeqNum(next), checker.TCPAckNum(uint32(0)), checker.TCPFlags(header.TCPFlagRst)),
	)

	if got := c.Stack().Stats().TCP.EstablishedTimedout.Value(); got != 1 {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedTimedout.Value() = %d, want = 1", got)
	}

	ept.CheckReadError(t, &tcpip.ErrTimeout{})

	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

func executeHandshake(t *testing.T, c *context.Context, srcPort uint16, synCookieInUse bool) (irs, iss seqnum.Value) {
	t.Helper()
	// Send a SYN request.
	irs = seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: srcPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	iss = seqnum.Value(tcp.SequenceNumber())
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(srcPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs) + 1),
	}

	if synCookieInUse {
		// When cookies are in use window scaling is disabled.
		tcpCheckers = append(tcpCheckers, checker.TCPSynOptions(header.TCPSynOptions{
			WS:  -1,
			MSS: c.MSSWithoutOptions(),
		}))
	}

	checker.IPv4(t, b, checker.TCP(tcpCheckers...))

	// Send ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: srcPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})
	return irs, iss
}

func executeV6Handshake(t *testing.T, c *context.Context, srcPort uint16, synCookieInUse bool) (irs, iss seqnum.Value) {
	t.Helper()
	// Send a SYN request.
	irs = seqnum.Value(context.TestInitialSequenceNumber)
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: srcPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetV6Packet()
	tcp := header.TCP(header.IPv6(b).Payload())
	iss = seqnum.Value(tcp.SequenceNumber())
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(srcPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs) + 1),
	}

	if synCookieInUse {
		// When cookies are in use window scaling is disabled.
		tcpCheckers = append(tcpCheckers, checker.TCPSynOptions(header.TCPSynOptions{
			WS:  -1,
			MSS: c.MSSWithoutOptionsV6(),
		}))
	}

	checker.IPv6(t, b, checker.TCP(tcpCheckers...))

	// Send ACK.
	c.SendV6Packet(nil, &context.Headers{
		SrcPort: srcPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})
	return irs, iss
}

// TestListenBacklogFull tests that netstack does not complete handshakes if the
// listen backlog for the endpoint is full.
func TestListenBacklogFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	// Start listening.
	listenBacklog := 10
	if err := c.EP.Listen(listenBacklog); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	lastPortOffset := uint16(0)
	for ; int(lastPortOffset) < listenBacklog; lastPortOffset++ {
		executeHandshake(t, c, context.TestPort+lastPortOffset, false /*synCookieInUse */)
	}

	time.Sleep(50 * time.Millisecond)

	// Now execute send one more SYN. The stack should not respond as the backlog
	// is full at this point.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort + lastPortOffset,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(context.TestInitialSequenceNumber),
		RcvWnd:  30000,
	})
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Try to accept the connections in the backlog.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	for i := 0; i < listenBacklog; i++ {
		_, _, err = c.EP.Accept(nil)
		if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
			// Wait for connection to be established.
			select {
			case <-ch:
				_, _, err = c.EP.Accept(nil)
				if err != nil {
					t.Fatalf("Accept failed: %s", err)
				}

			case <-time.After(1 * time.Second):
				t.Fatalf("Timed out waiting for accept")
			}
		}
	}

	// Now verify that there are no more connections that can be accepted.
	_, _, err = c.EP.Accept(nil)
	if !cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		select {
		case <-ch:
			t.Fatalf("unexpected endpoint delivered on Accept: %+v", c.EP)
		case <-time.After(1 * time.Second):
		}
	}

	// Now a new handshake must succeed.
	executeHandshake(t, c, context.TestPort+lastPortOffset, false /*synCookieInUse */)

	newEP, _, err := c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			newEP, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that the TCP socket is usable and in a connected state.
	data := "Don't panic"
	var r strings.Reader
	r.Reset(data)
	newEP.Write(&r, tcpip.WriteOptions{})
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	if string(tcp.Payload()) != data {
		t.Fatalf("unexpected data: got %s, want %s", string(tcp.Payload()), data)
	}
}

// TestListenNoAcceptMulticastBroadcastV4 makes sure that TCP segments with a
// non unicast IPv4 address are not accepted.
func TestListenNoAcceptNonUnicastV4(t *testing.T) {
	multicastAddr := tcpiptestutil.MustParse4("224.0.1.2")
	otherMulticastAddr := tcpiptestutil.MustParse4("224.0.1.3")
	subnet := context.StackAddrWithPrefix.Subnet()
	subnetBroadcastAddr := subnet.Broadcast()

	tests := []struct {
		name    string
		srcAddr tcpip.Address
		dstAddr tcpip.Address
	}{
		{
			name:    "SourceUnspecified",
			srcAddr: header.IPv4Any,
			dstAddr: context.StackAddr,
		},
		{
			name:    "SourceBroadcast",
			srcAddr: header.IPv4Broadcast,
			dstAddr: context.StackAddr,
		},
		{
			name:    "SourceOurMulticast",
			srcAddr: multicastAddr,
			dstAddr: context.StackAddr,
		},
		{
			name:    "SourceOtherMulticast",
			srcAddr: otherMulticastAddr,
			dstAddr: context.StackAddr,
		},
		{
			name:    "DestUnspecified",
			srcAddr: context.TestAddr,
			dstAddr: header.IPv4Any,
		},
		{
			name:    "DestBroadcast",
			srcAddr: context.TestAddr,
			dstAddr: header.IPv4Broadcast,
		},
		{
			name:    "DestOurMulticast",
			srcAddr: context.TestAddr,
			dstAddr: multicastAddr,
		},
		{
			name:    "DestOtherMulticast",
			srcAddr: context.TestAddr,
			dstAddr: otherMulticastAddr,
		},
		{
			name:    "SrcSubnetBroadcast",
			srcAddr: subnetBroadcastAddr,
			dstAddr: context.StackAddr,
		},
		{
			name:    "DestSubnetBroadcast",
			srcAddr: context.TestAddr,
			dstAddr: subnetBroadcastAddr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.Create(-1)

			if err := c.Stack().JoinGroup(header.IPv4ProtocolNumber, 1, multicastAddr); err != nil {
				t.Fatalf("JoinGroup failed: %s", err)
			}

			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				t.Fatalf("Bind failed: %s", err)
			}

			if err := c.EP.Listen(1); err != nil {
				t.Fatalf("Listen failed: %s", err)
			}

			irs := seqnum.Value(context.TestInitialSequenceNumber)
			c.SendPacketWithAddrs(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: context.StackPort,
				Flags:   header.TCPFlagSyn,
				SeqNum:  irs,
				RcvWnd:  30000,
			}, test.srcAddr, test.dstAddr)
			c.CheckNoPacket("Should not have received a response")

			// Handle normal packet.
			c.SendPacketWithAddrs(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: context.StackPort,
				Flags:   header.TCPFlagSyn,
				SeqNum:  irs,
				RcvWnd:  30000,
			}, context.TestAddr, context.StackAddr)
			checker.IPv4(t, c.GetPacket(),
				checker.TCP(
					checker.SrcPort(context.StackPort),
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
					checker.TCPAckNum(uint32(irs)+1)))
		})
	}
}

// TestListenNoAcceptMulticastBroadcastV6 makes sure that TCP segments with a
// non unicast IPv6 address are not accepted.
func TestListenNoAcceptNonUnicastV6(t *testing.T) {
	multicastAddr := tcpiptestutil.MustParse6("ff0e::101")
	otherMulticastAddr := tcpiptestutil.MustParse6("ff0e::102")

	tests := []struct {
		name    string
		srcAddr tcpip.Address
		dstAddr tcpip.Address
	}{
		{
			"SourceUnspecified",
			header.IPv6Any,
			context.StackV6Addr,
		},
		{
			"SourceAllNodes",
			header.IPv6AllNodesMulticastAddress,
			context.StackV6Addr,
		},
		{
			"SourceOurMulticast",
			multicastAddr,
			context.StackV6Addr,
		},
		{
			"SourceOtherMulticast",
			otherMulticastAddr,
			context.StackV6Addr,
		},
		{
			"DestUnspecified",
			context.TestV6Addr,
			header.IPv6Any,
		},
		{
			"DestAllNodes",
			context.TestV6Addr,
			header.IPv6AllNodesMulticastAddress,
		},
		{
			"DestOurMulticast",
			context.TestV6Addr,
			multicastAddr,
		},
		{
			"DestOtherMulticast",
			context.TestV6Addr,
			otherMulticastAddr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateV6Endpoint(true)

			if err := c.Stack().JoinGroup(header.IPv6ProtocolNumber, 1, multicastAddr); err != nil {
				t.Fatalf("JoinGroup failed: %s", err)
			}

			if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
				t.Fatalf("Bind failed: %s", err)
			}

			if err := c.EP.Listen(1); err != nil {
				t.Fatalf("Listen failed: %s", err)
			}

			irs := seqnum.Value(context.TestInitialSequenceNumber)
			c.SendV6PacketWithAddrs(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: context.StackPort,
				Flags:   header.TCPFlagSyn,
				SeqNum:  irs,
				RcvWnd:  30000,
			}, test.srcAddr, test.dstAddr)
			c.CheckNoPacket("Should not have received a response")

			// Handle normal packet.
			c.SendV6PacketWithAddrs(nil, &context.Headers{
				SrcPort: context.TestPort,
				DstPort: context.StackPort,
				Flags:   header.TCPFlagSyn,
				SeqNum:  irs,
				RcvWnd:  30000,
			}, context.TestV6Addr, context.StackV6Addr)
			checker.IPv6(t, c.GetV6Packet(),
				checker.TCP(
					checker.SrcPort(context.StackPort),
					checker.DstPort(context.TestPort),
					checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
					checker.TCPAckNum(uint32(irs)+1)))
		})
	}
}

func TestListenSynRcvdQueueFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Test acceptance.
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send two SYN's the first one should get a SYN-ACK, the
	// second one should not get any response and is dropped as
	// the accept queue is full.
	irs := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs) + 1),
	}
	checker.IPv4(t, b, checker.TCP(tcpCheckers...))

	// Now complete the previous connection.
	// Send ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	// Verify if that is delivered to the accept queue.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)
	<-ch

	// Now execute send one more SYN. The stack should not respond as the backlog
	// is full at this point.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort + 1,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(889),
		RcvWnd:  30000,
	})
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Try to accept the connections in the backlog.
	newEP, _, err := c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			newEP, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that the TCP socket is usable and in a connected state.
	data := "Don't panic"
	var r strings.Reader
	r.Reset(data)
	newEP.Write(&r, tcpip.WriteOptions{})
	pkt := c.GetPacket()
	tcp = header.IPv4(pkt).Payload()
	if string(tcp.Payload()) != data {
		t.Fatalf("unexpected data: got %s, want %s", string(tcp.Payload()), data)
	}
}

func TestListenBacklogFullSynCookieInUse(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Test for SynCookies usage after filling up the backlog.
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	executeHandshake(t, c, context.TestPort, false)

	// Wait for this to be delivered to the accept queue.
	time.Sleep(50 * time.Millisecond)

	// Send a SYN request.
	irs := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		// pick a different src port for new SYN.
		SrcPort: context.TestPort + 1,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})
	// The Syn should be dropped as the endpoint's backlog is full.
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Verify that there is only one acceptable connection at this point.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	_, _, err = c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that there are no more connections that can be accepted.
	_, _, err = c.EP.Accept(nil)
	if !cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		select {
		case <-ch:
			t.Fatalf("unexpected endpoint delivered on Accept: %+v", c.EP)
		case <-time.After(1 * time.Second):
		}
	}
}

func TestSYNRetransmit(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Start listening.
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send the same SYN packet multiple times. We should still get a valid SYN-ACK
	// reply.
	irs := seqnum.Value(context.TestInitialSequenceNumber)
	for i := 0; i < 5; i++ {
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  irs,
			RcvWnd:  30000,
		})
	}

	// Receive the SYN-ACK reply.
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs) + 1),
	}
	checker.IPv4(t, c.GetPacket(), checker.TCP(tcpCheckers...))
}

func TestSynRcvdBadSeqNumber(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	// Start listening.
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN to get a SYN-ACK. This should put the ep into SYN-RCVD state
	irs := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	iss := seqnum.Value(tcpHdr.SequenceNumber())
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs) + 1),
	}
	checker.IPv4(t, b, checker.TCP(tcpCheckers...))

	// Now send a packet with an out-of-window sequence number
	largeSeqnum := irs + seqnum.Value(tcpHdr.WindowSize()) + 1
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  largeSeqnum,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	// Should receive an ACK with the expected SEQ number
	b = c.GetPacket()
	tcpCheckers = []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPAckNum(uint32(irs) + 1),
		checker.TCPSeqNum(uint32(iss + 1)),
	}
	checker.IPv4(t, b, checker.TCP(tcpCheckers...))

	// Now that the socket replied appropriately with the ACK,
	// complete the connection to test that the large SEQ num
	// did not change the state from SYN-RCVD.

	// Send ACK to move to ESTABLISHED state.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	newEP, _, err := c.EP.Accept(nil)
	switch err.(type) {
	case nil, *tcpip.ErrWouldBlock:
	default:
		t.Fatalf("Accept failed: %s", err)
	}

	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Try to accept the connections in the backlog.
		we, ch := waiter.NewChannelEntry(nil)
		c.WQ.EventRegister(&we, waiter.ReadableEvents)
		defer c.WQ.EventUnregister(&we)

		// Wait for connection to be established.
		<-ch
		newEP, _, err = c.EP.Accept(nil)
		if err != nil {
			t.Fatalf("Accept failed: %s", err)
		}
	}

	// Now verify that the TCP socket is usable and in a connected state.
	data := "Don't panic"
	var r strings.Reader
	r.Reset(data)
	if _, err := newEP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	pkt := c.GetPacket()
	tcpHdr = header.IPv4(pkt).Payload()
	if string(tcpHdr.Payload()) != data {
		t.Fatalf("unexpected data: got %s, want %s", string(tcpHdr.Payload()), data)
	}
}

func TestPassiveConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	c.EP = ep
	if err := ep.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateBound; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateListen; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	stats := c.Stack().Stats()
	want := stats.TCP.PassiveConnectionOpenings.Value() + 1

	srcPort := uint16(context.TestPort)
	executeHandshake(t, c, srcPort+1, false)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	// Verify that there is only one acceptable connection at this point.
	_, _, err = c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	if got := stats.TCP.PassiveConnectionOpenings.Value(); got != want {
		t.Errorf("got stats.TCP.PassiveConnectionOpenings.Value() = %d, want = %d", got, want)
	}
}

func TestPassiveFailedConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	c.EP = ep
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	srcPort := uint16(context.TestPort)
	// Now attempt a handshakes it will fill up the accept backlog.
	executeHandshake(t, c, srcPort, false)

	// Give time for the final ACK to be processed as otherwise the next handshake could
	// get accepted before the previous one based on goroutine scheduling.
	time.Sleep(50 * time.Millisecond)

	want := stats.TCP.ListenOverflowSynDrop.Value() + 1

	// Now we will send one more SYN and this one should get dropped
	// Send a SYN request.
	c.SendPacket(nil, &context.Headers{
		SrcPort: srcPort + 2,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(context.TestInitialSequenceNumber),
		RcvWnd:  30000,
	})

	checkValid := func() []error {
		var errors []error
		if got := stats.TCP.ListenOverflowSynDrop.Value(); got != want {
			errors = append(errors, fmt.Errorf("got stats.TCP.ListenOverflowSynDrop.Value() = %d, want = %d", got, want))
		}
		if got := c.EP.Stats().(*tcp.Stats).ReceiveErrors.ListenOverflowSynDrop.Value(); got != want {
			errors = append(errors, fmt.Errorf("got EP stats Stats.ReceiveErrors.ListenOverflowSynDrop = %d, want = %d", got, want))
		}
		return errors
	}

	start := time.Now()
	for time.Since(start) < time.Minute && len(checkValid()) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	for _, err := range checkValid() {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.ReadableEvents)
	defer c.WQ.EventUnregister(&we)

	// Now check that there is one acceptable connections.
	_, _, err = c.EP.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		<-ch
		_, _, err = c.EP.Accept(nil)
		if err != nil {
			t.Fatalf("Accept failed: %s", err)
		}
	}
}

func TestListenDropIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	c.Create(-1 /*epRcvBuf*/)

	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if err := c.EP.Listen(1 /*backlog*/); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	initialDropped := stats.DroppedPackets.Value()

	// Send RST, FIN segments, that are expected to be dropped by the listener.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagRst,
	})
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagFin,
	})

	// To ensure that the RST, FIN sent earlier are indeed received and ignored
	// by the listener, send a SYN and wait for the SYN to be ACKd.
	irs := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
	})
	checker.IPv4(t, c.GetPacket(), checker.TCP(checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs)+1),
	))

	if got, want := stats.DroppedPackets.Value(), initialDropped+2; got != want {
		t.Fatalf("got stats.DroppedPackets.Value() = %d, want = %d", got, want)
	}
}

func TestEndpointBindListenAcceptState(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateBound; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	ept := endpointTester{ep}
	ept.CheckReadError(t, &tcpip.ErrNotConnected{})
	if got := ep.Stats().(*tcp.Stats).ReadErrors.NotConnected.Value(); got != 1 {
		t.Errorf("got EP stats Stats.ReadErrors.NotConnected got %d want %d", got, 1)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateListen; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	c.PassiveConnectWithOptions(100, 5, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	aep, _, err := ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			aep, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}
	if got, want := tcp.EndpointState(aep.State()), tcp.StateEstablished; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}
	{
		err := aep.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
		if d := cmp.Diff(&tcpip.ErrAlreadyConnected{}, err); d != "" {
			t.Errorf("Connect(...) mismatch (-want +got):\n%s", d)
		}
	}
	// Listening endpoint remains in listen state.
	if got, want := tcp.EndpointState(ep.State()), tcp.StateListen; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

	ep.Close()
	// Give worker goroutines time to receive the close notification.
	time.Sleep(1 * time.Second)
	if got, want := tcp.EndpointState(ep.State()), tcp.StateClose; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}
	// Accepted endpoint remains open when the listen endpoint is closed.
	if got, want := tcp.EndpointState(aep.State()), tcp.StateEstablished; got != want {
		t.Errorf("unexpected endpoint state: want %s, got %s", want, got)
	}

}

// This test verifies that the auto tuning does not grow the receive buffer if
// the application is not reading the data actively.
func TestReceiveBufferAutoTuningApplicationLimited(t *testing.T) {
	const mtu = 1500
	const mss = mtu - header.IPv4MinimumSize - header.TCPMinimumSize

	c := context.New(t, mtu)
	defer c.Cleanup()

	stk := c.Stack()
	// Set lower limits for auto-tuning tests. This is required because the
	// test stops the worker which can cause packets to be dropped because
	// the segment queue holding unprocessed packets is limited to 500.
	const receiveBufferSize = 80 << 10 // 80KB.
	const maxReceiveBufferSize = receiveBufferSize * 10
	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: receiveBufferSize, Max: maxReceiveBufferSize}
		if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	// Enable auto-tuning.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}
	// Change the expected window scale to match the value needed for the
	// maximum buffer size defined above.
	c.WindowScale = uint8(tcp.FindWndScale(maxReceiveBufferSize))

	rawEP := c.CreateConnectedWithOptions(header.TCPSynOptions{TS: true, WS: 4})

	// NOTE: The timestamp values in the sent packets are meaningless to the
	// peer so we just increment the timestamp value by 1 every batch as we
	// are not really using them for anything. Send a single byte to verify
	// the advertised window.
	tsVal := rawEP.TSVal + 1

	// Introduce a 25ms latency by delaying the first byte.
	latency := 25 * time.Millisecond
	time.Sleep(latency)
	// Send an initial payload with atleast segment overhead size. The receive
	// window would not grow for smaller segments.
	rawEP.SendPacketWithTS(make([]byte, tcp.SegSize), tsVal)

	pkt := rawEP.VerifyAndReturnACKWithTS(tsVal)
	rcvWnd := header.TCP(header.IPv4(pkt).Payload()).WindowSize()

	time.Sleep(25 * time.Millisecond)

	// Allocate a large enough payload for the test.
	payloadSize := receiveBufferSize * 2
	b := make([]byte, payloadSize)

	worker := (c.EP).(interface {
		StopWork()
		ResumeWork()
	})
	tsVal++

	// Stop the worker goroutine.
	worker.StopWork()
	start := 0
	end := payloadSize / 2
	packetsSent := 0
	for ; start < end; start += mss {
		packetEnd := start + mss
		if start+mss > end {
			packetEnd = end
		}
		rawEP.SendPacketWithTS(b[start:packetEnd], tsVal)
		packetsSent++
	}

	// Resume the worker so that it only sees the packets once all of them
	// are waiting to be read.
	worker.ResumeWork()

	// Since we sent almost the full receive buffer worth of data (some may have
	// been dropped due to segment overheads), we should get a zero window back.
	pkt = c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(pkt).Payload())
	gotRcvWnd := tcpHdr.WindowSize()
	wantAckNum := tcpHdr.AckNumber()
	if got, want := int(gotRcvWnd), 0; got != want {
		t.Fatalf("got rcvWnd: %d, want: %d", got, want)
	}

	time.Sleep(25 * time.Millisecond)
	// Verify that sending more data when receiveBuffer is exhausted.
	rawEP.SendPacketWithTS(b[start:start+mss], tsVal)

	// Now read all the data from the endpoint and verify that advertised
	// window increases to the full available buffer size.
	for {
		_, err := c.EP.Read(ioutil.Discard, tcpip.ReadOptions{})
		if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
			break
		}
	}

	// Verify that we receive a non-zero window update ACK. When running
	// under thread santizer this test can end up sending more than 1
	// ack, 1 for the non-zero window
	p := c.GetPacket()
	checker.IPv4(t, p, checker.TCP(
		checker.TCPAckNum(wantAckNum),
		func(t *testing.T, h header.Transport) {
			tcp, ok := h.(header.TCP)
			if !ok {
				return
			}
			// We use 10% here as the error margin upwards as the initial window we
			// got was afer 1 segment was already in the receive buffer queue.
			tolerance := 1.1
			if w := tcp.WindowSize(); w == 0 || w > uint16(float64(rcvWnd)*tolerance) {
				t.Errorf("expected a non-zero window: got %d, want <= %d", w, uint16(float64(rcvWnd)*tolerance))
			}
		},
	))
}

// This test verifies that the advertised window is auto-tuned up as the
// application is reading the data that is being received.
func TestReceiveBufferAutoTuning(t *testing.T) {
	const mtu = 1500
	const mss = mtu - header.IPv4MinimumSize - header.TCPMinimumSize

	c := context.New(t, mtu)
	defer c.Cleanup()

	// Enable Auto-tuning.
	stk := c.Stack()
	// Disable out of window rate limiting for this test by setting it to 0 as we
	// use out of window ACKs to measure the advertised window.
	var tcpInvalidRateLimit stack.TCPInvalidRateLimitOption
	if err := stk.SetOption(tcpInvalidRateLimit); err != nil {
		t.Fatalf("e.stack.SetOption(%#v) = %s", tcpInvalidRateLimit, err)
	}

	const receiveBufferSize = 80 << 10 // 80KB.
	const maxReceiveBufferSize = receiveBufferSize * 10
	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: receiveBufferSize, Max: maxReceiveBufferSize}
		if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%#v): %s", tcp.ProtocolNumber, opt, err)
		}
	}

	// Enable auto-tuning.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}
	// Change the expected window scale to match the value needed for the
	// maximum buffer size used by stack.
	c.WindowScale = uint8(tcp.FindWndScale(maxReceiveBufferSize))

	rawEP := c.CreateConnectedWithOptions(header.TCPSynOptions{TS: true, WS: 4})
	tsVal := rawEP.TSVal
	rawEP.NextSeqNum--
	rawEP.SendPacketWithTS(nil, tsVal)
	rawEP.NextSeqNum++
	pkt := rawEP.VerifyAndReturnACKWithTS(tsVal)
	curRcvWnd := int(header.TCP(header.IPv4(pkt).Payload()).WindowSize()) << c.WindowScale
	scaleRcvWnd := func(rcvWnd int) uint16 {
		return uint16(rcvWnd >> c.WindowScale)
	}
	// Allocate a large array to send to the endpoint.
	b := make([]byte, receiveBufferSize*48)

	// In every iteration we will send double the number of bytes sent in
	// the previous iteration and read the same from the app. The received
	// window should grow by at least 2x of bytes read by the app in every
	// RTT.
	offset := 0
	payloadSize := receiveBufferSize / 8
	worker := (c.EP).(interface {
		StopWork()
		ResumeWork()
	})
	latency := 1 * time.Millisecond
	for i := 0; i < 5; i++ {
		tsVal++

		// Stop the worker goroutine.
		worker.StopWork()
		start := offset
		end := offset + payloadSize
		totalSent := 0
		packetsSent := 0
		for ; start < end; start += mss {
			rawEP.SendPacketWithTS(b[start:start+mss], tsVal)
			totalSent += mss
			packetsSent++
		}

		// Resume it so that it only sees the packets once all of them
		// are waiting to be read.
		worker.ResumeWork()

		// Give 1ms for the worker to process the packets.
		time.Sleep(1 * time.Millisecond)

		lastACK := c.GetPacket()
		// Discard any intermediate ACKs and only check the last ACK we get in a
		// short time period of few ms.
		for {
			time.Sleep(1 * time.Millisecond)
			pkt := c.GetPacketNonBlocking()
			if pkt == nil {
				break
			}
			lastACK = pkt
		}
		if got, want := int(header.TCP(header.IPv4(lastACK).Payload()).WindowSize()), int(scaleRcvWnd(curRcvWnd)); got > want {
			t.Fatalf("advertised window got: %d, want <= %d", got, want)
		}

		// Now read all the data from the endpoint and invoke the
		// moderation API to allow for receive buffer auto-tuning
		// to happen before we measure the new window.
		totalCopied := 0
		for {
			res, err := c.EP.Read(ioutil.Discard, tcpip.ReadOptions{})
			if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
				break
			}
			totalCopied += res.Count
		}

		// Invoke the moderation API. This is required for auto-tuning
		// to happen. This method is normally expected to be invoked
		// from a higher layer than tcpip.Endpoint. So we simulate
		// copying to userspace by invoking it explicitly here.
		c.EP.ModerateRecvBuf(totalCopied)

		// Now send a keep-alive packet to trigger an ACK so that we can
		// measure the new window.
		rawEP.NextSeqNum--
		rawEP.SendPacketWithTS(nil, tsVal)
		rawEP.NextSeqNum++

		if i == 0 {
			// In the first iteration the receiver based RTT is not
			// yet known as a result the moderation code should not
			// increase the advertised window.
			rawEP.VerifyACKRcvWnd(scaleRcvWnd(curRcvWnd))
		} else {
			// Read loop above could generate an ACK if the window had dropped to
			// zero and then read had opened it up.
			lastACK := c.GetPacket()
			// Discard any intermediate ACKs and only check the last ACK we get in a
			// short time period of few ms.
			for {
				time.Sleep(1 * time.Millisecond)
				pkt := c.GetPacketNonBlocking()
				if pkt == nil {
					break
				}
				lastACK = pkt
			}
			curRcvWnd = int(header.TCP(header.IPv4(lastACK).Payload()).WindowSize()) << c.WindowScale
			// If thew new current window is close maxReceiveBufferSize then terminate
			// the loop. This can happen before all iterations are done due to timing
			// differences when running the test.
			if int(float64(curRcvWnd)*1.1) > maxReceiveBufferSize/2 {
				break
			}
			// Increase the latency after first two iterations to
			// establish a low RTT value in the receiver since it
			// only tracks the lowest value. This ensures that when
			// ModerateRcvBuf is called the elapsed time is always >
			// rtt. Without this the test is flaky due to delays due
			// to scheduling/wakeup etc.
			latency += 50 * time.Millisecond
		}
		time.Sleep(latency)
		offset += payloadSize
		payloadSize *= 2
	}
	// Check that at the end of our iterations the receive window grew close to the maximum
	// permissible size of maxReceiveBufferSize/2
	if got, want := int(float64(curRcvWnd)*1.1), maxReceiveBufferSize/2; got < want {
		t.Fatalf("unexpected rcvWnd got: %d, want > %d", got, want)
	}

}

func TestDelayEnabled(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	checkDelayOption(t, c, false, false) // Delay is disabled by default.

	for _, delayEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayEnabled=%t", delayEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()
			opt := tcpip.TCPDelayEnabled(delayEnabled)
			if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
				t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, delayEnabled, err)
			}
			checkDelayOption(t, c, opt, delayEnabled)
		})
	}
}

func checkDelayOption(t *testing.T, c *context.Context, wantDelayEnabled tcpip.TCPDelayEnabled, wantDelayOption bool) {
	t.Helper()

	var gotDelayEnabled tcpip.TCPDelayEnabled
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &gotDelayEnabled); err != nil {
		t.Fatalf("TransportProtocolOption(tcp, &gotDelayEnabled) failed: %s", err)
	}
	if gotDelayEnabled != wantDelayEnabled {
		t.Errorf("TransportProtocolOption(tcp, &gotDelayEnabled) got %t, want %t", gotDelayEnabled, wantDelayEnabled)
	}

	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, new(waiter.Queue))
	if err != nil {
		t.Fatalf("NewEndPoint(tcp, ipv4, new(waiter.Queue)) failed: %s", err)
	}
	gotDelayOption := ep.SocketOptions().GetDelayOption()
	if gotDelayOption != wantDelayOption {
		t.Errorf("ep.GetSockOptBool(tcpip.DelayOption) got: %t, want: %t", gotDelayOption, wantDelayOption)
	}
}

func TestTCPLingerTimeout(t *testing.T) {
	c := context.New(t, 1500 /* mtu */)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	testCases := []struct {
		name             string
		tcpLingerTimeout time.Duration
		want             time.Duration
	}{
		{"NegativeLingerTimeout", -123123, -1},
		// Zero is treated same as the stack's default TCP_LINGER2 timeout.
		{"ZeroLingerTimeout", 0, tcp.DefaultTCPLingerTimeout},
		{"InRangeLingerTimeout", 10 * time.Second, 10 * time.Second},
		// Values > stack's TCPLingerTimeout are capped to the stack's
		// value. Defaults to tcp.DefaultTCPLingerTimeout(60 seconds)
		{"AboveMaxLingerTimeout", tcp.MaxTCPLingerTimeout + 5*time.Second, tcp.MaxTCPLingerTimeout},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := tcpip.TCPLingerTimeoutOption(tc.tcpLingerTimeout)
			if err := c.EP.SetSockOpt(&v); err != nil {
				t.Fatalf("SetSockOpt(&%T(%s)) = %s", v, tc.tcpLingerTimeout, err)
			}

			v = 0
			if err := c.EP.GetSockOpt(&v); err != nil {
				t.Fatalf("GetSockOpt(&%T) = %s", v, err)
			}
			if got, want := time.Duration(v), tc.want; got != want {
				t.Fatalf("got linger timeout = %s, want = %s", got, want)
			}
		})
	}
}

func TestTCPTimeWaitRSTIgnored(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	c.EP.Close()
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// Now send a RST and this should be ignored and not
	// generate an ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})

	c.CheckNoPacketTimeout("unexpected packet received in TIME_WAIT state", 1*time.Second)

	// Out of order ACK should generate an immediate ACK in
	// TIME_WAIT.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 3,
	})

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))
}

func TestTCPTimeWaitOutOfOrder(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	c.EP.Close()
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// Out of order ACK should generate an immediate ACK in
	// TIME_WAIT.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 3,
	})

	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))
}

func TestTCPTimeWaitNewSyn(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	c.EP.Close()
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// Send a SYN request w/ sequence number lower than
	// the highest sequence number sent. We just reuse
	// the same number.
	iss = seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	c.CheckNoPacketTimeout("unexpected packet received in response to SYN", 1*time.Second)

	// drain any older notifications from the notification channel before attempting
	// 2nd connection.
	select {
	case <-ch:
	default:
	}

	// Send a SYN request w/ sequence number higher than
	// the highest sequence number sent.
	iss = iss.Add(3)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b = c.GetPacket()
	tcpHdr = header.IPv4(b).Payload()
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders = &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}
}

func TestTCPTimeWaitDuplicateFINExtendsTimeWait(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPTimeWaitTimeout to 5 seconds so that sockets are marked closed
	// after 5 seconds in TIME_WAIT state.
	tcpTimeWaitTimeout := 5 * time.Second
	opt := tcpip.TCPTimeWaitTimeoutOption(tcpTimeWaitTimeout)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, tcpTimeWaitTimeout, err)
	}

	want := c.Stack().Stats().TCP.EstablishedClosed.Value() + 1

	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	c.EP.Close()
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	time.Sleep(2 * time.Second)

	// Now send a duplicate FIN. This should cause the TIME_WAIT to extend
	// by another 5 seconds and also send us a duplicate ACK as it should
	// indicate that the final ACK was potentially lost.
	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// Sleep for 4 seconds so at this point we are 1 second past the
	// original tcpLingerTimeout of 5 seconds.
	time.Sleep(4 * time.Second)

	// Send an ACK and it should not generate any packet as the socket
	// should still be in TIME_WAIT for another another 5 seconds due
	// to the duplicate FIN we sent earlier.
	*ackHeaders = *finHeaders
	ackHeaders.SeqNum = ackHeaders.SeqNum + 1
	ackHeaders.Flags = header.TCPFlagAck
	c.SendPacket(nil, ackHeaders)

	c.CheckNoPacketTimeout("unexpected packet received from endpoint in TIME_WAIT", 1*time.Second)
	// Now sleep for another 2 seconds so that we are past the
	// extended TIME_WAIT of 7 seconds (2 + 5).
	time.Sleep(2 * time.Second)

	// Resend the same ACK.
	c.SendPacket(nil, ackHeaders)

	// Receive the RST that should be generated as there is no valid
	// endpoint.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(ackHeaders.AckNum)),
		checker.TCPAckNum(0),
		checker.TCPFlags(header.TCPFlagRst)))

	if got := c.Stack().Stats().TCP.EstablishedClosed.Value(); got != want {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedClosed = %d, want = %d", got, want)
	}
	if got := c.Stack().Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentEstablished.Value() = %d, want = 0", got)
	}
}

func TestTCPCloseWithData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set TCPTimeWaitTimeout to 5 seconds so that sockets are marked closed
	// after 5 seconds in TIME_WAIT state.
	tcpTimeWaitTimeout := 5 * time.Second
	opt := tcpip.TCPTimeWaitTimeoutOption(tcpTimeWaitTimeout)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, tcpTimeWaitTimeout, err)
	}

	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %s", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.GetPacket()
	tcpHdr := header.TCP(header.IPv4(b).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	ackHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
		RcvWnd:  30000,
	}

	// Send ACK.
	c.SendPacket(nil, ackHeaders)

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.ReadableEvents)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept(nil)
	if cmp.Equal(&tcpip.ErrWouldBlock{}, err) {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept(nil)
			if err != nil {
				t.Fatalf("Accept failed: %s", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now trigger a passive close by sending a FIN.
	finHeaders := &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
		RcvWnd:  30000,
	}

	c.SendPacket(nil, finHeaders)

	// Get the ACK to the FIN we just sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// Now write a few bytes and then close the endpoint.
	data := []byte{1, 2, 3}

	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	// Check that data is received.
	b = c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+2), // Acknum is initial sequence number + 1
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; !bytes.Equal(data, p) {
		t.Errorf("got data = %x, want = %x", p, data)
	}

	c.EP.Close()
	// Check the FIN.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)+uint32(len(data))),
		checker.TCPAckNum(uint32(iss+2)),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	// First send a partial ACK.
	ackHeaders = &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 2,
		AckNum:  c.IRS + 1 + seqnum.Value(len(data)-1),
		RcvWnd:  30000,
	}
	c.SendPacket(nil, ackHeaders)

	// Now send a full ACK.
	ackHeaders = &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 2,
		AckNum:  c.IRS + 1 + seqnum.Value(len(data)),
		RcvWnd:  30000,
	}
	c.SendPacket(nil, ackHeaders)

	// Now ACK the FIN.
	ackHeaders.AckNum++
	c.SendPacket(nil, ackHeaders)

	// Now send an ACK and we should get a RST back as the endpoint should
	// be in CLOSED state.
	ackHeaders = &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 2,
		AckNum:  c.IRS + 1 + seqnum.Value(len(data)),
		RcvWnd:  30000,
	}
	c.SendPacket(nil, ackHeaders)

	// Check the RST.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(ackHeaders.AckNum)),
		checker.TCPAckNum(0),
		checker.TCPFlags(header.TCPFlagRst)))
}

func TestTCPUserTimeout(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&waitEntry, waiter.EventHUp)
	defer c.WQ.EventUnregister(&waitEntry)

	origEstablishedTimedout := c.Stack().Stats().TCP.EstablishedTimedout.Value()

	// Ensure that on the next retransmit timer fire, the user timeout has
	// expired.
	initRTO := 1 * time.Second
	userTimeout := initRTO / 2
	v := tcpip.TCPUserTimeoutOption(userTimeout)
	if err := c.EP.SetSockOpt(&v); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s): %s", v, userTimeout, err)
	}

	// Send some data and wait before ACKing it.
	view := make([]byte, 3)
	var r bytes.Reader
	r.Reset(view)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	next := uint32(c.IRS) + 1
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Wait for the retransmit timer to be fired and the user timeout to cause
	// close of the connection.
	select {
	case <-notifyCh:
	case <-time.After(2 * initRTO):
		t.Fatalf("connection still alive after %s, should have been closed after %s", 2*initRTO, userTimeout)
	}

	// No packet should be received as the connection should be silently
	// closed due to timeout.
	c.CheckNoPacket("unexpected packet received after userTimeout has expired")

	next += uint32(len(view))

	// The connection should be terminated after userTimeout has expired.
	// Send an ACK to trigger a RST from the stack as the endpoint should
	// be dead.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(next),
			checker.TCPAckNum(uint32(0)),
			checker.TCPFlags(header.TCPFlagRst),
		),
	)

	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrTimeout{})

	if got, want := c.Stack().Stats().TCP.EstablishedTimedout.Value(), origEstablishedTimedout+1; got != want {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedTimedout = %d, want = %d", got, want)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

func TestKeepaliveWithUserTimeout(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	origEstablishedTimedout := c.Stack().Stats().TCP.EstablishedTimedout.Value()

	const keepAliveIdle = 100 * time.Millisecond
	const keepAliveInterval = 3 * time.Second
	keepAliveIdleOption := tcpip.KeepaliveIdleOption(keepAliveIdle)
	if err := c.EP.SetSockOpt(&keepAliveIdleOption); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", keepAliveIdleOption, keepAliveIdle, err)
	}
	keepAliveIntervalOption := tcpip.KeepaliveIntervalOption(keepAliveInterval)
	if err := c.EP.SetSockOpt(&keepAliveIntervalOption); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", keepAliveIntervalOption, keepAliveInterval, err)
	}
	if err := c.EP.SetSockOptInt(tcpip.KeepaliveCountOption, 10); err != nil {
		t.Fatalf("c.EP.SetSockOptInt(tcpip.KeepaliveCountOption, 10): %s", err)
	}
	c.EP.SocketOptions().SetKeepAlive(true)

	// Set userTimeout to be the duration to be 1 keepalive
	// probes. Which means that after the first probe is sent
	// the second one should cause the connection to be
	// closed due to userTimeout being hit.
	userTimeout := tcpip.TCPUserTimeoutOption(keepAliveInterval)
	if err := c.EP.SetSockOpt(&userTimeout); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", userTimeout, keepAliveInterval, err)
	}

	// Check that the connection is still alive.
	ept := endpointTester{c.EP}
	ept.CheckReadError(t, &tcpip.ErrWouldBlock{})

	// Now receive 1 keepalives, but don't ACK it.
	b := c.GetPacket()
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	checker.IPv4(t, b,
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)),
			checker.TCPAckNum(uint32(iss)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Sleep for a litte over the KeepAlive interval to make sure
	// the timer has time to fire after the last ACK and close the
	// close the socket.
	time.Sleep(keepAliveInterval + keepAliveInterval/2)

	// The connection should be closed with a timeout.
	// Send an ACK to trigger a RST from the stack as the endpoint should
	// be dead.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  c.IRS + 1,
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS+1)),
			checker.TCPAckNum(uint32(0)),
			checker.TCPFlags(header.TCPFlagRst),
		),
	)

	ept.CheckReadError(t, &tcpip.ErrTimeout{})
	if got, want := c.Stack().Stats().TCP.EstablishedTimedout.Value(), origEstablishedTimedout+1; got != want {
		t.Errorf("got c.Stack().Stats().TCP.EstablishedTimedout = %d, want = %d", got, want)
	}
	if got := c.Stack().Stats().TCP.CurrentConnected.Value(); got != 0 {
		t.Errorf("got stats.TCP.CurrentConnected.Value() = %d, want = 0", got)
	}
}

func TestIncreaseWindowOnRead(t *testing.T) {
	// This test ensures that the endpoint sends an ack,
	// after read() when the window grows by more than 1 MSS.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	const rcvBuf = 65535 * 10
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, rcvBuf)

	// Write chunks of ~30000 bytes. It's important that two
	// payloads make it equal or longer than MSS.
	remain := rcvBuf * 2
	sent := 0
	data := make([]byte, defaultMTU/2)
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for remain > len(data) {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(seqnum.Size(sent)),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		pkt := c.GetPacket()
		checker.IPv4(t, pkt,
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPAckNum(uint32(iss)+uint32(sent)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
		// Break once the window drops below defaultMTU/2
		if wnd := header.TCP(header.IPv4(pkt).Payload()).WindowSize(); wnd < defaultMTU/2 {
			break
		}
	}

	// We now have < 1 MSS in the buffer space. Read at least > 2 MSS
	// worth of data as receive buffer space
	w := tcpip.LimitedWriter{
		W: ioutil.Discard,
		// defaultMTU is a good enough estimate for the MSS used for this
		// connection.
		N: defaultMTU * 2,
	}
	for w.N != 0 {
		_, err := c.EP.Read(&w, tcpip.ReadOptions{})
		if err != nil {
			t.Fatalf("Read failed: %s", err)
		}
	}

	// After reading > MSS worth of data, we surely crossed MSS. See the ack:
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(sent)),
			checker.TCPWindow(uint16(0xffff)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestIncreaseWindowOnBufferResize(t *testing.T) {
	// This test ensures that the endpoint sends an ack,
	// after available recv buffer grows to more than 1 MSS.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	const rcvBuf = 65535 * 10
	c.CreateConnected(context.TestInitialSequenceNumber, 30000, rcvBuf)

	// Write chunks of ~30000 bytes. It's important that two
	// payloads make it equal or longer than MSS.
	remain := rcvBuf
	sent := 0
	data := make([]byte, defaultMTU/2)
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	for remain > len(data) {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  iss.Add(seqnum.Size(sent)),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		checker.IPv4(t, c.GetPacket(),
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.TCPSeqNum(uint32(c.IRS)+1),
				checker.TCPAckNum(uint32(iss)+uint32(sent)),
				checker.TCPWindowLessThanEq(0xffff),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Increasing the buffer from should generate an ACK,
	// since window grew from small value to larger equal MSS
	c.EP.SocketOptions().SetReceiveBufferSize(rcvBuf*2, true)
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1),
			checker.TCPAckNum(uint32(iss)+uint32(sent)),
			checker.TCPWindow(uint16(0xffff)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestTCPDeferAccept(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	const tcpDeferAccept = 1 * time.Second
	tcpDeferAcceptOption := tcpip.TCPDeferAcceptOption(tcpDeferAccept)
	if err := c.EP.SetSockOpt(&tcpDeferAcceptOption); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)): %s", tcpDeferAcceptOption, tcpDeferAccept, err)
	}

	irs, iss := executeHandshake(t, c, context.TestPort, false /* synCookiesInUse */)

	_, _, err := c.EP.Accept(nil)
	if d := cmp.Diff(&tcpip.ErrWouldBlock{}, err); d != "" {
		t.Fatalf("c.EP.Accept(nil) mismatch (-want +got):\n%s", d)
	}

	// Send data. This should result in an acceptable endpoint.
	c.SendPacket([]byte{1, 2, 3, 4}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
	})

	// Receive ACK for the data we sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))

	// Give a bit of time for the socket to be delivered to the accept queue.
	time.Sleep(50 * time.Millisecond)
	aep, _, err := c.EP.Accept(nil)
	if err != nil {
		t.Fatalf("got c.EP.Accept(nil) = %s, want: nil", err)
	}

	aep.Close()
	// Closing aep without reading the data should trigger a RST.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))
}

func TestTCPDeferAcceptTimeout(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.Create(-1)

	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatal("Bind failed:", err)
	}

	if err := c.EP.Listen(10); err != nil {
		t.Fatal("Listen failed:", err)
	}

	const tcpDeferAccept = 1 * time.Second
	tcpDeferAcceptOpt := tcpip.TCPDeferAcceptOption(tcpDeferAccept)
	if err := c.EP.SetSockOpt(&tcpDeferAcceptOpt); err != nil {
		t.Fatalf("c.EP.SetSockOpt(&%T(%s)) failed: %s", tcpDeferAcceptOpt, tcpDeferAccept, err)
	}

	irs, iss := executeHandshake(t, c, context.TestPort, false /* synCookiesInUse */)

	_, _, err := c.EP.Accept(nil)
	if d := cmp.Diff(&tcpip.ErrWouldBlock{}, err); d != "" {
		t.Fatalf("c.EP.Accept(nil) mismatch (-want +got):\n%s", d)
	}

	// Sleep for a little of the tcpDeferAccept timeout.
	time.Sleep(tcpDeferAccept + 100*time.Millisecond)

	// On timeout expiry we should get a SYN-ACK retransmission.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
		checker.TCPAckNum(uint32(irs)+1)))

	// Send data. This should result in an acceptable endpoint.
	c.SendPacket([]byte{1, 2, 3, 4}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
	})

	// Receive ACK for the data we sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))

	// Give sometime for the endpoint to be delivered to the accept queue.
	time.Sleep(50 * time.Millisecond)
	aep, _, err := c.EP.Accept(nil)
	if err != nil {
		t.Fatalf("got c.EP.Accept(nil) = %s, want: nil", err)
	}

	aep.Close()
	// Closing aep without reading the data should trigger a RST.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
		checker.TCPSeqNum(uint32(iss+1)),
		checker.TCPAckNum(uint32(irs+5))))
}

func TestResetDuringClose(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRecvBuf */)
	// Send some data to make sure there is some unread
	// data to trigger a reset on c.Close.
	irs := c.IRS
	iss := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendPacket([]byte{1, 2, 3, 4}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss,
		AckNum:  irs.Add(1),
		RcvWnd:  30000,
	})

	// Receive ACK for the data we sent.
	checker.IPv4(t, c.GetPacket(), checker.TCP(
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPSeqNum(uint32(irs.Add(1))),
		checker.TCPAckNum(uint32(iss)+4)))

	// Close in a separate goroutine so that we can trigger
	// a race with the RST we send below. This should not
	// panic due to the route being released depeding on
	// whether Close() sends an active RST or the RST sent
	// below is processed by the worker first.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			SeqNum:  iss.Add(4),
			AckNum:  c.IRS.Add(5),
			RcvWnd:  30000,
			Flags:   header.TCPFlagRst,
		})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.EP.Close()
	}()

	wg.Wait()
}

func TestStackTimeWaitReuse(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	var twReuse tcpip.TCPTimeWaitReuseOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &twReuse); err != nil {
		t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &twReuse, err)
	}
	if got, want := twReuse, tcpip.TCPTimeWaitReuseLoopbackOnly; got != want {
		t.Fatalf("got tcpip.TCPTimeWaitReuseOption: %v, want: %v", got, want)
	}
}

func TestSetStackTimeWaitReuse(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	testCases := []struct {
		v   int
		err tcpip.Error
	}{
		{int(tcpip.TCPTimeWaitReuseDisabled), nil},
		{int(tcpip.TCPTimeWaitReuseGlobal), nil},
		{int(tcpip.TCPTimeWaitReuseLoopbackOnly), nil},
		{int(tcpip.TCPTimeWaitReuseLoopbackOnly) + 1, &tcpip.ErrInvalidOptionValue{}},
		{int(tcpip.TCPTimeWaitReuseDisabled) - 1, &tcpip.ErrInvalidOptionValue{}},
	}

	for _, tc := range testCases {
		opt := tcpip.TCPTimeWaitReuseOption(tc.v)
		err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
		if got, want := err, tc.err; got != want {
			t.Fatalf("s.SetTransportProtocolOption(%d, &%T(%d)) = %s, want = %s", tcp.ProtocolNumber, tc.v, tc.v, err, tc.err)
		}
		if tc.err != nil {
			continue
		}

		var twReuse tcpip.TCPTimeWaitReuseOption
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &twReuse); err != nil {
			t.Fatalf("s.TransportProtocolOption(%v, %v) = %v, want nil", tcp.ProtocolNumber, &twReuse, err)
		}

		if got, want := twReuse, tcpip.TCPTimeWaitReuseOption(tc.v); got != want {
			t.Fatalf("got tcpip.TCPTimeWaitReuseOption: %v, want: %v", got, want)
		}
	}
}

// generateRandomPayload generates a random byte slice of the specified length
// causing a fatal test failure if it is unable to do so.
func generateRandomPayload(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read(buf) failed: %s", err)
	}
	return buf
}
