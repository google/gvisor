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
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

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
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Register for notification, then start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	defer wq.EventUnregister(&waitEntry)

	if err := ep.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort}); err != tcpip.ErrConnectStarted {
		t.Fatalf("got ep.Connect(...) = %v, want = %v", err, tcpip.ErrConnectStarted)
	}

	// Close the connection, wait for completion.
	ep.Close()

	// Wait for ep to become writable.
	<-notifyCh
	if err := ep.GetSockOpt(tcpip.ErrorOption{}); err != tcpip.ErrAborted {
		t.Fatalf("got ep.GetSockOpt(tcpip.ErrorOption{}) = %v, want = %v", err, tcpip.ErrAborted)
	}
}

func TestConnectIncrementActiveConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.ActiveConnectionOpenings.Value() + 1

	c.CreateConnected(789, 30000, nil)
	if got := stats.TCP.ActiveConnectionOpenings.Value(); got != want {
		t.Errorf("got stats.TCP.ActtiveConnectionOpenings.Value() = %v, want = %v", got, want)
	}
}

func TestConnectDoesNotIncrementFailedConnectionAttempts(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.FailedConnectionAttempts.Value()

	c.CreateConnected(789, 30000, nil)
	if got := stats.TCP.FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got stats.TCP.FailedConnectionOpenings.Value() = %v, want = %v", got, want)
	}
}

func TestActiveFailedConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	c.EP = ep
	want := stats.TCP.FailedConnectionAttempts.Value() + 1

	if err := c.EP.Connect(tcpip.FullAddress{NIC: 2, Addr: context.TestAddr, Port: context.TestPort}); err != tcpip.ErrNoRoute {
		t.Errorf("got c.EP.Connect(...) = %v, want = %v", err, tcpip.ErrNoRoute)
	}

	if got := stats.TCP.FailedConnectionAttempts.Value(); got != want {
		t.Errorf("got stats.TCP.FailedConnectionAttempts.Value() = %v, want = %v", got, want)
	}
}

func TestTCPSegmentsSentIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	// SYN and ACK
	want := stats.TCP.SegmentsSent.Value() + 2
	c.CreateConnected(789, 30000, nil)

	if got := stats.TCP.SegmentsSent.Value(); got != want {
		t.Errorf("got stats.TCP.SegmentsSent.Value() = %v, want = %v", got, want)
	}
}

func TestTCPResetsSentIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	stats := c.Stack().Stats()
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	want := stats.TCP.SegmentsSent.Value() + 1

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	iss := seqnum.Value(789)
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
	if got := stats.TCP.ResetsSent.Value(); got != want {
		t.Errorf("got stats.TCP.ResetsSent.Value() = %v, want = %v", got, want)
	}
}

func TestTCPResetsReceivedIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	want := stats.TCP.ResetsReceived.Value() + 1
	ackNum := seqnum.Value(789)
	rcvWnd := seqnum.Size(30000)
	c.CreateConnected(ackNum, rcvWnd, nil)

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		SeqNum:  c.IRS.Add(2),
		AckNum:  ackNum.Add(2),
		RcvWnd:  rcvWnd,
		Flags:   header.TCPFlagRst,
	})

	if got := stats.TCP.ResetsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.ResetsReceived.Value() = %v, want = %v", got, want)
	}
}

func TestActiveHandshake(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)
}

func TestNonBlockingClose(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)
	ep := c.EP
	c.EP = nil

	// Close the endpoint and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		t.Fatalf("Took too long to close: %v", diff)
	}
}

func TestConnectResetAfterClose(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)
	ep := c.EP
	c.EP = nil

	// Close the endpoint, make sure we get a FIN segment, then acknowledge
	// to complete closure of sender, but don't send our own FIN.
	ep.Close()
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for the ep to give up waiting for a FIN, and send a RST.
	time.Sleep(3 * time.Second)
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
				checker.SeqNum(uint32(c.IRS)+1),
				checker.AckNum(790),
				checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
			),
		)
		break
	}
}

func TestSimpleReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
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
	v, _, err := c.EP.Read(nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	// Check that ACK is received.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestOutOfOrderReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Send second half of data first, with seqnum 3 ahead of expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	c.SendPacket(data[3:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  793,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that we get an ACK specifying which seqnum is expected.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Wait 200ms and check that no data has been received.
	time.Sleep(200 * time.Millisecond)
	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Send the first 3 bytes now.
	c.SendPacket(data[:3], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Receive data.
	read := make([]byte, 0, 6)
	for len(read) < len(data) {
		v, _, err := c.EP.Read(nil)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				// Wait for receive to be notified.
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatalf("Timed out waiting for data to arrive")
				}
				continue
			}
			t.Fatalf("Read failed: %v", err)
		}

		read = append(read, v...)
	}

	// Check that we received the data in proper order.
	if !bytes.Equal(data, read) {
		t.Fatalf("got data = %v, want = %v", read, data)
	}

	// Check that the whole data is acknowledged.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestOutOfOrderFlood(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create a new connection with initial window size of 10.
	opt := tcpip.ReceiveBufferSizeOption(10)
	c.CreateConnected(789, 30000, &opt)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Send 100 packets before the actual one that is expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	for i := 0; i < 100; i++ {
		c.SendPacket(data[3:], &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  796,
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})

		checker.IPv4(t, c.GetPacket(),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)+1),
				checker.AckNum(790),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Send packet with seqnum 793. It must be discarded because the
	// out-of-order buffer was filled by the previous packets.
	c.SendPacket(data[3:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  793,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Now send the expected packet, seqnum 790.
	c.SendPacket(data[:3], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that only packet 790 is acknowledged.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(793),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestRstOnCloseWithUnreadData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
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
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
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
			checker.SeqNum(uint32(c.IRS)+1),
		))
	// The RST puts the endpoint into an error state.
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateError; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// This final ACK should be ignored because an ACK on a reset doesn't mean
	// anything.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(790 + len(data)),
		AckNum:  c.IRS.Add(seqnum.Size(2)),
		RcvWnd:  30000,
	})
}

func TestRstOnCloseWithUnreadDataFinConvertRst(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
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
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
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
			checker.SeqNum(uint32(c.IRS)+1),
		))

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateFinWait1; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// Cause a RST to be generated by closing the read end now since we have
	// unread data.
	c.EP.Shutdown(tcpip.ShutdownRead)

	// Make sure we get the RST
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
			// We shouldn't consume a sequence number on RST.
			checker.SeqNum(uint32(c.IRS)+1),
		))
	// The RST puts the endpoint into an error state.
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateError; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// The ACK to the FIN should now be rejected since the connection has been
	// closed by a RST.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(790 + len(data)),
		AckNum:  c.IRS.Add(seqnum.Size(2)),
		RcvWnd:  30000,
	})
}

func TestShutdownRead(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	if err := c.EP.Shutdown(tcpip.ShutdownRead); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrClosedForReceive {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrClosedForReceive)
	}
}

func TestFullWindowReceive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	opt := tcpip.ReceiveBufferSizeOption(10)
	c.CreateConnected(789, 30000, &opt)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	_, _, err := c.EP.Read(nil)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("Read failed: %v", err)
	}

	// Fill up the window.
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
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
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(0),
		),
	)

	// Receive data and check it.
	v, _, err := c.EP.Read(nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	// Check that we get an ACK for the newly non-zero window.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(10),
		),
	)
}

func TestNoWindowShrinking(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Start off with a window size of 10, then shrink it to 5.
	opt := tcpip.ReceiveBufferSizeOption(10)
	c.CreateConnected(789, 30000, &opt)

	opt = 5
	if err := c.EP.SetSockOpt(opt); err != nil {
		t.Fatalf("SetSockOpt failed: %v", err)
	}

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Send 3 bytes, check that the peer acknowledges them.
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.SendPacket(data[:3], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that data is acknowledged, and that window doesn't go to zero
	// just yet because it was previously set to 10. It must go to 7 now.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(793),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(7),
		),
	)

	// Send 7 more bytes, check that the window fills up.
	c.SendPacket(data[3:], &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  793,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(0),
		),
	)

	// Receive data and check it.
	read := make([]byte, 0, 10)
	for len(read) < len(data) {
		v, _, err := c.EP.Read(nil)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		read = append(read, v...)
	}

	if !bytes.Equal(data, read) {
		t.Fatalf("got data = %v, want = %v", read, data)
	}

	// Check that we get an ACK for the newly non-zero window, which is the
	// new size.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(5),
		),
	)
}

func TestSimpleSend(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
		SeqNum:  790,
		AckNum:  c.IRS.Add(1 + seqnum.Size(len(data))),
		RcvWnd:  30000,
	})
}

func TestZeroWindowSend(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 0, nil)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	_, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{})
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Since the window is currently zero, check that no packet is received.
	c.CheckNoPacket("Packet received when window is zero")

	// Open up the window. Data should be received now.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	// Check that data is received.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
		SeqNum:  790,
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
	opt := tcpip.ReceiveBufferSizeOption(65535 * 3)
	c.CreateConnectedWithRawOptions(789, 30000, &opt, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received, and that advertised window is 0xbfff,
	// that is, that it is scaled.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(0xbfff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestNonScaledWindowConnect(t *testing.T) {
	// This test ensures that window scaling is not used when the peer
	// doesn't advertise it and connection is established with Connect().
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set the window size greater than the maximum non-scaled window.
	opt := tcpip.ReceiveBufferSizeOption(65535 * 3)
	c.CreateConnected(789, 30000, &opt)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(65535 * 3)); err != nil {
		t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	c.PassiveConnectWithOptions(100, 2, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received, and that advertised window is 0xbfff,
	// that is, that it is scaled.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(0xbfff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(65535 * 3)); err != nil {
		t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	c.PassiveConnect(100, 2, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestZeroScaledWindowReceive(t *testing.T) {
	// This test ensures that the endpoint sends a non-zero window size
	// advertisement when the scaled window transitions from 0 to non-zero,
	// but the actual window (not scaled) hasn't gotten to zero.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Set the window size such that a window scale of 4 will be used.
	const wnd = 65535 * 10
	const ws = uint32(4)
	opt := tcpip.ReceiveBufferSizeOption(wnd)
	c.CreateConnectedWithRawOptions(789, 30000, &opt, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	// Write chunks of 50000 bytes.
	remain := wnd
	sent := 0
	data := make([]byte, 50000)
	for remain > len(data) {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  seqnum.Value(790 + sent),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		checker.IPv4(t, c.GetPacket(),
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)+1),
				checker.AckNum(uint32(790+sent)),
				checker.Window(uint16(remain>>ws)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Make the window non-zero, but the scaled window zero.
	if remain >= 16 {
		data = data[:remain-15]
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  seqnum.Value(790 + sent),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		checker.IPv4(t, c.GetPacket(),
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)+1),
				checker.AckNum(uint32(790+sent)),
				checker.Window(0),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Read some data. An ack should be sent in response to that.
	v, _, err := c.EP.Read(nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(790+sent)),
			checker.Window(uint16(len(v)>>ws)),
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
				ep.SetSockOpt(tcpip.CorkOption(1))
			},
			func(ep tcpip.Endpoint) {
				ep.SetSockOpt(tcpip.CorkOption(0))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateConnected(789, 30000, nil)

			// Prevent the endpoint from processing packets.
			test.stop(c.EP)

			var allData []byte
			for i, data := range [][]byte{{1, 2, 3, 4}, {5, 6, 7}, {8, 9}, {10}, {11}} {
				allData = append(allData, data...)
				view := buffer.NewViewFromBytes(data)
				if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write #%d failed: %v", i+1, err)
				}
			}

			// Let the endpoint process the segments that we just sent.
			test.resume(c.EP)

			// Check that data is received.
			b := c.GetPacket()
			checker.IPv4(t, b,
				checker.PayloadLen(len(allData)+header.TCPMinimumSize),
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.SeqNum(uint32(c.IRS)+1),
					checker.AckNum(790),
					checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
				SeqNum:  790,
				AckNum:  c.IRS.Add(1 + seqnum.Size(len(allData))),
				RcvWnd:  30000,
			})
		})
	}
}

func TestDelay(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	c.EP.SetSockOpt(tcpip.DelayOption(1))

	var allData []byte
	for i, data := range [][]byte{{0}, {1, 2, 3, 4}, {5, 6, 7}, {8, 9}, {10}, {11}} {
		allData = append(allData, data...)
		view := buffer.NewViewFromBytes(data)
		if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write #%d failed: %v", i+1, err)
		}
	}

	seq := c.IRS.Add(1)
	for _, want := range [][]byte{allData[:1], allData[1:]} {
		// Check that data is received.
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.PayloadLen(len(want)+header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(seq)),
				checker.AckNum(790),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
			SeqNum:  790,
			AckNum:  seq,
			RcvWnd:  30000,
		})
	}
}

func TestUndelay(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	c.EP.SetSockOpt(tcpip.DelayOption(1))

	allData := [][]byte{{0}, {1, 2, 3}}
	for i, data := range allData {
		view := buffer.NewViewFromBytes(data)
		if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write #%d failed: %v", i+1, err)
		}
	}

	seq := c.IRS.Add(1)

	// Check that data is received.
	first := c.GetPacket()
	checker.IPv4(t, first,
		checker.PayloadLen(len(allData[0])+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(seq)),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	if got, want := first[header.IPv4MinimumSize+header.TCPMinimumSize:], allData[0]; !bytes.Equal(got, want) {
		t.Fatalf("got first packet's data = %v, want = %v", got, want)
	}

	seq = seq.Add(seqnum.Size(len(allData[0])))

	// Check that we don't get the second packet yet.
	c.CheckNoPacketTimeout("delayed second packet transmitted", 100*time.Millisecond)

	c.EP.SetSockOpt(tcpip.DelayOption(0))

	// Check that data is received.
	second := c.GetPacket()
	checker.IPv4(t, second,
		checker.PayloadLen(len(allData[1])+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(seq)),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
		SeqNum:  790,
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
		{"delay", func(ep tcpip.Endpoint) { ep.SetSockOpt(tcpip.DelayOption(1)) }},
		{"cork", func(ep tcpip.Endpoint) { ep.SetSockOpt(tcpip.CorkOption(1)) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const maxPayload = 100
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			c.CreateConnectedWithRawOptions(789, 30000, nil, []byte{
				header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
			})

			test.fn(c.EP)

			allData := [][]byte{{0}, make([]byte, maxPayload), make([]byte, maxPayload)}
			for i, data := range allData {
				view := buffer.NewViewFromBytes(data)
				if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
					t.Fatalf("Write #%d failed: %v", i+1, err)
				}
			}

			seq := c.IRS.Add(1)

			for i, data := range allData {
				// Check that data is received.
				packet := c.GetPacket()
				checker.IPv4(t, packet,
					checker.PayloadLen(len(data)+header.TCPMinimumSize),
					checker.TCP(
						checker.DstPort(context.TestPort),
						checker.SeqNum(uint32(seq)),
						checker.AckNum(790),
						checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
				SeqNum:  790,
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

	view := buffer.NewView(len(data))
	copy(view, data)

	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that data is received in chunks.
	bytesReceived := 0
	numPackets := 0
	for bytesReceived != dataLen {
		b := c.GetPacket()
		numPackets++
		tcpHdr := header.TCP(header.IPv4(b).Payload())
		payloadLen := len(tcpHdr.Payload())
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)+1+uint32(bytesReceived)),
				checker.AckNum(790),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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
			SeqNum:  790,
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

	c.CreateConnected(789, 30000, nil)
	testBrokenUpWrite(t, c, maxPayload)
}

func TestActiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	c := context.New(t, 65535)
	defer c.Cleanup()

	c.CreateConnectedWithRawOptions(789, 30000, nil, []byte{
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	const wndScale = 2
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(rcvBufferSize)); err != nil {
		t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, wndScale, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
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

	// Set the SynRcvd threshold to zero to force a syn cookie based accept
	// to happen.
	saved := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = saved
	}()
	tcp.SynRcvdCountThreshold = 0

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.EP, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.EP, _, err = ep.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
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
	ch := make(chan *tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err *tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, 1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Wait for connection to be available.
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %v", err)
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
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	const wndScale = 2
	if err := c.EP.SetSockOpt(tcpip.ReceiveBufferSizeOption(rcvBufferSize)); err != nil {
		t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventOut)
	defer c.WQ.EventUnregister(&we)

	if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort}); err != tcpip.ErrConnectStarted {
		t.Fatalf("got c.EP.Connect(...) = %v, want = %v", err, tcpip.ErrConnectStarted)
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
			checker.SeqNum(tcpHdr.SequenceNumber()),
			checker.TCPSynOptions(header.TCPSynOptions{MSS: mss, WS: wndScale}),
		),
	)

	// Send SYN-ACK.
	iss := seqnum.Value(789)
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
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		if err := c.EP.GetSockOpt(tcpip.ErrorOption{}); err != nil {
			t.Fatalf("GetSockOpt failed: %v", err)
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Close the listener and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		t.Fatalf("Took too long to close: %v", diff)
	}
}

func TestReceiveOnResetConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Send RST segment.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  790,
		RcvWnd:  30000,
	})

	// Try to read.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

loop:
	for {
		switch _, _, err := c.EP.Read(nil); err {
		case tcpip.ErrWouldBlock:
			select {
			case <-ch:
			case <-time.After(1 * time.Second):
				t.Fatalf("Timed out waiting for reset to arrive")
			}
		case tcpip.ErrConnectionReset:
			break loop
		default:
			t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrConnectionReset)
		}
	}
}

func TestSendOnResetConnection(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Send RST segment.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  790,
		RcvWnd:  30000,
	})

	// Wait for the RST to be received.
	time.Sleep(1 * time.Second)

	// Try to write.
	view := buffer.NewView(10)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != tcpip.ErrConnectionReset {
		t.Fatalf("got c.EP.Write(...) = %v, want = %v", err, tcpip.ErrConnectionReset)
	}
}

func TestFinImmediately(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Shutdown immediately, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+2),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinRetransmit(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Shutdown immediately, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Don't acknowledge yet. We should get a retransmit of the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+2),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithNoPendingData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Write something out, and have it acknowledged.
	view := buffer.NewView(10)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	next := uint32(c.IRS) + 1
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Shutdown, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Ack and send FIN as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingDataCwndFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Write enough segments to fill the congestion window before ACK'ing
	// any of them.
	view := buffer.NewView(10)
	for i := tcp.InitialCwnd; i > 0; i-- {
		if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	next := uint32(c.IRS) + 1
	for i := tcp.InitialCwnd; i > 0; i-- {
		checker.IPv4(t, c.GetPacket(),
			checker.PayloadLen(len(view)+header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(next),
				checker.AckNum(790),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
			),
		)
		next += uint32(len(view))
	}

	// Shutdown the connection, check that the FIN segment isn't sent
	// because the congestion window doesn't allow it. Wait until a
	// retransmit is received.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Send the ACK that will allow the FIN to be sent as well.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingData(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Write something out, and acknowledge it to get cwnd to 2.
	view := buffer.NewView(10)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	next := uint32(c.IRS) + 1
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Write new data, but don't acknowledge it.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPartialAck(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Write something out, and acknowledge it to get cwnd to 2. Also send
	// FIN from the test side.
	view := buffer.NewView(10)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	next := uint32(c.IRS) + 1
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  seqnum.Value(next),
		RcvWnd:  30000,
	})

	// Check that we get an ACK for the fin.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Write new data, but don't acknowledge it.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send an ACK for the data, but not for the FIN yet.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  791,
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
		SeqNum:  791,
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Update the backlog with another Listen() on the same endpoint.
	if err := ep.Listen(20); err != nil {
		t.Fatalf("Listen failed to update backlog: %v", err)
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
	c.CreateConnectedWithRawOptions(789, 0, nil, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
		header.TCPOptionWS, 3, scale, header.TCPOptionNOP,
	})

	// Open up the window with a scaled value.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
		AckNum:  c.IRS.Add(1),
		RcvWnd:  1,
	})

	// Send some data. Check that it's capped by the window size.
	view := buffer.NewView(65535)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check that only data that fits in the scaled window is sent.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen((1<<scale)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Reset the connection to free resources.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagRst,
		SeqNum:  790,
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
	c.CreateConnected(789, 30000, nil)
	stats := c.Stack().Stats()
	want := stats.TCP.ValidSegmentsReceived.Value() + 1

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(790),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})

	if got := stats.TCP.ValidSegmentsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.ValidSegmentsReceived.Value() = %v, want = %v", got, want)
	}
}

func TestReceivedInvalidSegmentCountIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	c.CreateConnected(789, 30000, nil)
	stats := c.Stack().Stats()
	want := stats.TCP.InvalidSegmentsReceived.Value() + 1
	vv := c.BuildSegment(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(790),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	tcpbuf := vv.First()[header.IPv4MinimumSize:]
	tcpbuf[header.TCPDataOffset] = ((header.TCPMinimumSize - 1) / 4) << 4

	c.SendSegment(vv)

	if got := stats.TCP.InvalidSegmentsReceived.Value(); got != want {
		t.Errorf("got stats.TCP.InvalidSegmentsReceived.Value() = %v, want = %v", got, want)
	}
}

func TestReceivedIncorrectChecksumIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	c.CreateConnected(789, 30000, nil)
	stats := c.Stack().Stats()
	want := stats.TCP.ChecksumErrors.Value() + 1
	vv := c.BuildSegment([]byte{0x1, 0x2, 0x3}, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seqnum.Value(790),
		AckNum:  c.IRS.Add(1),
		RcvWnd:  30000,
	})
	tcpbuf := vv.First()[header.IPv4MinimumSize:]
	// Overwrite a byte in the payload which should cause checksum
	// verification to fail.
	tcpbuf[(tcpbuf[header.TCPDataOffset]>>4)*4] = 0x4

	c.SendSegment(vv)

	if got := stats.TCP.ChecksumErrors.Value(); got != want {
		t.Errorf("got stats.TCP.ChecksumErrors.Value() = %d, want = %d", got, want)
	}
}

func TestReceivedSegmentQueuing(t *testing.T) {
	// This test sends 200 segments containing a few bytes each to an
	// endpoint and checks that they're all received and acknowledged by
	// the endpoint, that is, that none of the segments are dropped by
	// internal queues.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	// Send 200 segments.
	data := []byte{1, 2, 3}
	for i := 0; i < 200; i++ {
		c.SendPacket(data, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  seqnum.Value(790 + i*len(data)),
			AckNum:  c.IRS.Add(1),
			RcvWnd:  30000,
		})
	}

	// Receive ACKs for all segments.
	last := seqnum.Value(790 + 200*len(data))
	for {
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)+1),
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

	c.CreateConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Shutdown immediately for write, check that we get a FIN.
	if err := c.EP.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateFinWait1; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// Send some data and acknowledge the FIN.
	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  790,
		AckNum:  c.IRS.Add(2),
		RcvWnd:  30000,
	})

	// Check that ACK is received.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+2),
			checker.AckNum(uint32(791+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Give the stack the chance to transition to closed state. Note that since
	// both the sender and receiver are now closed, we effectively skip the
	// TIME-WAIT state.
	time.Sleep(1 * time.Second)

	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateClose; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that peek works.
	peekBuf := make([]byte, 10)
	n, _, err := c.EP.Peek([][]byte{peekBuf})
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}

	peekBuf = peekBuf[:n]
	if !bytes.Equal(data, peekBuf) {
		t.Fatalf("got data = %v, want = %v", peekBuf, data)
	}

	// Receive data.
	v, _, err := c.EP.Read(nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(data, v) {
		t.Fatalf("got data = %v, want = %v", v, data)
	}

	// Now that we drained the queue, check that functions fail with the
	// right error code.
	if _, _, err := c.EP.Read(nil); err != tcpip.ErrClosedForReceive {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrClosedForReceive)
	}

	if _, _, err := c.EP.Peek([][]byte{peekBuf}); err != tcpip.ErrClosedForReceive {
		t.Fatalf("got c.EP.Peek(...) = %v, want = %v", err, tcpip.ErrClosedForReceive)
	}
}

func TestReusePort(t *testing.T) {
	// This test ensures that ports are immediately available for reuse
	// after Close on the endpoints using them returns.
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// First case, just an endpoint that was bound.
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	c.EP.Close()
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	c.EP.Close()

	// Second case, an endpoint that was bound and is connecting..
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort}); err != tcpip.ErrConnectStarted {
		t.Fatalf("got c.EP.Connect(...) = %v, want = %v", err, tcpip.ErrConnectStarted)
	}
	c.EP.Close()

	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	c.EP.Close()

	// Third case, an endpoint that was bound and is listening.
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	c.EP.Close()

	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if err := c.EP.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
}

func checkRecvBufferSize(t *testing.T, ep tcpip.Endpoint, v int) {
	t.Helper()

	var s tcpip.ReceiveBufferSizeOption
	if err := ep.GetSockOpt(&s); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	if int(s) != v {
		t.Fatalf("got receive buffer size = %v, want = %v", s, v)
	}
}

func checkSendBufferSize(t *testing.T, ep tcpip.Endpoint, v int) {
	t.Helper()

	var s tcpip.SendBufferSizeOption
	if err := ep.GetSockOpt(&s); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	if int(s) != v {
		t.Fatalf("got send buffer size = %v, want = %v", s, v)
	}
}

func TestDefaultBufferSizes(t *testing.T) {
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName}, stack.Options{})

	// Check the default values.
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	defer func() {
		if ep != nil {
			ep.Close()
		}
	}()

	checkSendBufferSize(t, ep, tcp.DefaultBufferSize)
	checkRecvBufferSize(t, ep, tcp.DefaultBufferSize)

	// Change the default send buffer size.
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SendBufferSizeOption{1, tcp.DefaultBufferSize * 2, tcp.DefaultBufferSize * 20}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	ep.Close()
	ep, err = s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}

	checkSendBufferSize(t, ep, tcp.DefaultBufferSize*2)
	checkRecvBufferSize(t, ep, tcp.DefaultBufferSize)

	// Change the default receive buffer size.
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.ReceiveBufferSizeOption{1, tcp.DefaultBufferSize * 3, tcp.DefaultBufferSize * 30}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	ep.Close()
	ep, err = s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}

	checkSendBufferSize(t, ep, tcp.DefaultBufferSize*2)
	checkRecvBufferSize(t, ep, tcp.DefaultBufferSize*3)
}

func TestMinMaxBufferSizes(t *testing.T) {
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName}, stack.Options{})

	// Check the default values.
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatalf("NewEndpoint failed; %v", err)
	}
	defer ep.Close()

	// Change the min/max values for send/receive
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.ReceiveBufferSizeOption{200, tcp.DefaultBufferSize * 2, tcp.DefaultBufferSize * 20}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SendBufferSizeOption{300, tcp.DefaultBufferSize * 3, tcp.DefaultBufferSize * 30}); err != nil {
		t.Fatalf("SetTransportProtocolOption failed: %v", err)
	}

	// Set values below the min.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(199)); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	checkRecvBufferSize(t, ep, 200)

	if err := ep.SetSockOpt(tcpip.SendBufferSizeOption(299)); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	checkSendBufferSize(t, ep, 300)

	// Set values above the max.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(1 + tcp.DefaultBufferSize*20)); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	checkRecvBufferSize(t, ep, tcp.DefaultBufferSize*20)

	if err := ep.SetSockOpt(tcpip.SendBufferSizeOption(1 + tcp.DefaultBufferSize*30)); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	checkSendBufferSize(t, ep, tcp.DefaultBufferSize*30)
}

func makeStack() (*stack.Stack, *tcpip.Error) {
	s := stack.New([]string{
		ipv4.ProtocolName,
		ipv6.ProtocolName,
	}, []string{tcp.ProtocolName}, stack.Options{})

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
			Destination: "\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
		{
			Destination: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Gateway:     "",
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
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Register for notification, then start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	defer wq.EventUnregister(&waitEntry)

	if err := ep.Connect(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != tcpip.ErrConnectStarted {
		t.Fatalf("got ep.Connect(...) = %v, want = %v", err, tcpip.ErrConnectStarted)
	}

	<-notifyCh
	if err := ep.GetSockOpt(tcpip.ErrorOption{}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Write something.
	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)
	if _, _, err := ep.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read back what was written.
	wq.EventUnregister(&waitEntry)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	rd, _, err := ep.Read(nil)
	if err != nil {
		if err != tcpip.ErrWouldBlock {
			t.Fatalf("Read failed: %v", err)
		}
		<-notifyCh
		rd, _, err = ep.Read(nil)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

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
													t.Fatalf("NewEndpoint failed: %v", err)
												}
												eps = append(eps, ep)
												switch network {
												case "ipv4":
												case "ipv6":
													if err := ep.SetSockOpt(tcpip.V6OnlyOption(1)); err != nil {
														t.Fatalf("SetSockOpt(V6OnlyOption(1)) failed: %v", err)
													}
												case "dual":
													if err := ep.SetSockOpt(tcpip.V6OnlyOption(0)); err != nil {
														t.Fatalf("SetSockOpt(V6OnlyOption(0)) failed: %v", err)
													}
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

											for i := ports.FirstEphemeral; i <= math.MaxUint16; i++ {
												if makeEP(exhaustedNetwork).Bind(tcpip.FullAddress{Addr: address(t, exhaustedAddressType, isAny), Port: uint16(i)}); err != nil {
													t.Fatalf("Bind(%d) failed: %v", i, err)
												}
											}
											want := tcpip.ErrConnectStarted
											if collides {
												want = tcpip.ErrNoPortAvailable
											}
											if err := makeEP(candidateNetwork).Connect(tcpip.FullAddress{Addr: address(t, candidateAddressType, false), Port: 31337}); err != want {
												t.Fatalf("got ep.Connect(..) = %v, want = %v", err, want)
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
	c.CreateConnectedWithRawOptions(789, 30000, nil, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	})

	// Send 3200 bytes of data.
	const writeSize = 3200
	data := buffer.NewView(writeSize)
	for i := range data {
		data[i] = byte(i)
	}

	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	receivePackets := func(c *context.Context, sizes []int, which int, seqNum uint32) []byte {
		var ret []byte
		for i, size := range sizes {
			p := c.GetPacket()
			if i == which {
				ret = p
			}
			checker.IPv4(t, p,
				checker.PayloadLen(size+header.TCPMinimumSize),
				checker.TCP(
					checker.DstPort(context.TestPort),
					checker.SeqNum(seqNum),
					checker.AckNum(790),
					checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
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

	c.CreateConnected(789, 30000, nil)

	data := []byte{1, 2, 3}
	c.SendPacket(data, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  790,
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
		err *tcpip.Error
	}{
		{"reno", nil},
		{"cubic", nil},
		{"blahblah", tcpip.ErrNoSuchFile},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("SetTransportProtocolOption(.., %v)", tc.cc), func(t *testing.T) {
			c := context.New(t, 1500)
			defer c.Cleanup()

			s := c.Stack()

			var oldCC tcpip.CongestionControlOption
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &oldCC); err != nil {
				t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &oldCC, err)
			}

			if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tc.cc); err != tc.err {
				t.Fatalf("s.SetTransportProtocolOption(%v, %v) = %v, want %v", tcp.ProtocolNumber, tc.cc, err, tc.err)
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
	var aCC tcpip.AvailableCongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &aCC); err != nil {
		t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &aCC, err)
	}
	if got, want := aCC, tcpip.AvailableCongestionControlOption("reno cubic"); got != want {
		t.Fatalf("got tcpip.AvailableCongestionControlOption: %v, want: %v", got, want)
	}
}

func TestStackSetAvailableCongestionControl(t *testing.T) {
	c := context.New(t, 1500)
	defer c.Cleanup()

	s := c.Stack()

	// Setting AvailableCongestionControlOption should fail.
	aCC := tcpip.AvailableCongestionControlOption("xyz")
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &aCC); err == nil {
		t.Fatalf("s.TransportProtocolOption(%v, %v) = nil, want non-nil", tcp.ProtocolNumber, &aCC)
	}

	// Verify that we still get the expected list of congestion control options.
	var cc tcpip.AvailableCongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
		t.Fatalf("s.TransportProtocolOption(%v, %v) = %v", tcp.ProtocolNumber, &cc, err)
	}
	if got, want := cc, tcpip.AvailableCongestionControlOption("reno cubic"); got != want {
		t.Fatalf("got tcpip.AvailableCongestionControlOption: %v, want: %v", got, want)
	}
}

func TestEndpointSetCongestionControl(t *testing.T) {
	testCases := []struct {
		cc  tcpip.CongestionControlOption
		err *tcpip.Error
	}{
		{"reno", nil},
		{"cubic", nil},
		{"blahblah", tcpip.ErrNoSuchFile},
	}

	for _, connected := range []bool{false, true} {
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("SetSockOpt(.., %v) w/ connected = %v", tc.cc, connected), func(t *testing.T) {
				c := context.New(t, 1500)
				defer c.Cleanup()

				// Create TCP endpoint.
				var err *tcpip.Error
				c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
				if err != nil {
					t.Fatalf("NewEndpoint failed: %v", err)
				}

				var oldCC tcpip.CongestionControlOption
				if err := c.EP.GetSockOpt(&oldCC); err != nil {
					t.Fatalf("c.EP.SockOpt(%v) = %v", &oldCC, err)
				}

				if connected {
					c.Connect(789 /* iss */, 32768 /* rcvWnd */, nil)
				}

				if err := c.EP.SetSockOpt(tc.cc); err != tc.err {
					t.Fatalf("c.EP.SetSockOpt(%v) = %v, want %v", tc.cc, err, tc.err)
				}

				var cc tcpip.CongestionControlOption
				if err := c.EP.GetSockOpt(&cc); err != nil {
					t.Fatalf("c.EP.SockOpt(%v) = %v", &cc, err)
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
					t.Fatalf("got congestion control: %v, want: %v", got, want)
				}
			})
		}
	}
}

func enableCUBIC(t *testing.T, c *context.Context) {
	t.Helper()
	opt := tcpip.CongestionControlOption("cubic")
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(tcp.ProtocolNumber, %v = %v", opt, err)
	}
}

func TestKeepalive(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnected(789, 30000, nil)

	c.EP.SetSockOpt(tcpip.KeepaliveIdleOption(10 * time.Millisecond))
	c.EP.SetSockOpt(tcpip.KeepaliveIntervalOption(10 * time.Millisecond))
	c.EP.SetSockOpt(tcpip.KeepaliveCountOption(5))
	c.EP.SetSockOpt(tcpip.KeepaliveEnabledOption(1))

	// 5 unacked keepalives are sent. ACK each one, and check that the
	// connection stays alive after 5.
	for i := 0; i < 10; i++ {
		b := c.GetPacket()
		checker.IPv4(t, b,
			checker.TCP(
				checker.DstPort(context.TestPort),
				checker.SeqNum(uint32(c.IRS)),
				checker.AckNum(uint32(790)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)

		// Acknowledge the keepalive.
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: c.Port,
			Flags:   header.TCPFlagAck,
			SeqNum:  790,
			AckNum:  c.IRS,
			RcvWnd:  30000,
		})
	}

	// Check that the connection is still alive.
	if _, _, err := c.EP.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrWouldBlock)
	}

	// Send some data and wait before ACKing it. Keepalives should be disabled
	// during this period.
	view := buffer.NewView(3)
	if _, _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	next := uint32(c.IRS) + 1
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Wait for the packet to be retransmitted. Verify that no keepalives
	// were sent.
	checker.IPv4(t, c.GetPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(next),
			checker.AckNum(790),
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
		SeqNum:  790,
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
				checker.SeqNum(uint32(next-1)),
				checker.AckNum(uint32(790)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// The connection should be terminated after 5 unacked keepalives.
	checker.IPv4(t, c.GetPacket(),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(next)),
			checker.AckNum(uint32(790)),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
		),
	)

	if _, _, err := c.EP.Read(nil); err != tcpip.ErrConnectionReset {
		t.Fatalf("got c.EP.Read(nil) = %v, want = %v", err, tcpip.ErrConnectionReset)
	}
}

func executeHandshake(t *testing.T, c *context.Context, srcPort uint16, synCookieInUse bool) (irs, iss seqnum.Value) {
	// Send a SYN request.
	irs = seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: srcPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.w
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	iss = seqnum.Value(tcp.SequenceNumber())
	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(srcPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.AckNum(uint32(irs) + 1),
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

// TestListenBacklogFull tests that netstack does not complete handshakes if the
// listen backlog for the endpoint is full.
func TestListenBacklogFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	// Start listening.
	listenBacklog := 2
	if err := c.EP.Listen(listenBacklog); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	for i := 0; i < listenBacklog; i++ {
		executeHandshake(t, c, context.TestPort+uint16(i), false /*synCookieInUse */)
	}

	time.Sleep(50 * time.Millisecond)

	// Now execute send one more SYN. The stack should not respond as the backlog
	// is full at this point.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort + 2,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(789),
		RcvWnd:  30000,
	})
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Try to accept the connections in the backlog.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	for i := 0; i < listenBacklog; i++ {
		_, _, err = c.EP.Accept()
		if err == tcpip.ErrWouldBlock {
			// Wait for connection to be established.
			select {
			case <-ch:
				_, _, err = c.EP.Accept()
				if err != nil {
					t.Fatalf("Accept failed: %v", err)
				}

			case <-time.After(1 * time.Second):
				t.Fatalf("Timed out waiting for accept")
			}
		}
	}

	// Now verify that there are no more connections that can be accepted.
	_, _, err = c.EP.Accept()
	if err != tcpip.ErrWouldBlock {
		select {
		case <-ch:
			t.Fatalf("unexpected endpoint delivered on Accept: %+v", c.EP)
		case <-time.After(1 * time.Second):
		}
	}

	// Now a new handshake must succeed.
	executeHandshake(t, c, context.TestPort+2, false /*synCookieInUse */)

	newEP, _, err := c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			newEP, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that the TCP socket is usable and in a connected state.
	data := "Don't panic"
	newEP.Write(tcpip.SlicePayload(buffer.NewViewFromBytes([]byte(data))), tcpip.WriteOptions{})
	b := c.GetPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	if string(tcp.Payload()) != data {
		t.Fatalf("Unexpected data: got %v, want %v", string(tcp.Payload()), data)
	}
}

func TestListenSynRcvdQueueFull(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	// Start listening.
	listenBacklog := 1
	if err := c.EP.Listen(listenBacklog); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Send two SYN's the first one should get a SYN-ACK, the
	// second one should not get any response and is dropped as
	// the synRcvd count will be equal to backlog.
	irs := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(789),
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
		checker.AckNum(uint32(irs) + 1),
	}
	checker.IPv4(t, b, checker.TCP(tcpCheckers...))

	// Now execute send one more SYN. The stack should not respond as the backlog
	// is full at this point.
	//
	// NOTE: we did not complete the handshake for the previous one so the
	// accept backlog should be empty and there should be one connection in
	// synRcvd state.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort + 1,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  seqnum.Value(889),
		RcvWnd:  30000,
	})
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Now complete the previous connection and verify that there is a connection
	// to accept.
	// Send ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  irs + 1,
		AckNum:  iss + 1,
		RcvWnd:  30000,
	})

	// Try to accept the connections in the backlog.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	newEP, _, err := c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			newEP, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that the TCP socket is usable and in a connected state.
	data := "Don't panic"
	newEP.Write(tcpip.SlicePayload(buffer.NewViewFromBytes([]byte(data))), tcpip.WriteOptions{})
	pkt := c.GetPacket()
	tcp = header.TCP(header.IPv4(pkt).Payload())
	if string(tcp.Payload()) != data {
		t.Fatalf("Unexpected data: got %v, want %v", string(tcp.Payload()), data)
	}
}

func TestListenBacklogFullSynCookieInUse(t *testing.T) {
	saved := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = saved
	}()
	tcp.SynRcvdCountThreshold = 1

	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	// Create TCP endpoint.
	var err *tcpip.Error
	c.EP, err = c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	// Start listening.
	listenBacklog := 1
	portOffset := uint16(0)
	if err := c.EP.Listen(listenBacklog); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	executeHandshake(t, c, context.TestPort+portOffset, false)
	portOffset++
	// Wait for this to be delivered to the accept queue.
	time.Sleep(50 * time.Millisecond)

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  irs,
		RcvWnd:  30000,
	})
	// The Syn should be dropped as the endpoint's backlog is full.
	c.CheckNoPacketTimeout("unexpected packet received", 50*time.Millisecond)

	// Verify that there is only one acceptable connection at this point.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	_, _, err = c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	// Now verify that there are no more connections that can be accepted.
	_, _, err = c.EP.Accept()
	if err != tcpip.ErrWouldBlock {
		select {
		case <-ch:
			t.Fatalf("unexpected endpoint delivered on Accept: %+v", c.EP)
		case <-time.After(1 * time.Second):
		}
	}
}

func TestPassiveConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	c.EP = ep
	if err := ep.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateBound; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	if got, want := tcp.EndpointState(c.EP.State()), tcp.StateListen; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	stats := c.Stack().Stats()
	want := stats.TCP.PassiveConnectionOpenings.Value() + 1

	srcPort := uint16(context.TestPort)
	executeHandshake(t, c, srcPort+1, false)

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	// Verify that there is only one acceptable connection at this point.
	_, _, err = c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}

	if got := stats.TCP.PassiveConnectionOpenings.Value(); got != want {
		t.Errorf("got stats.TCP.PassiveConnectionOpenings.Value() = %v, want = %v", got, want)
	}
}

func TestPassiveFailedConnectionAttemptIncrement(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	stats := c.Stack().Stats()
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.WQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	c.EP = ep
	if err := c.EP.Bind(tcpip.FullAddress{Addr: context.StackAddr, Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if err := c.EP.Listen(1); err != nil {
		t.Fatalf("Listen failed: %v", err)
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
		SeqNum:  seqnum.Value(789),
		RcvWnd:  30000,
	})

	time.Sleep(50 * time.Millisecond)
	if got := stats.TCP.ListenOverflowSynDrop.Value(); got != want {
		t.Errorf("got stats.TCP.ListenOverflowSynDrop.Value() = %v, want = %v", got, want)
	}

	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	// Now check that there is one acceptable connections.
	_, _, err = c.EP.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			_, _, err = c.EP.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}
}

func TestEndpointBindListenAcceptState(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()
	wq := &waiter.Queue{}
	ep, err := c.Stack().NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateBound; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	if got, want := tcp.EndpointState(ep.State()), tcp.StateListen; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	c.PassiveConnectWithOptions(100, 5, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	aep, _, err := ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			aep, _, err = ep.Accept()
			if err != nil {
				t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			t.Fatalf("Timed out waiting for accept")
		}
	}
	if got, want := tcp.EndpointState(aep.State()), tcp.StateEstablished; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}
	// Listening endpoint remains in listen state.
	if got, want := tcp.EndpointState(ep.State()), tcp.StateListen; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

	ep.Close()
	// Give worker goroutines time to receive the close notification.
	time.Sleep(1 * time.Second)
	if got, want := tcp.EndpointState(ep.State()), tcp.StateClose; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}
	// Accepted endpoint remains open when the listen endpoint is closed.
	if got, want := tcp.EndpointState(aep.State()), tcp.StateEstablished; got != want {
		t.Errorf("Unexpected endpoint state: want %v, got %v", want, got)
	}

}
