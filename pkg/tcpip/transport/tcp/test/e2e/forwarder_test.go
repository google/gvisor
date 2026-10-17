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

package forwarder_test

import (
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

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
		close(ch)
		r.Complete(false)
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
	e2e.CheckBrokenUpWrite(t, c, maxPayload)
}

func TestForwarderDoesNotRejectECNFlags(t *testing.T) {
	testCases := []struct {
		name  string
		flags header.TCPFlags
	}{
		{name: "non-setup ECN SYN w/ ECE", flags: header.TCPFlagEce},
		{name: "non-setup ECN SYN w/ CWR", flags: header.TCPFlagCwr},
		{name: "setup ECN SYN", flags: header.TCPFlagEce | header.TCPFlagCwr},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
				close(ch)
				r.Complete(false)
			})
			s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

			// Do 3-way handshake.
			c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize, Flags: tc.flags})

			// Wait for connection to be available.
			select {
			case err := <-ch:
				if err != nil {
					t.Fatalf("Error creating endpoint: %s", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Timed out waiting for connection")
			}
		})
	}
}

func TestForwarderFailedConnect(t *testing.T) {
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		close(ch)
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Initiate a connection that will be forwarded by the Forwarder.
	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply. Make sure MSS and other expected options
	// are present.
	v := c.GetPacket()
	defer v.Release()
	tcp := header.TCP(header.IPv4(v.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(iss) + 1),
	}
	checker.IPv4(t, v, checker.TCP(tcpCheckers...))

	// Now send an active RST to abort the handshake.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss + 1,
		RcvWnd:  0,
	})

	// Wait for connect to fail.
	select {
	case err := <-ch:
		if err == nil {
			t.Fatalf("endpoint creation should have failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection to fail")
	}
}

func TestForwarderReopenAfterTimeWait(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	// Buffered so the handler for either connection can send its result
	// without waiting on the test to catch up.
	ch := make(chan tcpip.Error, 2)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then immediately
	// close the resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	b := c.GetPacket()
	defer b.Release()
	tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	c.EP.Close()

	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	// Ack our FIN and send our own, which puts the forwarded endpoint into
	// TIME_WAIT once we ack it below.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// The 4-tuple is now in TIME_WAIT. Per RFC 1122, a new SYN with a
	// sequence number higher than anything seen on the old connection
	// should be allowed to reopen the connection. Since this stack only
	// has a tcp.Forwarder and no bound listening endpoint, the new SYN
	// must reach the forwarder just like a brand new connection would.
	newISS := iss.Add(3)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  newISS,
		RcvWnd:  30000,
	})

	b = c.GetPacket()
	defer b.Release()
	tcpHdr = header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())
	checker.IPv4(t, b, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
		checker.TCPAckNum(uint32(newISS)+1)))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  newISS + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint for reopened connection: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for reopened connection")
	}
}

// TestForwarderTimeWaitRejectedGetsReset checks that a segment arriving
// during TIME_WAIT that the default handler declines to claim (a SYN-ACK,
// which tcp.Forwarder.HandlePacket rejects rather than a new-connection
// SYN) is answered with a RST instead of being dropped silently.
func TestForwarderTimeWaitRejectedGetsReset(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then immediately
	// close the resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	b := c.GetPacket()
	defer b.Release()
	tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	c.EP.Close()

	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	// Ack our FIN and send our own, which puts the forwarded endpoint into
	// TIME_WAIT once we ack it below.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// The 4-tuple is now in TIME_WAIT. A SYN-ACK with a sequence number
	// higher than anything seen on the old connection still counts as a
	// "new SYN" for handleTimeWaitSegments's purposes and gets reflected
	// to the default handler, but tcp.Forwarder.HandlePacket only claims
	// bare SYNs and returns false for it. The stack must fall back to a
	// RST for this segment, the same way the normal (non-TIME_WAIT)
	// delivery path does when the default handler declines a segment,
	// rather than dropping it without a reply.
	newISS := iss.Add(3)
	rejectedAck := c.IRS.Add(100)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  newISS,
		AckNum:  rejectedAck,
		RcvWnd:  30000,
	})

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst),
		checker.TCPSeqNum(uint32(rejectedAck))))

	select {
	case err := <-ch:
		t.Fatalf("forwarder unexpectedly created an endpoint for a rejected SYN-ACK: %s", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestForwarderDroppedStats(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	const maxInFlight = 2
	iters := atomicbitops.FromInt64(maxInFlight)
	s := c.Stack()
	checkedStats := make(chan struct{})
	done := make(chan struct{})
	f := tcp.NewForwarder(s, 65536, maxInFlight, func(r *tcp.ForwarderRequest) {
		<-checkedStats
		// Complete all requests without doing anything
		r.Complete(false)
		if iter := iters.Add(-1); iter == 0 {
			close(done)
		}
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	for i := 0; i < maxInFlight+1; i++ {
		iss := seqnum.Value(context.TestInitialSequenceNumber + i)
		c.SendPacket(nil, &context.Headers{
			SrcPort: uint16(context.TestPort + i),
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  iss,
			RcvWnd:  30000,
		})
	}

	// Verify that we got one ignored packet.
	if curr := s.Stats().TCP.ForwardMaxInFlightDrop.Value(); curr != 1 {
		t.Errorf("Expected one dropped connection, but got %d", curr)
	}
	close(checkedStats)
	<-done
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
