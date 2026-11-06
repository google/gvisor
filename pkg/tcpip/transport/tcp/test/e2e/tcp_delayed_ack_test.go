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

package tcp_delayed_ack_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// delayedAckTimeout is Linux's TCP_DELACK_MIN.
	delayedAckTimeout = 40 * time.Millisecond

	// quickAcks is Linux's TCP_MAX_QUICKACKS.
	quickAcks = 16

	// peerMSS is the MSS that the peer advertises.
	peerMSS = 1460
)

type delayedAckContext struct {
	*context.Context
	t     *testing.T
	clock *faketime.ManualClock
	peer  *context.RawEndpoint

	// unread is the number of bytes the peer sent in order that the
	// endpoint has not read.
	unread int
}

// newDelayedAckContext connects an endpoint to a peer that advertises
// peerMSS. setup, if not nil, is called before connecting.
func newDelayedAckContext(t *testing.T, opts context.Options, setup func(tcpip.Endpoint)) *delayedAckContext {
	clock := faketime.NewManualClock()
	opts.EnableV4 = true
	opts.MTU = e2e.DefaultMTU
	opts.Clock = clock
	c := context.NewWithOpts(t, opts)
	t.Cleanup(c.Cleanup)
	c.Create(-1 /* epRcvBuf */)
	if setup != nil {
		setup(c.EP)
	}
	const iss = context.TestInitialSequenceNumber
	mssOpt := make([]byte, header.TCPOptionMSSLength)
	header.EncodeMSSOption(peerMSS, mssOpt)
	c.Connect(iss, 30000, mssOpt)
	return &delayedAckContext{
		Context: c,
		t:       t,
		clock:   clock,
		peer: &context.RawEndpoint{
			C:          c,
			SrcPort:    context.TestPort,
			DstPort:    c.Port,
			Flags:      header.TCPFlagAck,
			NextSeqNum: iss + 1,
			AckNum:     c.IRS + 1,
			WndSize:    30000,
		},
	}
}

// send sends n bytes in order and waits until the endpoint has processed them.
func (c *delayedAckContext) send(n int) {
	c.t.Helper()
	c.peer.SendPacket(make([]byte, n), nil)
	c.unread += n
	// The queue size is read under the endpoint lock, so once it includes the
	// data, the endpoint has also decided whether to acknowledge it.
	if err := testutil.Poll(func() error {
		if got, err := c.EP.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err != nil || got != c.unread {
			return fmt.Errorf("receive queue size = (%d, %v), want %d", got, err, c.unread)
		}
		return nil
	}, time.Second); err != nil {
		c.t.Fatal(err)
	}
}

// read reads everything the peer sent.
func (c *delayedAckContext) read() {
	c.t.Helper()
	res, err := c.EP.Read(io.Discard, tcpip.ReadOptions{})
	if err != nil || res.Count != c.unread {
		c.t.Fatalf("Read = (%d, %s), want %d", res.Count, err, c.unread)
	}
	c.unread = 0
}

// respond sends one byte, checks that it acknowledges everything the peer
// sent, and acknowledges it from the peer's next segment.
func (c *delayedAckContext) respond() {
	c.t.Helper()
	if _, err := c.EP.Write(bytes.NewReader([]byte{1}), tcpip.WriteOptions{}); err != nil {
		c.t.Fatalf("Write: %s", err)
	}
	b := c.GetPacket()
	defer b.Release()
	checker.IPv4(c.t, b,
		checker.PayloadLen(header.TCPMinimumSize+1),
		checker.TCP(
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			checker.TCPAckNum(uint32(c.peer.NextSeqNum)),
		),
	)
	c.peer.AckNum++
}

// warmUp uses up the quick ACKs at the start of the connection.
func (c *delayedAckContext) warmUp() {
	c.t.Helper()
	for i := 0; i < quickAcks; i++ {
		c.send(1)
		c.checkACK()
	}
}

// checkACK checks that the endpoint has acknowledged everything the peer sent.
func (c *delayedAckContext) checkACK() {
	c.t.Helper()
	b := c.GetPacket()
	defer b.Release()
	checker.IPv4(c.t, b, checker.TCP(
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPAckNum(uint32(c.peer.NextSeqNum)),
	))
}

// checkNoPacket checks that the endpoint has not sent anything. Packets sent
// for received data or from timers are queued before send and Advance return.
func (c *delayedAckContext) checkNoPacket(msg string) {
	c.t.Helper()
	if b := c.GetPacketNonBlocking(); b != nil {
		b.Release()
		c.t.Fatal(msg)
	}
}

// checkDelayedACK checks that the endpoint acknowledges everything the peer
// sent after delayedAckTimeout, and not before.
func (c *delayedAckContext) checkDelayedACK() {
	c.t.Helper()
	c.checkNoPacket("ACK sent without delay")
	c.clock.Advance(delayedAckTimeout - time.Millisecond)
	c.checkNoPacket("ACK sent before the delayed ACK timeout")
	c.clock.Advance(time.Millisecond)
	c.checkACK()
}

func TestDelayedACK(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, nil)
	// Data sent before any data is received is not a response, so the
	// connection keeps its quick ACKs.
	c.respond()
	c.warmUp()
	c.send(1)
	c.checkDelayedACK()
}

func TestDelayedACKTwoFullSegments(t *testing.T) {
	// Full-sized segments from the peer are smaller than the segments the
	// endpoint may send.
	const mss = 536
	c := newDelayedAckContext(t, context.Options{}, func(ep tcpip.Endpoint) {
		if err := ep.SetSockOptInt(tcpip.MaxSegOption, mss); err != nil {
			t.Fatalf("SetSockOptInt(MaxSegOption, %d): %s", mss, err)
		}
	})
	c.warmUp()
	c.send(mss)
	c.checkNoPacket("ACK sent for one full-sized segment")
	c.send(mss)
	c.checkACK()
}

func TestDelayedACKSmallerFullSegments(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, nil)
	c.warmUp()
	c.send(peerMSS)
	c.checkDelayedACK()

	// The peer now sends smaller full-sized segments, for example after its
	// path MTU decreased.
	const mss = 536
	c.send(mss)
	c.checkNoPacket("ACK sent for one full-sized segment")
	c.send(mss)
	c.checkACK()
}

// groDispatcher delivers packets from GRO to the endpoint.
type groDispatcher struct {
	c *delayedAckContext
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.DeliverNetworkPacket.
func (d groDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.c.InjectInbound(protocol, pkt)
}

// DeliverLinkPacket implements stack.NetworkDispatcher.DeliverLinkPacket.
func (groDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestDelayedACKGRO(t *testing.T) {
	// GRO does not update checksums, so links that use it validate them.
	c := newDelayedAckContext(t, context.Options{RXChecksumOffload: true}, nil)
	c.warmUp()

	// GRO coalesces two full-sized segments, which are acknowledged
	// immediately.
	g := gro.GRO{Dispatcher: groDispatcher{c}}
	g.Init(true)
	rcvd := c.Stack().Stats().IP.PacketsReceived.Value()
	for i := 0; i < 2; i++ {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: c.BuildSegment(make([]byte, peerMSS), &context.Headers{
				SrcPort: c.peer.SrcPort,
				DstPort: c.peer.DstPort,
				Flags:   header.TCPFlagAck,
				SeqNum:  c.peer.NextSeqNum,
				AckNum:  c.peer.AckNum,
				RcvWnd:  c.peer.WndSize,
			}),
		})
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
		g.Enqueue(pkt)
		pkt.DecRef()
		c.peer.NextSeqNum = c.peer.NextSeqNum.Add(peerMSS)
	}
	g.Flush()
	c.checkACK()
	if got := c.Stack().Stats().IP.PacketsReceived.Value() - rcvd; got != 1 {
		t.Fatalf("got %d packets from GRO, want 1", got)
	}
}

func TestDelayedACKFilledGap(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, nil)
	c.warmUp()

	// Out-of-order data is acknowledged immediately.
	gap := c.peer.NextSeqNum
	c.peer.NextSeqNum++
	c.peer.SendPacket([]byte{1}, nil)
	c.peer.NextSeqNum = gap
	b := c.GetPacket()
	checker.IPv4(t, b, checker.TCP(
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPAckNum(uint32(gap)),
	))
	b.Release()

	// So is the data that fills the gap.
	c.peer.SendPacket([]byte{1}, nil)
	c.peer.NextSeqNum++
	c.checkACK()
}

func TestDelayedACKPiggyback(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, nil)
	c.warmUp()
	c.send(1)
	c.checkNoPacket("ACK sent without delay")
	c.respond()
	c.clock.Advance(delayedAckTimeout)
	c.checkNoPacket("ACK sent after the response carried it")
}

func TestDelayedACKRead(t *testing.T) {
	// The initial rcvMSS.
	const mss = 536
	for _, tc := range []struct {
		name    string
		flags   header.TCPFlags
		size    int
		wantACK bool
	}{
		{"Small", header.TCPFlagAck, 1, true},
		{"FullSizedPushed", header.TCPFlagAck | header.TCPFlagPsh, mss, true},
		{"FullSized", header.TCPFlagAck, mss, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newDelayedAckContext(t, context.Options{}, nil)
			c.warmUp()
			c.peer.Flags = tc.flags
			c.send(tc.size)
			c.checkNoPacket("ACK sent without delay")
			c.read()
			if tc.wantACK {
				c.checkACK()
			} else {
				c.checkDelayedACK()
			}
		})
	}
}

func TestDelayedACKInteractive(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, nil)
	c.warmUp()
	c.send(1)
	c.respond()

	// Responses carry the ACKs of requests that the application read.
	c.send(1)
	c.read()
	c.checkNoPacket("ACK sent after reading a request")
	c.respond()

	// Unless the application reads more than one small segment.
	c.send(1)
	c.send(1)
	c.checkNoPacket("ACK sent without delay")
	c.read()
	c.checkACK()

	// The connection is not interactive after a response misses the delayed
	// ACK.
	c.send(1)
	c.read()
	c.checkDelayedACK()
	c.send(1)
	c.read()
	c.checkACK()
}

func TestDelayedACKLinkWriteError(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{
		LinkWriteError: func(pkts stack.PacketBufferList) tcpip.Error {
			for _, pkt := range pkts.AsSlice() {
				if pkt.Data().Size() != 0 {
					return &tcpip.ErrNoBufferSpace{}
				}
			}
			return nil
		},
	}, nil)
	c.warmUp()
	c.send(1)

	// The link rejects the response, so the ACK is still sent on time.
	if _, err := c.EP.Write(bytes.NewReader([]byte{1}), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write: %s", err)
	}
	c.checkDelayedACK()
}

func TestDelayedACKQuickAck(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		c := newDelayedAckContext(t, context.Options{}, nil)
		c.warmUp()
		c.send(1)
		c.respond()
		c.send(1)
		c.read()
		c.checkNoPacket("ACK sent after reading a request")
		c.EP.SocketOptions().SetQuickAck(true)
		c.checkACK()
	})
	t.Run("Clear", func(t *testing.T) {
		c := newDelayedAckContext(t, context.Options{}, func(ep tcpip.Endpoint) {
			ep.SocketOptions().SetQuickAck(false)
		})
		c.send(1)
		c.checkDelayedACK()
	})
}

func TestDelayedACKRestore(t *testing.T) {
	c := newDelayedAckContext(t, context.Options{}, func(ep tcpip.Endpoint) {
		ep.SocketOptions().SetQuickAck(false)
	})
	c.Stack().SetAllowLiveTCPMigration(true)
	c.Stack().SetRemoveConf(true)
	c.send(1)
	c.checkNoPacket("ACK sent without delay")

	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, c.Stack()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	defer s.Destroy()
	s.SetAllowLiveTCPMigration(true)
	if _, err := state.Load(t.Context(), &buf, s); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ep := channel.New(10, e2e.DefaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: context.StackAddrWithPrefix,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	s.Restore()

	// The ACK that was delayed at save is sent after restore. The restored
	// stack uses the saved clock.
	s.Clock().(*faketime.ManualClock).Advance(delayedAckTimeout)
	pkt := ep.Read()
	if pkt == nil {
		t.Fatal("no ACK after restore")
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.TCPFlags(header.TCPFlagAck),
		checker.TCPAckNum(uint32(c.peer.NextSeqNum)),
	))
}
