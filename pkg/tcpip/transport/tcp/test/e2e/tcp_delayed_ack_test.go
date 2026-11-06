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

	// rcvd is the number of bytes the peer sent in order.
	rcvd int
}

// newDelayedAckContext connects an endpoint to a peer that advertises
// peerMSS. setup, if not nil, is called before connecting.
func newDelayedAckContext(t *testing.T, linkWriteError func(stack.PacketBufferList) tcpip.Error, setup func(tcpip.Endpoint)) *delayedAckContext {
	clock := faketime.NewManualClock()
	c := context.NewWithOpts(t, context.Options{
		EnableV4:       true,
		MTU:            e2e.DefaultMTU,
		Clock:          clock,
		LinkWriteError: linkWriteError,
	})
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
	c.rcvd += n
	// The queue size is read under the endpoint lock, so once it includes the
	// data, the endpoint has also decided whether to acknowledge it.
	if err := testutil.Poll(func() error {
		if got, err := c.EP.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err != nil || got != c.rcvd {
			return fmt.Errorf("receive queue size = (%d, %v), want %d", got, err, c.rcvd)
		}
		return nil
	}, time.Second); err != nil {
		c.t.Fatal(err)
	}
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
	c := newDelayedAckContext(t, nil, nil)
	c.warmUp()
	c.send(1)
	c.checkDelayedACK()
}

func TestDelayedACKTwoFullSegments(t *testing.T) {
	// Full-sized segments from the peer are smaller than the segments the
	// endpoint may send.
	const mss = 536
	c := newDelayedAckContext(t, nil, func(ep tcpip.Endpoint) {
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
	c := newDelayedAckContext(t, nil, nil)
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

func TestDelayedACKFilledGap(t *testing.T) {
	c := newDelayedAckContext(t, nil, nil)
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
	c := newDelayedAckContext(t, nil, nil)
	c.warmUp()
	c.send(1)
	c.checkNoPacket("ACK sent without delay")

	// The response carries the ACK.
	if _, err := c.EP.Write(bytes.NewReader([]byte{1}), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write: %s", err)
	}
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(header.TCPMinimumSize+1),
		checker.TCP(
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
			checker.TCPAckNum(uint32(c.peer.NextSeqNum)),
		),
	)
	b.Release()
	c.clock.Advance(delayedAckTimeout)
	c.checkNoPacket("ACK sent after the response carried it")
}

func TestDelayedACKLinkWriteError(t *testing.T) {
	c := newDelayedAckContext(t, func(pkts stack.PacketBufferList) tcpip.Error {
		for _, pkt := range pkts.AsSlice() {
			if pkt.Data().Size() != 0 {
				return &tcpip.ErrNoBufferSpace{}
			}
		}
		return nil
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
		c := newDelayedAckContext(t, nil, nil)
		c.warmUp()
		c.send(1)
		c.checkNoPacket("ACK sent without delay")
		c.EP.SocketOptions().SetQuickAck(true)
		c.checkACK()
	})
	t.Run("Clear", func(t *testing.T) {
		c := newDelayedAckContext(t, nil, func(ep tcpip.Endpoint) {
			ep.SocketOptions().SetQuickAck(false)
		})
		c.send(1)
		c.checkDelayedACK()
	})
}

func TestDelayedACKRestore(t *testing.T) {
	c := newDelayedAckContext(t, nil, func(ep tcpip.Endpoint) {
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
