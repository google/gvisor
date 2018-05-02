// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4_test

import (
	"context"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

const stackAddr = "\x0a\x00\x00\x01"

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack
}

func newTestContext(t *testing.T) *testContext {
	s := stack.New(&tcpip.StdClock{}, []string{ipv4.ProtocolName}, []string{ipv4.PingProtocolName})

	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: "\x00\x00\x00\x00",
		Mask:        "\x00\x00\x00\x00",
		Gateway:     "",
		NIC:         1,
	}})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

func (c *testContext) cleanup() {
	close(c.linkEP.C)
}

func (c *testContext) loopback() {
	go func() {
		for pkt := range c.linkEP.C {
			v := make(buffer.View, len(pkt.Header)+len(pkt.Payload))
			copy(v, pkt.Header)
			copy(v[len(pkt.Header):], pkt.Payload)
			vv := v.ToVectorisedView([1]buffer.View{})
			c.linkEP.Inject(pkt.Proto, &vv)
		}
	}()
}

func TestEcho(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()
	c.loopback()

	ch := make(chan ipv4.PingReply, 1)
	p := ipv4.Pinger{
		Stack: c.s,
		NICID: 1,
		Addr:  stackAddr,
		Wait:  10 * time.Millisecond,
		Count: 1, // one ping only
	}
	if err := p.Ping(context.Background(), ch); err != nil {
		t.Fatalf("icmp.Ping failed: %v", err)
	}

	ping := <-ch
	if ping.Error != nil {
		t.Errorf("bad ping response: %v", ping.Error)
	}
}

func TestEchoSequence(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()
	c.loopback()

	const numPings = 3
	ch := make(chan ipv4.PingReply, numPings)
	p := ipv4.Pinger{
		Stack: c.s,
		NICID: 1,
		Addr:  stackAddr,
		Wait:  10 * time.Millisecond,
		Count: numPings,
	}
	if err := p.Ping(context.Background(), ch); err != nil {
		t.Fatalf("icmp.Ping failed: %v", err)
	}

	for i := uint16(0); i < numPings; i++ {
		ping := <-ch
		if ping.Error != nil {
			t.Errorf("i=%d bad ping response: %v", i, ping.Error)
		}
		if ping.SeqNumber != i {
			t.Errorf("SeqNumber=%d, want %d", ping.SeqNumber, i)
		}
	}
}
