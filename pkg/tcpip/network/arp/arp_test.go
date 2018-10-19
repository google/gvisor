// Copyright 2018 Google LLC
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

package arp_test

import (
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/arp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/ping"
)

const (
	stackLinkAddr = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c")
	stackAddr1    = tcpip.Address("\x0a\x00\x00\x01")
	stackAddr2    = tcpip.Address("\x0a\x00\x00\x02")
	stackAddrBad  = tcpip.Address("\x0a\x00\x00\x03")
)

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack
}

func newTestContext(t *testing.T) *testContext {
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName}, []string{ping.ProtocolName4}, stack.Options{})

	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, stackLinkAddr)
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr1); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr2); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		t.Fatalf("AddAddress for arp failed: %v", err)
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

func TestDirectRequest(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make(buffer.View, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), senderMAC)
	copy(h.ProtocolAddressSender(), senderIPv4)

	inject := func(addr tcpip.Address) {
		copy(h.ProtocolAddressTarget(), addr)
		c.linkEP.Inject(arp.ProtocolNumber, v.ToVectorisedView())
	}

	inject(stackAddr1)
	{
		pkt := <-c.linkEP.C
		if pkt.Proto != arp.ProtocolNumber {
			t.Fatalf("stackAddr1: expected ARP response, got network protocol number %v", pkt.Proto)
		}
		rep := header.ARP(pkt.Header)
		if !rep.IsValid() {
			t.Fatalf("stackAddr1: invalid ARP response len(pkt.Header)=%d", len(pkt.Header))
		}
		if tcpip.Address(rep.ProtocolAddressSender()) != stackAddr1 {
			t.Errorf("stackAddr1: expected sender to be set")
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
			t.Errorf("stackAddr1: expected sender to be stackLinkAddr, got %q", got)
		}
	}

	inject(stackAddr2)
	{
		pkt := <-c.linkEP.C
		if pkt.Proto != arp.ProtocolNumber {
			t.Fatalf("stackAddr2: expected ARP response, got network protocol number %v", pkt.Proto)
		}
		rep := header.ARP(pkt.Header)
		if !rep.IsValid() {
			t.Fatalf("stackAddr2: invalid ARP response len(pkt.Header)=%d", len(pkt.Header))
		}
		if tcpip.Address(rep.ProtocolAddressSender()) != stackAddr2 {
			t.Errorf("stackAddr2: expected sender to be set")
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
			t.Errorf("stackAddr2: expected sender to be stackLinkAddr, got %q", got)
		}
	}

	inject(stackAddrBad)
	select {
	case pkt := <-c.linkEP.C:
		t.Errorf("stackAddrBad: unexpected packet sent, Proto=%v", pkt.Proto)
	case <-time.After(100 * time.Millisecond):
		// Sleep tests are gross, but this will only potentially flake
		// if there's a bug. If there is no bug this will reliably
		// succeed.
	}
}
