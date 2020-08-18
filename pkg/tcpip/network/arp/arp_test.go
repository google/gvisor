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

package arp_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	stackLinkAddr1 = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c")
	stackLinkAddr2 = tcpip.LinkAddress("\x0b\x0b\x0c\x0c\x0d\x0d")
	stackAddr1     = tcpip.Address("\x0a\x00\x00\x01")
	stackAddr2     = tcpip.Address("\x0a\x00\x00\x02")
	stackAddrBad   = tcpip.Address("\x0a\x00\x00\x03")

	defaultChannelSize = 1
	defaultMTU         = 65536
)

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack
}

func newTestContext(t *testing.T) *testContext {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4()},
	})

	ep := channel.New(defaultChannelSize, defaultMTU, stackLinkAddr1)
	wep := stack.LinkEndpoint(ep)

	if testing.Verbose() {
		wep = sniffer.New(ep)
	}
	if err := s.CreateNIC(1, wep); err != nil {
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
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: ep,
	}
}

func (c *testContext) cleanup() {
	c.linkEP.Close()
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
		c.linkEP.InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: v.ToVectorisedView(),
		}))
	}

	for i, address := range []tcpip.Address{stackAddr1, stackAddr2} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			inject(address)
			pi, _ := c.linkEP.ReadContext(context.Background())
			if pi.Proto != arp.ProtocolNumber {
				t.Fatalf("expected ARP response, got network protocol number %d", pi.Proto)
			}
			rep := header.ARP(pi.Pkt.NetworkHeader().View())
			if !rep.IsValid() {
				t.Fatalf("invalid ARP response: len = %d; response = %x", len(rep), rep)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressSender()), stackLinkAddr1; got != want {
				t.Errorf("got HardwareAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressSender()), tcpip.Address(h.ProtocolAddressTarget()); got != want {
				t.Errorf("got ProtocolAddressSender = %s, want = %s", got, want)
			}
			if got, want := tcpip.LinkAddress(rep.HardwareAddressTarget()), tcpip.LinkAddress(h.HardwareAddressSender()); got != want {
				t.Errorf("got HardwareAddressTarget = %s, want = %s", got, want)
			}
			if got, want := tcpip.Address(rep.ProtocolAddressTarget()), tcpip.Address(h.ProtocolAddressSender()); got != want {
				t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, want)
			}
		})
	}

	inject(stackAddrBad)
	// Sleep tests are gross, but this will only potentially flake
	// if there's a bug. If there is no bug this will reliably
	// succeed.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if pkt, ok := c.linkEP.ReadContext(ctx); ok {
		t.Errorf("stackAddrBad: unexpected packet sent, Proto=%v", pkt.Proto)
	}
}

func TestLinkAddressRequest(t *testing.T) {
	tests := []struct {
		name           string
		remoteLinkAddr tcpip.LinkAddress
		expectLinkAddr tcpip.LinkAddress
	}{
		{
			name:           "Unicast",
			remoteLinkAddr: stackLinkAddr2,
			expectLinkAddr: stackLinkAddr2,
		},
		{
			name:           "Multicast",
			remoteLinkAddr: "",
			expectLinkAddr: header.EthernetBroadcastAddress,
		},
	}

	for _, test := range tests {
		p := arp.NewProtocol()
		linkRes, ok := p.(stack.LinkAddressResolver)
		if !ok {
			t.Fatal("expected ARP protocol to implement stack.LinkAddressResolver")
		}

		linkEP := channel.New(defaultChannelSize, defaultMTU, stackLinkAddr1)
		if err := linkRes.LinkAddressRequest(stackAddr1, stackAddr2, test.remoteLinkAddr, linkEP); err != nil {
			t.Errorf("got p.LinkAddressRequest(%s, %s, %s, _) = %s", stackAddr1, stackAddr2, test.remoteLinkAddr, err)
		}

		pkt, ok := linkEP.Read()
		if !ok {
			t.Fatal("expected to send a link address request")
		}

		if got, want := pkt.Route.RemoteLinkAddress, test.expectLinkAddr; got != want {
			t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", got, want)
		}
	}
}
