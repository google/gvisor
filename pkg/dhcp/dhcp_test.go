// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dhcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
)

func TestDHCP(t *testing.T) {
	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}

	go func() {
		for pkt := range linkEP.C {
			v := make(buffer.View, len(pkt.Header)+len(pkt.Payload))
			copy(v, pkt.Header)
			copy(v[len(pkt.Header):], pkt.Payload)
			vv := v.ToVectorisedView([1]buffer.View{})
			linkEP.Inject(pkt.Proto, &vv)
		}
	}()

	s := stack.New(&tcpip.StdClock{}, []string{ipv4.ProtocolName}, []string{udp.ProtocolName})

	const nicid tcpip.NICID = 1
	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAddress(nicid, ipv4.ProtocolNumber, "\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAddress(nicid, ipv4.ProtocolNumber, "\xff\xff\xff\xff"); err != nil {
		t.Fatal(err)
	}
	const serverAddr = tcpip.Address("\xc0\xa8\x03\x01")
	if err := s.AddAddress(nicid, ipv4.ProtocolNumber, serverAddr); err != nil {
		t.Fatal(err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: tcpip.Address(strings.Repeat("\x00", 4)),
		Mask:        tcpip.Address(strings.Repeat("\x00", 4)),
		Gateway:     "",
		NIC:         nicid,
	}})

	var clientAddrs = []tcpip.Address{"\xc0\xa8\x03\x02", "\xc0\xa8\x03\x03"}

	serverCfg := Config{
		ServerAddress:    serverAddr,
		SubnetMask:       "\xff\xff\xff\x00",
		Gateway:          "\xc0\xa8\x03\xF0",
		DomainNameServer: "\x08\x08\x08\x08",
		LeaseLength:      24 * time.Hour,
	}
	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := NewServer(serverCtx, s, clientAddrs, serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	const clientLinkAddr0 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x52")
	c0 := NewClient(s, nicid, clientLinkAddr0)
	if err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}
	if err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	const clientLinkAddr1 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x53")
	c1 := NewClient(s, nicid, clientLinkAddr1)
	if err := c1.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c1.Address(), clientAddrs[1]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	if err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	if got, want := c0.Config(), serverCfg; got != want {
		t.Errorf("client config:\n\t%#+v\nwant:\n\t%#+v", got, want)
	}
}
