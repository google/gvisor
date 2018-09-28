// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const nicid = tcpip.NICID(1)
const serverAddr = tcpip.Address("\xc0\xa8\x03\x01")

func createStack(t *testing.T) *stack.Stack {
	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}

	go func() {
		for pkt := range linkEP.C {
			linkEP.Inject(pkt.Proto, buffer.NewVectorisedView(len(pkt.Header)+len(pkt.Payload), []buffer.View{pkt.Header, pkt.Payload}))
		}
	}()

	s := stack.New([]string{ipv4.ProtocolName}, []string{udp.ProtocolName}, stack.Options{})

	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAddress(nicid, ipv4.ProtocolNumber, serverAddr); err != nil {
		t.Fatal(err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: tcpip.Address(strings.Repeat("\x00", 4)),
		Mask:        tcpip.AddressMask(strings.Repeat("\x00", 4)),
		Gateway:     "",
		NIC:         nicid,
	}})

	return s
}

func TestDHCP(t *testing.T) {
	s := createStack(t)
	clientAddrs := []tcpip.Address{"\xc0\xa8\x03\x02", "\xc0\xa8\x03\x03"}

	serverCfg := Config{
		ServerAddress: serverAddr,
		SubnetMask:    "\xff\xff\xff\x00",
		Gateway:       "\xc0\xa8\x03\xF0",
		DNS: []tcpip.Address{
			"\x08\x08\x08\x08", "\x08\x08\x04\x04",
		},
		LeaseLength: 24 * time.Hour,
	}
	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := newEPConnServer(serverCtx, s, clientAddrs, serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	const clientLinkAddr0 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x52")
	c0 := NewClient(s, nicid, clientLinkAddr0, nil)
	if _, err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}
	if _, err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	const clientLinkAddr1 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x53")
	c1 := NewClient(s, nicid, clientLinkAddr1, nil)
	if _, err := c1.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c1.Address(), clientAddrs[1]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	if _, err := c0.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got, want := c0.Address(), clientAddrs[0]; got != want {
		t.Errorf("c.Addr()=%s, want=%s", got, want)
	}

	if got, want := c0.Config(), serverCfg; !equalConfig(got, want) {
		t.Errorf("client config:\n\t%#+v\nwant:\n\t%#+v", got, want)
	}
}

func equalConfig(c0, c1 Config) bool {
	if c0.Error != c1.Error || c0.ServerAddress != c1.ServerAddress || c0.SubnetMask != c1.SubnetMask || c0.Gateway != c1.Gateway || c0.LeaseLength != c1.LeaseLength {
		return false
	}
	if len(c0.DNS) != len(c1.DNS) {
		return false
	}
	for i := 0; i < len(c0.DNS); i++ {
		if c0.DNS[i] != c1.DNS[i] {
			return false
		}
	}
	return true
}

func TestRenew(t *testing.T) {
	s := createStack(t)
	clientAddrs := []tcpip.Address{"\xc0\xa8\x03\x02"}

	serverCfg := Config{
		ServerAddress: serverAddr,
		SubnetMask:    "\xff\xff\xff\x00",
		Gateway:       "\xc0\xa8\x03\xF0",
		DNS:           []tcpip.Address{"\x08\x08\x08\x08"},
		LeaseLength:   1 * time.Second,
	}
	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := newEPConnServer(serverCtx, s, clientAddrs, serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	var curAddr tcpip.Address
	addrCh := make(chan tcpip.Address)
	acquiredFunc := func(oldAddr, newAddr tcpip.Address, cfg Config) {
		if err := cfg.Error; err != nil {
			t.Fatalf("acquisition %d failed: %v", count, err)
		}
		if oldAddr != curAddr {
			t.Fatalf("aquisition %d: curAddr=%v, oldAddr=%v", count, curAddr, oldAddr)
		}
		if cfg.LeaseLength != time.Second {
			t.Fatalf("aquisition %d: lease length: %v, want %v", count, cfg.LeaseLength, time.Second)
		}
		count++
		curAddr = newAddr
		addrCh <- newAddr
	}

	clientCtx, cancel := context.WithCancel(context.Background())
	const clientLinkAddr0 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x52")
	c := NewClient(s, nicid, clientLinkAddr0, acquiredFunc)
	c.Run(clientCtx)

	var addr tcpip.Address
	select {
	case addr = <-addrCh:
		t.Logf("got first address: %v", addr)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout acquiring initial address")
	}

	select {
	case newAddr := <-addrCh:
		t.Logf("got renewal: %v", newAddr)
		if newAddr != addr {
			t.Fatalf("renewal address is %v, want %v", newAddr, addr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for address renewal")
	}

	cancel()
}

// Regression test for https://fuchsia.atlassian.net/browse/NET-17
func TestNoNullTerminator(t *testing.T) {
	v := "\x02\x01\x06\x00" +
		"\xc8\x37\xbe\x73\x00\x00\x80\x00\x00\x00\x00\x00\xc0\xa8\x2b\x92" +
		"\xc0\xa8\x2b\x01\x00\x00\x00\x00\x00\x0f\x60\x0a\x23\x93\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x02\x36" +
		"\x04\xc0\xa8\x2b\x01\x33\x04\x00\x00\x0e\x10\x3a\x04\x00\x00\x07" +
		"\x08\x3b\x04\x00\x00\x0c\x4e\x01\x04\xff\xff\xff\x00\x1c\x04\xc0" +
		"\xa8\x2b\xff\x03\x04\xc0\xa8\x2b\x01\x06\x04\xc0\xa8\x2b\x01\x2b" +
		"\x0f\x41\x4e\x44\x52\x4f\x49\x44\x5f\x4d\x45\x54\x45\x52\x45\x44" +
		"\xff"
	h := header(v)
	if !h.isValid() {
		t.Error("failed to decode header")
	}

	if got, want := h.op(), opReply; got != want {
		t.Errorf("h.op()=%v, want=%v", got, want)
	}

	if _, err := h.options(); err != nil {
		t.Errorf("bad options: %v", err)
	}
}

func teeConn(c conn) (conn, conn) {
	dup1 := &dupConn{
		c:   c,
		dup: make(chan connMsg, 8),
	}
	dup2 := &chConn{
		c:  c,
		ch: dup1.dup,
	}
	return dup1, dup2
}

type connMsg struct {
	buf  buffer.View
	addr tcpip.FullAddress
	err  error
}

type dupConn struct {
	c   conn
	dup chan connMsg
}

func (c *dupConn) Read() (buffer.View, tcpip.FullAddress, error) {
	v, addr, err := c.c.Read()
	c.dup <- connMsg{v, addr, err}
	return v, addr, err
}
func (c *dupConn) Write(b []byte, addr *tcpip.FullAddress) error { return c.c.Write(b, addr) }

type chConn struct {
	ch chan connMsg
	c  conn
}

func (c *chConn) Read() (buffer.View, tcpip.FullAddress, error) {
	msg := <-c.ch
	return msg.buf, msg.addr, msg.err
}
func (c *chConn) Write(b []byte, addr *tcpip.FullAddress) error { return c.c.Write(b, addr) }

func TestTwoServers(t *testing.T) {
	s := createStack(t)

	wq := new(waiter.Queue)
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("dhcp: server endpoint: %v", err)
	}
	if err = ep.Bind(tcpip.FullAddress{Port: ServerPort}, nil); err != nil {
		t.Fatalf("dhcp: server bind: %v", err)
	}

	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c1, c2 := teeConn(newEPConn(serverCtx, wq, ep))

	if _, err := NewServer(serverCtx, c1, []tcpip.Address{"\xc0\xa8\x03\x02"}, Config{
		ServerAddress: "\xc0\xa8\x03\x01",
		SubnetMask:    "\xff\xff\xff\x00",
		Gateway:       "\xc0\xa8\x03\xF0",
		DNS:           []tcpip.Address{"\x08\x08\x08\x08"},
		LeaseLength:   30 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(serverCtx, c2, []tcpip.Address{"\xc0\xa8\x04\x02"}, Config{
		ServerAddress: "\xc0\xa8\x04\x01",
		SubnetMask:    "\xff\xff\xff\x00",
		Gateway:       "\xc0\xa8\x03\xF0",
		DNS:           []tcpip.Address{"\x08\x08\x08\x08"},
		LeaseLength:   30 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	const clientLinkAddr0 = tcpip.LinkAddress("\x52\x11\x22\x33\x44\x52")
	c := NewClient(s, nicid, clientLinkAddr0, nil)
	if _, err := c.Request(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}
