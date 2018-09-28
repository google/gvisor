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

package gonet

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/nettest"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/loopback"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	NICID = 1
)

func TestTimeouts(t *testing.T) {
	nc := NewConn(nil, nil)
	dlfs := []struct {
		name string
		f    func(time.Time) error
	}{
		{"SetDeadline", nc.SetDeadline},
		{"SetReadDeadline", nc.SetReadDeadline},
		{"SetWriteDeadline", nc.SetWriteDeadline},
	}

	for _, dlf := range dlfs {
		if err := dlf.f(time.Time{}); err != nil {
			t.Errorf("got %s(time.Time{}) = %v, want = %v", dlf.name, err, nil)
		}
	}
}

func newLoopbackStack() (*stack.Stack, *tcpip.Error) {
	// Create the stack and add a NIC.
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	if err := s.CreateNIC(NICID, loopback.New()); err != nil {
		return nil, err
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		// IPv4
		{
			Destination: tcpip.Address(strings.Repeat("\x00", 4)),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", 4)),
			Gateway:     "",
			NIC:         NICID,
		},

		// IPv6
		{
			Destination: tcpip.Address(strings.Repeat("\x00", 16)),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", 16)),
			Gateway:     "",
			NIC:         NICID,
		},
	})

	return s, nil
}

type testConnection struct {
	wq *waiter.Queue
	e  *waiter.Entry
	ch chan struct{}
	ep tcpip.Endpoint
}

func connect(s *stack.Stack, addr tcpip.FullAddress) (*testConnection, *tcpip.Error) {
	wq := &waiter.Queue{}
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)

	entry, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&entry, waiter.EventOut)

	err = ep.Connect(addr)
	if err == tcpip.ErrConnectStarted {
		<-ch
		err = ep.GetSockOpt(tcpip.ErrorOption{})
	}
	if err != nil {
		return nil, err
	}

	wq.EventUnregister(&entry)
	wq.EventRegister(&entry, waiter.EventIn)

	return &testConnection{wq, &entry, ch, ep}, nil
}

func (c *testConnection) close() {
	c.wq.EventUnregister(c.e)
	c.ep.Close()
}

// TestCloseReader tests that Conn.Close() causes Conn.Read() to unblock.
func TestCloseReader(t *testing.T) {
	s, err := newLoopbackStack()
	if err != nil {
		t.Fatalf("newLoopbackStack() = %v", err)
	}

	addr := tcpip.FullAddress{NICID, tcpip.Address(net.IPv4(169, 254, 10, 1).To4()), 11211}

	s.AddAddress(NICID, ipv4.ProtocolNumber, addr.Addr)

	l, e := NewListener(s, addr, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatalf("NewListener() = %v", e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			t.Fatalf("l.Accept() = %v", err)
		}

		// Give c.Read() a chance to block before closing the connection.
		time.AfterFunc(time.Millisecond*50, func() {
			c.Close()
		})

		buf := make([]byte, 256)
		n, err := c.Read(buf)
		got, ok := err.(*net.OpError)
		want := tcpip.ErrConnectionAborted
		if n != 0 || !ok || got.Err.Error() != want.String() {
			t.Errorf("c.Read() = (%d, %v), want (0, OpError(%v))", n, err, want)
		}
	}()
	sender, err := connect(s, addr)
	if err != nil {
		t.Fatalf("connect() = %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Errorf("c.Read() didn't unblock")
	}
	sender.close()
}

// TestCloseReaderWithForwarder tests that Conn.Close() wakes Conn.Read() when
// using tcp.Forwarder.
func TestCloseReaderWithForwarder(t *testing.T) {
	s, err := newLoopbackStack()
	if err != nil {
		t.Fatalf("newLoopbackStack() = %v", err)
	}

	addr := tcpip.FullAddress{NICID, tcpip.Address(net.IPv4(169, 254, 10, 1).To4()), 11211}
	s.AddAddress(NICID, ipv4.ProtocolNumber, addr.Addr)

	done := make(chan struct{})

	fwd := tcp.NewForwarder(s, 30000, 10, func(r *tcp.ForwarderRequest) {
		defer close(done)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			t.Fatalf("r.CreateEndpoint() = %v", err)
		}
		defer ep.Close()
		r.Complete(false)

		c := NewConn(&wq, ep)

		// Give c.Read() a chance to block before closing the connection.
		time.AfterFunc(time.Millisecond*50, func() {
			c.Close()
		})

		buf := make([]byte, 256)
		n, e := c.Read(buf)
		got, ok := e.(*net.OpError)
		want := tcpip.ErrConnectionAborted
		if n != 0 || !ok || got.Err.Error() != want.String() {
			t.Errorf("c.Read() = (%d, %v), want (0, OpError(%v))", n, e, want)
		}
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	sender, err := connect(s, addr)
	if err != nil {
		t.Fatalf("connect() = %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Errorf("c.Read() didn't unblock")
	}
	sender.close()
}

// TestDeadlineChange tests that changing the deadline affects currently blocked reads.
func TestDeadlineChange(t *testing.T) {
	s, err := newLoopbackStack()
	if err != nil {
		t.Fatalf("newLoopbackStack() = %v", err)
	}

	addr := tcpip.FullAddress{NICID, tcpip.Address(net.IPv4(169, 254, 10, 1).To4()), 11211}

	s.AddAddress(NICID, ipv4.ProtocolNumber, addr.Addr)

	l, e := NewListener(s, addr, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatalf("NewListener() = %v", e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			t.Fatalf("l.Accept() = %v", err)
		}

		c.SetDeadline(time.Now().Add(time.Minute))
		// Give c.Read() a chance to block before closing the connection.
		time.AfterFunc(time.Millisecond*50, func() {
			c.SetDeadline(time.Now().Add(time.Millisecond * 10))
		})

		buf := make([]byte, 256)
		n, err := c.Read(buf)
		got, ok := err.(*net.OpError)
		want := "i/o timeout"
		if n != 0 || !ok || got.Err == nil || got.Err.Error() != want {
			t.Errorf("c.Read() = (%d, %v), want (0, OpError(%s))", n, err, want)
		}
	}()
	sender, err := connect(s, addr)
	if err != nil {
		t.Fatalf("connect() = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Millisecond * 500):
		t.Errorf("c.Read() didn't unblock")
	}
	sender.close()
}

func TestPacketConnTransfer(t *testing.T) {
	s, e := newLoopbackStack()
	if e != nil {
		t.Fatalf("newLoopbackStack() = %v", e)
	}

	ip1 := tcpip.Address(net.IPv4(169, 254, 10, 1).To4())
	addr1 := tcpip.FullAddress{NICID, ip1, 11211}
	s.AddAddress(NICID, ipv4.ProtocolNumber, ip1)
	ip2 := tcpip.Address(net.IPv4(169, 254, 10, 2).To4())
	addr2 := tcpip.FullAddress{NICID, ip2, 11311}
	s.AddAddress(NICID, ipv4.ProtocolNumber, ip2)

	c1, err := NewPacketConn(s, addr1, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("NewPacketConn(port 4):", err)
	}
	c2, err := NewPacketConn(s, addr2, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("NewPacketConn(port 5):", err)
	}

	c1.SetDeadline(time.Now().Add(time.Second))
	c2.SetDeadline(time.Now().Add(time.Second))

	sent := "abc123"
	sendAddr := fullToUDPAddr(addr2)
	if n, err := c1.WriteTo([]byte(sent), sendAddr); err != nil || n != len(sent) {
		t.Errorf("got c1.WriteTo(%q, %v) = %d, %v, want = %d, %v", sent, sendAddr, n, err, len(sent), nil)
	}
	recv := make([]byte, len(sent))
	n, recvAddr, err := c2.ReadFrom(recv)
	if err != nil || n != len(recv) {
		t.Errorf("got c2.ReadFrom() = %d, %v, want = %d, %v", n, err, len(recv), nil)
	}

	if recv := string(recv); recv != sent {
		t.Errorf("got recv = %q, want = %q", recv, sent)
	}

	if want := fullToUDPAddr(addr1); !reflect.DeepEqual(recvAddr, want) {
		t.Errorf("got recvAddr = %v, want = %v", recvAddr, want)
	}

	if err := c1.Close(); err != nil {
		t.Error("c1.Close():", err)
	}
	if err := c2.Close(); err != nil {
		t.Error("c2.Close():", err)
	}
}

func makePipe() (c1, c2 net.Conn, stop func(), err error) {
	s, e := newLoopbackStack()
	if e != nil {
		return nil, nil, nil, fmt.Errorf("newLoopbackStack() = %v", e)
	}

	ip := tcpip.Address(net.IPv4(169, 254, 10, 1).To4())
	addr := tcpip.FullAddress{NICID, ip, 11211}
	s.AddAddress(NICID, ipv4.ProtocolNumber, ip)

	l, err := NewListener(s, addr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("NewListener: %v", err)
	}

	c1, err = DialTCP(s, addr, ipv4.ProtocolNumber)
	if err != nil {
		l.Close()
		return nil, nil, nil, fmt.Errorf("DialTCP: %v", err)
	}

	c2, err = l.Accept()
	if err != nil {
		l.Close()
		c1.Close()
		return nil, nil, nil, fmt.Errorf("l.Accept: %v", err)
	}

	stop = func() {
		c1.Close()
		c2.Close()
	}

	if err := l.Close(); err != nil {
		stop()
		return nil, nil, nil, fmt.Errorf("l.Close(): %v", err)
	}

	return c1, c2, stop, nil
}

func TestTCPConnTransfer(t *testing.T) {
	c1, c2, _, err := makePipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c1.Close(); err != nil {
			t.Error("c1.Close():", err)
		}
		if err := c2.Close(); err != nil {
			t.Error("c2.Close():", err)
		}
	}()

	c1.SetDeadline(time.Now().Add(time.Second))
	c2.SetDeadline(time.Now().Add(time.Second))

	const sent = "abc123"

	tests := []struct {
		name string
		c1   net.Conn
		c2   net.Conn
	}{
		{"connected to accepted", c1, c2},
		{"accepted to connected", c2, c1},
	}

	for _, test := range tests {
		if n, err := test.c1.Write([]byte(sent)); err != nil || n != len(sent) {
			t.Errorf("%s: got test.c1.Write(%q) = %d, %v, want = %d, %v", test.name, sent, n, err, len(sent), nil)
			continue
		}

		recv := make([]byte, len(sent))
		n, err := test.c2.Read(recv)
		if err != nil || n != len(recv) {
			t.Errorf("%s: got test.c2.Read() = %d, %v, want = %d, %v", test.name, n, err, len(recv), nil)
			continue
		}

		if recv := string(recv); recv != sent {
			t.Errorf("%s: got recv = %q, want = %q", test.name, recv, sent)
		}
	}
}

func TestTCPDialError(t *testing.T) {
	s, e := newLoopbackStack()
	if e != nil {
		t.Fatalf("newLoopbackStack() = %v", e)
	}

	ip := tcpip.Address(net.IPv4(169, 254, 10, 1).To4())
	addr := tcpip.FullAddress{NICID, ip, 11211}

	_, err := DialTCP(s, addr, ipv4.ProtocolNumber)
	got, ok := err.(*net.OpError)
	want := tcpip.ErrNoRoute
	if !ok || got.Err.Error() != want.String() {
		t.Errorf("Got DialTCP() = %v, want = %v", err, tcpip.ErrNoRoute)
	}
}

func TestNetTest(t *testing.T) {
	nettest.TestConn(t, makePipe)
}
