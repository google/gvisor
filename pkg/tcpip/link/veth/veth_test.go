// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package veth_test

import (
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestSetLinkAddress(t *testing.T) {
	addrs := []tcpip.LinkAddress{"abc", "def"}
	e, e2 := veth.NewPair(1500)
	defer e.Close()
	defer e2.Close()
	for _, addr := range addrs {
		e.SetLinkAddress(addr)

		if want, v := addr, e.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}

type testNetworkDispatcher struct {
	ch chan *stack.PacketBuffer
}

func (d *testNetworkDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	pkt.IncRef()
	d.ch <- pkt
}

func (*testNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	panic("not implemented")
}

func TestWritePacket(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")

		netProto = 55
		nicID    = 5
	)

	veth1, veth2 := veth.NewPair(1500)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer, 1)}
	veth2Ethernet := ethernet.New(veth2)
	veth2Ethernet.Attach(sink)

	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}
	pkt := <-sink.ch
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}

	eth := header.Ethernet(pkt.LinkHeader().Slice())
	pkt.DecRef()
	if got := eth.SourceAddress(); got != localLinkAddr {
		t.Errorf("got eth.SourceAddress() = %s, want = %s", got, localLinkAddr)
	}
	if got := eth.DestinationAddress(); got != remoteLinkAddr {
		t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
	}
	if got := eth.Type(); got != netProto {
		t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
	}
}

func TestDestroyDevices(t *testing.T) {
	const (
		vethFirstID  = 5
		vethSecondID = 6
	)

	veth1, veth2 := veth.NewPair(1500)

	s1 := stack.New(stack.Options{})
	if err := s1.CreateNIC(vethFirstID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethFirstID, err)
	}

	s2 := stack.New(stack.Options{})
	if err := s2.CreateNIC(vethSecondID, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethSecondID, err)
	}

	s1.RemoveNIC(vethFirstID)
	timeout := time.Millisecond
	for s2.HasNIC(vethSecondID) && timeout < 5*time.Second {
		time.Sleep(timeout)
		timeout += timeout
	}
	if s2.HasNIC(vethSecondID) {
		t.Fatalf("veth2 hasn't been destroyed")
	}
}

func TestMTU(t *testing.T) {
	mtus := []uint32{100, 200}
	e, e2 := veth.NewPair(1500)
	defer e.Close()
	defer e2.Close()
	for _, mtu := range mtus {
		e.SetMTU(mtu)

		if want, v := mtu, e.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
