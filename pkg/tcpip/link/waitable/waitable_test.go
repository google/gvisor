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

package waitable

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*countedEndpoint)(nil)

type countedEndpoint struct {
	dispatchCount int
	writeCount    int
	attachCount   int

	mtu          uint32
	capabilities stack.LinkEndpointCapabilities
	hdrLen       uint16
	linkAddr     tcpip.LinkAddress

	dispatcher stack.NetworkDispatcher
}

func (e *countedEndpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	e.dispatchCount++
}

func (*countedEndpoint) DeliverLinkPacket(tcpip.NetworkProtocolNumber, stack.PacketBufferPtr, bool) {
	panic("not implemented")
}

func (e *countedEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.attachCount++
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *countedEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *countedEndpoint) MTU() uint32 {
	return e.mtu
}

func (e *countedEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.capabilities
}

func (e *countedEndpoint) MaxHeaderLength() uint16 {
	return e.hdrLen
}

func (e *countedEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *countedEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.writeCount += pkts.Len()
	return pkts.Len(), nil
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*countedEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("unimplemented")
}

// Wait implements stack.LinkEndpoint.Wait.
func (*countedEndpoint) Wait() {}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*countedEndpoint) AddHeader(stack.PacketBufferPtr) {
	panic("unimplemented")
}

func TestWaitWrite(t *testing.T) {
	ep := &countedEndpoint{}
	wep := New(ep)
	{
		var pkts stack.PacketBufferList
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{}))
		// Write and check that it goes through.
		if n, err := wep.WritePackets(pkts); err != nil {
			t.Fatalf("WritePackets(_): %s", err)
		} else if n != 1 {
			t.Fatalf("got WritePackets(_) = %d, want = 1", n)
		}
		if want := 1; ep.writeCount != want {
			t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
		}
		pkts.DecRef()
	}
	{
		var pkts stack.PacketBufferList
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{}))
		// Wait on dispatches, then try to write. It must go through.
		wep.WaitDispatch()
		if n, err := wep.WritePackets(pkts); err != nil {
			t.Fatalf("WritePackets(_): %s", err)
		} else if n != 1 {
			t.Fatalf("got WritePackets(_) = %d, want = 1", n)
		}
		if want := 2; ep.writeCount != want {
			t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
		}
		pkts.DecRef()
	}

	{
		var pkts stack.PacketBufferList
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{}))
		// Wait on writes, then try to write. It must not go through.
		wep.WaitWrite()
		if n, err := wep.WritePackets(pkts); err != nil {
			t.Fatalf("WritePackets(_): %s", err)
		} else if n != 1 {
			t.Fatalf("got WritePackets(_) = %d, want = 1", n)
		}
		if want := 2; ep.writeCount != want {
			t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
		}
		pkts.DecRef()
	}
}

func TestWaitDispatch(t *testing.T) {
	ep := &countedEndpoint{}
	wep := New(ep)

	// Check that attach happens.
	wep.Attach(ep)
	if want := 1; ep.attachCount != want {
		t.Fatalf("Unexpected attachCount: got=%v, want=%v", ep.attachCount, want)
	}

	// Dispatch and check that it goes through.
	{
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		ep.dispatcher.DeliverNetworkPacket(0, p)
		if want := 1; ep.dispatchCount != want {
			t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
		}
		p.DecRef()
	}

	// Wait on writes, then try to dispatch. It must go through.
	{
		wep.WaitWrite()
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		ep.dispatcher.DeliverNetworkPacket(0, p)
		if want := 2; ep.dispatchCount != want {
			t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
		}
		p.DecRef()
	}

	// Wait on dispatches, then try to dispatch. It must not go through.
	{
		wep.WaitDispatch()
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		ep.dispatcher.DeliverNetworkPacket(0, p)
		if want := 2; ep.dispatchCount != want {
			t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
		}
		p.DecRef()
	}
}

func TestOtherMethods(t *testing.T) {
	const (
		mtu          = 0xdead
		capabilities = 0xbeef
		hdrLen       = 0x1234
		linkAddr     = "test address"
	)
	ep := &countedEndpoint{
		mtu:          mtu,
		capabilities: capabilities,
		hdrLen:       hdrLen,
		linkAddr:     linkAddr,
	}
	wep := New(ep)

	if v := wep.MTU(); v != mtu {
		t.Fatalf("Unexpected mtu: got=%v, want=%v", v, mtu)
	}

	if v := wep.Capabilities(); v != capabilities {
		t.Fatalf("Unexpected capabilities: got=%v, want=%v", v, capabilities)
	}

	if v := wep.MaxHeaderLength(); v != hdrLen {
		t.Fatalf("Unexpected MaxHeaderLength: got=%v, want=%v", v, hdrLen)
	}

	if v := wep.LinkAddress(); v != linkAddr {
		t.Fatalf("Unexpected LinkAddress: got=%q, want=%q", v, linkAddr)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
