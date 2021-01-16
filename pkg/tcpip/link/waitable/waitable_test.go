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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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

func (e *countedEndpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.dispatchCount++
}

func (e *countedEndpoint) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
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

func (e *countedEndpoint) WritePacket(stack.RouteInfo, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	e.writeCount++
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *countedEndpoint) WritePackets(_ stack.RouteInfo, _ *stack.GSO, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
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
func (e *countedEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
}

func TestWaitWrite(t *testing.T) {
	ep := &countedEndpoint{}
	wep := New(ep)

	// Write and check that it goes through.
	wep.WritePacket(stack.RouteInfo{}, nil /* gso */, 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 1; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on dispatches, then try to write. It must go through.
	wep.WaitDispatch()
	wep.WritePacket(stack.RouteInfo{}, nil /* gso */, 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 2; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on writes, then try to write. It must not go through.
	wep.WaitWrite()
	wep.WritePacket(stack.RouteInfo{}, nil /* gso */, 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 2; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
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
	ep.dispatcher.DeliverNetworkPacket("", "", 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 1; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on writes, then try to dispatch. It must go through.
	wep.WaitWrite()
	ep.dispatcher.DeliverNetworkPacket("", "", 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 2; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on dispatches, then try to dispatch. It must not go through.
	wep.WaitDispatch()
	ep.dispatcher.DeliverNetworkPacket("", "", 0, stack.NewPacketBuffer(stack.PacketBufferOptions{}))
	if want := 2; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
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
