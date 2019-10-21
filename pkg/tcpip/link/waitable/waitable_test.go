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
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
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

func (e *countedEndpoint) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView, linkHeader buffer.View) {
	e.dispatchCount++
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

func (e *countedEndpoint) WritePacket(r *stack.Route, _ *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	e.writeCount++
	return nil
}

func (e *countedEndpoint) WriteRawPacket(packet buffer.VectorisedView) *tcpip.Error {
	e.writeCount++
	return nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*countedEndpoint) Wait() {}

func TestWaitWrite(t *testing.T) {
	ep := &countedEndpoint{}
	wep := New(ep)

	// Write and check that it goes through.
	wep.WritePacket(nil, nil /* gso */, buffer.Prependable{}, buffer.VectorisedView{}, 0)
	if want := 1; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on dispatches, then try to write. It must go through.
	wep.WaitDispatch()
	wep.WritePacket(nil, nil /* gso */, buffer.Prependable{}, buffer.VectorisedView{}, 0)
	if want := 2; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on writes, then try to write. It must not go through.
	wep.WaitWrite()
	wep.WritePacket(nil, nil /* gso */, buffer.Prependable{}, buffer.VectorisedView{}, 0)
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
	ep.dispatcher.DeliverNetworkPacket(ep, "", "", 0, buffer.VectorisedView{}, buffer.View{})
	if want := 1; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on writes, then try to dispatch. It must go through.
	wep.WaitWrite()
	ep.dispatcher.DeliverNetworkPacket(ep, "", "", 0, buffer.VectorisedView{}, buffer.View{})
	if want := 2; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on dispatches, then try to dispatch. It must not go through.
	wep.WaitDispatch()
	ep.dispatcher.DeliverNetworkPacket(ep, "", "", 0, buffer.VectorisedView{}, buffer.View{})
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
