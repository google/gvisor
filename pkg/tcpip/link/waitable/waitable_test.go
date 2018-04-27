// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package waitable

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
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

func (e *countedEndpoint) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remoteLinkAddr tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	e.dispatchCount++
}

func (e *countedEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.attachCount++
	e.dispatcher = dispatcher
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

func (e *countedEndpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	e.writeCount++
	return nil
}

func TestWaitWrite(t *testing.T) {
	ep := &countedEndpoint{}
	_, wep := New(stack.RegisterLinkEndpoint(ep))

	// Write and check that it goes through.
	wep.WritePacket(nil, nil, nil, 0)
	if want := 1; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on dispatches, then try to write. It must go through.
	wep.WaitDispatch()
	wep.WritePacket(nil, nil, nil, 0)
	if want := 2; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}

	// Wait on writes, then try to write. It must not go through.
	wep.WaitWrite()
	wep.WritePacket(nil, nil, nil, 0)
	if want := 2; ep.writeCount != want {
		t.Fatalf("Unexpected writeCount: got=%v, want=%v", ep.writeCount, want)
	}
}

func TestWaitDispatch(t *testing.T) {
	ep := &countedEndpoint{}
	_, wep := New(stack.RegisterLinkEndpoint(ep))

	// Check that attach happens.
	wep.Attach(ep)
	if want := 1; ep.attachCount != want {
		t.Fatalf("Unexpected attachCount: got=%v, want=%v", ep.attachCount, want)
	}

	// Dispatch and check that it goes through.
	ep.dispatcher.DeliverNetworkPacket(ep, "", 0, nil)
	if want := 1; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on writes, then try to dispatch. It must go through.
	wep.WaitWrite()
	ep.dispatcher.DeliverNetworkPacket(ep, "", 0, nil)
	if want := 2; ep.dispatchCount != want {
		t.Fatalf("Unexpected dispatchCount: got=%v, want=%v", ep.dispatchCount, want)
	}

	// Wait on dispatches, then try to dispatch. It must not go through.
	wep.WaitDispatch()
	ep.dispatcher.DeliverNetworkPacket(ep, "", 0, nil)
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
	_, wep := New(stack.RegisterLinkEndpoint(ep))

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
