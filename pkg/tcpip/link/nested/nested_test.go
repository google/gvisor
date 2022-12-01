// Copyright 2020 The gVisor Authors.
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

package nested_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type parentEndpoint struct {
	nested.Endpoint
}

var _ stack.LinkEndpoint = (*parentEndpoint)(nil)
var _ stack.NetworkDispatcher = (*parentEndpoint)(nil)

type childEndpoint struct {
	stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
}

var _ stack.LinkEndpoint = (*childEndpoint)(nil)

func (c *childEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	c.dispatcher = dispatcher
}

func (c *childEndpoint) IsAttached() bool {
	return c.dispatcher != nil
}

type counterDispatcher struct {
	count int
}

var _ stack.NetworkDispatcher = (*counterDispatcher)(nil)

func (d *counterDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, stack.PacketBufferPtr) {
	d.count++
}

func (*counterDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, stack.PacketBufferPtr, bool) {
	panic("not implemented")
}

func TestNestedLinkEndpoint(t *testing.T) {
	var (
		childEP  childEndpoint
		nestedEP parentEndpoint
		disp     counterDispatcher
	)
	nestedEP.Endpoint.Init(&childEP, &nestedEP)

	if childEP.IsAttached() {
		t.Error("On init, childEP.IsAttached() = true, want = false")
	}
	if nestedEP.IsAttached() {
		t.Error("On init, nestedEP.IsAttached() = true, want = false")
	}

	nestedEP.Attach(&disp)
	if disp.count != 0 {
		t.Fatalf("After attach, got disp.count = %d, want = 0", disp.count)
	}
	if !childEP.IsAttached() {
		t.Error("After attach, childEP.IsAttached() = false, want = true")
	}
	if !nestedEP.IsAttached() {
		t.Error("After attach, nestedEP.IsAttached() = false, want = true")
	}

	{
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		nestedEP.DeliverNetworkPacket(header.IPv4ProtocolNumber, p)
		p.DecRef()
		if disp.count != 1 {
			t.Errorf("After first packet with dispatcher attached, got disp.count = %d, want = 1", disp.count)
		}
	}

	nestedEP.Attach(nil)
	if childEP.IsAttached() {
		t.Error("After detach, childEP.IsAttached() = true, want = false")
	}
	if nestedEP.IsAttached() {
		t.Error("After detach, nestedEP.IsAttached() = true, want = false")
	}

	{
		disp.count = 0
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		nestedEP.DeliverNetworkPacket(header.IPv4ProtocolNumber, p)
		p.DecRef()
		if disp.count != 0 {
			t.Errorf("After second packet with dispatcher detached, got disp.count = %d, want = 0", disp.count)
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
