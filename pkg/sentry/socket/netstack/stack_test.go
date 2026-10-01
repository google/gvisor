// Copyright 2026 The gVisor Authors.
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

package netstack_test

import (
	"testing"
	"testing/synctest"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestDestroyNilStack(t *testing.T) {
	s := &netstack.Stack{
		Stack: nil,
	}
	// This should not panic.
	s.Destroy()
}

func TestRemoveRouteRemovesFirstMatchOnly(t *testing.T) {
	s := &netstack.Stack{
		Stack: stack.New(stack.Options{}),
	}
	dst := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 0, 0, 0}),
		PrefixLen: 24,
	}.Subnet()
	s.Stack.AddRoute(tcpip.Route{Destination: dst, NIC: 1})
	s.Stack.AddRoute(tcpip.Route{Destination: dst, NIC: 2})

	delRoute := func() *syserr.Error {
		msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
			Type: linux.RTM_DELROUTE,
		})
		msg.Put(&linux.RouteMessage{
			Family: linux.AF_INET,
			DstLen: 24,
		})
		msg.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{10, 0, 0, 0}))
		return s.RemoveRoute(context.Background(), msg)
	}

	if err := delRoute(); err != nil {
		t.Fatalf("first RemoveRoute failed: %v", err)
	}
	if got := s.Stack.GetRouteTable(); len(got) != 1 || got[0].NIC != 2 {
		t.Fatalf("route table after first RemoveRoute = %v, want only the NIC 2 route", got)
	}
	if err := delRoute(); err != nil {
		t.Fatalf("second RemoveRoute failed: %v", err)
	}
	if got := s.Stack.GetRouteTable(); len(got) != 0 {
		t.Fatalf("route table after second RemoveRoute = %v, want empty", got)
	}
	if err := delRoute(); err != syserr.ErrNoProcess {
		t.Fatalf("third RemoveRoute = %v, want %v", err, syserr.ErrNoProcess)
	}
}

type blockedCloseEndpoint struct {
	*channel.Endpoint
	closing chan struct{}
	resume  chan struct{}
}

func (e *blockedCloseEndpoint) Close() {
	close(e.closing)
	<-e.resume
	e.Endpoint.Close()
}

func TestDestroyWaitsForNICs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := netstack.NewStack(stack.New(stack.Options{}), 1)
		ep := &blockedCloseEndpoint{
			Endpoint: channel.New(1, 1500, ""),
			closing:  make(chan struct{}),
			resume:   make(chan struct{}),
		}
		if err := s.Stack.CreateNIC(1, ep); err != nil {
			t.Fatalf("CreateNIC: %s", err)
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		var packets stack.PacketBufferList
		packets.PushBack(pkt)
		n, err := ep.WritePackets(packets)
		pkt.DecRef()
		if n != 1 || err != nil {
			t.Fatalf("WritePackets = (%d, %v), want (1, nil)", n, err)
		}
		done := make(chan struct{})
		go func() {
			s.Destroy()
			close(done)
		}()
		<-ep.closing
		synctest.Wait()
		select {
		case <-done:
			t.Error("Destroy returned before NIC cleanup released its packet")
		default:
		}
		close(ep.resume)
		<-done
		synctest.Wait()
		if got := ep.NumQueued(); got != 0 {
			t.Errorf("NumQueued after Destroy = %d, want 0", got)
		}
	})
}
