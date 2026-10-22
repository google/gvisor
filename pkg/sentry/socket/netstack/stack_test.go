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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
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

func TestSetBridgePort(t *testing.T) {
	const (
		bridgeID = 1
		portID   = 2
		loneID   = 3
	)
	s := &netstack.Stack{Stack: stack.New(stack.Options{})}
	defer s.Stack.Destroy()
	if err := s.Stack.CreateNIC(bridgeID, stack.NewBridgeEndpoint(1500)); err != nil {
		t.Fatalf("CreateNIC(%d): %s", bridgeID, err)
	}
	for _, id := range []tcpip.NICID{portID, loneID} {
		ch := channel.New(1, header.EthernetMinimumSize, "\x02\x02\x03\x04\x05\x06")
		defer ch.Close()
		if err := s.Stack.CreateNIC(id, ethernet.New(ch)); err != nil {
			t.Fatalf("CreateNIC(%d): %s", id, err)
		}
	}
	if err := s.Stack.SetNICCoordinator(portID, bridgeID); err != nil {
		t.Fatalf("SetNICCoordinator(%d, %d): %s", portID, bridgeID, err)
	}

	wantFlags := func(want stack.BridgePortFlags) {
		t.Helper()
		if got, err := s.Stack.BridgePortFlags(portID); err != nil || got != want {
			t.Errorf("BridgePortFlags(%d) = %#x, %v, want %#x", portID, got, err, want)
		}
	}
	ctx := context.Background()
	on, off := true, false

	if err := s.SetBridgePort(ctx, portID, inet.BridgePortConfig{Hairpin: &on, Learning: &off}); err != nil {
		t.Fatalf("SetBridgePort(hairpin on, learning off) = %v", err)
	}
	wantFlags(stack.BridgePortHairpin)
	if err := s.SetBridgePort(ctx, portID, inet.BridgePortConfig{Learning: &on}); err != nil {
		t.Fatalf("SetBridgePort(learning on) = %v", err)
	}
	wantFlags(stack.BridgePortHairpin | stack.BridgePortLearning)

	for _, test := range []struct {
		name string
		id   int32
		want *syserr.Error
	}{
		{"unknown interface", 99, syserr.ErrUnknownNICID},
		{"interface without a bridge", loneID, syserr.ErrNotSupported},
		{"the bridge itself", bridgeID, syserr.ErrNotSupported},
	} {
		if err := s.SetBridgePort(ctx, test.id, inet.BridgePortConfig{Hairpin: &on}); err != test.want {
			t.Errorf("%s: SetBridgePort() = %v, want %v", test.name, err, test.want)
		}
	}
}
