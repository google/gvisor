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
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
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
