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
	"fmt"
	"net"
	"slices"
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

func mustSubnet(t *testing.T, cidr string) tcpip.Subnet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q): %v", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(ipNet.IP),
		PrefixLen: ones,
	}.Subnet()
}

// RouteTable lists routes in Linux FIB dump order instead of netstack's
// longest-prefix-first lookup order.
func TestRouteTableDumpOrder(t *testing.T) {
	s := &netstack.Stack{
		Stack: stack.New(stack.Options{}),
	}
	v4Gateway := tcpip.AddrFrom4([4]byte{10, 88, 0, 1})
	v6Gateway := tcpip.AddrFromSlice(net.ParseIP("2001:db8:0:1::1"))
	for _, rt := range []struct {
		cidr    string
		nic     tcpip.NICID
		gateway tcpip.Address
	}{
		{"0.0.0.0/0", 1, v4Gateway},
		{"::/0", 1, v6Gateway},
		{"192.168.0.0/16", 1, tcpip.Address{}},
		{"10.0.0.0/8", 1, v4Gateway},
		{"fe80::/64", 1, tcpip.Address{}},
		{"2001:db8::/32", 1, v6Gateway},
		{"10.0.0.0/24", 1, v4Gateway},
		{"10.0.0.0/24", 2, v4Gateway},
		{"127.0.0.0/8", 3, tcpip.Address{}},
		{"2001:db8:1::/48", 1, v6Gateway},
		{"::1/128", 3, tcpip.Address{}},
		{"169.254.1.1/32", 1, tcpip.Address{}},
		{"2001:db8:1:2::/64", 1, v6Gateway},
		{"10.1.0.0/16", 1, v4Gateway},
		{"2001:db8:0:1::/64", 1, tcpip.Address{}},
	} {
		s.Stack.AddRoute(tcpip.Route{
			Destination: mustSubnet(t, rt.cidr),
			Gateway:     rt.gateway,
			NIC:         rt.nic,
		})
	}

	var got []string
	for _, rt := range s.RouteTable() {
		got = append(got, fmt.Sprintf("%s/%d nic%d", net.IP(rt.DstAddr), rt.DstLen, rt.OutputInterface))
	}
	want := []string{
		// IPv4 by ascending destination, longer prefixes first for equal
		// destinations; same-destination routes keep their relative order.
		"0.0.0.0/0 nic1",
		"10.0.0.0/24 nic1",
		"10.0.0.0/24 nic2",
		"10.0.0.0/8 nic1",
		"10.1.0.0/16 nic1",
		"127.0.0.0/8 nic3",
		"169.254.1.1/32 nic1",
		"192.168.0.0/16 nic1",
		// IPv6 in fib6 post-order: more specific routes precede the routes
		// containing them, so the default route comes last.
		"::1/128 nic3",
		"2001:db8:0:1::/64 nic1",
		"2001:db8:1:2::/64 nic1",
		"2001:db8:1::/48 nic1",
		"2001:db8::/32 nic1",
		"fe80::/64 nic1",
		"::/0 nic1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("RouteTable() order:\ngot  %q\nwant %q", got, want)
	}

	// Lookups still use netstack's longest-prefix-first order.
	if got := s.Stack.GetRouteTable()[0].Destination.Prefix(); got != 128 {
		t.Errorf("GetRouteTable()[0] prefix = %d, want 128", got)
	}
}
