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

package route

import (
	"bytes"
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
)

func TestTypeKind(t *testing.T) {
	tests := []struct {
		typ  uint16
		kind commandKind
	}{
		{linux.RTM_NEWLINK, kindNew},
		{linux.RTM_DELLINK, kindDel},
		{linux.RTM_GETLINK, kindGet},
		{linux.RTM_SETLINK, kindSet},
		{linux.RTM_NEWADDR, kindNew},
		{linux.RTM_DELADDR, kindDel},
		{linux.RTM_GETADDR, kindGet},
		{linux.RTM_NEWROUTE, kindNew},
		{linux.RTM_DELROUTE, kindDel},
		{linux.RTM_GETROUTE, kindGet},
	}

	for _, tc := range tests {
		if got := typeKind(tc.typ); got != tc.kind {
			t.Errorf("typeKind(%d) = %d, want %d", tc.typ, got, tc.kind)
		}
	}
}

func TestProtocolBasics(t *testing.T) {
	p, err := NewProtocol(nil)
	if err != nil {
		t.Fatalf("NewProtocol failed: %v", err)
	}
	if p.Protocol() != linux.NETLINK_ROUTE {
		t.Errorf("Protocol() = %d, want %d", p.Protocol(), linux.NETLINK_ROUTE)
	}
	if !p.CanSend() {
		t.Errorf("CanSend() = false, want true")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want int
	}{
		{
			name: "exact IPv4",
			a:    net.ParseIP("192.168.1.1").To4(),
			b:    net.ParseIP("192.168.1.1").To4(),
			want: 32,
		},
		{
			name: "24-bit match IPv4",
			a:    net.ParseIP("192.168.1.1").To4(),
			b:    net.ParseIP("192.168.1.2").To4(),
			want: 30, // 1 = 00000001, 2 = 00000010 -> first 6 bits match in 4th byte
		},
		{
			name: "16-bit match IPv4",
			a:    net.ParseIP("192.168.1.1").To4(),
			b:    net.ParseIP("192.168.2.1").To4(),
			want: 22, // 1 = 00000001, 2 = 00000010 -> 16 + 6 = 22 bits
		},
		{
			name: "0-bit match IPv4",
			a:    net.ParseIP("10.0.0.1").To4(),
			b:    net.ParseIP("192.168.1.1").To4(),
			want: 0,
		},
		{
			name: "exact IPv6",
			a:    net.ParseIP("2001:db8::1"),
			b:    net.ParseIP("2001:db8::1"),
			want: 128,
		},
		{
			name: "partial IPv6",
			a:    net.ParseIP("2001:db8::1"),
			b:    net.ParseIP("2001:db8::2"),
			want: 126,
		},
		{
			name: "empty slices",
			a:    []byte{},
			b:    []byte{},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := commonPrefixLen(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("commonPrefixLen(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestFillRoute(t *testing.T) {
	origFallback := FallbackNonHostRoutes
	FallbackNonHostRoutes = true
	defer func() {
		FallbackNonHostRoutes = origFallback
	}()

	v4Dst := net.ParseIP("192.168.1.100").To4()
	v4Net1 := net.ParseIP("192.168.1.0").To4()
	v4Net2 := net.ParseIP("192.168.0.0").To4()
	v4Gw := net.ParseIP("10.0.0.1").To4()
	v4Other := net.ParseIP("8.8.8.8").To4()

	routes := []inet.Route{
		{
			Family:          linux.AF_INET,
			DstAddr:         v4Net2,
			DstLen:          16,
			OutputInterface: 1,
			Scope:           linux.RT_SCOPE_UNIVERSE,
		},
		{
			Family:          linux.AF_INET,
			DstAddr:         v4Net1,
			DstLen:          24,
			OutputInterface: 2,
			Scope:           linux.RT_SCOPE_UNIVERSE,
		},
		{
			Family:          linux.AF_INET,
			GatewayAddr:     v4Gw,
			DstLen:          0,
			OutputInterface: 3,
			Scope:           linux.RT_SCOPE_UNIVERSE,
		},
	}

	t.Run("longest_prefix_match", func(t *testing.T) {
		rt, err := fillRoute(routes, v4Dst)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Dst, err)
		}
		if rt.OutputInterface != 2 {
			t.Errorf("got OutputInterface = %d, want 2", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Dst) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Dst)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("default_route_match", func(t *testing.T) {
		rt, err := fillRoute(routes, v4Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Other, err)
		}
		if rt.OutputInterface != 3 {
			t.Errorf("got OutputInterface = %d, want 3 (default gateway)", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("fallback_non_host_route", func(t *testing.T) {
		routesNoDefault := []inet.Route{
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("10.0.0.0").To4(),
				DstLen:          8,
				OutputInterface: 5,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		rt, err := fillRoute(routesNoDefault, v4Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Other, err)
		}
		if rt.OutputInterface != 5 {
			t.Errorf("got OutputInterface = %d, want 5", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("fallback_prefers_non_host_over_host_route", func(t *testing.T) {
		mixedRoutes := []inet.Route{
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("127.0.0.1").To4(),
				DstLen:          32,
				OutputInterface: 1,
				Scope:           linux.RT_SCOPE_HOST,
			},
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("10.0.0.0").To4(),
				DstLen:          8,
				OutputInterface: 2,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		rt, err := fillRoute(mixedRoutes, v4Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Other, err)
		}
		if rt.OutputInterface != 2 {
			t.Errorf("got OutputInterface = %d, want 2 (non-host route preferred)", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("fallback_all_host_routes_selects_first", func(t *testing.T) {
		hostOnlyRoutes := []inet.Route{
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("127.0.0.1").To4(),
				DstLen:          32,
				OutputInterface: 10,
				Scope:           linux.RT_SCOPE_HOST,
			},
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("127.0.0.2").To4(),
				DstLen:          32,
				OutputInterface: 20,
				Scope:           linux.RT_SCOPE_HOST,
			},
		}
		rt, err := fillRoute(hostOnlyRoutes, v4Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Other, err)
		}
		if rt.OutputInterface != 10 {
			t.Errorf("got OutputInterface = %d, want 10 (first available route)", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("fallback_mismatched_family_selects_first", func(t *testing.T) {
		v6OnlyRoutes := []inet.Route{
			{
				Family:          linux.AF_INET6,
				DstAddr:         net.ParseIP("2001:db8::").To16(),
				DstLen:          64,
				OutputInterface: 77,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		rt, err := fillRoute(v6OnlyRoutes, v4Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v4Other, err)
		}
		if rt.OutputInterface != 77 {
			t.Errorf("got OutputInterface = %d, want 77 (first route when len > 0)", rt.OutputInterface)
		}
		if rt.DstLen != 32 {
			t.Errorf("got DstLen = %d, want 32", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v4Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v4Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("empty_routes_returns_err_host_unreachable", func(t *testing.T) {
		tests := []struct {
			name   string
			routes []inet.Route
		}{
			{name: "nil_routes", routes: nil},
			{name: "empty_slice", routes: []inet.Route{}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := fillRoute(tc.routes, v4Dst)
				if err != syserr.ErrHostUnreachable {
					t.Errorf("fillRoute(%v, %v) = %v, want %v", tc.routes, v4Dst, err, syserr.ErrHostUnreachable)
				}
			})
		}
	})

	t.Run("ipv6_longest_prefix_match", func(t *testing.T) {
		v6Dst := net.ParseIP("2001:db8::1")
		v6Net := net.ParseIP("2001:db8::")
		v6Routes := []inet.Route{
			{
				Family:          linux.AF_INET6,
				DstAddr:         v6Net,
				DstLen:          64,
				OutputInterface: 4,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		rt, err := fillRoute(v6Routes, v6Dst)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v6Dst, err)
		}
		if rt.OutputInterface != 4 {
			t.Errorf("got OutputInterface = %d, want 4", rt.OutputInterface)
		}
		if rt.DstLen != 128 {
			t.Errorf("got DstLen = %d, want 128", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v6Dst) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v6Dst)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("ipv6_fallback_non_host_route", func(t *testing.T) {
		v6Other := net.ParseIP("2001:db8:beef::1")
		v6RoutesNoDefault := []inet.Route{
			{
				Family:          linux.AF_INET6,
				DstAddr:         net.ParseIP("fe80::"),
				DstLen:          64,
				OutputInterface: 8,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		rt, err := fillRoute(v6RoutesNoDefault, v6Other)
		if err != nil {
			t.Fatalf("fillRoute(%v) unexpected error: %v", v6Other, err)
		}
		if rt.OutputInterface != 8 {
			t.Errorf("got OutputInterface = %d, want 8", rt.OutputInterface)
		}
		if rt.DstLen != 128 {
			t.Errorf("got DstLen = %d, want 128", rt.DstLen)
		}
		if !bytes.Equal(rt.DstAddr, v6Other) {
			t.Errorf("got DstAddr = %v, want %v", rt.DstAddr, v6Other)
		}
		if (rt.Flags & linux.RTM_F_CLONED) == 0 {
			t.Errorf("expected RTM_F_CLONED flag to be set, got %x", rt.Flags)
		}
	})

	t.Run("ipv6_empty_routes_returns_err_host_unreachable", func(t *testing.T) {
		v6Dst := net.ParseIP("2001:db8::1")
		_, err := fillRoute(nil, v6Dst)
		if err != syserr.ErrHostUnreachable {
			t.Errorf("fillRoute(nil, %v) = %v, want %v", v6Dst, err, syserr.ErrHostUnreachable)
		}
	})

	t.Run("fallback_disabled_unmatched_route_returns_err_net_unreachable", func(t *testing.T) {
		orig := FallbackNonHostRoutes
		FallbackNonHostRoutes = false
		defer func() { FallbackNonHostRoutes = orig }()

		routesNoDefault := []inet.Route{
			{
				Family:          linux.AF_INET,
				DstAddr:         net.ParseIP("10.0.0.0").To4(),
				DstLen:          8,
				OutputInterface: 5,
				Scope:           linux.RT_SCOPE_UNIVERSE,
			},
		}
		_, err := fillRoute(routesNoDefault, v4Other)
		if err != syserr.ErrNetworkUnreachable {
			t.Errorf("fillRoute(%v, %v) with fallback disabled = %v, want %v", routesNoDefault, v4Other, err, syserr.ErrNetworkUnreachable)
		}
	})
}

func TestParseForDestination(t *testing.T) {
	dstIP := net.ParseIP("192.168.1.1").To4()

	// 1. Valid message with RTA_DST attribute.
	msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_GETROUTE,
	})
	msg.Put(&linux.RouteMessage{
		Family: linux.AF_INET,
	})
	msg.PutAttr(linux.RTA_DST, primitive.AsByteSlice(dstIP))

	gotDst, err := parseForDestination(msg)
	if err != nil {
		t.Fatalf("parseForDestination failed: %v", err)
	}
	if !bytes.Equal(gotDst, dstIP) {
		t.Errorf("got dst = %v, want %v", gotDst, dstIP)
	}

	// 2. Message with multiple attributes, RTA_DST not first.
	msgMulti := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_GETROUTE,
	})
	msgMulti.Put(&linux.RouteMessage{
		Family: linux.AF_INET,
	})
	msgMulti.PutAttr(linux.RTA_OIF, primitive.AllocateInt32(2))
	msgMulti.PutAttr(linux.RTA_DST, primitive.AsByteSlice(dstIP))

	gotDst, err = parseForDestination(msgMulti)
	if err != nil {
		t.Fatalf("parseForDestination with multiple attrs failed: %v", err)
	}
	if !bytes.Equal(gotDst, dstIP) {
		t.Errorf("got dst = %v, want %v", gotDst, dstIP)
	}

	// 3. Message without RTA_DST attribute.
	msgNoDst := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_GETROUTE,
	})
	msgNoDst.Put(&linux.RouteMessage{
		Family: linux.AF_INET,
	})
	msgNoDst.PutAttr(linux.RTA_OIF, primitive.AllocateInt32(2))

	_, err = parseForDestination(msgNoDst)
	if err != syserr.ErrInvalidArgument {
		t.Errorf("got err = %v, want ErrInvalidArgument", err)
	}

	// 4. Empty message.
	emptyMsg := nlmsg.NewMessage(linux.NetlinkMessageHeader{})
	_, err = parseForDestination(emptyMsg)
	if err != syserr.ErrInvalidArgument {
		t.Errorf("got err = %v, want ErrInvalidArgument", err)
	}
}

func TestWriteLinkInfo(t *testing.T) {
	ms := nlmsg.NewMessageSet(0, 12345)
	p := &Protocol{}

	iface := inet.Interface{
		DeviceType: linux.ARPHRD_ETHER,
		Flags:      linux.IFF_UP | linux.IFF_RUNNING,
		Name:       "eth0",
		Addr:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MTU:        1500,
		Master:     3,
		Kind:       "veth",
	}

	p.AddNewLinkMessage(ms, 2, iface)
	if len(ms.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(ms.Messages))
	}
	m := ms.Messages[0]
	if m.Header().Type != linux.RTM_NEWLINK {
		t.Errorf("got type = %d, want RTM_NEWLINK", m.Header().Type)
	}

	var ifi linux.InterfaceInfoMessage
	attrs, ok := m.GetData(&ifi)
	if !ok {
		t.Fatalf("GetData failed")
	}
	if ifi.Index != 2 {
		t.Errorf("got Index = %d, want 2", ifi.Index)
	}
	if ifi.Flags != iface.Flags {
		t.Errorf("got Flags = %d, want %d", ifi.Flags, iface.Flags)
	}
	if ifi.Type != iface.DeviceType {
		t.Errorf("got Type = %d, want %d", ifi.Type, iface.DeviceType)
	}

	var foundName, foundKind, foundMaster bool
	for !attrs.Empty() {
		ahdr, val, rest, ok := attrs.ParseFirst()
		if !ok {
			break
		}
		attrs = rest
		switch ahdr.Type {
		case linux.IFLA_IFNAME:
			foundName = true
			if string(val[:len(val)-1]) != "eth0" {
				t.Errorf("got name = %s, want eth0", string(val))
			}
		case linux.IFLA_MASTER:
			foundMaster = true
		case linux.IFLA_LINKINFO:
			foundKind = true
		}
	}
	if !foundName {
		t.Errorf("IFLA_IFNAME not found")
	}
	if !foundMaster {
		t.Errorf("IFLA_MASTER not found")
	}
	if !foundKind {
		t.Errorf("IFLA_LINKINFO not found")
	}

	// Test AddDelLinkMessage
	msDel := nlmsg.NewMessageSet(0, 12345)
	p.AddDelLinkMessage(msDel, 2, iface)
	if len(msDel.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(msDel.Messages))
	}
	if msDel.Messages[0].Header().Type != linux.RTM_DELLINK {
		t.Errorf("got type = %d, want RTM_DELLINK", msDel.Messages[0].Header().Type)
	}
}

func TestWriteLinkInfoLoopback(t *testing.T) {
	ms := nlmsg.NewMessageSet(0, 12345)
	p := &Protocol{}

	lo := inet.Interface{
		DeviceType: linux.ARPHRD_LOOPBACK,
		Flags:      linux.IFF_UP | linux.IFF_LOOPBACK,
		Name:       "lo",
		MTU:        65536,
	}

	p.AddNewLinkMessage(ms, 1, lo)
	if len(ms.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(ms.Messages))
	}

	var ifi linux.InterfaceInfoMessage
	attrs, ok := ms.Messages[0].GetData(&ifi)
	if !ok {
		t.Fatalf("GetData failed")
	}
	if ifi.Index != 1 {
		t.Errorf("got Index = %d, want 1", ifi.Index)
	}

	var foundAddr, foundBrd bool
	for !attrs.Empty() {
		ahdr, val, rest, ok := attrs.ParseFirst()
		if !ok {
			break
		}
		attrs = rest
		switch ahdr.Type {
		case linux.IFLA_ADDRESS:
			foundAddr = true
			if len(val) != 6 {
				t.Errorf("got addr len = %d, want 6", len(val))
			}
		case linux.IFLA_BROADCAST:
			foundBrd = true
			if len(val) != 6 {
				t.Errorf("got brd len = %d, want 6", len(val))
			}
		}
	}
	if !foundAddr {
		t.Errorf("IFLA_ADDRESS not found")
	}
	if !foundBrd {
		t.Errorf("IFLA_BROADCAST not found")
	}
}

func TestProcessMessageMissingFamily(t *testing.T) {
	p := &Protocol{}
	ms := nlmsg.NewMessageSet(0, 12345)
	emptyMsg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  linux.RTM_GETLINK,
		Flags: linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
	})
	if err := p.ProcessMessage(nil, nil, emptyMsg, ms); err != nil {
		t.Errorf("ProcessMessage on empty msg got err = %v, want nil", err)
	}
}

func TestProcessMessageUnsupported(t *testing.T) {
	p := &Protocol{}
	ms := nlmsg.NewMessageSet(0, 12345)
	family := primitive.Uint8(linux.AF_UNSPEC)

	// GET with NLM_F_DUMP but unsupported type (e.g. RTM_GETRULE)
	msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  linux.RTM_GETRULE,
		Flags: linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
	})
	msg.Put(&family)

	if err := p.ProcessMessage(nil, nil, msg, ms); err != syserr.ErrNotSupported {
		t.Errorf("ProcessMessage on unsupported GET type got err = %v, want ErrNotSupported", err)
	}

	// No flags (neither dump/root nor request)
	msgNoFlags := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  linux.RTM_GETLINK,
		Flags: 0,
	})
	msgNoFlags.Put(&family)
	if err := p.ProcessMessage(nil, nil, msgNoFlags, ms); err != syserr.ErrNotSupported {
		t.Errorf("ProcessMessage on no-flags msg got err = %v, want ErrNotSupported", err)
	}

	// REQUEST with unsupported type
	msgUnsuppReq := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  0xFFFF&^0x3 | 0x2, // GET kind to pass cap check without socket
		Flags: linux.NLM_F_REQUEST,
	})
	msgUnsuppReq.Put(&family)
	if err := p.ProcessMessage(nil, nil, msgUnsuppReq, ms); err != syserr.ErrNotSupported {
		t.Errorf("ProcessMessage on unsupported REQUEST type got err = %v, want ErrNotSupported", err)
	}
}
