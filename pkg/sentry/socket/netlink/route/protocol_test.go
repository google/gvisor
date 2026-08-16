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
	v4Dst := net.ParseIP("192.168.1.100").To4()
	v4Net1 := net.ParseIP("192.168.1.0").To4()
	v4Net2 := net.ParseIP("192.168.0.0").To4()
	v4Gw := net.ParseIP("10.0.0.1").To4()

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

	// 1. Longest prefix match selects the /24 route over /16 and default.
	rt, err := fillRoute(routes, v4Dst)
	if err != nil {
		t.Fatalf("fillRoute failed: %v", err)
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
		t.Errorf("expected RTM_F_CLONED flag to be set")
	}

	// 2. Destination matching only default route.
	v4Other := net.ParseIP("8.8.8.8").To4()
	rt, err = fillRoute(routes, v4Other)
	if err != nil {
		t.Fatalf("fillRoute failed: %v", err)
	}
	if rt.OutputInterface != 3 {
		t.Errorf("got OutputInterface = %d, want 3 (default gateway)", rt.OutputInterface)
	}

	// 3. No match and no default route -> ErrNetworkUnreachable.
	routesNoDefault := []inet.Route{
		{
			Family:          linux.AF_INET,
			DstAddr:         net.ParseIP("10.0.0.0").To4(),
			DstLen:          8,
			OutputInterface: 5,
			Scope:           linux.RT_SCOPE_UNIVERSE,
		},
	}
	_, err = fillRoute(routesNoDefault, v4Other)
	if err != syserr.ErrNetworkUnreachable {
		t.Errorf("got err = %v, want ErrNetworkUnreachable", err)
	}

	// 4. Empty routes slice -> ErrNetworkUnreachable.
	_, err = fillRoute(nil, v4Dst)
	if err != syserr.ErrNetworkUnreachable {
		t.Errorf("got err = %v, want ErrNetworkUnreachable", err)
	}

	// 6. IPv6 route matching.
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
	rt, err = fillRoute(v6Routes, v6Dst)
	if err != nil {
		t.Fatalf("fillRoute IPv6 failed: %v", err)
	}
	if rt.OutputInterface != 4 {
		t.Errorf("got OutputInterface = %d, want 4", rt.OutputInterface)
	}
	if rt.DstLen != 128 {
		t.Errorf("got DstLen = %d, want 128", rt.DstLen)
	}
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
