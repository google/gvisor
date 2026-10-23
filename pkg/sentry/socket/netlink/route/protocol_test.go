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
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
			name: "different lengths",
			a:    net.ParseIP("2001:db8::1"),
			b:    net.ParseIP("192.168.1.1").To4(),
			want: 0,
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
	rt, err := fillRoute(routes, linux.AF_INET, v4Dst)
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
	rt, err = fillRoute(routes, linux.AF_INET, v4Other)
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
	_, err = fillRoute(routesNoDefault, linux.AF_INET, v4Other)
	if err != syserr.ErrNetworkUnreachable {
		t.Errorf("got err = %v, want ErrNetworkUnreachable", err)
	}

	// 4. Empty routes slice -> ErrNetworkUnreachable.
	_, err = fillRoute(nil, linux.AF_INET, v4Dst)
	if err != syserr.ErrNetworkUnreachable {
		t.Errorf("got err = %v, want ErrNetworkUnreachable", err)
	}

	// 5. Route without destination.
	routesNoDst := []inet.Route{
		{
			Family:          linux.AF_INET,
			DstLen:          0,
			OutputInterface: 9,
			Scope:           linux.RT_SCOPE_UNIVERSE,
		},
	}
	_, err = fillRoute(routesNoDst, linux.AF_INET, v4Dst)
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
	rt, err = fillRoute(v6Routes, linux.AF_INET6, v6Dst)
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

	_, gotDst, err := parseForDestination(msg)
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

	_, gotDst, err = parseForDestination(msgMulti)
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

	_, _, err = parseForDestination(msgNoDst)
	if err != syserr.ErrInvalidArgument {
		t.Errorf("got err = %v, want ErrInvalidArgument", err)
	}

	// 4. Empty message.
	emptyMsg := nlmsg.NewMessage(linux.NetlinkMessageHeader{})
	_, _, err = parseForDestination(emptyMsg)
	if err != syserr.ErrInvalidArgument {
		t.Errorf("got err = %v, want ErrInvalidArgument", err)
	}

	// 5. Message with an IPv6 RTA_DST attribute.
	dstIP6 := net.ParseIP("2001:db8::1").To16()
	msgDst6 := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_GETROUTE,
	})
	msgDst6.Put(&linux.RouteMessage{
		Family: linux.AF_INET6,
	})
	msgDst6.PutAttr(linux.RTA_DST, primitive.AsByteSlice(dstIP6))

	_, gotDst, err = parseForDestination(msgDst6)
	if err != nil {
		t.Fatalf("parseForDestination with an IPv6 RTA_DST failed: %v", err)
	}
	if !bytes.Equal(gotDst, dstIP6) {
		t.Errorf("got dst = %v, want %v", gotDst, dstIP6)
	}

	// 6. RTA_DST shorter than the address of the requested family.
	for _, size := range []int{1, header.IPv4AddressSize, header.IPv6AddressSize - 1} {
		msgBadDst := nlmsg.NewMessage(linux.NetlinkMessageHeader{
			Type: linux.RTM_GETROUTE,
		})
		msgBadDst.Put(&linux.RouteMessage{
			Family: linux.AF_INET6,
		})
		msgBadDst.PutAttr(linux.RTA_DST, primitive.AsByteSlice(make([]byte, size)))

		_, _, err = parseForDestination(msgBadDst)
		if err != syserr.ErrInvalidArgument {
			t.Errorf("got err = %v for a %d byte RTA_DST, want ErrInvalidArgument", err, size)
		}
	}
}

func TestParseForDestinationFamily(t *testing.T) {
	v4 := net.ParseIP("192.168.1.1").To4()
	v6 := net.ParseIP("2001:db8::1").To16()

	tests := []struct {
		name    string
		family  uint8
		dst     []byte
		wantDst []byte
		wantErr *syserr.Error
	}{
		{
			name:    "ipv4",
			family:  linux.AF_INET,
			dst:     v4,
			wantDst: v4,
		},
		{
			name:    "ipv6",
			family:  linux.AF_INET6,
			dst:     v6,
			wantDst: v6,
		},
		{
			name:    "ipv4 with an ipv6 sized destination",
			family:  linux.AF_INET,
			dst:     v6,
			wantDst: v6[:header.IPv4AddressSize],
		},
		{
			name:    "ipv6 with an ipv4 sized destination",
			family:  linux.AF_INET6,
			dst:     v4,
			wantErr: syserr.ErrInvalidArgument,
		},
		{
			name:    "destination longer than an ipv6 address",
			family:  linux.AF_INET6,
			dst:     append(append([]byte{}, v6...), 9),
			wantDst: v6,
		},
		{
			name:    "destination shorter than an ipv4 address",
			family:  linux.AF_INET,
			dst:     v4[:3],
			wantErr: syserr.ErrInvalidArgument,
		},
		{
			name:    "unspecified family",
			family:  linux.AF_UNSPEC,
			dst:     v4,
			wantErr: syserr.ErrNotSupported,
		},
		{
			name:    "packet family",
			family:  linux.AF_PACKET,
			dst:     v4,
			wantErr: syserr.ErrNotSupported,
		},
		{
			name:    "unspecified family without a destination",
			family:  linux.AF_UNSPEC,
			wantErr: syserr.ErrNotSupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
				Type: linux.RTM_GETROUTE,
			})
			msg.Put(&linux.RouteMessage{
				Family: test.family,
			})
			if test.dst != nil {
				msg.PutAttr(linux.RTA_DST, primitive.AsByteSlice(test.dst))
			}

			gotFamily, gotDst, err := parseForDestination(msg)
			if err != test.wantErr {
				t.Fatalf("got err = %v, want %v", err, test.wantErr)
			}
			if test.wantErr != nil {
				return
			}
			if gotFamily != test.family {
				t.Errorf("got family = %d, want %d", gotFamily, test.family)
			}
			if !bytes.Equal(gotDst, test.wantDst) {
				t.Errorf("got dst = %v, want %v", gotDst, test.wantDst)
			}
		})
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

// fakeBridgeStack implements the bridge port part of inet.Stack and records the
// configurations it applies.
type fakeBridgeStack struct {
	inet.Stack
	known   bool
	isPort  bool
	applied []string
}

func (f *fakeBridgeStack) SetBridgePort(ctx context.Context, idx int32, cfg inet.BridgePortConfig) *syserr.Error {
	if !f.known {
		return syserr.ErrNoDevice
	}
	if !f.isPort {
		return syserr.ErrNotSupported
	}
	str := func(b *bool) string {
		if b == nil {
			return "-"
		}
		return fmt.Sprint(*b)
	}
	f.applied = append(f.applied, fmt.Sprintf("hairpin=%s learning=%s", str(cfg.Hairpin), str(cfg.Learning)))
	return nil
}

// nlAttr encodes a netlink attribute.
func nlAttr(typ uint16, payload ...[]byte) []byte {
	var value []byte
	for _, p := range payload {
		value = append(value, p...)
	}
	b := make([]byte, linux.NetlinkAttrHeaderSize, linux.NetlinkAttrHeaderSize+len(value)+3)
	binary.NativeEndian.PutUint16(b, uint16(linux.NetlinkAttrHeaderSize+len(value)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	b = append(b, value...)
	for len(b)%linux.NLA_ALIGNTO != 0 {
		b = append(b, 0)
	}
	return b
}

func TestSetBridgePort(t *testing.T) {
	protinfo := func(attrs ...[]byte) []byte {
		return nlAttr(linux.IFLA_PROTINFO|linux.NLA_F_NESTED, attrs...)
	}
	u8 := func(typ uint16, v byte) []byte { return nlAttr(typ, []byte{v}) }

	for _, test := range []struct {
		name   string
		known  bool
		isPort bool
		attrs  []byte
		want   *syserr.Error
		// orWant is also accepted. A request with both an interface error and
		// an attribute error gets the interface error on Linux and the
		// attribute error here.
		orWant  *syserr.Error
		applied []string
	}{
		{
			name:    "hairpin on",
			known:   true,
			isPort:  true,
			attrs:   protinfo(u8(linux.IFLA_BRPORT_MODE, 1)),
			applied: []string{"hairpin=true learning=-"},
		},
		{
			name:    "hairpin off and learning on",
			known:   true,
			isPort:  true,
			attrs:   protinfo(u8(linux.IFLA_BRPORT_MODE, 0), u8(linux.IFLA_BRPORT_LEARNING, 1)),
			applied: []string{"hairpin=false learning=true"},
		},
		{
			name:    "any nonzero value is on",
			known:   true,
			isPort:  true,
			attrs:   protinfo(u8(linux.IFLA_BRPORT_MODE, 2)),
			applied: []string{"hairpin=true learning=-"},
		},
		{
			name:    "longer value uses the first byte",
			known:   true,
			isPort:  true,
			attrs:   protinfo(nlAttr(linux.IFLA_BRPORT_LEARNING, []byte{0, 1, 0, 0})),
			applied: []string{"hairpin=- learning=false"},
		},
		{
			name:    "last attribute of a type wins",
			known:   true,
			isPort:  true,
			attrs:   protinfo(u8(linux.IFLA_BRPORT_MODE, 1), u8(linux.IFLA_BRPORT_MODE, 0)),
			applied: []string{"hairpin=false learning=-"},
		},
		{
			name:    "attributes Linux ignores",
			known:   true,
			isPort:  true,
			attrs:   protinfo(u8(linux.IFLA_BRPORT_UNSPEC, 1), u8(linux.IFLA_BRPORT_MAX+1, 1)),
			applied: []string{"hairpin=- learning=-"},
		},
		{
			name:   "empty value",
			known:  true,
			isPort: true,
			attrs:  protinfo(nlAttr(linux.IFLA_BRPORT_MODE)),
			want:   syserr.ErrRange,
		},
		{
			name:   "unsupported flag",
			known:  true,
			isPort: true,
			attrs:  protinfo(u8(linux.IFLA_BRPORT_GUARD, 1)),
			want:   syserr.ErrNotSupported,
		},
		{
			name:   "unsupported flag after a supported one changes nothing",
			known:  true,
			isPort: true,
			attrs:  protinfo(u8(linux.IFLA_BRPORT_MODE, 1), u8(linux.IFLA_BRPORT_UNICAST_FLOOD, 0)),
			want:   syserr.ErrNotSupported,
		},
		{
			name:   "unsupported attribute with a value that is too short",
			known:  true,
			isPort: true,
			attrs:  protinfo(u8(linux.IFLA_BRPORT_MODE, 1), nlAttr(linux.IFLA_BRPORT_COST)),
			want:   syserr.ErrNotSupported,
		},
		{
			name:   "spanning tree port state",
			known:  true,
			isPort: true,
			attrs:  nlAttr(linux.IFLA_PROTINFO, []byte{0}),
			want:   syserr.ErrNotSupported,
		},
		{
			name:   "af_spec changes nothing",
			known:  true,
			isPort: true,
			attrs:  append(protinfo(u8(linux.IFLA_BRPORT_MODE, 1)), nlAttr(linux.IFLA_AF_SPEC|linux.NLA_F_NESTED)...),
			want:   syserr.ErrNotSupported,
		},
		{
			name:   "truncated nested attribute",
			known:  true,
			isPort: true,
			attrs:  nlAttr(linux.IFLA_PROTINFO|linux.NLA_F_NESTED, []byte{9, 0, 4}),
			want:   syserr.ErrInvalidArgument,
		},
		{
			name:    "no attributes",
			known:   true,
			isPort:  true,
			applied: []string{"hairpin=- learning=-"},
		},
		{
			name:    "unrelated attributes",
			known:   true,
			isPort:  true,
			attrs:   nlAttr(linux.IFLA_MTU, []byte{0, 0, 0, 0}),
			applied: []string{"hairpin=- learning=-"},
		},
		{
			name:  "not a bridge port",
			known: true,
			attrs: protinfo(u8(linux.IFLA_BRPORT_MODE, 1)),
			want:  syserr.ErrNotSupported,
		},
		{
			name:   "malformed request on something that is not a bridge port",
			known:  true,
			attrs:  protinfo(nlAttr(linux.IFLA_BRPORT_MODE)),
			want:   syserr.ErrNotSupported,
			orWant: syserr.ErrRange,
		},
		{
			name:  "no attributes on something that is not a bridge port",
			known: true,
			want:  syserr.ErrNotSupported,
		},
		{
			name:  "unknown interface",
			attrs: protinfo(u8(linux.IFLA_BRPORT_MODE, 1)),
			want:  syserr.ErrNoDevice,
		},
		{
			name:   "unsupported flag on an unknown interface",
			attrs:  protinfo(u8(linux.IFLA_BRPORT_GUARD, 1)),
			want:   syserr.ErrNoDevice,
			orWant: syserr.ErrNotSupported,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeBridgeStack{known: test.known, isPort: test.isPort}
			p := &Protocol{}
			got := p.setBridgePort(context.Background(), f, 7, nlmsg.AttrsView(test.attrs))
			if got != test.want && (test.orWant == nil || got != test.orWant) {
				if test.orWant != nil {
					t.Errorf("setBridgePort() = %v, want %v or %v", got, test.want, test.orWant)
				} else {
					t.Errorf("setBridgePort() = %v, want %v", got, test.want)
				}
			}
			if len(f.applied) != len(test.applied) {
				t.Fatalf("applied flags = %v, want %v", f.applied, test.applied)
			}
			for i := range f.applied {
				if f.applied[i] != test.applied[i] {
					t.Errorf("applied flags = %v, want %v", f.applied, test.applied)
				}
			}
		})
	}
}
