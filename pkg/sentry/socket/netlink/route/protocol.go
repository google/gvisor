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

// Package route provides a NETLINK_ROUTE socket protocol.
package route

import (
	"bytes"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/syserr"
)

// commandKind describes the operational class of a message type.
//
// The route message types use the lower 2 bits of the type to describe class
// of command.
type commandKind int

const (
	kindNew commandKind = 0x0
	kindDel commandKind = 0x1
	kindGet commandKind = 0x2
	kindSet commandKind = 0x3
)

func typeKind(typ uint16) commandKind {
	return commandKind(typ & 0x3)
}

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_ROUTE netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_ROUTE
}

// CanSend implements netlink.Protocol.CanSend.
func (p *Protocol) CanSend() bool {
	return true
}

// dumpLinks handles RTM_GETLINK dump requests.
func (p *Protocol) dumpLinks(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	// NLM_F_DUMP + RTM_GETLINK messages are supposed to include an
	// ifinfomsg. However, Linux <3.9 only checked for rtgenmsg, and some
	// userspace applications (including glibc) still include rtgenmsg.
	// Linux has a workaround based on the total message length.
	//
	// We don't bother to check for either, since we don't support any
	// extra attributes that may be included anyways.
	//
	// The message may also contain netlink attribute IFLA_EXT_MASK, which
	// we don't support.

	// The RTM_GETLINK dump response is a set of messages each containing
	// an InterfaceInfoMessage followed by a set of netlink attributes.

	// We always send back an NLMSG_DONE.
	ms.Multi = true

	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network devices.
		return nil
	}

	for idx, i := range stack.Interfaces() {
		addNewLinkMessage(ms, idx, i)
	}

	return nil
}

// getLinks handles RTM_GETLINK requests.
func (p *Protocol) getLink(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network devices.
		return nil
	}

	// Parse message.
	var ifi linux.InterfaceInfoMessage
	attrs, ok := msg.GetData(&ifi)
	if !ok {
		return syserr.ErrInvalidArgument
	}

	// Parse attributes.
	var byName []byte
	for !attrs.Empty() {
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		attrs = rest

		switch ahdr.Type {
		case linux.IFLA_IFNAME:
			if len(value) < 1 {
				return syserr.ErrInvalidArgument
			}
			byName = value[:len(value)-1]

			// TODO(gvisor.dev/issue/578): Support IFLA_EXT_MASK.
		}
	}

	found := false
	for idx, i := range stack.Interfaces() {
		switch {
		case ifi.Index > 0:
			if idx != ifi.Index {
				continue
			}
		case byName != nil:
			if string(byName) != i.Name {
				continue
			}
		default:
			// Criteria not specified.
			return syserr.ErrInvalidArgument
		}

		addNewLinkMessage(ms, idx, i)
		found = true
		break
	}
	if !found {
		return syserr.ErrNoDevice
	}
	return nil
}

// delLink handles RTM_DELLINK requests.
func (p *Protocol) delLink(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network stack.
		return syserr.ErrProtocolNotSupported
	}

	var ifinfomsg linux.InterfaceInfoMessage
	attrs, ok := msg.GetData(&ifinfomsg)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	if ifinfomsg.Index == 0 {
		// The index is unspecified, search by the interface name.
		ahdr, value, _, ok := attrs.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		switch ahdr.Type {
		case linux.IFLA_IFNAME:
			if len(value) < 1 {
				return syserr.ErrInvalidArgument
			}
			ifname := string(value[:len(value)-1])
			for idx, ifa := range stack.Interfaces() {
				if ifname == ifa.Name {
					ifinfomsg.Index = idx
					break
				}
			}
		default:
			return syserr.ErrInvalidArgument
		}
		if ifinfomsg.Index == 0 {
			return syserr.ErrNoDevice
		}
	}
	return syserr.FromError(stack.RemoveInterface(ifinfomsg.Index))
}

// addNewLinkMessage appends RTM_NEWLINK message for the given interface into
// the message set.
func addNewLinkMessage(ms *netlink.MessageSet, idx int32, i inet.Interface) {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_NEWLINK,
	})

	m.Put(&linux.InterfaceInfoMessage{
		Family: linux.AF_UNSPEC,
		Type:   i.DeviceType,
		Index:  idx,
		Flags:  i.Flags,
	})

	m.PutAttrString(linux.IFLA_IFNAME, i.Name)
	m.PutAttr(linux.IFLA_MTU, primitive.AllocateUint32(i.MTU))

	mac := make([]byte, 6)
	brd := mac
	if len(i.Addr) > 0 {
		mac = i.Addr
		brd = bytes.Repeat([]byte{0xff}, len(i.Addr))
	}
	m.PutAttr(linux.IFLA_ADDRESS, primitive.AsByteSlice(mac))
	m.PutAttr(linux.IFLA_BROADCAST, primitive.AsByteSlice(brd))

	// TODO(gvisor.dev/issue/578): There are many more attributes.
}

// dumpAddrs handles RTM_GETADDR dump requests.
func (p *Protocol) dumpAddrs(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	// RTM_GETADDR dump requests need not contain anything more than the
	// netlink header and 1 byte protocol family common to all
	// NETLINK_ROUTE requests.
	//
	// TODO(b/68878065): Filter output by passed protocol family.

	// The RTM_GETADDR dump response is a set of RTM_NEWADDR messages each
	// containing an InterfaceAddrMessage followed by a set of netlink
	// attributes.

	// We always send back an NLMSG_DONE.
	ms.Multi = true

	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network devices.
		return nil
	}

	for id, as := range stack.InterfaceAddrs() {
		for _, a := range as {
			m := ms.AddMessage(linux.NetlinkMessageHeader{
				Type: linux.RTM_NEWADDR,
			})

			m.Put(&linux.InterfaceAddrMessage{
				Family:    a.Family,
				PrefixLen: a.PrefixLen,
				Index:     uint32(id),
			})

			addr := primitive.ByteSlice([]byte(a.Addr))
			m.PutAttr(linux.IFA_LOCAL, &addr)
			m.PutAttr(linux.IFA_ADDRESS, &addr)

			// TODO(gvisor.dev/issue/578): There are many more attributes.
		}
	}

	return nil
}

// commonPrefixLen reports the length of the longest IP address prefix.
// This is a simplied version from Golang's src/net/addrselect.go.
func commonPrefixLen(a, b []byte) (cpl int) {
	for len(a) > 0 {
		if a[0] == b[0] {
			cpl += 8
			a = a[1:]
			b = b[1:]
			continue
		}
		bits := 8
		ab, bb := a[0], b[0]
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}

// fillRoute returns the Route using LPM algorithm. Refer to Linux's
// net/ipv4/route.c:rt_fill_info().
func fillRoute(routes []inet.Route, addr []byte) (inet.Route, *syserr.Error) {
	family := uint8(linux.AF_INET)
	if len(addr) != 4 {
		family = linux.AF_INET6
	}

	idx := -1    // Index of the Route rule to be returned.
	idxDef := -1 // Index of the default route rule.
	prefix := 0  // Current longest prefix.
	for i, route := range routes {
		if route.Family != family {
			continue
		}

		if len(route.GatewayAddr) > 0 && route.DstLen == 0 {
			idxDef = i
			continue
		}

		cpl := commonPrefixLen(addr, route.DstAddr)
		if cpl < int(route.DstLen) {
			continue
		}
		cpl = int(route.DstLen)
		if cpl > prefix {
			idx = i
			prefix = cpl
		}
	}
	if idx == -1 {
		idx = idxDef
	}
	if idx == -1 {
		return inet.Route{}, syserr.ErrNoRoute
	}

	route := routes[idx]
	if family == linux.AF_INET {
		route.DstLen = 32
	} else {
		route.DstLen = 128
	}
	route.DstAddr = addr
	route.Flags |= linux.RTM_F_CLONED // This route is cloned.
	return route, nil
}

// parseForDestination parses a message as format of RouteMessage-RtAttr-dst.
func parseForDestination(msg *netlink.Message) ([]byte, *syserr.Error) {
	var rtMsg linux.RouteMessage
	attrs, ok := msg.GetData(&rtMsg)
	if !ok {
		return nil, syserr.ErrInvalidArgument
	}
	// iproute2 added the RTM_F_LOOKUP_TABLE flag in version v4.4.0. See
	// commit bc234301af12. Note we don't check this flag for backward
	// compatibility.
	if rtMsg.Flags != 0 && rtMsg.Flags != linux.RTM_F_LOOKUP_TABLE {
		return nil, syserr.ErrNotSupported
	}

	// Expect first attribute is RTA_DST.
	if hdr, value, _, ok := attrs.ParseFirst(); ok && hdr.Type == linux.RTA_DST {
		return value, nil
	}
	return nil, syserr.ErrInvalidArgument
}

// dumpRoutes handles RTM_GETROUTE requests.
func (p *Protocol) dumpRoutes(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	// RTM_GETROUTE dump requests need not contain anything more than the
	// netlink header and 1 byte protocol family common to all
	// NETLINK_ROUTE requests.

	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network routes.
		return nil
	}

	hdr := msg.Header()
	routeTables := stack.RouteTable()

	if hdr.Flags == linux.NLM_F_REQUEST {
		dst, err := parseForDestination(msg)
		if err != nil {
			return err
		}
		route, err := fillRoute(routeTables, dst)
		if err != nil {
			// TODO(gvisor.dev/issue/1237): return NLMSG_ERROR with ENETUNREACH.
			return syserr.ErrNotSupported
		}
		routeTables = append([]inet.Route{}, route)
	} else if hdr.Flags&linux.NLM_F_DUMP == linux.NLM_F_DUMP {
		// We always send back an NLMSG_DONE.
		ms.Multi = true
	} else {
		// TODO(b/68878065): Only above cases are supported.
		return syserr.ErrNotSupported
	}

	for _, rt := range routeTables {
		m := ms.AddMessage(linux.NetlinkMessageHeader{
			Type: linux.RTM_NEWROUTE,
		})

		m.Put(&linux.RouteMessage{
			Family: rt.Family,
			DstLen: rt.DstLen,
			SrcLen: rt.SrcLen,
			TOS:    rt.TOS,

			// Always return the main table since we don't have multiple
			// routing tables.
			Table:    linux.RT_TABLE_MAIN,
			Protocol: rt.Protocol,
			Scope:    rt.Scope,
			Type:     rt.Type,

			Flags: rt.Flags,
		})

		m.PutAttr(254, primitive.AsByteSlice([]byte{123}))
		if rt.DstLen > 0 {
			m.PutAttr(linux.RTA_DST, primitive.AsByteSlice(rt.DstAddr))
		}
		if rt.SrcLen > 0 {
			m.PutAttr(linux.RTA_SRC, primitive.AsByteSlice(rt.SrcAddr))
		}
		if rt.OutputInterface != 0 {
			m.PutAttr(linux.RTA_OIF, primitive.AllocateInt32(rt.OutputInterface))
		}
		if len(rt.GatewayAddr) > 0 {
			m.PutAttr(linux.RTA_GATEWAY, primitive.AsByteSlice(rt.GatewayAddr))
		}

		// TODO(gvisor.dev/issue/578): There are many more attributes.
	}

	return nil
}

// newAddr handles RTM_NEWADDR requests.
func (p *Protocol) newAddr(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network stack.
		return syserr.ErrProtocolNotSupported
	}

	var ifa linux.InterfaceAddrMessage
	attrs, ok := msg.GetData(&ifa)
	if !ok {
		return syserr.ErrInvalidArgument
	}

	for !attrs.Empty() {
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		attrs = rest

		// NOTE: A netlink message will contain multiple header attributes.
		// Both the IFA_ADDRESS and IFA_LOCAL attributes are typically sent
		// with IFA_ADDRESS being a prefix address and IFA_LOCAL being the
		// local interface address. We add the local interface address here
		// and ignore the IFA_ADDRESS.
		switch ahdr.Type {
		case linux.IFA_LOCAL:
			err := stack.AddInterfaceAddr(int32(ifa.Index), inet.InterfaceAddr{
				Family:    ifa.Family,
				PrefixLen: ifa.PrefixLen,
				Flags:     ifa.Flags,
				Addr:      value,
			})
			if err == unix.EEXIST {
				flags := msg.Header().Flags
				if flags&linux.NLM_F_EXCL != 0 {
					return syserr.ErrExists
				}
			} else if err != nil {
				return syserr.ErrInvalidArgument
			}
		case linux.IFA_ADDRESS:
		default:
			return syserr.ErrNotSupported
		}
	}
	return nil
}

// delAddr handles RTM_DELADDR requests.
func (p *Protocol) delAddr(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network stack.
		return syserr.ErrProtocolNotSupported
	}

	var ifa linux.InterfaceAddrMessage
	attrs, ok := msg.GetData(&ifa)
	if !ok {
		return syserr.ErrInvalidArgument
	}

	for !attrs.Empty() {
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		attrs = rest

		// NOTE: A netlink message will contain multiple header attributes.
		// Both the IFA_ADDRESS and IFA_LOCAL attributes are typically sent
		// with IFA_ADDRESS being a prefix address and IFA_LOCAL being the
		// local interface address. We use the local interface address to
		// remove the address and ignore the IFA_ADDRESS.
		switch ahdr.Type {
		case linux.IFA_LOCAL:
			err := stack.RemoveInterfaceAddr(int32(ifa.Index), inet.InterfaceAddr{
				Family:    ifa.Family,
				PrefixLen: ifa.PrefixLen,
				Flags:     ifa.Flags,
				Addr:      value,
			})
			if err != nil {
				return syserr.ErrBadLocalAddress
			}
		case linux.IFA_ADDRESS:
		default:
			return syserr.ErrNotSupported
		}
	}

	return nil
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	hdr := msg.Header()

	// All messages start with a 1 byte protocol family.
	var family primitive.Uint8
	if _, ok := msg.GetData(&family); !ok {
		// Linux ignores messages missing the protocol family. See
		// net/core/rtnetlink.c:rtnetlink_rcv_msg.
		return nil
	}

	// Non-GET message types require CAP_NET_ADMIN.
	if typeKind(hdr.Type) != kindGet {
		creds := auth.CredentialsFromContext(ctx)
		if !creds.HasCapability(linux.CAP_NET_ADMIN) {
			return syserr.ErrPermissionDenied
		}
	}

	if hdr.Flags&linux.NLM_F_DUMP == linux.NLM_F_DUMP {
		// TODO(b/68878065): Only the dump variant of the types below are
		// supported.
		switch hdr.Type {
		case linux.RTM_GETLINK:
			return p.dumpLinks(ctx, msg, ms)
		case linux.RTM_GETADDR:
			return p.dumpAddrs(ctx, msg, ms)
		case linux.RTM_GETROUTE:
			return p.dumpRoutes(ctx, msg, ms)
		default:
			return syserr.ErrNotSupported
		}
	} else if hdr.Flags&linux.NLM_F_REQUEST == linux.NLM_F_REQUEST {
		switch hdr.Type {
		case linux.RTM_GETLINK:
			return p.getLink(ctx, msg, ms)
		case linux.RTM_DELLINK:
			return p.delLink(ctx, msg, ms)
		case linux.RTM_GETROUTE:
			return p.dumpRoutes(ctx, msg, ms)
		case linux.RTM_NEWADDR:
			return p.newAddr(ctx, msg, ms)
		case linux.RTM_DELADDR:
			return p.delAddr(ctx, msg, ms)
		default:
			return syserr.ErrNotSupported
		}
	}
	return syserr.ErrNotSupported
}

// init registers the NETLINK_ROUTE provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_ROUTE, NewProtocol)
}
