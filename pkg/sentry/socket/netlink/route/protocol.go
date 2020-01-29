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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
)

// commandKind describes the operational class of a message type.
//
// The route message types use the lower 2 bits of the type to describe class
// of command.
type commandKind int

const (
	kindNew commandKind = 0x0
	kindDel             = 0x1
	kindGet             = 0x2
	kindSet             = 0x3
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
func (p *Protocol) dumpLinks(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
	// TODO(b/68878065): Only the dump variant of the types below are
	// supported.
	if hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}

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

	for id, i := range stack.Interfaces() {
		m := ms.AddMessage(linux.NetlinkMessageHeader{
			Type: linux.RTM_NEWLINK,
		})

		m.Put(linux.InterfaceInfoMessage{
			Family: linux.AF_UNSPEC,
			Type:   i.DeviceType,
			Index:  id,
			Flags:  i.Flags,
		})

		m.PutAttrString(linux.IFLA_IFNAME, i.Name)
		m.PutAttr(linux.IFLA_MTU, i.MTU)

		mac := make([]byte, 6)
		brd := mac
		if len(i.Addr) > 0 {
			mac = i.Addr
			brd = bytes.Repeat([]byte{0xff}, len(i.Addr))
		}
		m.PutAttr(linux.IFLA_ADDRESS, mac)
		m.PutAttr(linux.IFLA_BROADCAST, brd)

		// TODO(gvisor.dev/issue/578): There are many more attributes.
	}

	return nil
}

// dumpAddrs handles RTM_GETADDR dump requests.
func (p *Protocol) dumpAddrs(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
	// TODO(b/68878065): Only the dump variant of the types below are
	// supported.
	if hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}

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

			m.Put(linux.InterfaceAddrMessage{
				Family:    a.Family,
				PrefixLen: a.PrefixLen,
				Index:     uint32(id),
			})

			m.PutAttr(linux.IFA_ADDRESS, []byte(a.Addr))

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
func parseForDestination(data []byte) ([]byte, *syserr.Error) {
	var rtMsg linux.RouteMessage
	if len(data) < linux.SizeOfRouteMessage {
		return nil, syserr.ErrInvalidArgument
	}
	binary.Unmarshal(data[:linux.SizeOfRouteMessage], usermem.ByteOrder, &rtMsg)
	// iproute2 added the RTM_F_LOOKUP_TABLE flag in version v4.4.0. See
	// commit bc234301af12. Note we don't check this flag for backward
	// compatibility.
	if rtMsg.Flags != 0 && rtMsg.Flags != linux.RTM_F_LOOKUP_TABLE {
		return nil, syserr.ErrNotSupported
	}

	data = data[linux.SizeOfRouteMessage:]

	// TODO(gvisor.dev/issue/1611): Add generic attribute parsing.
	var rtAttr linux.RtAttr
	if len(data) < linux.SizeOfRtAttr {
		return nil, syserr.ErrInvalidArgument
	}
	binary.Unmarshal(data[:linux.SizeOfRtAttr], usermem.ByteOrder, &rtAttr)
	if rtAttr.Type != linux.RTA_DST {
		return nil, syserr.ErrInvalidArgument
	}

	if len(data) < int(rtAttr.Len) {
		return nil, syserr.ErrInvalidArgument
	}
	return data[linux.SizeOfRtAttr:rtAttr.Len], nil
}

// dumpRoutes handles RTM_GETROUTE requests.
func (p *Protocol) dumpRoutes(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
	// RTM_GETROUTE dump requests need not contain anything more than the
	// netlink header and 1 byte protocol family common to all
	// NETLINK_ROUTE requests.

	stack := inet.StackFromContext(ctx)
	if stack == nil {
		// No network routes.
		return nil
	}

	routeTables := stack.RouteTable()

	if hdr.Flags == linux.NLM_F_REQUEST {
		dst, err := parseForDestination(data)
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

		m.Put(linux.RouteMessage{
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

		m.PutAttr(254, []byte{123})
		if rt.DstLen > 0 {
			m.PutAttr(linux.RTA_DST, rt.DstAddr)
		}
		if rt.SrcLen > 0 {
			m.PutAttr(linux.RTA_SRC, rt.SrcAddr)
		}
		if rt.OutputInterface != 0 {
			m.PutAttr(linux.RTA_OIF, rt.OutputInterface)
		}
		if len(rt.GatewayAddr) > 0 {
			m.PutAttr(linux.RTA_GATEWAY, rt.GatewayAddr)
		}

		// TODO(gvisor.dev/issue/578): There are many more attributes.
	}

	return nil
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
	// All messages start with a 1 byte protocol family.
	if len(data) < 1 {
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

	switch hdr.Type {
	case linux.RTM_GETLINK:
		return p.dumpLinks(ctx, hdr, data, ms)
	case linux.RTM_GETADDR:
		return p.dumpAddrs(ctx, hdr, data, ms)
	case linux.RTM_GETROUTE:
		return p.dumpRoutes(ctx, hdr, data, ms)
	default:
		return syserr.ErrNotSupported
	}
}

// init registers the NETLINK_ROUTE provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_ROUTE, NewProtocol)
}
