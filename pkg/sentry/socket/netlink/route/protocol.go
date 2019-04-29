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

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
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

// dumpLinks handles RTM_GETLINK + NLM_F_DUMP requests.
func (p *Protocol) dumpLinks(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
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

		// TODO(b/68878065): There are many more attributes.
	}

	return nil
}

// dumpAddrs handles RTM_GETADDR + NLM_F_DUMP requests.
func (p *Protocol) dumpAddrs(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
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

			// TODO(b/68878065): There are many more attributes.
		}
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

	// TODO(b/68878065): Only the dump variant of the types below are
	// supported.
	if hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}

	switch hdr.Type {
	case linux.RTM_GETLINK:
		return p.dumpLinks(ctx, hdr, data, ms)
	case linux.RTM_GETADDR:
		return p.dumpAddrs(ctx, hdr, data, ms)
	default:
		return syserr.ErrNotSupported
	}
}

// init registers the NETLINK_ROUTE provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_ROUTE, NewProtocol)
}
