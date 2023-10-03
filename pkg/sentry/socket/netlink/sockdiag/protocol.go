// Copyright 2023 The gVisor Authors.
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

// Package sockdiag provides a NETLINK_SOCK_DIAG socket protocol.
package sockdiag

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// commandKind describes the operational class of a message type.
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

// NewProtocol creates a NETLINK_SOCK_DIAG netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_SOCK_DIAG
}

// CanSend implements netlink.Protocol.CanSend.
func (p *Protocol) CanSend() bool {
	return true
}

func getAddress(addr [4]uint32, family uint8) tcpip.Address {
	var buf []byte
	if family == linux.AF_INET {
		buf = binary.AppendUint32(buf, binary.BigEndian, addr[0])
	} else {
		for i := 0; i < 4; i++ {
			buf = binary.AppendUint32(buf, binary.BigEndian, addr[i])
		}
	}
	return tcpip.AddrFromSlice(buf)
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	hdr := msg.Header()

	// All messages start with a 1 byte protocol family.
	var family primitive.Uint8
	if _, ok := msg.GetData(&family); !ok {
		// Linux ignores messages missing the protocol family.
		return nil
	}
	// Non-GET message types require CAP_NET_ADMIN.
	if typeKind(hdr.Type) != kindGet {
		creds := auth.CredentialsFromContext(ctx)
		if !creds.HasCapability(linux.CAP_NET_ADMIN) {
			return syserr.ErrPermissionDenied
		}
	}

	if hdr.Flags&linux.NLM_F_REQUEST != linux.NLM_F_REQUEST {
		return syserr.ErrNotSupported
	}

	if hdr.Type&linux.SOCK_DIAG_BY_FAMILY != linux.SOCK_DIAG_BY_FAMILY {
		return syserr.ErrNotSupported
	}

	var data linux.InetDiagReqV2
	if _, ok := msg.GetData(&data); !ok {
		return syserr.ErrInvalidArgument
	}

	// Find the endpoint.
	s := inet.StackFromContext(ctx)
	if s == nil {
		// No network devices.
		return syserr.ErrProtocolNotSupported
	}
	var networkFamily tcpip.NetworkProtocolNumber
	switch data.Family {
	case linux.AF_INET:
		networkFamily = header.IPv4ProtocolNumber
	case linux.AF_INET6:
		networkFamily = header.IPv6ProtocolNumber
	default:
		return syserr.ErrInvalidArgument
	}
	id := stack.TransportEndpointID{
		LocalPort:     data.ID.SrcPort,
		LocalAddress:  getAddress(data.ID.SrcAddr, data.Family),
		RemotePort:    data.ID.DstPort,
		RemoteAddress: getAddress(data.ID.DstAddr, data.Family),
	}
	st := s.(*netstack.Stack).Stack
	transEP := st.FindTransportEndpoint(networkFamily, tcpip.TransportProtocolNumber(data.Protocol), id, tcpip.NICID(data.ID.Iface))
	if transEP == nil {
		return syserr.ErrInvalidArgument
	}

	// Get all the relevant info from the endpoint.
	ep := transEP.(tcpip.Endpoint)
	var res linux.InetDiagMsg
	res.UID = ep.Owner().KUID()

	// Return it in ms.
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: linux.SOCK_DIAG_BY_FAMILY,
	})
	m.Put(&res)
	return nil
}

// init registers the NETLINK_SOCK_DIAG provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_SOCK_DIAG, NewProtocol)
}
