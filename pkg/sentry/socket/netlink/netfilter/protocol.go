// Copyright 2025 The gVisor Authors.
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

// Package netfilter provides a NETLINK_NETFILTER socket protocol.
package netfilter

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
)

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_NETFILTER netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_NETFILTER
}

// CanSend implements netlink.Protocol.CanSend.
// Netfilter sockets should be able to send responses back, namely
// if a user wants to see the current state of the netfilter tables.
func (p *Protocol) CanSend() bool {
	return true
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()

	// Netlink message payloads must be of at least the size of the genmsg. Return early if it is not,
	// from linux/net/netfilter/nfnetlink.c.
	if netLinkMessagePayloadSize(&hdr) < linux.SizeOfNetfilterGenMsg {
		return nil
	}

	msgType := hdr.NetFilterMsgType()
	// TODO: b/421437663 - Match the message type and call the appropriate Nftables function.
	switch msgType {
	default:
		return syserr.ErrInvalidArgument
	}
}

// init registers the NETLINK_NETFILTER provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_NETFILTER, NewProtocol)
}

func netLinkMessagePayloadSize(h *linux.NetlinkMessageHeader) int {
	return int(h.Length) - linux.NetlinkMessageHeaderSize
}
