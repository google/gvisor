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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/nftables"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_NETFILTER netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	if !nftables.IsNFTablesEnabled() {
		return nil, syserr.ErrProtocolNotSupported
	}

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
		log.Debugf("Netlink message payload is too small: %d < %d", netLinkMessagePayloadSize(&hdr), linux.SizeOfNetfilterGenMsg)
		return nil
	}

	msgType := hdr.NetFilterMsgType()
	st := inet.StackFromContext(ctx).(*netstack.Stack).Stack
	nft := (st.NFTables()).(*nftables.NFTables)
	var nfGenMsg linux.NetFilterGenMsg

	// The payload of a message is its attributes.
	atr, ok := msg.GetData(&nfGenMsg)
	if !ok {
		log.Debugf("Failed to get message data")
		return syserr.ErrInvalidArgument
	}

	attrs, ok := atr.Parse()
	if !ok {
		log.Debugf("Failed to parse message attributes")
		return syserr.ErrInvalidArgument
	}

	// Nftables functions error check the address family value.
	family := stack.AddressFamily(nfGenMsg.Family)
	// TODO: b/421437663 - Match the message type and call the appropriate Nftables function.
	switch msgType {
	case linux.NFT_MSG_NEWTABLE:
		return p.newTable(nft, attrs, family, hdr.Flags, ms)
	case linux.NFT_MSG_GETTABLE:
		return p.getTable(nft, attrs, family, hdr.Flags, ms)
	default:
		log.Debugf("Unsupported message type: %d", msgType)
		return syserr.ErrInvalidArgument
	}
}

// newTable creates a new table for the given family.
func (p *Protocol) newTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.Error {
	// TODO: b/421437663 - Handle the case where the table name is set to empty string.
	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		log.Debugf("Nftables: Table name attribute is malformed or not found")
		return syserr.ErrInvalidArgument
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil && err != syserr.ErrNoFileOrDir {
		return err
	}

	// If a table already exists, only update its dormant flags if NLM_F_EXCL and NLM_F_REPLACE
	// are not set. From net/netfilter/nf_tables_api.c:nf_tables_newtable:nf_tables_updtable
	if tab != nil {
		if flags&linux.NLM_F_EXCL == linux.NLM_F_EXCL {
			log.Debugf("Nftables: Table with name: %s already exists", tabNameBytes.String())
			return syserr.ErrExists
		}

		if flags&linux.NLM_F_REPLACE == linux.NLM_F_REPLACE {
			log.Debugf("Nftables: Table with name: %s already exists and NLM_F_REPLACE is not supported", tabNameBytes.String())
			return syserr.ErrNotSupported
		}
	} else {
		tab, err = nft.CreateTable(family, tabNameBytes.String())
		if err != nil {
			log.Debugf("Nftables: Failed to create table with name: %s. Error: %s", tabNameBytes.String(), err)
			return err
		}

		if udata, ok := attrs[linux.NFTA_TABLE_USERDATA]; ok {
			tab.SetUserData(udata)
		}

		if _, ok := attrs[linux.NFTA_TABLE_OWNER]; ok {
			log.Debugf("Nftables: Setting table owner to: %d", uint32(ms.PortID))
			tab.SetOwner(uint32(ms.PortID))
		}
	}

	// TODO: b/421437663 - Support additional user-specified table flags.
	if uflags, ok := attrs[linux.NFTA_TABLE_FLAGS]; ok {
		attrFlags, _ := uflags.Uint32()
		// Flags sent through the NFTA_TABLE_FLAGS attribute are of type uint32
		// but should only have user flags set.
		if attrFlags & ^uint32(linux.NFT_TABLE_F_MASK) > 0 {
			log.Infof("Nftables: Table flags set are not supported")
			return syserr.ErrNotSupported
		}

		dormant := (attrFlags & uint32(linux.NFT_TABLE_F_DORMANT)) == uint32(linux.NFT_TABLE_F_DORMANT)
		tab.SetDormant(dormant)

		setOwner := (attrFlags & uint32(linux.NFT_TABLE_F_OWNER)) == uint32(linux.NFT_TABLE_F_OWNER)
		if setOwner {
			tab.SetOwner(uint32(ms.PortID))
		}
	}
	return nil
}

// getTable returns a table for the given family. Returns nil on success and
// a sys.error on failure.
func (p *Protocol) getTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.Error {
	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		log.Debugf("Nftables: Table name attribute is malformed or not found")
		return syserr.ErrInvalidArgument
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil {
		log.Debugf("Nftables: error %s for table with name: %s", err, tabNameBytes.String())
		return err
	}

	tabName := tab.GetName()
	userFlags := tab.GetLinuxUserFlagSet()
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_GETTABLE),
	})

	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(family),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})
	m.PutAttrString(linux.NFTA_TABLE_NAME, tabName)
	m.PutAttr(linux.NFTA_TABLE_USE, primitive.AllocateUint32(uint32(tab.ChainCount())))
	m.PutAttr(linux.NFTA_TABLE_HANDLE, primitive.AllocateUint64(tab.GetHandle()))
	m.PutAttr(linux.NFTA_TABLE_FLAGS, primitive.AllocateUint8(userFlags))

	if tab.HasOwner() {
		m.PutAttr(linux.NFTA_TABLE_OWNER, primitive.AllocateUint32(tab.GetOwner()))
	}

	if tab.HasUserData() {
		m.PutAttr(linux.NFTA_TABLE_USERDATA, primitive.AsByteSlice(tab.GetUserData()))
	}

	return nil
}

func netLinkMessagePayloadSize(h *linux.NetlinkMessageHeader) int {
	return int(h.Length) - linux.NetlinkMessageHeaderSize
}

// init registers the NETLINK_NETFILTER provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_NETFILTER, NewProtocol)
}
