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
	"fmt"

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

	family := nftables.AFtoNetlinkAF(nfGenMsg.Family)
	// TODO: b/421437663 - Match the message type and call the appropriate Nftables function.
	switch msgType {
	case linux.NFT_MSG_NEWTABLE:
		if err := p.newTable(nft, attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables new table error: %s", err)
			return err.GetError()
		}
		return nil
	case linux.NFT_MSG_GETTABLE:
		if err := p.getTable(nft, attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables get table error: %s", err)
			return err.GetError()
		}
		return nil
	case linux.NFT_MSG_DELTABLE, linux.NFT_MSG_DESTROYTABLE:
		if err := p.deleteTable(nft, attrs, family, hdr, msgType, ms); err != nil {
			log.Debugf("Nftables delete table error: %s", err)
			return err.GetError()
		}
		return nil
	default:
		log.Debugf("Unsupported message type: %d", msgType)
		return syserr.ErrNotSupported
	}
}

// newTable creates a new table for the given family.
func (p *Protocol) newTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if family == stack.NumAFs {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Address family is not supported"))
	}

	// TODO: b/421437663 - Handle the case where the table name is set to empty string.
	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Table name attribute is malformed or not found"))
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil && err.GetError() != syserr.ErrNoFileOrDir {
		return err
	}

	// If a table already exists, only update its dormant flags if NLM_F_EXCL and NLM_F_REPLACE
	// are not set. From net/netfilter/nf_tables_api.c:nf_tables_newtable:nf_tables_updtable
	if tab != nil {
		if flags&linux.NLM_F_EXCL != 0 {
			return syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("Nftables: Table with name: %s already exists", tab.GetName()))
		}

		if flags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table with name: %s already exists and NLM_F_REPLACE is not supported", tab.GetName()))
		}

		return p.updateTable(nft, tab, attrs, family, ms)
	}

	// TODO: b/421437663 - Support additional user-specified table flags.
	var attrFlags uint32 = 0
	if uflags, ok := attrs[linux.NFTA_TABLE_FLAGS]; ok {
		attrFlags, _ = uflags.Uint32()
		// Flags sent through the NFTA_TABLE_FLAGS attribute are of type uint32
		// but should only have user flags set. This check needs to be done before table creation.
		if attrFlags & ^uint32(linux.NFT_TABLE_F_MASK) != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table flags set are not supported"))
		}
	}

	tab, err = nft.CreateTable(family, tabNameBytes.String())
	if err != nil {
		return err
	}

	if udata, ok := attrs[linux.NFTA_TABLE_USERDATA]; ok {
		tab.SetUserData(udata)
	}

	// Flags should only be assigned after we have successfully created the table.
	dormant := (attrFlags & uint32(linux.NFT_TABLE_F_DORMANT)) != 0
	tab.SetDormant(dormant)

	owner := (attrFlags & uint32(linux.NFT_TABLE_F_OWNER)) != 0
	if owner {
		if err := tab.SetOwner(uint32(ms.PortID)); err != nil {
			return err
		}
	}

	return nil
}

// updateTable updates an existing table.
func (p *Protocol) updateTable(nft *nftables.NFTables, tab *nftables.Table, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	var attrFlags uint32
	if uflags, ok := attrs[linux.NFTA_TABLE_FLAGS]; ok {
		attrFlags, _ = uflags.Uint32()
		// This check needs to be done before table update.
		if attrFlags & ^uint32(linux.NFT_TABLE_F_MASK) > 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table flags set are not supported"))
		}
	}

	// When updating the table, if the table has an owner but the owner flag isn't set,
	// the table should not be updated.
	// From net/netfilter/nf_tables_api.c:nf_tables_updtable.
	if tab.HasOwner() && (attrFlags&uint32(linux.NFT_TABLE_F_OWNER)) == 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table with name: %s already has an owner but NFT_TABLE_F_OWNER was not set when updating the table", tab.GetName()))
	}

	// The owner is only updated if the table has no previous owner.
	if !tab.HasOwner() && attrFlags&uint32(linux.NFT_TABLE_F_OWNER) != 0 {
		if err := tab.SetOwner(uint32(ms.PortID)); err != nil {
			return err
		}
	}

	dormant := (attrFlags & uint32(linux.NFT_TABLE_F_DORMANT)) != 0
	tab.SetDormant(dormant)
	return nil
}

// getTable returns a table for the given family.
func (p *Protocol) getTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Table name attribute is malformed or not found"))
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil {
		return err
	}

	tabName := tab.GetName()
	userFlags, err := tab.GetLinuxUserFlagSet()
	if err != nil {
		return err
	}
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

// deleteTable deletes a table for the given family.
func (p *Protocol) deleteTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, hdr linux.NetlinkMessageHeader, msgType linux.NfTableMsgType, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if family == stack.Unspec || (!hasAttr(linux.NFTA_TABLE_NAME, attrs) && !hasAttr(linux.NFTA_TABLE_HANDLE, attrs)) {
		nft.Flush(attrs, family, uint32(ms.PortID))
		return nil
	}

	var tab *nftables.Table
	var err *syserr.AnnotatedError
	if tabHandleBytes, ok := attrs[linux.NFTA_TABLE_HANDLE]; ok {
		tabHandle, ok := tabHandleBytes.Uint64()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Table handle attribute is malformed or not found"))
		}

		tab, err = nft.GetTableByHandle(family, uint64(tabHandle), uint32(ms.PortID))
	} else {
		tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Table name attribute is malformed or not found"))
		}
		tab, err = nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	}

	if err != nil {
		// Ignore ENOENT if DESTROY_TABLE is set
		if err.GetError() == syserr.ErrNoFileOrDir && msgType == linux.NFT_MSG_DESTROYTABLE {
			return nil
		}
		return err
	}

	// Don't delete the table if it is not empty and NLM_F_NONREC is set.
	if hdr.Flags&linux.NLM_F_NONREC == linux.NLM_F_NONREC && tab.ChainCount() > 0 {
		return syserr.NewAnnotatedError(syserr.ErrBusy, fmt.Sprintf("Nftables: Table with family: %d and name: %s already exists", int(family), tab.GetName()))
	}

	_, err = nft.DeleteTable(family, tab.GetName())
	return err
}

// netLinkMessagePayloadSize returns the size of the netlink message payload.
func netLinkMessagePayloadSize(h *linux.NetlinkMessageHeader) int {
	return int(h.Length) - linux.NetlinkMessageHeaderSize
}

// hasAttr returns whether the given attribute key is present in the attribute map.
func hasAttr(attrName uint16, attrs map[uint16]nlmsg.BytesView) bool {
	_, ok := attrs[attrName]
	return ok
}

// init registers the NETLINK_NETFILTER provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_NETFILTER, NewProtocol)
}
