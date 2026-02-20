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
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bits"
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

// Receive implements netlink.Protocol.Receive.
// From net/netfilter/nfnetlink.c:nfnetlink_rcv.
func (p *Protocol) Receive(ctx context.Context, s *netlink.Socket, buf []byte) *syserr.Error {
	hdr, ok := nlmsg.PeekHeader(buf)
	// Linux ignores messages that are less than the NetlinkMessageHeaderSize.
	if !ok || hdr.Length < linux.NetlinkMessageHeaderSize || uint32(len(buf)) < hdr.Length {
		return nil
	}

	// Currently, the kernel is the only valid destination so simply return
	// the error to the caller.
	if !s.NetworkNamespace().HasCapability(ctx, linux.CAP_NET_ADMIN) {
		return syserr.ErrNotPermittedNet
	}

	// TODO: b/434785410 - Support batch messages.
	if hdr.Type == linux.NFNL_MSG_BATCH_BEGIN {
		ms := nlmsg.NewMessageSet(s.GetPortID(), hdr.Seq)
		if err := p.receiveBatchMessage(ctx, ms, buf); err != nil {
			log.Debugf("Nftables: Failed to process batch message: %v", err)
			netlink.DumpErrorMessage(hdr, ms, err.GetError())
		}

		// At this point, the message set contains all the errors and acks that
		// occurred during batch message processing.
		return s.SendResponse(ctx, ms)
	}

	return s.ProcessMessages(ctx, buf)
}

// newTable creates a new table for the given family.
func (p *Protocol) newTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	// TODO: b/434242152 - Handle the case where the table name is set to empty string.
	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table name attribute is malformed or not found")
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil && err.GetError() != syserr.ErrNoFileOrDir {
		return err
	}

	// If a table already exists, only update its dormant flags if NLM_F_EXCL
	// and NLM_F_REPLACE are not set. From
	// net/netfilter/nf_tables_api.c:nf_tables_newtable:nf_tables_updtable
	if tab != nil {
		if flags&linux.NLM_F_EXCL != 0 {
			return syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("Nftables: Table with name: %s already exists", tab.GetName()))
		}

		if flags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table with name: %s already exists and NLM_F_REPLACE is not supported", tab.GetName()))
		}

		return p.updateTable(nft, tab, attrs, family, ms)
	}

	// TODO: b/434242152 - Support additional user-specified table flags.
	var attrFlags uint32 = 0
	if uflags, ok := attrs[linux.NFTA_TABLE_FLAGS]; ok {
		attrFlags, _ = uflags.Uint32()
		attrFlags = nlmsg.NetToHostU32(attrFlags)
		// Flags sent through the NFTA_TABLE_FLAGS attribute are of type uint32
		// but should only have user flags set. This check needs to be done
		// before table creation.
		if attrFlags & ^uint32(linux.NFT_TABLE_F_MASK) != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Table flags set are not supported")
		}
	}

	tab, err = nft.CreateTable(family, tabNameBytes.String())
	if err != nil {
		return err
	}

	if udata, ok := attrs[linux.NFTA_TABLE_USERDATA]; ok {
		if err := tab.SetUserData(udata); err != nil {
			return err
		}
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
	if uflagsBytes, ok := attrs[linux.NFTA_TABLE_FLAGS]; ok {
		attrFlags, ok := uflagsBytes.Uint32()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table flags attribute is malformed or not found")
		}

		// User Flags are read in network byte order.
		attrFlags = nlmsg.NetToHostU32(attrFlags)
		// This check needs to be done before table update.
		if attrFlags & ^uint32(linux.NFT_TABLE_F_MASK) > 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Table flags %d are not supported", attrFlags))
		}
	}

	// When updating the table, if the table has an owner but the owner flag
	// isn't set, the table should not be updated. From
	// net/netfilter/nf_tables_api.c:nf_tables_updtable.
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
func (p *Protocol) getTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if (msgFlags & linux.NLM_F_DUMP) != 0 {
		return dumpTables(nft, family, ms)
	}

	// The table name is required.
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table name attribute is malformed or not found")
	}

	// Tables can be retrieved by anybody, so we pass in 0 as the port ID.
	// From net/netfilter/nf_tables_api.c:nf_tables_gettable
	tab, err := nft.GetTable(family, tabNameBytes.String(), 0)
	if err != nil {
		return err
	}

	return fillTableInfo(tab, ms)
}

// dumpTablesForFamily populates the message set with information about all tables
// for a specific address family.
func dumpTablesForFamily(nft *nftables.NFTables, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	for _, tab := range nft.GetAddressFamilyTables(family) {
		if err := fillTableInfo(tab, ms); err != nil {
			return err
		}
	}

	return nil
}

// dumpTables populates the message set with information about all tables for
// a given address family or all address families if the family is unspecified.
func dumpTables(nft *nftables.NFTables, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	// Dumps are multi-part messages.
	ms.Multi = true
	if family != stack.Unspec {
		return dumpTablesForFamily(nft, family, ms)
	}

	for family := range stack.NumAFs {
		if err := dumpTablesForFamily(nft, family, ms); err != nil {
			return err
		}
	}

	return nil
}

// fillTableInfo populates the message set with information about a table.
func fillTableInfo(tab *nftables.Table, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabName := tab.GetName()
	userFlags, err := tab.GetLinuxUserFlagSet()
	if err != nil {
		return err
	}

	// From net/netfilter/nf_tables_api.c:nf_tables_gettable
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWTABLE),
	})

	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(nftables.AfProtocol(tab.GetAddressFamily())),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})
	m.PutAttrString(linux.NFTA_TABLE_NAME, tabName)
	m.PutAttr(linux.NFTA_TABLE_USE, nlmsg.PutU32(uint32(tab.ChainCount())))
	m.PutAttr(linux.NFTA_TABLE_HANDLE, nlmsg.PutU64(tab.GetHandle()))
	m.PutAttr(linux.NFTA_TABLE_FLAGS, nlmsg.PutU32(uint32(userFlags)))

	if tab.HasOwner() {
		m.PutAttr(linux.NFTA_TABLE_OWNER, nlmsg.PutU32(tab.GetOwner()))
	}

	if tab.HasUserData() {
		m.PutAttr(linux.NFTA_TABLE_USERDATA, primitive.AsByteSlice(tab.GetUserData()))
	}

	return nil
}

// deleteTable deletes a table for the given family.
func (p *Protocol) deleteTable(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, hdr linux.NetlinkMessageHeader, msgType linux.NfTableMsgType, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if family == stack.Unspec || (!nftables.HasAttr(linux.NFTA_TABLE_NAME, attrs) && !nftables.HasAttr(linux.NFTA_TABLE_HANDLE, attrs)) {
		nft.Flush(attrs, uint32(ms.PortID))
		return nil
	}

	var tab *nftables.Table
	var err *syserr.AnnotatedError
	if tabHandleBytes, ok := attrs[linux.NFTA_TABLE_HANDLE]; ok {
		tabHandle, ok := tabHandleBytes.Uint64()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table handle attribute is malformed or not found")
		}

		tab, err = nft.GetTableByHandle(family, nlmsg.HostToNetU64(tabHandle), uint32(ms.PortID))
	} else {
		tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table name attribute is malformed or not found")
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

// newChain creates a new chain for the given family.
func (p *Protocol) newChain(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Table name attribute is malformed or not found")
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil {
		return err
	}

	chain, err := getChain(tab, attrs)
	// NFTA_CHAIN_ID must exist if name and handle attributes are not set.
	if chain == nil && err == nil && !nftables.HasAttr(linux.NFTA_CHAIN_ID, attrs) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain handle or name attribute is malformed or not found")
	}

	// If the chain is not found, that means we are creating a completely new chain.
	if err != nil && err.GetError() != syserr.ErrNoFileOrDir {
		return err
	}

	// Default policy is NF_ACCEPT.
	var policy uint8 = linux.NF_ACCEPT
	if policyBytes, ok := attrs[linux.NFTA_CHAIN_POLICY]; ok {
		if chain != nil && !chain.IsBaseChain() {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain policy attribute is not supported for non-base chains")
		}

		if chain == nil && !nftables.HasAttr(linux.NFTA_CHAIN_HOOK, attrs) {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain policy attribute is not supported for new chains without a hook")
		}
		policyData, ok := policyBytes.Uint32()

		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain policy attribute is malformed or not found")
		}

		// The policy attribute is purposely truncated here to be one byte in size.
		// From net/netfilter/nf_tables_api.c:nf_tables_newchain
		policy = uint8(nlmsg.NetToHostU32(policyData))

		if policy != linux.NF_DROP && policy != linux.NF_ACCEPT {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Chain policy attribute %d is an invalid value", policy))
		}
	}

	var chainFlags uint32 = 0
	if chainFlagBytes, ok := attrs[linux.NFTA_CHAIN_FLAGS]; ok {
		flagData, ok := chainFlagBytes.Uint32()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain flags attribute is malformed or not found")
		}
		chainFlags = nlmsg.NetToHostU32(flagData)
	} else if chain != nil {
		chainFlags = uint32(chain.GetFlags())
	}

	if chainFlags & ^linux.NFT_CHAIN_FLAGS != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain flags set are not supported")
	}

	// Update the chain if it exists.
	if chain != nil {
		if flags&linux.NLM_F_EXCL != 0 {
			return syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("Nftables: Chain with handle: %d already exists and NLM_F_EXCL is set", chain.GetHandle()))
		}

		if flags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Chain with handle: %d already exists and NLM_F_REPLACE is not supported", chain.GetHandle()))
		}

		// TODO: b/434243967: Support updating existing chains.
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain flags attribute is not supported for existing chains")
	}

	return p.addChain(attrs, tab, family, policy, chainFlags)
}

// getChain returns a chain if it exists.
func getChain(tab *nftables.Table, attrs map[uint16]nlmsg.BytesView) (*nftables.Chain, *syserr.AnnotatedError) {
	var chain *nftables.Chain
	var err *syserr.AnnotatedError
	if chainHandleBytes, ok := attrs[linux.NFTA_CHAIN_HANDLE]; ok {
		chainHandle, ok := chainHandleBytes.Uint64()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain handle attribute is malformed or not found")
		}

		chain, err = tab.GetChainByHandle(nlmsg.NetToHostU64(chainHandle))
		if err != nil {
			return nil, err
		}
	} else if chainNameBytes, ok := attrs[linux.NFTA_CHAIN_NAME]; ok {
		chainName := chainNameBytes.String()
		chain, err = tab.GetChain(chainName)
		// Only continue if the error is that the chain does not exist.
		if err != nil {
			return nil, err
		}
	}
	return chain, nil
}

var chainCounter atomicbitops.Uint64

// addChain adds a chain to a table.
func (p *Protocol) addChain(attrs map[uint16]nlmsg.BytesView, tab *nftables.Table, family stack.AddressFamily, policy uint8, chainFlags uint32) *syserr.AnnotatedError {
	var bcInfo *nftables.BaseChainInfo
	var err *syserr.AnnotatedError
	if hookDataBytes, ok := attrs[linux.NFTA_CHAIN_HOOK]; ok {
		if chainFlags&linux.NFT_CHAIN_BINDING != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain binding attribute is not supported for chains with a hook")
		}

		bcInfo, err = p.chainParseHook(nil, family, nlmsg.AttrsView(hookDataBytes), attrs)
		if err != nil {
			return err
		}
		// TODO: b/434243967 - support NFTA_CHAIN_COUNTERS (nested attribute)
		if _, ok := attrs[linux.NFTA_CHAIN_COUNTERS]; ok {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain counters attribute is currently not supported")
		}
	} else {
		if chainFlags&linux.NFT_CHAIN_BASE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain base attribute is invalid for chains without a hook")
		}
		if chainFlags&linux.NFT_CHAIN_HW_OFFLOAD != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chain hardware offload attribute is not supported for chains without a hook")
		}
	}

	var name string
	if nameBytes, ok := attrs[linux.NFTA_CHAIN_NAME]; ok {
		name = nameBytes.String()
	} else {
		if chainFlags&linux.NFT_CHAIN_BINDING == 0 {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain name attribute is not found and chain binding is not set")
		}

		name = fmt.Sprintf("__chain%d", chainCounter.Add(1))
	}

	// Add the chain to the table, appending, by priority, to the stack of base
	// chains for the hook.
	chain, err := tab.AddChain(name, bcInfo, "", true)
	if err != nil {
		return err
	}

	chain.SetFlags(uint8(chainFlags))

	if udata, ok := attrs[linux.NFTA_CHAIN_USERDATA]; ok {
		if err := chain.SetUserData(udata); err != nil {
			return err
		}
	}

	if chain.IsBaseChain() {
		chain.GetBaseChainInfo().PolicyDrop = policy == linux.NF_DROP
	}

	return nil
}

// chainParseHook parses the hook attributes and returns a complete
// BaseChainInfo.
func (p *Protocol) chainParseHook(chain *nftables.Chain, family stack.AddressFamily, hdata nlmsg.AttrsView, attrs map[uint16]nlmsg.BytesView) (*nftables.BaseChainInfo, *syserr.AnnotatedError) {
	hookAttrs, ok := nftables.NfParse(hdata)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse hook attributes")
	}

	var hookInfo nftables.HookInfo
	if chain != nil {
		// TODO: b/434243967 - Support updating existing chains.
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Updating hook attributes are not supported for existing chains")
	}

	if !nftables.HasAttr(linux.NFTA_HOOK_HOOKNUM, hookAttrs) || !nftables.HasAttr(linux.NFTA_HOOK_PRIORITY, hookAttrs) {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, "Nftables: Hook attributes HOOK_HOOKNUM and/or HOOK_PRIORITY are not found")
	}

	// These attributes are known to exist after the previous check.
	if hookNumBytes, ok := hookAttrs[linux.NFTA_HOOK_HOOKNUM]; ok {
		hookNum, ok := hookNumBytes.Uint32()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Hook attributes HOOK_HOOKNUM is malformed or not found")
		}
		hookInfo.HookNum = nlmsg.NetToHostU32(hookNum)
	}

	if priorityBytes, ok := hookAttrs[linux.NFTA_HOOK_PRIORITY]; ok {
		priority, ok := priorityBytes.Uint32()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Hook attributes HOOK_PRIORITY is malformed or not found")
		}
		hookInfo.Priority = int32(nlmsg.NetToHostU32(priority))
	}

	// All families default to filter type.
	hookInfo.ChainType = nftables.BaseChainTypeFilter

	if chainTypeBytes, ok := attrs[linux.NFTA_CHAIN_TYPE]; ok {
		// TODO - b/434243967: Support base chain types other than filter.
		switch chainType := chainTypeBytes.String(); chainType {
		case "filter":
			hookInfo.ChainType = nftables.BaseChainTypeFilter
		case "route":
			hookInfo.ChainType = nftables.BaseChainTypeRoute
		case "nat":
			hookInfo.ChainType = nftables.BaseChainTypeNat
		default:
			return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("Nftables: Unknown chain type not found: %s", chainType))
		}
	}

	// Check whether the chain type is supported for the given hook number and
	// family.
	if !nftables.ValidLinuxHook(family, hookInfo.ChainType, hookInfo.HookNum) {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hook attributes HOOK_HOOKNUM is invalid for the given family and chain type")
	}

	if hookInfo.ChainType == nftables.BaseChainTypeNat && hookInfo.Priority <= linux.NF_IP_PRI_CONNTRACK {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hook attributes HOOK_PRIORITY is invalid for chain type NAT")
	}

	var netDevName string
	if isNetDevHook(family, hookInfo.HookNum) {
		// TODO: b/434243967 - Support chains for the netdev family.
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Netdev hooks are not currently supported")
	}

	if nftables.HasAttr(linux.NFTA_HOOK_DEV, hookAttrs) || nftables.HasAttr(linux.NFTA_HOOK_DEVS, hookAttrs) {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hook attributes DEV and DEVS are not supported for non-netdev hooks")
	}

	stackHook, err := nftables.StackHook(family, hookInfo.HookNum)
	if err != nil {
		return nil, err
	}

	baseChainInfo := &nftables.BaseChainInfo{
		Hook:         stackHook,
		LinuxHookNum: hookInfo.HookNum,
		BcType:       hookInfo.ChainType,
		Priority:     nftables.NewIntPriority(int(hookInfo.Priority)),
		Device:       netDevName,
	}

	return baseChainInfo, nil
}

// getChain fills the message set with information about a chain.
func (p *Protocol) getChain(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if (msgFlags & linux.NLM_F_DUMP) != 0 {
		return dumpChains(nft, family, ms)
	}

	tabNameBytes, ok := attrs[linux.NFTA_CHAIN_TABLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_CHAIN_TABLE attribute is malformed or not found")
	}

	tabName := tabNameBytes.String()

	// Tables can be retrieved by anybody, so we pass in 0 for the port id.
	// From net/netfilter/nf_tables_api.c:nf_tables_getchain
	tab, err := nft.GetTable(family, tabName, 0)
	if err != nil {
		return err
	}

	chainNameBytes, ok := attrs[linux.NFTA_CHAIN_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_CHAIN_NAME attribute is malformed or not found")
	}

	chainName := chainNameBytes.String()
	chain, err := tab.GetChain(chainName)
	if err != nil {
		return err
	}

	return fillChainInfo(chain, ms)
}

// getBaseChainHookInfo creates a NFTA_CHAIN_HOOK attribute with all the
// corresponding nested attributes.
func getBaseChainHookInfo(chain *nftables.Chain, m *nlmsg.Message) *syserr.AnnotatedError {
	baseChainInfo := chain.GetBaseChainInfo()
	var nestedAttrs nlmsg.NestedAttr

	nestedAttrs.PutAttr(linux.NFTA_HOOK_HOOKNUM, nlmsg.PutU32(baseChainInfo.LinuxHookNum))
	nestedAttrs.PutAttr(linux.NFTA_HOOK_PRIORITY, nlmsg.PutU32(uint32(baseChainInfo.Priority.GetValue())))

	if isNetDevHook(chain.GetAddressFamily(), baseChainInfo.LinuxHookNum) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Netdev basechains or basechains attached to Ingress or Egress are not currently supported for getting")
	}

	m.PutNestedAttr(linux.NFTA_CHAIN_HOOK, nestedAttrs)
	return nil
}

// dumpChainsForFamily populates the message set with information about all
// chains for a specific address family.
func dumpChainsForFamily(nft *nftables.NFTables, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	for _, tab := range nft.GetAddressFamilyTables(family) {
		for _, chain := range tab.GetChains() {
			if err := fillChainInfo(chain, ms); err != nil {
				return err
			}
		}
	}
	return nil
}

// dumpChains populates the message set with information about all chains for
// a given address family or all address families if the family is unspecified.
func dumpChains(nft *nftables.NFTables, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	ms.Multi = true
	if family != stack.Unspec {
		return dumpChainsForFamily(nft, family, ms)
	}

	for family := range stack.NumAFs {
		if err := dumpChainsForFamily(nft, family, ms); err != nil {
			return err
		}
	}

	return nil
}

// fillChainInfo populates the message set with information about a chain.
func fillChainInfo(chain *nftables.Chain, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWCHAIN),
	})

	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(nftables.AfProtocol(chain.GetAddressFamily())),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})
	m.PutAttrString(linux.NFTA_CHAIN_TABLE, chain.GetTable().GetName())
	m.PutAttrString(linux.NFTA_CHAIN_NAME, chain.GetName())
	m.PutAttr(linux.NFTA_CHAIN_HANDLE, nlmsg.PutU64(chain.GetHandle()))

	if chain.IsBaseChain() {
		err := getBaseChainHookInfo(chain, m)
		if err != nil {
			return err
		}

		baseChainInfo := chain.GetBaseChainInfo()
		m.PutAttr(linux.NFTA_CHAIN_POLICY, nlmsg.PutU32(uint32(baseChainInfo.PolicyBoolToValue())))
		m.PutAttrString(linux.NFTA_CHAIN_TYPE, baseChainInfo.BcType.String())
	}

	chainFlags := chain.GetFlags()
	if chainFlags != 0 {
		m.PutAttr(linux.NFTA_CHAIN_FLAGS, nlmsg.PutU32(uint32(chainFlags)))
	}

	m.PutAttr(linux.NFTA_CHAIN_USE, nlmsg.PutU32(uint32(chain.GetChainUse())))
	if chain.HasUserData() {
		m.PutAttr(linux.NFTA_CHAIN_USERDATA, primitive.AsByteSlice(chain.GetUserData()))
	}

	return nil
}

// deleteChain deletes a chain from a table.
func (p *Protocol) deleteChain(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, msgType linux.NfTableMsgType, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabNameBytes, ok := attrs[linux.NFTA_TABLE_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_TABLE_NAME attribute is malformed or not found")
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil {
		return err
	}

	chain, err := getChain(tab, attrs)
	if err != nil {
		if err.GetError() == syserr.ErrNoFileOrDir && msgType == linux.NFT_MSG_DESTROYCHAIN {
			return nil
		}
		return err
	}

	chainFlags := chain.GetFlags()
	if chainFlags&linux.NFT_CHAIN_BINDING != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Chains with binding cannot be deleted")
	}

	if nftables.HasAttr(linux.NFTA_CHAIN_HOOK, attrs) {
		if msgType == linux.NFT_MSG_DESTROYCHAIN && chainFlags&linux.NFT_CHAIN_HW_OFFLOAD != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hardware offload chains cannot be deleted")
		}

		if chain.IsBaseChain() {
			// TODO: b/434243967 - Support deleting netdev basechains.
			if isNetDevHook(family, chain.GetBaseChainInfo().LinuxHookNum) {
				return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Netdev basechains or basechains attached to Ingress or Egress are not currently supported for deleting")
			}
		}
	}

	if msgFlags&linux.NLM_F_NONREC != 0 && chain.GetChainUse() != 0 {
		return syserr.NewAnnotatedError(syserr.ErrBusy, fmt.Sprintf("Nftables: Non-recursive delete on a chain with use > 0 is not supported. Chain %s has chain use %d", chain.GetName(), chain.GetChainUse()))
	}

	// TODO: b/434243967 - Support iteratively deleting rules in a chain to then
	// delete chains. After deleting all the possible rules, if the chain is
	// still in use, it cannot be deleted.
	if chain.GetChainUse() != 0 {
		return syserr.NewAnnotatedError(syserr.ErrBusy, fmt.Sprintf("Nftables: Deleting a chain with chain use > 0 is not supported. Chain %s has chain use %d", chain.GetName(), chain.GetChainUse()))
	}

	// We don't worry about whether a delete operation succeeded or not, rather
	// only that the chain is gone.
	deleted := tab.DeleteChain(chain.GetName())
	if !deleted {
		log.Debugf("Failed to delete chain %s", chain.GetName())
	}
	return nil
}

// NFT_RULE_MAXEXPRS is the maximum number of expressions that can be specified
// for a rule. From include/uapi/linux/netfilter/nf_tables_api.c.
const NFT_RULE_MAXEXPRS = 128

// newRule creates a new rule in the given chain.
func (p *Protocol) newRule(nft *nftables.NFTables, st *stack.Stack, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabNameBytes, ok := attrs[linux.NFTA_RULE_TABLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_CHAIN_TABLE attribute is malformed or not found")
	}

	tab, err := nft.GetTable(family, tabNameBytes.String(), uint32(ms.PortID))
	if err != nil {
		return err
	}

	var chain *nftables.Chain
	if chainNameBytes, ok := attrs[linux.NFTA_RULE_CHAIN]; ok {
		chain, err = tab.GetChain(chainNameBytes.String())
		if err != nil {
			return err
		}
	} else if _, ok := attrs[linux.NFTA_RULE_CHAIN_ID]; ok {
		// TODO - b/434244017: Support looking up chains via their transaction id.
		// This has to do with Linux's transaction system for committing tables
		// atomically. This allows users to modify chains that have not yet been
		// committed, but given that we do not have a transaction system (tables
		// are committed atomically as soon as a mutex is acquired), this may not
		// be necessary. It is a relatively new flag.
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Looking up chains via their id is not supported")
	} else {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_RULE_CHAIN or NFTA_RULE_CHAIN_ID attribute is malformed or not found")
	}

	if chain.IsBound() {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: New rules cannot be added to bound chains")
	}

	var oldRule *nftables.Rule
	// NFTA_RULE_HANDLE is used in the replace case. NFTA_RULE_POSITION is used to
	// to insert before or after an existing rule.
	if handleBytes, ok := attrs[linux.NFTA_RULE_HANDLE]; ok {
		ruleHandle, ok := handleBytes.Uint64()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Rule handle attribute is malformed or not found")
		}

		rule, err := chain.GetRuleByHandle(nlmsg.NetToHostU64(ruleHandle))
		if err != nil {
			return err
		}

		if msgFlags&linux.NLM_F_EXCL != 0 {
			return syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("Nftables: Rule handle %d already exists and NLM_F_EXCL is set", ruleHandle))
		}

		if msgFlags&linux.NLM_F_REPLACE == 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Rule handle %d exists but NLM_F_REPLACE is not set", ruleHandle))
		}

		oldRule = rule
	} else {
		// Create or replace a rule.
		if msgFlags&linux.NLM_F_CREATE == 0 ||
			msgFlags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Rule handle is not specified and NLM_F_CREATE is not set or NLM_F_REPLACE is set")
		}

		if posHandleBytes, ok := attrs[linux.NFTA_RULE_POSITION]; ok {
			posHandle, ok := posHandleBytes.Uint64()
			if !ok {
				return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Rule position attribute is malformed or not found")
			}

			oldRule, err = chain.GetRuleByHandle(nlmsg.NetToHostU64(posHandle))
			if err != nil {
				return err
			}
		} else if _, ok := attrs[linux.NFTA_RULE_POSITION_ID]; ok {
			// TODO - b/434244017: Support looking up rules via their position id.
			// ID is used for Linux's transaction system like stated above.
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Rule position id is not supported.")
		}
	}

	var exprInfos []nftables.ExprInfo
	if exprBytes, ok := attrs[linux.NFTA_RULE_EXPRESSIONS]; ok {
		exprInfos, err = parseNestedExprs(nlmsg.AttrsView(exprBytes))
		if err != nil {
			return err
		}
	}

	rule := &nftables.Rule{}
	// TODO: b/434244017 - Support error-checking the size of the expressions.
	if udataBytes, ok := attrs[linux.NFTA_RULE_USERDATA]; ok {
		if err := rule.SetUserData(udataBytes); err != nil {
			return err
		}
	}

	for _, exprInfo := range exprInfos {
		err = rule.AddOpFromExprInfo(tab, exprInfo)
		// TODO - b/434244017: Create a copy of nftables structure when modifying the table.
		// Because we will create a copy of the table, no cleanup is necessary on the error case.
		// The table will simply be reverted to the original state.
		if err != nil {
			return err
		}
	}

	if chain.GetFlags()&linux.NFT_CHAIN_HW_OFFLOAD != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hardware offload chains are not supported.")
	}

	if !chain.IncrementChainUse() {
		return syserr.NewAnnotatedError(syserr.ErrTooManyOpenFiles, fmt.Sprintf("Nftables: Chain %s has the maximum chain use value at %d", chain.GetName(), chain.GetChainUse()))
	}

	// TODO - b/434244017: Support replace operations on rules.
	if msgFlags&linux.NLM_F_REPLACE != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Replace operations are not currently supported.")
	}

	if msgFlags&linux.NLM_F_APPEND != 0 {
		if oldRule != nil {
			err = chain.RegisterAfterExistingRule(rule, oldRule)
		} else {
			err = chain.RegisterRule(rule, -1)
		}
	} else {
		if oldRule != nil {
			err = chain.RegisterBeforeExistingRule(rule, oldRule)
		} else {
			err = chain.RegisterRule(rule, 0)
		}
	}

	// Rule registration should not fail, as all validation checks have already
	// been performed.
	if err != nil {
		log.Warningf("Failed to register rule, this should not happen: %v", err)
		return err
	}

	// Once we have a at least one rule registered on a base chain, nftables can
	// be called to potentially filter the packet.
	st.SetNFTablesConfigured(chain.IsBaseChain())

	// TODO - b/434244017: Support validating the entire table before returning.
	return nil
}

// parseNestedExprs parses the rule expressions attributes and adds the
// operations to the rule.
func parseNestedExprs(nestedAttrBytes nlmsg.AttrsView) ([]nftables.ExprInfo, *syserr.AnnotatedError) {
	// NFTA_EXPRESSIONS -> many NFTA_LIST_ELEM that each hold -> NFTA_EXPR_NAME
	// and NFTA_EXPR_DATA.
	var exprInfos []nftables.ExprInfo
	numExprs := 0
	for !nestedAttrBytes.Empty() {
		hdr, value, rest, ok := nestedAttrBytes.ParseFirst()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse list atttribute for rules")
		}

		nestedAttrBytes = rest
		if nlaType(hdr) != linux.NFTA_LIST_ELEM {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: parsed attribute is not of type NFTA_LIST_ELEM")
		}

		if numExprs == NFT_RULE_MAXEXPRS {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Too many expressions specified for rule")
		}
		numExprs++

		exprAttrs, ok := nftables.NfParse(nlmsg.AttrsView(value))
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse attributes for expression")
		}

		exprNameBytes, ok := exprAttrs[linux.NFTA_EXPR_NAME]
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_EXPR_NAME attribute is malformed or not found")
		}

		// exprData holds the expression data for a specific operation.
		exprData := nlmsg.AttrsView{}
		// Only assign exprData if the data is present. Later validation will
		// check if it is needed for the specific operation type.
		// From linux/net/netfilter/nf_tables_api.c: nf_tables_expr_parse
		if exprDataBytes, ok := exprAttrs[linux.NFTA_EXPR_DATA]; ok {
			exprData = nlmsg.AttrsView(exprDataBytes)
		}

		exprInfos = append(exprInfos, nftables.ExprInfo{
			ExprName: exprNameBytes.String(),
			ExprData: exprData,
		})
	}

	return exprInfos, nil
}

// nlaType returns the type of the netlink attribute.
func nlaType(hdr linux.NetlinkAttrHeader) uint16 {
	return hdr.Type & linux.NLA_TYPE_MASK
}

// getRule returns the rule for the given family and message flags.
func (p *Protocol) getRule(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if (msgFlags & linux.NLM_F_DUMP) != 0 {
		return dumpRules(nft, attrs, family, ms)
	}

	tabName, ok := attrs[linux.NFTA_RULE_TABLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_TABLE attribute is malformed or not found")
	}

	// Any process can get any table.
	tab, err := nft.GetTable(family, tabName.String(), 0)
	if err != nil {
		return err
	}

	chainName, ok := attrs[linux.NFTA_RULE_CHAIN]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_CHAIN_NAME attribute is malformed or not found")
	}

	chain, err := tab.GetChain(chainName.String())
	if err != nil {
		return err
	}

	ruleHandleBytes, ok := attrs[linux.NFTA_RULE_HANDLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_RULE_HANDLE attribute is malformed or not found")
	}

	ruleHandle, ok := ruleHandleBytes.Uint64()
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Rule handle attribute is malformed or not found")
	}

	ruleHandle = nlmsg.NetToHostU64(ruleHandle)
	rule, err := chain.GetRuleByHandle(ruleHandle)
	if err != nil {
		return err
	}

	return fillRuleInfo(rule, ms)
}

// dumpRulesForFamily dumps all rules for a given family.
func dumpRulesForFamily(nft *nftables.NFTables, family stack.AddressFamily, tabName *string, chainName *string, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	// Linux allows rules to be retrieved for specific tables and chains via
	// attributes, unlike dump operations for tables and chains.
	// From linux/net/netfilter/nf_tables_api.c: nf_tables_dump_rules
	for _, tab := range nft.GetAddressFamilyTables(family) {
		if tabName != nil && tab.GetName() != *tabName {
			continue
		}

		for _, chain := range tab.GetChains() {
			if chainName != nil && chain.GetName() != *chainName {
				continue
			}

			for _, rule := range chain.GetRules() {
				if err := fillRuleInfo(rule, ms); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// dumpRules dumps all rules for a given family or all families if the family
// is unspecified.
func dumpRules(nft *nftables.NFTables, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	ms.Multi = true
	var tabName *string
	var chainName *string

	if tabNameBytes, ok := attrs[linux.NFTA_RULE_TABLE]; ok {
		attrName := tabNameBytes.String()
		tabName = &attrName
	}

	if chainNameBytes, ok := attrs[linux.NFTA_RULE_CHAIN]; ok {
		attrName := chainNameBytes.String()
		chainName = &attrName
	}
	if family != stack.Unspec {
		return dumpRulesForFamily(nft, family, tabName, chainName, ms)
	}

	for family := range stack.NumAFs {
		if err := dumpRulesForFamily(nft, family, tabName, chainName, ms); err != nil {
			return err
		}
	}
	return nil
}

// fillRuleInfo adds the rule information to the message set.
func fillRuleInfo(rule *nftables.Rule, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	chain := rule.GetChain()
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWCHAIN),
	})

	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(nftables.AfProtocol(rule.GetAddressFamily())),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})
	m.PutAttrString(linux.NFTA_RULE_TABLE, chain.GetTable().GetName())
	m.PutAttrString(linux.NFTA_RULE_CHAIN, chain.GetName())
	m.PutAttr(linux.NFTA_RULE_HANDLE, nlmsg.PutU64(rule.GetHandle()))

	if (chain.GetFlags() & linux.NFT_CHAIN_HW_OFFLOAD) != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Hardware offload chains are not supported")
	}

	// The NLA_F_NESTED flag is explicitly not set here, for backwards
	// compatibility with older kernels.
	// From linux/net/netfilter/nf_tables_api.c: nf_tables_fill_rule_info
	var nestedList nlmsg.NestedAttr
	for _, op := range rule.GetOperations() {
		var exprs nlmsg.NestedAttr
		exprs.PutAttrString(linux.NFTA_EXPR_NAME, op.GetExprName())
		exprDump, err := op.Dump()
		if err != nil {
			return err
		}
		if len(exprDump) > 0 {
			exprs.PutAttr(linux.NFTA_EXPR_DATA, primitive.AsByteSlice(exprDump))
		}
		nestedList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(exprs))
	}
	m.PutNestedAttr(linux.NFTA_RULE_EXPRESSIONS, nestedList)

	if rule.HasUserData() {
		m.PutAttr(linux.NFTA_RULE_USERDATA, primitive.AsByteSlice(rule.GetUserData()))
	}
	return nil
}

// getGen returns the generation info for the current nftables instance.
func (p *Protocol) getGen(nft *nftables.NFTables, task *kernel.Task, attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWGEN),
	})
	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(nftables.AfProtocol(stack.Unspec)),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})

	m.PutAttr(linux.NFTA_GEN_ID, nlmsg.PutU32(nft.GetGenID()))
	m.PutAttr(linux.NFTA_GEN_PROC_PID, nlmsg.PutU32(uint32(task.ThreadGroup().ID())))
	// TODO - b/434244017: Add support for dumping the process name.
	m.PutAttrString(linux.NFTA_GEN_PROC_NAME, "placeholder")
	return nil
}

// isNetDevHook returns whether the given family and hook number represent a
// netdev hook, or if the family is inet and is attempting to attach to
// Ingress or Egress hooks.
func isNetDevHook(family stack.AddressFamily, hookNum uint32) bool {
	return family == stack.Netdev ||
		(family == stack.Inet && hookNum == linux.NF_INET_INGRESS)
}

// netlinkMsgPayloadSize returns the size of the netlink message payload.
func netlinkMsgPayloadSize(h *linux.NetlinkMessageHeader) int {
	return int(h.Length) - linux.NetlinkMessageHeaderSize
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
// TODO: 434785410 - Support batch messages.
func (p *Protocol) ProcessMessage(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()

	// Netlink message payloads must be of at least the size of the genmsg.
	// Return early if it is not, from linux/net/netfilter/nfnetlink.c.
	if netlinkMsgPayloadSize(&hdr) < linux.SizeOfNetfilterGenMsg {
		log.Debugf("Netlink message payload is too small: %d < %d", netlinkMsgPayloadSize(&hdr), linux.SizeOfNetfilterGenMsg)
		return nil
	}

	msgType := hdr.NetFilterMsgType()
	st := inet.StackFromContext(ctx).(*netstack.Stack).Stack
	nft := (st.NFTables()).(*nftables.NFTables)
	var nfGenMsg linux.NetFilterGenMsg

	// The payload of a netfilter generic message is its attributes.
	atr, ok := msg.GetData(&nfGenMsg)
	if !ok {
		log.Debugf("Failed to get message data")
		return syserr.ErrInvalidArgument
	}

	attrs, ok := nftables.NfParse(atr)
	if !ok {
		log.Debugf("Failed to parse message attributes")
		return syserr.ErrInvalidArgument
	}

	// Nftables functions error check the address family value.
	family, _ := nftables.AFtoNetlinkAF(nfGenMsg.Family)

	nft.Mu.RLock()
	defer nft.Mu.RUnlock()
	switch msgType {
	case linux.NFT_MSG_GETTABLE:
		if err := p.getTable(nft, attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables get table error: %s", err)
			return err.GetError()
		}
		return nil
	case linux.NFT_MSG_GETCHAIN:
		if err := p.getChain(nft, attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables get chain error: %s", err)
			return err.GetError()
		}
		return nil
	case linux.NFT_MSG_GETRULE:
		if err := p.getRule(nft, attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables get rule error: %s", err)
			return err.GetError()
		}

		return nil
	case linux.NFT_MSG_GETGEN:
		if err := p.getGen(nft, kernel.TaskFromContext(ctx), attrs, family, hdr.Flags, ms); err != nil {
			log.Debugf("Nftables get gen error: %s", err)
			return err.GetError()
		}
		return nil
	case linux.NFT_MSG_GETSET:
		// TODO - b/421437663: Implement sets for nftables. This skeleton is
		// left here to satisfy auxiliary calls from the nft CLI not needed
		// for packet filtering functionality.
		ms.Multi = true
		return nil
	case linux.NFT_MSG_GETRULE_RESET, linux.NFT_MSG_GETSETELEM,
		linux.NFT_MSG_GETSETELEM_RESET,
		linux.NFT_MSG_GETOBJ, linux.NFT_MSG_GETOBJ_RESET,
		linux.NFT_MSG_GETFLOWTABLE:

		log.Debugf("Nftables: Unsupported message type: %d", msgType)
		return syserr.ErrNotSupported
	default:
		log.Debugf("Nftables: Received an invalid single message type: %d", msgType)
		return syserr.ErrInvalidArgument
	}
}

// receiveBatchMessage processes a NETFILTER batch message.
func (p *Protocol) receiveBatchMessage(ctx context.Context, ms *nlmsg.MessageSet, buf []byte) *syserr.AnnotatedError {
	// Linux ignores messages that are too small.
	// From net/netfilter/nfnetlink.c:nfnetlink_rcv_skb_batch
	if len(buf) < linux.NetlinkMessageHeaderSize+linux.SizeOfNetfilterGenMsg {
		return nil
	}

	// The first message in the batch is the batch begin message.
	msg, rest, ok := nlmsg.ParseMessage(buf)
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse first batch message")
	}
	buf = rest

	hdr := msg.Header()
	var nfGenMsg linux.NetFilterGenMsg
	atr, ok := msg.GetData(&nfGenMsg)
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to get message data")
	}

	attrs, ok := nftables.NfParse(atr)
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse message attributes for batch message")
	}

	// We don't use the genID, but Linux does. If it appears, we simply check
	// that it is well formed.
	if genIDBytes, ok := attrs[linux.NFNL_BATCH_GENID]; ok {
		_, ok := genIDBytes.Uint32()
		// This should not happen.
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse batch message genid attribute")
		}
	}

	// The resource ID is a 16-bit value that is stored in network byte order.
	// We ensure that it is in host byte order before passing it for processing.
	resID := nlmsg.NetToHostU16(nfGenMsg.ResourceID)
	if err := p.processBatchMessage(ctx, buf, ms, hdr, resID); err != nil {
		log.Debugf("Failed to process batch message: %v", err)
		netlink.DumpErrorMessage(hdr, ms, err.GetError())
	}

	return nil
}

// processBatchMessage processes a batch message.
func (p *Protocol) processBatchMessage(ctx context.Context, buf []byte, ms *nlmsg.MessageSet, batchHdr linux.NetlinkMessageHeader, subsysID uint16) *syserr.AnnotatedError {
	if subsysID >= linux.NFNL_SUBSYS_COUNT {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Unknown subsystem id %d", subsysID))
	}

	// Only the NFTABLES subsystem is currently supported.
	if subsysID != linux.NFNL_SUBSYS_NFTABLES {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Nftables: Unsupported subsystem id %d", subsysID))
	}

	if batchHdr.Flags&linux.NLM_F_ACK != 0 {
		netlink.DumpAckMessage(batchHdr, ms)
	}

	st := inet.StackFromContext(ctx).(*netstack.Stack).Stack
	nft := (st.NFTables()).(*nftables.NFTables)

	// **********************************************************************
	// TODO: b/436922484 - Add a transaction system to avoid deep copying the
	// entire NFTables structure.
	// **********************************************************************
	nft.Mu.Lock()
	defer nft.Mu.Unlock()

	// No need to hold our own lock
	nftCopy := nft.DeepCopy()
	for len(buf) >= bits.AlignUp(linux.NetlinkMessageHeaderSize, linux.NLMSG_ALIGNTO) {
		msg, rest, ok := nlmsg.ParseMessage(buf)
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse the next message in the batch")
		}

		hdr := msg.Header()

		// Messages that are too small clear the error message set and return.
		// From net/netfilter/nfnetlink.c:nfnetlink_rcv_batch
		if hdr.Length < linux.NetlinkMessageHeaderSize || uint32(len(buf)) < hdr.Length || netlinkMsgPayloadSize(&hdr) < linux.SizeOfNetfilterGenMsg {
			ms.Clear()
			return nil
		}

		// Must update after the check above.
		buf = rest

		// On error, we simply add to the list of errors in the message set to
		// be returned at the end.
		if hdr.Flags&linux.NLM_F_REQUEST == 0 {
			netlink.DumpErrorMessage(hdr, ms, syserr.ErrInvalidArgument)
			continue
		}

		if hdr.Type == linux.NFNL_MSG_BATCH_BEGIN {
			ms.Clear()
			return nil
		}

		// A batch should be terminated with a batch end message.
		if hdr.Type == linux.NFNL_MSG_BATCH_END {
			// Replace the table if no errors were added into the message set.
			if !ms.ContainsError {
				// Batch end messages are only ACK'd if the batch was successful.
				if hdr.Flags&linux.NLM_F_ACK != 0 {
					netlink.DumpAckMessage(hdr, ms)
				}
				nft.ReplaceNFTables(nftCopy)
			}

			return nil
		}

		if hdr.Type < linux.NLMSG_MIN_TYPE {
			netlink.DumpErrorMessage(hdr, ms, syserr.ErrInvalidArgument)
			continue
		}

		if hdr.NetFilterSubsysID() != subsysID {
			netlink.DumpErrorMessage(hdr, ms, syserr.ErrInvalidArgument)
			continue
		}

		var nfGenMsg linux.NetFilterGenMsg

		// The payload of a netfilter generic message is its attributes.
		atr, ok := msg.GetData(&nfGenMsg)
		if !ok {
			netlink.DumpErrorMessage(hdr, ms, syserr.ErrInvalidArgument)
			continue
		}

		attrs, ok := nftables.NfParse(atr)
		if !ok {
			netlink.DumpErrorMessage(hdr, ms, syserr.ErrInvalidArgument)
			continue
		}

		// Nftables functions error check the address family value.
		family, err := nftables.AFtoNetlinkAF(nfGenMsg.Family)

		// TODO: b/421437663 - Support other subsystems besides NFTABLES.
		// Since NFTABLES is the only supported subsystem, interpret
		// the message type as a NFTABLES message.
		// Batch message methods from net/netfilter/nf_tables_api.c:nf_tables_cb.
		var subErr *syserr.AnnotatedError
		switch hdr.NetFilterMsgType() {
		case linux.NFT_MSG_NEWTABLE:
			// We only check the error value in the case of NFT_MSG_NEWTABLE as linux
			// returns an EOPNOTSUPP error only in that case. Otherwise the other
			// operations will return errors specific to their function.
			if err != nil {
				log.Debugf("Nftables: Unsupported address family: %d", int(nfGenMsg.Family))
				netlink.DumpErrorMessage(hdr, ms, err)
				continue
			}

			subErr = p.newTable(nftCopy, attrs, family, hdr.Flags, ms)
		case linux.NFT_MSG_DELTABLE, linux.NFT_MSG_DESTROYTABLE:
			subErr = p.deleteTable(nftCopy, attrs, family, hdr, hdr.NetFilterMsgType(), ms)
		case linux.NFT_MSG_NEWCHAIN:
			subErr = p.newChain(nftCopy, attrs, family, hdr.Flags, ms)
		case linux.NFT_MSG_DELCHAIN, linux.NFT_MSG_DESTROYCHAIN:
			subErr = p.deleteChain(nftCopy, attrs, family, hdr.Flags, hdr.NetFilterMsgType(), ms)
		case linux.NFT_MSG_NEWRULE:
			subErr = p.newRule(nftCopy, st, attrs, family, hdr.Flags, ms)
		case linux.NFT_MSG_DELRULE, linux.NFT_MSG_DESTROYRULE, linux.NFT_MSG_NEWSET,
			linux.NFT_MSG_DELSET, linux.NFT_MSG_DESTROYSET, linux.NFT_MSG_NEWSETELEM,
			linux.NFT_MSG_DELSETELEM, linux.NFT_MSG_DESTROYSETELEM,
			linux.NFT_MSG_NEWOBJ, linux.NFT_MSG_DELOBJ, linux.NFT_MSG_DESTROYOBJ,
			linux.NFT_MSG_NEWFLOWTABLE, linux.NFT_MSG_DELFLOWTABLE,
			linux.NFT_MSG_DESTROYFLOWTABLE:

			subErr = syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Received a currently unsupported batch message of type %d", hdr.NetFilterMsgType()))
		default:
			subErr = syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Received a non-batch message type %d", hdr.NetFilterMsgType()))
		}

		if subErr != nil {
			log.Debugf("%s error: %s", hdr.NetFilterMsgType(), subErr)
			netlink.DumpErrorMessage(hdr, ms, subErr.GetError())
		} else if hdr.Flags&linux.NLM_F_ACK > 0 {
			netlink.DumpAckMessage(hdr, ms)
		}
	}

	return nil
}

// init registers the NETLINK_NETFILTER provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_NETFILTER, NewProtocol)
}
