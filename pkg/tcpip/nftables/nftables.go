// Copyright 2024 The gVisor Authors.
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

package nftables

import (
	"fmt"
	"math"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

//
// Interface-Related Methods
//

// CheckPrerouting checks at the Prerouting hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckPrerouting(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFPrerouting)
}

// CheckInput checks at the Input hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckInput(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFInput)
}

// CheckForward checks at the Forward hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckForward(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFForward)
}

// CheckOutput checks at the Output hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckOutput(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFOutput)
}

// CheckPostrouting checks at the Postrouting hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckPostrouting(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFPostrouting)
}

// CheckIngress checks at the Ingress hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckIngress(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFIngress)
}

// CheckEgress checks at the Egress hook if the packet should continue traversing the stack.
func (nf *NFTables) CheckEgress(pkt *stack.PacketBuffer, af stack.AddressFamily) bool {
	return nf.checkHook(pkt, af, stack.NFEgress)
}

// checkHook returns true if the packet should continue traversing the stack or false
// if the packet should be dropped.
// If NFTables is not enabled, the packet is always allowed to continue traversing the stack.
func (nf *NFTables) checkHook(pkt *stack.PacketBuffer, af stack.AddressFamily, hook stack.NFHook) bool {
	if !IsNFTablesEnabled() {
		return true
	}
	v, err := nf.EvaluateHook(af, hook, pkt)

	if err != nil {
		return false
	}

	return v.Code == VC(linux.NF_ACCEPT)
}

//
// Core Evaluation Functions
//

// EvaluateHook evaluates a packet using the rules of the given hook for the
// given address family, returning a netfilter verdict and modifying the packet
// in place.
// Returns an error if address family or hook is invalid or they don't match.
// TODO(b/345684870): Consider removing error case if we never return an error.
func (nf *NFTables) EvaluateHook(family stack.AddressFamily, hook stack.NFHook, pkt *stack.PacketBuffer) (stack.NFVerdict, *syserr.AnnotatedError) {
	// Note: none of the other evaluate functions are public because they require
	// jumping to different chains in the same table, so all chains, rules, and
	// operations must be tied to a table. Thus, calling evaluate for standalone
	// chains, rules, or operations can be misleading and dangerous.

	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return stack.NFVerdict{}, err
	}

	// Ensures hook is valid.
	if err := validateHook(hook, family); err != nil {
		return stack.NFVerdict{}, err
	}

	// Immediately accept if there are no base chains for the specified hook.
	if nf.filters[family] == nil || nf.filters[family].hfStacks[hook] == nil ||
		len(nf.filters[family].hfStacks[hook].baseChains) == 0 {
		return stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, nil
	}

	regs := newRegisterSet()

	// Evaluates packet through all base chains for given hook in priority order.
	var bc *Chain
	for _, bc = range nf.filters[family].hfStacks[hook].baseChains {
		// Doesn't evaluate chain if it's table is flagged as dormant.
		if _, dormant := bc.table.flagSet[TableFlagDormant]; dormant {
			continue
		}

		err := bc.evaluate(&regs, pkt)
		if err != nil {
			return stack.NFVerdict{}, err
		}

		// Terminates immediately on netfilter terminal verdicts.
		switch regs.Verdict().Code {
		case VC(linux.NF_ACCEPT), VC(linux.NF_DROP), VC(linux.NF_STOLEN), VC(linux.NF_QUEUE):
			return regs.Verdict(), nil
		}
	}

	// Returns policy verdict of the last base chain evaluated if no terminal
	// verdict was issued.
	switch regs.Verdict().Code {
	case VC(linux.NFT_CONTINUE), VC(linux.NFT_RETURN):
		if bc.GetBaseChainInfo().PolicyDrop {
			return stack.NFVerdict{Code: VC(linux.NF_DROP)}, nil
		}
		return stack.NFVerdict{Code: VC(linux.NF_ACCEPT)}, nil
	}

	panic(fmt.Sprintf("unexpected verdict from hook evaluation: %s", VerdictCodeToString(regs.Verdict().Code)))
}

// evaluateFromRule is a helper function for Chain.evaluate that evaluates the
// packet through the rules in the chain starting at the specified rule index.
func (c *Chain) evaluateFromRule(rIdx int, jumpDepth int, regs *registerSet, pkt *stack.PacketBuffer) *syserr.AnnotatedError {
	if jumpDepth >= nestedJumpLimit {
		return syserr.NewAnnotatedError(syserr.ErrTooManyLinks, fmt.Sprintf("exceeded nested jump limit of %d", nestedJumpLimit))
	}

	// Resets verdict to continue for the next rule.
	regs.verdict.Code = VC(linux.NFT_CONTINUE)

	// Evaluates all rules in the chain (breaking on terminal verdicts).
evalLoop:
	for ; rIdx < len(c.rules); rIdx++ {
		rule := c.rules[rIdx]
		if err := rule.evaluate(regs, pkt); err != nil {
			return err
		}

		// Continues evaluation at target chains for jump and goto verdicts.
		jumped := false
		switch regs.Verdict().Code {
		case VC(linux.NFT_JUMP):
			jumpDepth++
			jumped = true
			fallthrough
		case VC(linux.NFT_GOTO):
			// Finds the chain named in the same table as the calling chain.
			nextChain, exists := c.table.chains[regs.verdict.ChainName]
			if !exists {
				return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("chain %s not found in table %s", regs.verdict.ChainName, c.table.name))
			}
			if err := nextChain.evaluateFromRule(0, jumpDepth, regs, pkt); err != nil {
				return err
			}
			// Ends evaluation for goto (and continues evaluation for jump).
			if !jumped {
				break evalLoop
			}
			jumpDepth--
		}

		// Only continues evaluation for Continue and Break verdicts.
		switch regs.Verdict().Code {
		case VC(linux.NFT_BREAK):
			// Resets verdict for next rule (after breaking from a single operation).
			regs.verdict.Code = VC(linux.NFT_CONTINUE)
		case VC(linux.NFT_CONTINUE):
			// Goes to next rule.
			continue
		default:
			// Break evaluation for all the netfilter verdicts.
			break evalLoop
		}
	}
	return nil
}

// evaluate for Chain evaluates the packet through the chain's rules and returns
// the verdict and modifies the packet in place.
func (c *Chain) evaluate(regs *registerSet, pkt *stack.PacketBuffer) *syserr.AnnotatedError {
	return c.evaluateFromRule(0, 0, regs, pkt)
}

// evaluate evaluates the rule on the given packet and register set, changing
// the register set and possibly the packet in place.
// The verdict in regs.Verdict() may be an nf table internal verdict or a
// netfilter terminal verdict.
func (r *Rule) evaluate(regs *registerSet, pkt *stack.PacketBuffer) *syserr.AnnotatedError {
	for _, op := range r.ops {
		op.evaluate(regs, pkt, r)
		if regs.Verdict().Code != VC(linux.NFT_CONTINUE) {
			break
		}
	}
	return nil
}

//
// Top-Level NFTables Functions
// Note: Provides wrapper functions for the creation and deletion of tables,
// chains, and rules for convenience.
//

// NewNFTables creates a new NFTables state object using the given clock for
// timing operations.
// Note: Expects random number generator to be initialized with a seed.
func NewNFTables(clock tcpip.Clock, rng rand.RNG) *NFTables {
	if clock == nil {
		panic("nftables state must be initialized with a non-nil clock")
	}
	if rng.Reader == nil {
		panic("nftables state must be initialized with a non-nil random number generator")
	}
	return &NFTables{clock: clock, startTime: clock.Now(), rng: rng, tableHandleCounter: atomicbitops.Uint64{}, genid: 1}
}

// GetGenID returns the generation ID for the NFTables object.
func (nf *NFTables) GetGenID() uint32 {
	return nf.genid
}

// Flush clears entire ruleset and all data for all address families
// except for the tables that are not owned by the given owner.
func (nf *NFTables) Flush(attrs map[uint16]nlmsg.BytesView, owner uint32) {
	for family := range stack.NumAFs {
		afFilter := nf.filters[family]
		if afFilter == nil {
			continue
		}

		var attrName *string = nil
		if nameBytes, ok := attrs[linux.NFTA_TABLE_NAME]; ok {
			name := nameBytes.String()
			attrName = &name
		}
		var tablesToDelete []TableInfo
		for name, table := range afFilter.tables {
			// Caller cannot delete a table they do not own.
			if table.HasOwner() && table.GetOwner() != owner {
				continue
			}

			if attrName != nil && *attrName != table.GetName() {
				continue
			}

			// TODO: b/434242152 - Support correctly deleting chains once
			// rules are deletable.
			for chainName := range table.chains {
				ok := table.DeleteChain(chainName)
				if !ok {
					log.Warningf("Failed to delete chain %s", chainName)
				}
			}

			tablesToDelete = append(tablesToDelete, TableInfo{Name: name, Handle: table.GetHandle()})
		}

		for _, tableData := range tablesToDelete {
			delete(afFilter.tables, tableData.Name)
			delete(afFilter.tableHandles, tableData.Handle)
		}
	}
}

// FlushAddressFamily clears ruleset and all data for the given address family,
// returning an error if the address family is invalid.
func (nf *NFTables) FlushAddressFamily(family stack.AddressFamily) *syserr.AnnotatedError {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return err
	}

	nf.filters[family] = nil
	return nil
}

// GetAddressFamilyTables returns the tables for the given address family.
func (nf *NFTables) GetAddressFamilyTables(family stack.AddressFamily) map[string]*Table {
	afFilter := nf.filters[family]
	if afFilter == nil {
		// An empty map is safe to iterate over.
		return nil
	}

	return afFilter.tables
}

// GetTable validates the inputs and gets a table if it exists, error otherwise.
func (nf *NFTables) GetTable(family stack.AddressFamily, tableName string, portID uint32) (*Table, *syserr.AnnotatedError) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Checks if the table map for the address family has been initialized.
	if nf.filters[family] == nil || nf.filters[family].tables == nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("table map for address family %v has no tables", family))
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables

	// Checks if a table with the name exists.
	t, exists := tableMap[tableName]
	if !exists {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("table %s not found for address family %v", tableName, family))
	}

	// If the table has an owner, it must match the Netlink portID of the calling process.
	// User space processes only have non-zero port ids.
	// Only the kernel can have a zero port id.
	if t.HasOwner() && portID != 0 && portID != t.GetOwner() {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotPermitted, fmt.Sprintf("table %s has owner %d, which does not match the Netlink portID of the calling process %d", tableName, t.GetOwner(), portID))
	}

	return t, nil
}

// GetTableByHandle validates the inputs and gets a table by its handle and family if it exists,
// error otherwise.
func (nf *NFTables) GetTableByHandle(family stack.AddressFamily, handle uint64, portID uint32) (*Table, *syserr.AnnotatedError) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Checks if the table handle map for the address family has been initialized.
	if nf.filters[family] == nil || nf.filters[family].tableHandles == nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("table handle map for address family %v has no tables", family))
	}

	// Gets the corresponding table map for the address family.
	tableHandleMap := nf.filters[family].tableHandles

	// Checks if a table with the name exists.
	t, exists := tableHandleMap[handle]
	if !exists {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("table with handle %d not found for address family %v", handle, family))
	}

	// If the table has an owner, it must match the Netlink portID of the calling process.
	// User space processes only have non-zero port ids.
	// Only the kernel can have a zero port id.
	if t.HasOwner() && portID != 0 && portID != t.GetOwner() {
		return nil, syserr.NewAnnotatedError(syserr.ErrNotPermitted, fmt.Sprintf("table with handle %d has owner %d, which does not match the Netlink portID of the calling process %d", handle, t.GetOwner(), portID))
	}

	return t, nil
}

// AddTable makes a new table for the specified address family, returning an
// error if the address family is invalid. Can return an error if a table by the
// same name already exists if errorOnDuplicate is true. Can be used to get an
// existing table by the same name if errorOnDuplicate is false.
// Note: if the table already exists, the existing table is returned without any
// modifications.
// Note: Table initialized as not dormant.
func (nf *NFTables) AddTable(family stack.AddressFamily, name string,
	errorOnDuplicate bool) (*Table, *syserr.AnnotatedError) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Initializes filter if first table for the address family.
	if nf.filters[family] == nil {
		nf.filters[family] = &addressFamilyFilter{
			family:       family,
			nftState:     nf,
			tables:       make(map[string]*Table),
			tableHandles: make(map[uint64]*Table),
			hfStacks:     make(map[stack.NFHook]*hookFunctionStack),
		}
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables
	tableHandleMap := nf.filters[family].tableHandles

	// Checks if a table with the same name already exists. If so, returns the
	// existing table (unless errorOnDuplicate is true).
	if existingTable, exists := tableMap[name]; exists {
		if errorOnDuplicate {
			return nil, syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("table %s already exists in address family %v", name, family))
		}
		return existingTable, nil
	}

	// Creates the new table and add it to the table map.
	t := &Table{
		name:          name,
		afFilter:      nf.filters[family],
		chains:        make(map[string]*Chain),
		chainHandles:  make(map[uint64]*Chain),
		flagSet:       make(map[TableFlag]struct{}),
		handle:        nf.getNewTableHandle(),
		handleCounter: atomicbitops.Uint64{},
	}
	tableMap[name] = t
	tableHandleMap[t.handle] = t

	return t, nil
}

// getNewTableHandle returns a new table handle for the NFTables object.
func (nf *NFTables) getNewTableHandle() uint64 {
	return nf.tableHandleCounter.Add(1)
}

// CreateTable makes a new table for the specified address family like AddTable
// but also returns an error if a table by the same name already exists.
// Note: this interface mirrors the difference between the create and add
// commands within the nft binary.
func (nf *NFTables) CreateTable(family stack.AddressFamily, name string) (*Table, *syserr.AnnotatedError) {
	return nf.AddTable(family, name, true)
}

// DeleteTable deletes the specified table from the NFTables object returning
// true if the table was deleted and false if the table doesn't exist. Returns
// an error if the address family is invalid.
func (nf *NFTables) DeleteTable(family stack.AddressFamily, tableName string) (bool, *syserr.AnnotatedError) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return false, err
	}

	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName, 0)
	if err != nil {
		return false, err
	}

	// Deletes all chains in the table.
	for chainName := range t.chains {
		t.DeleteChain(chainName)
	}

	// Deletes the table from the table map and from the table handle map.
	delete(nf.filters[family].tables, tableName)
	delete(nf.filters[family].tableHandles, t.handle)
	return true, nil
}

// GetChain validates the inputs and gets a chain if it exists, error otherwise.
func (nf *NFTables) GetChain(family stack.AddressFamily, tableName string, chainName string) (*Chain, *syserr.AnnotatedError) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName, 0)
	if err != nil {
		return nil, err
	}

	return t.GetChain(chainName)
}

// AddChain makes a new chain for the corresponding table and adds it to the
// chain map and hook function list, returning an error if the address family is
// invalid or the table doesn't exist. Can return an error if a chain by the
// same name already exists if errorOnDuplicate is true. Can be used to get an
// existing chain by the same name if errorOnDuplicate is false.
// Note: if the chain already exists, the existing chain is returned without any
// modifications.
// Note: if the chain is not a base chain, info should be nil.
func (nf *NFTables) AddChain(family stack.AddressFamily, tableName string, chainName string, info *BaseChainInfo, comment string, errorOnDuplicate bool) (*Chain, *syserr.AnnotatedError) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName, 0)
	if err != nil {
		return nil, err
	}

	return t.AddChain(chainName, info, comment, errorOnDuplicate)
}

// getNewHandle returns a new handle for a chain or rule.
func (t *Table) getNewHandle() uint64 {
	return t.handleCounter.Add(1)
}

// CreateChain makes a new chain for the corresponding table and adds it to the
// chain map and hook function list like AddChain but also returns an error if a
// chain by the same name already exists.
// Note: this interface mirrors the difference between the create and add
// commands within the nft binary.
func (nf *NFTables) CreateChain(family stack.AddressFamily, tableName string, chainName string, info *BaseChainInfo, comment string) (*Chain, *syserr.AnnotatedError) {
	return nf.AddChain(family, tableName, chainName, info, comment, true)
}

// DeleteChain deletes the specified chain from the NFTables object returning
// true if the chain was deleted and false if the chain doesn't exist. Returns
// an error if the address family is invalid or the table doesn't exist.
func (nf *NFTables) DeleteChain(family stack.AddressFamily, tableName string, chainName string) (bool, *syserr.AnnotatedError) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName, 0)
	if err != nil {
		return false, err
	}

	return t.DeleteChain(chainName), nil
}

// TableCount returns the number of tables in the NFTables object.
func (nf *NFTables) TableCount() int {
	return len(nf.filters)
}

//
// Table Functions
//

// GetName returns the name of the table.
func (t *Table) GetName() string {
	return t.name
}

// GetAddressFamily returns the address family of the table.
func (t *Table) GetAddressFamily() stack.AddressFamily {
	return t.afFilter.family
}

// GetHandle returns the handle of the table.
func (t *Table) GetHandle() uint64 {
	return t.handle
}

// GetOwner returns the owner of the table.
func (t *Table) GetOwner() uint32 {
	return t.owner
}

// SetOwner sets the owner of the table. If the table already has an owner, it
// is not updated.
func (t *Table) SetOwner(nlpid uint32) *syserr.AnnotatedError {
	// This should only be called once, when setting the owner of a table for the first time.
	if t.HasOwner() {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("table %s already has an owner", t.name))
	}

	t.flagSet[TableFlagOwner] = struct{}{}
	t.owner = nlpid
	return nil
}

// HasOwner returns whether the table has an owner.
func (t *Table) HasOwner() bool {
	_, ok := t.flagSet[TableFlagOwner]
	return ok
}

// GetUserData returns the user data of the table.
func (t *Table) GetUserData() []byte {
	return t.userData
}

// HasUserData returns whether the table has user data.
func (t *Table) HasUserData() bool {
	return t.userData != nil
}

// SetUserData sets the user data of the table.
func (t *Table) SetUserData(data []byte) *syserr.AnnotatedError {
	// User data should only be set once.
	if t.userData != nil {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("table %s already has user data", t.name))
	}

	t.userData = make([]byte, len(data))
	copy(t.userData, data)
	return nil
}

// IsDormant returns whether the table is dormant.
func (t *Table) IsDormant() bool {
	_, dormant := t.flagSet[TableFlagDormant]
	return dormant
}

// SetDormant sets the dormant flag for the table.
func (t *Table) SetDormant(dormant bool) {
	if dormant {
		t.flagSet[TableFlagDormant] = struct{}{}
	} else {
		delete(t.flagSet, TableFlagDormant)
	}
}

// GetLinuxFlagSet returns the flag set of the table.
// Although user flags map to uint8 space, internal flags could eventually be
// supported, which together map to a uint32 space.
func (t *Table) GetLinuxFlagSet() (uint32, *syserr.AnnotatedError) {
	var flags uint32 = 0
	for flag := range t.flagSet {
		switch flag {
		case TableFlagDormant:
			flags |= linux.NFT_TABLE_F_DORMANT
		case TableFlagOwner:
			flags |= linux.NFT_TABLE_F_OWNER
		default:
			return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("unsupported flag %v", flag))
		}
	}

	return flags, nil
}

// GetLinuxUserFlagSet returns the user flag set of the table.
func (t *Table) GetLinuxUserFlagSet() (uint8, *syserr.AnnotatedError) {
	flags, err := t.GetLinuxFlagSet()
	if err != nil {
		return 0, err
	}
	return uint8(flags & linux.NFT_TABLE_F_MASK), nil
}

// GetChain returns the chain with the specified name if it exists, error
// otherwise.
func (t *Table) GetChain(chainName string) (*Chain, *syserr.AnnotatedError) {
	// Checks if a chain with the name exists.
	c, exists := t.chains[chainName]
	if !exists {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("chain %s not found for table %s", chainName, t.name))
	}
	return c, nil
}

// GetChainByHandle returns the chain with the specified handle if it exists, error otherwise.
func (t *Table) GetChainByHandle(chainHandle uint64) (*Chain, *syserr.AnnotatedError) {
	// Checks if a chain with the handle exists. We don't support transactions/generations of tables
	// or chains, so those checks are not needed.
	c, exists := t.chainHandles[chainHandle]
	if !exists {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("chain %d not found for table %s", chainHandle, t.name))
	}
	return c, nil
}

// GetChains returns a map of all chains for the table.
func (t *Table) GetChains() map[string]*Chain {
	return t.chains
}

// AddChain makes a new chain for the table. Can return an error if a chain by
// the same name already exists if errorOnDuplicate is true.
func (t *Table) AddChain(name string, info *BaseChainInfo, comment string, errorOnDuplicate bool) (*Chain, *syserr.AnnotatedError) {
	// Checks if a chain with the same name already exists. If so, returns the
	// existing chain (unless errorOnDuplicate is true).
	if existingChain, exists := t.chains[name]; exists {
		if errorOnDuplicate {
			return nil, syserr.NewAnnotatedError(syserr.ErrExists, fmt.Sprintf("chain %s already exists for table %s", name, t.name))
		}
		return existingChain, nil
	}

	// Creates a new chain.
	c := &Chain{
		name:          name,
		table:         t,
		baseChainInfo: info,
		comment:       comment,
		handleToRule:  make(map[uint64]*Rule),
	}

	// Sets the base chain info if it's a base chain (and validates it).
	if info != nil {
		if err := c.SetBaseChainInfo(info); err != nil {
			return nil, err
		}
	}

	// Only assign a chain handle after error checks.
	c.handle = t.getNewHandle()

	// Adds the chain to the chain map (after successfully doing everything else).
	t.chains[name] = c
	t.chainHandles[c.handle] = c

	return c, nil
}

// DeleteChain deletes the specified chain from the table returning true if the
// chain was deleted and false if the chain doesn't exist.
func (t *Table) DeleteChain(name string) bool {
	// Checks if the chain exists.
	c, exists := t.chains[name]
	if !exists {
		return false
	}

	// Detaches the chain from the pipeline if it's a base chain.
	if c.baseChainInfo != nil {
		hfStack := t.afFilter.hfStacks[c.baseChainInfo.Hook]
		if err := hfStack.detachBaseChain(c.name); err != nil {
			panic(fmt.Sprintf("failed to detach base chain %s from hook %v: %v", c.GetName(), c.baseChainInfo.Hook, err))
		}
		if len(hfStack.baseChains) == 0 {
			delete(t.afFilter.hfStacks, c.baseChainInfo.Hook)
		}
	}

	// Deletes chain.
	delete(t.chains, name)
	delete(t.chainHandles, c.handle)
	return true
}

// ChainCount returns the number of chains in the table.
func (t *Table) ChainCount() int {
	return len(t.chains)
}

//
// Chain Functions
//

// GetName returns the name of the chain.
func (c *Chain) GetName() string {
	return c.name
}

// SetName sets the name of the chain. This should only be called on
// a chain that is not yet attached to a table.
func (c *Chain) SetName(name string) *syserr.AnnotatedError {
	if c.table != nil {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("Cannot change the name of chain %s that is already attached to table %s", c.name, c.table.name))
	}

	c.name = name
	return nil
}

// GetAddressFamily returns the address family of the chain.
func (c *Chain) GetAddressFamily() stack.AddressFamily {
	return c.table.GetAddressFamily()
}

// GetTable returns the table that the chain belongs to.
func (c *Chain) GetTable() *Table {
	return c.table
}

// GetHandle returns the handle of the chain.
func (c *Chain) GetHandle() uint64 {
	return c.handle
}

// GetFlags returns the flags of the chain.
func (c *Chain) GetFlags() uint8 {
	return c.flags
}

// SetFlags sets the flags of the chain.
func (c *Chain) SetFlags(flags uint8) {
	c.flags = flags
}

// GetUserData returns the user data of the chain.
func (c *Chain) GetUserData() []byte {
	return c.userData
}

// SetUserData sets the user data of the chain.
func (c *Chain) SetUserData(data []byte) *syserr.AnnotatedError {
	// User data should only be set once.
	if c.userData != nil {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("chain %s already has user data", c.name))
	}
	c.userData = make([]byte, len(data))
	copy(c.userData, data)
	return nil
}

// HasUserData returns whether the chain has user data.
func (c *Chain) HasUserData() bool {
	return c.userData != nil
}

// IsBaseChain returns whether the chain is a base chain.
func (c *Chain) IsBaseChain() bool {
	return c.baseChainInfo != nil
}

// IsBound returns true if the chain is bound.
func (c *Chain) IsBound() bool {
	return (c.flags&linux.NFT_CHAIN_BINDING != 0) && c.bound
}

// IncrementChainUse increments the chain use value of the chain.
func (c *Chain) IncrementChainUse() bool {
	if c.chainUse == math.MaxUint32 {
		return false
	}

	c.chainUse++
	return true
}

// GetBaseChainInfo returns the base chain info of the chain.
// Note: Returns nil if the chain is not a base chain.
func (c *Chain) GetBaseChainInfo() *BaseChainInfo {
	return c.baseChainInfo
}

// SetBaseChainInfo attaches the specified chain to the netfilter pipeline (and
// detaches the chain from the pipeline if it was previously attached to a
// different hook) by setting the base chain info for the chain, returning an
// error if the base chain info is invalid.
func (c *Chain) SetBaseChainInfo(info *BaseChainInfo) *syserr.AnnotatedError {
	// Ensures base chain info is valid if it's a base chain.
	if err := validateBaseChainInfo(info, c.GetAddressFamily()); err != nil {
		return err
	}

	hfStacks := c.table.afFilter.hfStacks

	// Detaches the chain if it was previously attached to a different hook.
	if c.baseChainInfo != nil && c.baseChainInfo.Hook != info.Hook {
		oldHfStack := hfStacks[c.baseChainInfo.Hook]
		if err := oldHfStack.detachBaseChain(c.name); err != nil {
			return err
		}
	}

	// Initializes hook function stack (and its slice of base chains) if
	// first base chain for this hook (for the given address family).
	if hfStacks[info.Hook] == nil {
		hfStacks[info.Hook] = &hookFunctionStack{hook: info.Hook}
	}

	// Sets the base chain info and attaches to the pipeline.
	c.baseChainInfo = info
	hfStacks[info.Hook].attachBaseChain(c)

	return nil
}

// GetChainUse returns the chain use value of the chain.
func (c *Chain) GetChainUse() uint32 {
	return c.chainUse
}

// GetComment returns the comment of the chain.
func (c *Chain) GetComment() string {
	return c.comment
}

// SetComment sets the comment of the chain.
func (c *Chain) SetComment(comment string) {
	c.comment = comment
}

// GetRules returns the rules of the chain.
func (c *Chain) GetRules() []*Rule {
	return c.rules
}

// RegisterRule assigns the chain to the rule and adds the rule to the chain's
// rule list at the given index.
// Valid indices are -1 (append) and [0, len]. Errors on invalid index.
// This also checks that the operations in the rule comply with the chain.
// Checks done:
// - All jump and goto operations have a valid target chain.
// - Loop checking for jump and goto operations.
// - TODO(b/345684870): Add more checks as more operations are supported.
// TODO - b/434244017: Update rules to be in a linked list for faster insertion and deletion.
func (c *Chain) RegisterRule(rule *Rule, index int) *syserr.AnnotatedError {
	// Error checks like these are not part of the nf_tables_api.c. Rather they are error
	// checked here for completeness for unit tests. Netfilter sockets should never attempt to register
	// the exact same rule struct twice.
	if rule.chain != nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "rule chain is malformed")
	}

	if index < -1 || index > c.RuleCount() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid index %d for rule registration with %d rule(s)", index, c.RuleCount()))
	}

	// Checks if there are loops from all jump and goto operations in the rule.
	for _, op := range rule.ops {
		isJumpOrGoto, targetChainName := isJumpOrGotoOperation(op)
		if !isJumpOrGoto {
			continue
		}
		nextChain, exists := c.table.chains[targetChainName]
		if !exists {
			return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("chain %s not found for table %s", targetChainName, c.table.name))
		}
		if err := nextChain.checkLoops(c, 0); err != nil {
			return err
		}
	}

	// Assigns chain to rule and adds rule to chain's rule list at given index with the given handle.
	rule.chain = c
	rule.handle = c.table.getNewHandle()
	c.handleToRule[rule.handle] = rule

	// Adds the rule to the chain's rule list at the correct index.
	if index == -1 || index == c.RuleCount() {
		c.rules = append(c.rules, rule)
	} else {
		c.rules = slices.Insert(c.rules, index, rule)
	}
	return nil
}

// RegisterBeforeExistingRule registers the new rule before the existing rule.
func (c *Chain) RegisterBeforeExistingRule(newRule *Rule, oldRule *Rule) *syserr.AnnotatedError {
	index, err := c.GetRuleIndex(oldRule)
	if err != nil {
		return err
	}

	return c.RegisterRule(newRule, index)
}

// RegisterAfterExistingRule registers the new rule after the existing rule.
func (c *Chain) RegisterAfterExistingRule(newRule *Rule, oldRule *Rule) *syserr.AnnotatedError {
	index, err := c.GetRuleIndex(oldRule)
	if err != nil {
		return err
	}
	return c.RegisterRule(newRule, index+1)
}

// UnregisterRuleByIndex removes the rule at the given index from the chain's rule list
// and un-assigns the chain from the rule then returns the unregistered rule.
// Valid indices are -1 (pop) and [0, len-1]. Errors on invalid index.
func (c *Chain) UnregisterRuleByIndex(index int) (*Rule, *syserr.AnnotatedError) {
	rule, err := c.GetRule(index)
	if err != nil {
		return nil, err
	}
	if index == -1 {
		index = c.RuleCount() - 1
	}
	c.rules = append(c.rules[:index], c.rules[index+1:]...)
	rule.chain = nil
	delete(c.handleToRule, rule.handle)
	return rule, nil
}

// GetRule returns the rule at the given index in the chain's rule list.
// Valid indices are -1 (last) and [0, len-1]. Errors on invalid index.
func (c *Chain) GetRule(index int) (*Rule, *syserr.AnnotatedError) {
	if index < -1 || index > c.RuleCount()-1 || (index == -1 && c.RuleCount() == 0) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid index %d for rule retrieval with %d rule(s)", index, c.RuleCount()))
	}
	if index == -1 {
		return c.rules[c.RuleCount()-1], nil
	}
	return c.rules[index], nil
}

// GetRuleByHandle returns the rule with the specified handle from the chain's rule list.
// Errors on rule not found.
func (c *Chain) GetRuleByHandle(handle uint64) (*Rule, *syserr.AnnotatedError) {
	rule, exists := c.handleToRule[handle]
	if !exists {
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("rule with handle %d not found for chain %s", handle, c.name))
	}
	return rule, nil
}

// GetRuleIndex returns the index of the rule in the chain's rule list.
func (c *Chain) GetRuleIndex(r *Rule) (int, *syserr.AnnotatedError) {
	for i, rule := range c.rules {
		if rule == r {
			return i, nil
		}
	}
	return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("index of rule with handle %d not found for chain %s", r.handle, c.name))
}

// RuleCount returns the number of rules in the chain.
func (c *Chain) RuleCount() int {
	return len(c.rules)
}

//
// Loop Checking Helper Functions
//

// isJumpOrGoto returns whether the operation is an immediate operation that
// sets the verdict register to a jump or goto verdict, returns the name of
// the target chain to jump or goto if so and returns the verdict code.
func isJumpOrGotoOperation(op operation) (bool, string) {
	imm, ok := op.(*immediate)
	if !ok {
		return false, ""
	}
	verdictData, ok := imm.data.(verdictData)
	if !ok {
		return false, ""
	}
	verdict := verdictData.data
	if verdict.Code != VC(linux.NFT_JUMP) && verdict.Code != VC(linux.NFT_GOTO) {
		return false, ""
	}
	return true, verdict.ChainName
}

// checkLoops detects if there are any loops via jumps and gotos between chains
// by tracing all immediate operations starting from the destination chain
// of a jump or goto operation and checking that no jump or goto operations lead
// back to the original source chain.
// Note: this loop checking is done whenever a rule is registered to a chain.
func (c *Chain) checkLoops(source *Chain, depth int) *syserr.AnnotatedError {
	// Depth is checked here to prevent invalid rules from being registered. This implicitly
	// checks if we revisit the same chain more than once in a loop.
	// From linux/net/netfilter/nf_tables_api.c:nft_chain_validate
	if depth >= nestedJumpLimit {
		return syserr.NewAnnotatedError(syserr.ErrTooManyLinks, fmt.Sprintf("chain %s has exceeded the nested jump limit of %d", c.name, nestedJumpLimit))
	}

	// Jumping to the same chain is not allowed and although implicitly checked, we explcitly
	// check it here for clarity.
	if c == source {
		return syserr.NewAnnotatedError(syserr.ErrTooManyLinks, fmt.Sprintf("chain %s cannot jump to itself", c.name))
	}

	for _, rule := range c.rules {
		for _, op := range rule.ops {
			isJumpOrGoto, targetChainName := isJumpOrGotoOperation(op)
			if !isJumpOrGoto {
				continue
			}
			nextChain, exists := c.table.chains[targetChainName]
			if !exists {
				return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("chain %s not found for table %s", targetChainName, c.table.name))
			}

			// Depth is incremented regardless if the verdict is a NFT_JUMP or NFT_GOTO.
			// From net/netfilter/nft_immediate.c:nft_immediate_validate
			depth++
			if err := nextChain.checkLoops(source, depth); err != nil {
				return err
			}
			depth--
		}
	}
	return nil
}

//
// Rule Functions
//

// addOperation adds an operation to the rule. Adding operations is only allowed
// before the rule is registered to a chain. Returns an error if the operation
// is nil or if the rule is already registered to a chain.
func (r *Rule) addOperation(op operation) *syserr.AnnotatedError {
	// From net/netfilter/nf_tables_api.c:nft_expr_type
	if op == nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "operation is nil")
	}

	// Netfilter sockets should not try to register operations to rules that
	// have already been registered to a chain. Instead, old rules should be unregistered
	// and new rules should be created.
	if r.chain != nil {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "cannot add operation to a rule that is already registered to a chain")
	}
	r.ops = append(r.ops, op)
	return nil
}

// AddOpFromExprInfo adds an operation to the rule given the expression information.
func (r *Rule) AddOpFromExprInfo(tab *Table, exprInfo ExprInfo) *syserr.AnnotatedError {
	// Centralized here so that operations can do their own validation when being created.
	// TODO - b/434244017: Support parsing expression types other than NFT_IMMEDIATE
	var op operation
	var err *syserr.AnnotatedError
	switch exprInfo.ExprName {
	case "immediate":
		if op, err = initImmediate(tab, exprInfo); err != nil {
			return err
		}
	case "payload":
		if op, err = initPayload(tab, exprInfo); err != nil {
			return err
		}
	case "meta":
		if op, err = initMeta(tab, exprInfo); err != nil {
			return err
		}
	case "cmp":
		if op, err = initComparison(tab, exprInfo); err != nil {
			return err
		}
	case "counter":
		if op, err = initCounter(tab, exprInfo); err != nil {
			return err
		}

	default:
		return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("Nftables: Unknown expression type not found: %s", exprInfo.ExprName))
	}

	return r.addOperation(op)
}

// GetChain returns the chain that the rule is registered to.
func (r *Rule) GetChain() *Chain {
	return r.chain
}

// GetHandle returns the handle of the rule.
func (r *Rule) GetHandle() uint64 {
	return r.handle
}

// SetUserData sets the user data of the rule.
func (r *Rule) SetUserData(data []byte) *syserr.AnnotatedError {
	if r.udata != nil {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "rule already has user data")
	}
	r.udata = make([]byte, len(data))
	copy(r.udata, data)
	return nil
}

// HasUserData returns whether the rule has user data.
func (r *Rule) HasUserData() bool {
	return r.udata != nil
}

// GetUserData returns the user data of the rule.
func (r *Rule) GetUserData() []byte {
	return r.udata
}

// GetAddressFamily returns the address family of the rule.
func (r *Rule) GetAddressFamily() stack.AddressFamily {
	return r.chain.GetAddressFamily()
}

// GetOperations returns the list of operations in the rule.
func (r *Rule) GetOperations() []operation {
	return r.ops
}

//
// Private hookFunctionStack functions
//

// attachBaseChain adds an (assumed/previously checked) base chain to the stack,
// maintaining ascending priority ordering.
// Note: assumes stack and base chains slice are initialized and is base chain.
func (hfStack *hookFunctionStack) attachBaseChain(chain *Chain) {
	if chain.baseChainInfo == nil {
		panic(fmt.Sprintf("chain %s is not a base chain; base chain info is nil", chain.name))
	}

	// Initializes the stack and simply appends the chain if the stack is empty.
	if len(hfStack.baseChains) == 0 {
		hfStack.baseChains = append(hfStack.baseChains, chain)
		return
	}

	pos, _ := slices.BinarySearchFunc(hfStack.baseChains, chain, func(a, b *Chain) int {
		return a.baseChainInfo.Priority.GetValue() - b.baseChainInfo.Priority.GetValue()
	})
	hfStack.baseChains = slices.Insert(hfStack.baseChains, pos, chain)
}

// detachBaseChain removes a base chain with the specified name from the stack,
// returning an error if the chain doesn't exist.
// Note: assumes stack is initialized.
func (hfStack *hookFunctionStack) detachBaseChain(name string) *syserr.AnnotatedError {
	prevLen := len(hfStack.baseChains)
	hfStack.baseChains = slices.DeleteFunc(hfStack.baseChains, func(chain *Chain) bool {
		return chain.name == name
	})
	if len(hfStack.baseChains) == prevLen {
		return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("chain %s not found for hook %v", name, hfStack.hook))
	}
	if len(hfStack.baseChains) < prevLen-1 {
		panic(fmt.Errorf("multiple base chains with name '%s' exist for hook %v", name, hfStack.hook))
	}
	return nil
}
