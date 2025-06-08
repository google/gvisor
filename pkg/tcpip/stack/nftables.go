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

package stack

import (
	"fmt"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
)

//
// Core Evaluation Functions
//

// EvaluateHook evaluates a packet using the rules of the given hook for the
// given address family, returning a netfilter verdict and modifying the packet
// in place.
// Returns an error if address family or hook is invalid or they don't match.
// TODO(b/345684870): Consider removing error case if we never return an error.
func (nf *NFTables) EvaluateHook(family AddressFamily, hook NFHook, pkt *PacketBuffer) (Verdict, error) {
	// Note: none of the other evaluate functions are public because they require
	// jumping to different chains in the same table, so all chains, rules, and
	// operations must be tied to a table. Thus, calling evaluate for standalone
	// chains, rules, or operations can be misleading and dangerous.

	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return Verdict{}, err
	}

	// Ensures hook is valid.
	if err := validateHook(hook, family); err != nil {
		return Verdict{}, err
	}

	// Immediately accept if there are no base chains for the specified hook.
	if nf.filters[family] == nil || nf.filters[family].hfStacks[hook] == nil ||
		len(nf.filters[family].hfStacks[hook].baseChains) == 0 {
		return Verdict{Code: VC(linux.NF_ACCEPT)}, nil
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
			return Verdict{}, err
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
			return Verdict{Code: VC(linux.NF_DROP)}, nil
		}
		return Verdict{Code: VC(linux.NF_ACCEPT)}, nil
	}

	panic(fmt.Sprintf("unexpected verdict from hook evaluation: %s", VerdictCodeToString(regs.Verdict().Code)))
}

// evaluateFromRule is a helper function for Chain.evaluate that evaluates the
// packet through the rules in the chain starting at the specified rule index.
func (c *Chain) evaluateFromRule(rIdx int, jumpDepth int, regs *registerSet, pkt *PacketBuffer) error {
	if jumpDepth >= nestedJumpLimit {
		return fmt.Errorf("jump stack limit of %d exceeded", nestedJumpLimit)
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
				return fmt.Errorf("chain '%s' does not exist in table %s", regs.verdict.ChainName, c.table.GetName())
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
func (c *Chain) evaluate(regs *registerSet, pkt *PacketBuffer) error {
	return c.evaluateFromRule(0, 0, regs, pkt)
}

// evaluate evaluates the rule on the given packet and register set, changing
// the register set and possibly the packet in place.
// The verdict in regs.Verdict() may be an nf table internal verdict or a
// netfilter terminal verdict.
func (r *NFRule) evaluate(regs *registerSet, pkt *PacketBuffer) error {
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
	return &NFTables{clock: clock, startTime: clock.Now(), rng: rng}
}

// Flush clears entire ruleset and all data for all address families.
func (nf *NFTables) Flush() {
	for family := range NumAFs {
		nf.filters[family] = nil
	}
}

// FlushAddressFamily clears ruleset and all data for the given address family,
// returning an error if the address family is invalid.
func (nf *NFTables) FlushAddressFamily(family AddressFamily) error {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return err
	}

	nf.filters[family] = nil
	return nil
}

// GetTable validates the inputs and gets a table if it exists, error otherwise.
func (nf *NFTables) GetTable(family AddressFamily, tableName string) (*NFTable, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Checks if the table map for the address family has been initialized.
	if nf.filters[family] == nil || nf.filters[family].tables == nil {
		return nil, fmt.Errorf("address family %v has no tables", family)
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables

	// Checks if a table with the name exists.
	t, exists := tableMap[tableName]
	if !exists {
		return nil, fmt.Errorf("table '%s' does not exists for address family %v", tableName, family)
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
func (nf *NFTables) AddTable(family AddressFamily, name string, comment string,
	errorOnDuplicate bool) (*NFTable, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Initializes filter if first table for the address family.
	if nf.filters[family] == nil {
		nf.filters[family] = &addressFamilyFilter{
			family:   family,
			nftState: nf,
			tables:   make(map[string]*NFTable),
			hfStacks: make(map[NFHook]*hookFunctionStack),
		}
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables

	// Checks if a table with the same name already exists. If so, returns the
	// existing table (unless errorOnDuplicate is true).
	if existingTable, exists := tableMap[name]; exists {
		if errorOnDuplicate {
			return nil, fmt.Errorf("table '%s' already exists in address family %v", name, family)
		}
		return existingTable, nil
	}

	// Creates the new table and add it to the table map.
	t := &NFTable{
		name:     name,
		afFilter: nf.filters[family],
		chains:   make(map[string]*Chain),
		comment:  comment,
		flagSet:  make(map[TableFlag]struct{}),
	}
	tableMap[name] = t

	return t, nil
}

// CreateTable makes a new table for the specified address family like AddTable
// but also returns an error if a table by the same name already exists.
// Note: this interface mirrors the difference between the create and add
// commands within the nft binary.
func (nf *NFTables) CreateTable(family AddressFamily, name string, comment string) (*NFTable, error) {
	return nf.AddTable(family, name, comment, true)
}

// DeleteTable deletes the specified table from the NFTables object returning
// true if the table was deleted and false if the table doesn't exist. Returns
// an error if the address family is invalid.
func (nf *NFTables) DeleteTable(family AddressFamily, tableName string) (bool, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return false, err
	}

	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName)
	if err != nil {
		return false, err
	}

	// Deletes all chains in the table.
	for chainName := range t.chains {
		t.DeleteChain(chainName)
	}

	// Deletes the table from the table map.
	delete(nf.filters[family].tables, tableName)
	return true, nil
}

// GetChain validates the inputs and gets a chain if it exists, error otherwise.
func (nf *NFTables) GetChain(family AddressFamily, tableName string, chainName string) (*Chain, error) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName)
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
func (nf *NFTables) AddChain(family AddressFamily, tableName string, chainName string, info *BaseChainInfo, comment string, errorOnDuplicate bool) (*Chain, error) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName)
	if err != nil {
		return nil, err
	}

	return t.AddChain(chainName, info, comment, errorOnDuplicate)
}

// CreateChain makes a new chain for the corresponding table and adds it to the
// chain map and hook function list like AddChain but also returns an error if a
// chain by the same name already exists.
// Note: this interface mirrors the difference between the create and add
// commands within the nft binary.
func (nf *NFTables) CreateChain(family AddressFamily, tableName string, chainName string, info *BaseChainInfo, comment string) (*Chain, error) {
	return nf.AddChain(family, tableName, chainName, info, comment, true)
}

// DeleteChain deletes the specified chain from the NFTables object returning
// true if the chain was deleted and false if the chain doesn't exist. Returns
// an error if the address family is invalid or the table doesn't exist.
func (nf *NFTables) DeleteChain(family AddressFamily, tableName string, chainName string) (bool, error) {
	// Gets and checks the table.
	t, err := nf.GetTable(family, tableName)
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

// GetName returns the name of the nf table.
func (t *NFTable) GetName() string {
	return t.name
}

// GetAddressFamily returns the address family of the nf table.
func (t *NFTable) GetAddressFamily() AddressFamily {
	return t.afFilter.family
}

// GetComment returns the comment of the nf table.
func (t *NFTable) GetComment() string {
	return t.comment
}

// SetComment sets the comment of the nf table.
func (t *NFTable) SetComment(comment string) {
	t.comment = comment
}

// IsDormant returns whether the nf table is dormant.
func (t *NFTable) IsDormant() bool {
	_, dormant := t.flagSet[TableFlagDormant]
	return dormant
}

// SetDormant sets the dormant flag for the nf table.
func (t *NFTable) SetDormant(dormant bool) {
	if dormant {
		t.flagSet[TableFlagDormant] = struct{}{}
	} else {
		delete(t.flagSet, TableFlagDormant)
	}
}

// GetChain returns the chain with the specified name if it exists, error
// otherwise.
func (t *NFTable) GetChain(chainName string) (*Chain, error) {
	// Checks if a chain with the name exists.
	c, exists := t.chains[chainName]
	if !exists {
		return nil, fmt.Errorf("chain '%s' does not exists for table %s", chainName, t.GetName())
	}
	return c, nil
}

// AddChain makes a new chain for the table. Can return an error if a chain by
// the same name already exists if errorOnDuplicate is true.
func (t *NFTable) AddChain(name string, info *BaseChainInfo, comment string, errorOnDuplicate bool) (*Chain, error) {
	// Checks if a chain with the same name already exists. If so, returns the
	// existing chain (unless errorOnDuplicate is true).
	if existingChain, exists := t.chains[name]; exists {
		if errorOnDuplicate {
			return nil, fmt.Errorf("chain '%s' already exists in table %s", name, t.GetName())
		}
		return existingChain, nil
	}

	// Creates a new chain.
	c := &Chain{
		name:          name,
		table:         t,
		baseChainInfo: info,
		comment:       comment,
	}

	// Sets the base chain info if it's a base chain (and validates it).
	if info != nil {
		if err := c.SetBaseChainInfo(info); err != nil {
			return nil, err
		}
	}

	// Adds the chain to the chain map (after successfully doing everything else).
	t.chains[name] = c

	return c, nil
}

// DeleteChain deletes the specified chain from the table returning true if the
// chain was deleted and false if the chain doesn't exist.
func (t *NFTable) DeleteChain(name string) bool {
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
	return true
}

// ChainCount returns the number of chains in the table.
func (t *NFTable) ChainCount() int {
	return len(t.chains)
}

//
// Chain Functions
//

// GetName returns the name of the chain.
func (c *Chain) GetName() string {
	return c.name
}

// GetAddressFamily returns the address family of the chain.
func (c *Chain) GetAddressFamily() AddressFamily {
	return c.table.GetAddressFamily()
}

// GetTable returns the NFtable that the chain belongs to.
func (c *Chain) GetTable() *NFTable {
	return c.table
}

// IsBaseChain returns whether the chain is a base chain.
func (c *Chain) IsBaseChain() bool {
	return c.baseChainInfo != nil
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
func (c *Chain) SetBaseChainInfo(info *BaseChainInfo) error {
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

// GetComment returns the comment of the chain.
func (c *Chain) GetComment() string {
	return c.comment
}

// SetComment sets the comment of the chain.
func (c *Chain) SetComment(comment string) {
	c.comment = comment
}

// RegisterRule assigns the chain to the rule and adds the rule to the chain's
// rule list at the given index.
// Valid indices are -1 (append) and [0, len]. Errors on invalid index.
// This also checks that the operations in the rule comply with the chain.
// Checks done:
// - All jump and goto operations have a valid target chain.
// - Loop checking for jump and goto operations.
// - TODO(b/345684870): Add more checks as more operations are supported.
func (c *Chain) RegisterRule(rule *NFRule, index int) error {
	if rule.chain != nil {
		return fmt.Errorf("rule is already registered to a chain")
	}

	if index < -1 || index > c.RuleCount() {
		return fmt.Errorf("invalid index %d for rule registration with %d rule(s)", index, c.RuleCount())
	}

	// Checks if there are loops from all jump and goto operations in the rule.
	for _, op := range rule.ops {
		isJumpOrGoto, targetChainName := isJumpOrGotoOperation(op)
		if !isJumpOrGoto {
			continue
		}
		nextChain, exists := c.table.chains[targetChainName]
		if !exists {
			return fmt.Errorf("chain '%s' does not exist in table %s", targetChainName, c.table.GetName())
		}
		if err := nextChain.checkLoops(c); err != nil {
			return err
		}
	}

	// Assigns chain to rule and adds rule to chain's rule list at given index.
	rule.chain = c

	// Adds the rule to the chain's rule list at the correct index.
	if index == -1 || index == c.RuleCount() {
		c.rules = append(c.rules, rule)
	} else {
		c.rules = slices.Insert(c.rules, index, rule)
	}
	return nil
}

// UnregisterRule removes the rule at the given index from the chain's rule list
// and unassigns the chain from the rule then returns the unregistered rule.
// Valid indices are -1 (pop) and [0, len-1]. Errors on invalid index.
func (c *Chain) UnregisterRule(index int) (*NFRule, error) {
	rule, err := c.GetRule(index)
	if err != nil {
		return nil, fmt.Errorf("invalid index %d for rule registration with %d rule(s)", index, c.RuleCount())
	}
	if index == -1 {
		index = c.RuleCount() - 1
	}
	c.rules = append(c.rules[:index], c.rules[index+1:]...)
	rule.chain = nil
	return rule, nil
}

// GetRule returns the rule at the given index in the chain's rule list.
// Valid indices are -1 (last) and [0, len-1]. Errors on invalid index.
func (c *Chain) GetRule(index int) (*NFRule, error) {
	if index < -1 || index > c.RuleCount()-1 || (index == -1 && c.RuleCount() == 0) {
		return nil, fmt.Errorf("invalid index %d for rule retrieval with %d rule(s)", index, c.RuleCount())
	}
	if index == -1 {
		return c.rules[c.RuleCount()-1], nil
	}
	return c.rules[index], nil
}

// RuleCount returns the number of rules in the chain.
func (c *Chain) RuleCount() int {
	return len(c.rules)
}

//
// Loop Checking Helper Functions
//

// isJumpOrGoto returns whether the operation is an immediate operation that
// sets the verdict register to a jump or goto verdict and returns the name of
// the target chain to jump or goto if so.
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
func (c *Chain) checkLoops(source *Chain) error {
	if c == source {
		return fmt.Errorf("loop detected between calling chain %s and source chain %s", c.name, source.name)
	}
	for _, rule := range c.rules {
		for _, op := range rule.ops {
			isJumpOrGoto, targetChainName := isJumpOrGotoOperation(op)
			if !isJumpOrGoto {
				continue
			}
			nextChain, exists := c.table.chains[targetChainName]
			if !exists {
				return fmt.Errorf("chain '%s' does not exist in table %s", targetChainName, c.table.GetName())
			}
			if err := nextChain.checkLoops(source); err != nil {
				return err
			}
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
func (r *NFRule) addOperation(op operation) error {
	if op == nil {
		return fmt.Errorf("operation is nil")
	}
	if r.chain != nil {
		return fmt.Errorf("cannot add operation to a rule that is already registered to a chain")
	}
	r.ops = append(r.ops, op)
	return nil
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
	return
}

// detachBaseChain removes a base chain with the specified name from the stack,
// returning an error if the chain doesn't exist.
// Note: assumes stack is initialized.
func (hfStack *hookFunctionStack) detachBaseChain(name string) error {
	prevLen := len(hfStack.baseChains)
	hfStack.baseChains = slices.DeleteFunc(hfStack.baseChains, func(chain *Chain) bool {
		return chain.name == name
	})
	if len(hfStack.baseChains) == prevLen {
		return fmt.Errorf("base chain '%s' does not exist for hook %v", name, hfStack.hook)
	}
	if len(hfStack.baseChains) < prevLen-1 {
		panic(fmt.Errorf("multiple base chains with name '%s' exist for hook %v", name, hfStack.hook))
	}
	return nil
}
