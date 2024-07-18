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

// Package nftables provides the interface to process packets through a
// netfilter (nf) ruleset and maintain/modify the ruleset accordingly. The
// package implements a bytecode nftables interpreter that accepts an nf ruleset
// (with the accompanying assembly and/or machine code) outputted from
// the nftables binary, along with network packets (as a stack.PacketBuffer) to
// filter, modify, and evaluate packets.
// We support a subset of the functionality of the nftables binary.
// The package is not yet thread-safe.
//
// To use the package, construct a ruleset using the official nft binary and
// then pass the ruleset as a string (with flag --debug=netlink on to get the
// assembly) to InterpretRuleset command. The interpreter has strict syntax and
// only accepts rulesets outputted directly from the nftables binary.
// Maintaining and modifying the ruleset is done through the other public
// functions (Add.., Flush.., etc).
//
// To evaluate a packet through the ruleset, call the EvaluatePacket function
// with the packet and the hook to evaluate at. The EvaluatePacket function
// returns the verdict issued by the ruleset and the packet modified by the
// ruleset (if the verdict is not Drop).
//
// Finally, note that error checking for parameters/inputs is only guaranteed
// for public functions. Most private functions are assumed to have
// valid/prechecked inputs.
package nftables

import (
	"fmt"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TODO(b/345684870): Remove unused functions once initial implementation is
// complete.

// Defines the default capacity for the slices of hook functions and rules.
const (
	defaultBaseChainCapacity = 8
	defaultRuleCapacity      = 8
)

// AddressFamily describes the 6 address families supported by nftables.
// The address family determines the type of packets processed, and each family
// contains hooks at specific stages of the packet processing pipeline.
type AddressFamily int

const (
	// IP     represents IPv4 Family.
	IP AddressFamily = iota

	// IP6    represents IPv6 Family.
	IP6

	// Inet   represents Internet Family for hybrid IPv4/IPv6 rules.
	Inet

	// Arp    represents ARP Family for IPv4 ARP packets.
	Arp

	// Bridge represents Bridge Family for Ethernet packets across bridge devices.
	Bridge

	// Netdev represents Netdev Family for packets on ingress and egress.
	Netdev

	// NumAFs is the number of address families supported by nftables.
	NumAFs
)

// String for AddressFamily returns the name of the address family.
func (f AddressFamily) String() string {
	switch f {
	case IP:
		return "IPv4"
	case IP6:
		return "IPv6"
	case Inet:
		return "Internet (Both IPv4/IPv6)"
	case Arp:
		return "ARP"
	case Bridge:
		return "Bridge"
	case Netdev:
		return "Netdev"
	default:
		panic(fmt.Sprintf("invalid address family: %d", int(f)))
	}
}

// validateAddressFamily ensures the family address is valid (within bounds).
func validateAddressFamily(family AddressFamily) error {
	if family < 0 || family >= NumAFs {
		return fmt.Errorf("invalid address family: %d", int(family))
	}
	return nil
}

// Hook describes specific points in the pipeline where chains can be attached.
// Each address family has its own set of hooks (defined in supportedHooks).
// For IPv4/IPv6/Inet and Bridge, there are two possible pipelines:
// 1. Prerouting -> Input -> ~Local Process~ -> Output -> Postrouting
// 2. Prerouting -> Forward -> Postrouting
type Hook int

const (
	// Prerouting Hook    is supported by IPv4/IPv6/Inet, Bridge Families.
	Prerouting Hook = iota

	// Input Hook         is supported by IPv4/IPv6/Inet, Bridge, ARP Families.
	Input

	// Forward Hook       is supported by IPv4/IPv6/Inet, Bridge Families.
	Forward

	// Output Hook        is supported by IPv4/IPv6/Inet, Bridge, ARP Families.
	Output

	// Postrouting Hook   is supported by IPv4/IPv6/Inet, Bridge Families.
	Postrouting

	// Ingress Hook       is supported by IPv4/IPv6/Inet, Bridge, Netdev Families.
	Ingress

	// Egress Hook        is supported by Netdev Family only.
	Egress

	// NumHooks is the number of hooks supported by nftables.
	NumHooks
)

// String for Hook returns the name of the hook.
func (h Hook) String() string {
	switch h {
	case Prerouting:
		return "Prerouting"
	case Input:
		return "Input"
	case Forward:
		return "Forward"
	case Output:
		return "Output"
	case Postrouting:
		return "Postrouting"
	case Ingress:
		return "Ingress"
	case Egress:
		return "Egress"
	default:
		panic(fmt.Sprintf("invalid hook: %d", int(h)))
	}
}

// supportedHooks maps each address family to its supported hooks.
var supportedHooks [NumAFs][]Hook = [NumAFs][]Hook{
	IP:     {Prerouting, Input, Forward, Output, Postrouting, Ingress},
	IP6:    {Prerouting, Input, Forward, Output, Postrouting, Ingress},
	Inet:   {Prerouting, Input, Forward, Output, Postrouting, Ingress},
	Arp:    {Input, Output},
	Bridge: {Prerouting, Input, Forward, Output, Postrouting, Ingress},
	Netdev: {Ingress, Egress},
}

// validateHook ensures the hook is within bounds and supported for the given
// address family.
func validateHook(hook Hook, family AddressFamily) error {
	if hook < 0 || hook >= NumHooks {
		return fmt.Errorf("invalid hook: %d", int(hook))
	}
	if slices.Contains(supportedHooks[family], hook) {
		return nil
	}

	return fmt.Errorf("hook %s is not valid for address family %s", hook.String(), family.String())
}

// NFTables represents the nftables state for all address families.
// Note: unlike iptables, nftables doesn't start with any initialized tables.
type NFTables struct {
	filters [NumAFs]*addressFamilyFilter
}

// addressFamilyFilter represents the nftables state for a specific address
// family.
type addressFamilyFilter struct {
	// family is the address family of the filter.
	family AddressFamily

	// tables is a map of tables for each address family.
	tables map[string]*Table

	// hfStacks is a map of hook function stacks (slice of base chains for a
	// given hook ordered by priority).
	hfStacks map[Hook]*hookFunctionStack
}

// Table represents a single table as a collection of named chains.
// Note: as tables are simply collections of chains, evaluations aren't done on
// the table-level and instead are done on the chain- and hook- level.
type Table struct {
	// name is the name of the table.
	name string

	// afFilter is the address family filter that the table belongs to.
	// Note: this is used to reference the hook function stack as necessary.
	afFilter *addressFamilyFilter

	// chains is a map of chains for each table.
	chains map[string]*Chain

	// flags is the set of optional flags for the table.
	// Note: currently nftables only has the single Dormant flag.
	flagSet map[TableFlag]struct{}

	// comment is the optional comment for the table.
	comment string
}

// hookFunctionStack represents the list of base chains for a specific hook.
// The stack is ordered by priority and built as chains are added to tables.
type hookFunctionStack struct {
	hook       Hook
	baseChains []*Chain
}

// TableFlag is a flag for a table as supported by the nftables binary.
type TableFlag int

const (
	// TableFlagDormant is set if the table is dormant. Dormant tables are not
	// evaluated by the kernel.
	TableFlagDormant TableFlag = iota
)

// Chain represents a single chain as a list of rules.
// A chain can be either a base chain or a regular chain.
// Base chains (aka hook functions) contain a hook which attaches it directly to
// the netfilter pipeline to be called whenever the hook is encountered.
// Regular chains have a nil hook and must be called by base chains for
// evaluation.
type Chain struct {
	// name is the name of the chain.
	name string

	// table is a pointer to the table that the chain belongs to.
	// Note: this is tracked to check if the table is dormant.
	table *Table

	// baseChainInfo is the base chain info for the chain if it is a base chain.
	// Otherwise, it is nil.
	baseChainInfo *BaseChainInfo

	// rules is a list of rules for the chain.
	rules []*Rule

	// comment is the optional comment for the table.
	comment string
}

// TODO(b/345684870): BaseChainInfo Implementation. Encode how bcType affects
// evaluation of a packet.

// BaseChainInfo stores hook-related info for attaching a chain to the pipeline.
type BaseChainInfo struct {
	// BcType is the base chain type of the chain (filter, nat, route).
	BcType BaseChainType

	// Hook is the hook to attach the chain to in the netfilter pipeline
	Hook Hook

	// Priority determines the order in which base chains with the same hook are
	// traversed. Each priority is associated with a signed integer priority value
	// which rank base chains in ascending order. See the Priority struct below
	// for more details.
	Priority Priority

	// Device is an optional parameter and is mainly relevant to the bridge and
	// netdev address families. It specifies the device associated with chain.
	Device string

	// PolicyDrop determines whether to change the chain's policy from Accept to
	// Drop. The policy of a chain is the verdict to issue when a packet is not
	// explicitly accepted or rejected by the rules. A chain's policy defaults to
	// Accept, but this can be used to specify otherwise.
	PolicyDrop bool
}

// NewBaseChainInfo creates a new BaseChainInfo object with the given values.
// The device and policyDrop parameters are optional in the nft binary and
// should be set to empty string and false if not needed.
func NewBaseChainInfo(bcType BaseChainType, hook Hook, priority Priority, device string, policyDrop bool) *BaseChainInfo {
	return &BaseChainInfo{
		BcType:     bcType,
		Hook:       hook,
		Priority:   priority,
		Device:     device,
		PolicyDrop: policyDrop,
	}
}

// BaseChainType represents the supported chain types for base chains.
type BaseChainType int

// Constants for BaseChainType
const (
	// BaseChainTypeFilter type  is supported by all Hooks.
	BaseChainTypeFilter BaseChainType = iota

	// BaseChainTypeNat type     is supported by Prerouting, Input, Output, Postrouting Hooks.
	BaseChainTypeNat

	// BaseChainTypeRoute type   is supported by the Output Hook only.
	BaseChainTypeRoute

	// NumBaseChainTypes is the number of base chain types supported by nftables.
	NumBaseChainTypes
)

// String for BaseChainType returns the name of the base chain type.
func (bcType BaseChainType) String() string {
	switch bcType {
	case BaseChainTypeFilter:
		return "filter"
	case BaseChainTypeNat:
		return "nat"
	case BaseChainTypeRoute:
		return "route"
	default:
		panic(fmt.Sprintf("invalid base chain type: %d", int(bcType)))
	}
}

// supportedAFsForBaseChainTypes maps each base chain type to its supported
// address families.
var supportedAFsForBaseChainTypes [NumBaseChainTypes][]AddressFamily = [NumBaseChainTypes][]AddressFamily{
	BaseChainTypeFilter: {IP, IP6, Inet, Bridge, Arp, Netdev},
	BaseChainTypeNat:    {IP, IP6, Inet},
	BaseChainTypeRoute:  {IP, IP6},
}

// supportedHooksForBaseChainTypes maps each base chain type to its supported
// hooks.
var supportedHooksForBaseChainTypes [NumBaseChainTypes][]Hook = [NumBaseChainTypes][]Hook{
	BaseChainTypeFilter: {Prerouting, Input, Forward, Output, Postrouting, Ingress, Egress},
	BaseChainTypeNat:    {Prerouting, Input, Output, Postrouting},
	BaseChainTypeRoute:  {Output},
}

//
// Priority Object Implementation.
// Object contents are hidden to prevent creating invalid Priority objects.
//

// Priority represents the priority of a base chain which specifies the order
// in which base chains with the same hook value are traversed.
// nftables allows for 2 types of priorities: 1) a simple signed integer value
// or 2) a predefined standard priority name (which is implicitly mapped to a
// signed integer value). Priorities are traversed in ascending order such that
// lower priority value have precedence.
// Use the respective NewIntPriority or NewStandardPriority to create new
// Priority objects.
type Priority struct {
	// Contents are hidden to prevent creating invalid Priority objects.

	// value is the priority value of the base chain (in ascending order). This is
	// set whether the priority is represented by a simple signed integer value or
	// a standard priority name.
	value int

	// standardPriority is the standard priority name if the priority is a
	// predefined standard priority name, otherwise it is the empty string.
	standardPriorityName string
}

// NewIntPriority creates a new Priority object given a simple signed integer
// priority value.
func NewIntPriority(value int) Priority {
	return Priority{value: value}
}

// NewStandardPriority creates a new Priority object given a standard priority
// name, returning an error if the standard priority name is not compatible with
// the given address family and hook.
func NewStandardPriority(name string, family AddressFamily, hook Hook) (Priority, error) {
	// Validates address family and hook first.
	if err := validateAddressFamily(family); err != nil {
		return Priority{}, err
	}
	if err := validateHook(hook, family); err != nil {
		return Priority{}, err
	}

	// Ensures the standard priority name is set.
	if name == "" {
		return Priority{}, fmt.Errorf("standard priority name cannot be empty")
	}

	// Looks up standard priority name in the standard priority matrix.
	familyMatrix, exists := standardPriorityMatrix[family]
	if !exists {
		return Priority{}, fmt.Errorf("standard priority names are not available for address family %s", family.String())
	}
	sp, exists := familyMatrix[name]
	if !exists {
		return Priority{}, fmt.Errorf("standard priority name '%s' is not compatible with address family %s", name, family.String())
	}

	// Checks for hook compatibility.
	if !slices.Contains(sp.hooks, hook) {
		return Priority{}, fmt.Errorf("standard priority %s is not compatible with hook %s", name, hook.String())
	}

	return Priority{value: sp.value, standardPriorityName: name}, nil
}

// IsStandardPriority returns true if the priority is a standard priority name.
func (p Priority) IsStandardPriority() bool {
	return p.standardPriorityName != ""
}

// GetValue returns the priority value for the Priority object.
func (p Priority) GetValue() int {
	return p.value
}

// GetStandardPriorityName returns the standard priority name for the Priority
// object. It panics if the priority is not a standard priority name.
func (p Priority) GetStandardPriorityName() string {
	if !p.IsStandardPriority() {
		panic("priority is not a standard priority")
	}
	return p.standardPriorityName
}

// String for Priority returns the string representation of the Priority object.
func (p Priority) String() string {
	if p.IsStandardPriority() {
		return p.standardPriorityName
	}
	return fmt.Sprintf("%d", p.value)
}

// standardPriority represents the information for a predefined standard
// priority name and mapping. Standard priorities are only available for the IP,
// IP6, Inet, and Bridge address families, and the matrix below maps each
// standard priority name to the priority value and hooks that the priority
// applies to for the supported address families.
type standardPriority struct {
	// name is the standard priority name.
	name string
	// value is the priority value of the standard priority name.
	value int
	// hooks are the hooks that are compatible with the standard priority name.
	hooks []Hook
}

// standardPriorityMatrix is used to look up information for the predefined
// standard priority names.
var standardPriorityMatrix = map[AddressFamily](map[string]standardPriority){
	IP: spmIP,
	// Note: IPv6 standard priorities constants currently have the same values as
	// IPv4's, but the definitions (in the linux kernel) may change in the future.
	IP6: map[string]standardPriority{ // from uapi/linux/netfilter_ipv6.h
		"raw":      {name: "raw", value: linux.NF_IP6_PRI_RAW, hooks: supportedHooks[IP6]},
		"mangle":   {name: "mangle", value: linux.NF_IP6_PRI_MANGLE, hooks: supportedHooks[IP6]},
		"dstnat":   {name: "dstnat", value: linux.NF_IP6_PRI_NAT_DST, hooks: []Hook{Prerouting}},
		"filter":   {name: "filter", value: linux.NF_IP6_PRI_FILTER, hooks: supportedHooks[IP6]},
		"security": {name: "security", value: linux.NF_IP6_PRI_SECURITY, hooks: supportedHooks[IP6]},
		"srcnat":   {name: "srcnat", value: linux.NF_IP6_PRI_NAT_SRC, hooks: []Hook{Postrouting}},
	},
	Inet: spmIP,
	Arp: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooks[Arp]},
	},
	Bridge: map[string]standardPriority{ // from uapi/linux/netfilter_bridge.h
		"dstnat": {name: "dstnat", value: linux.NF_BR_PRI_NAT_DST_BRIDGED, hooks: []Hook{Prerouting}},
		"filter": {name: "filter", value: linux.NF_BR_PRI_FILTER_BRIDGED, hooks: supportedHooks[Bridge]},
		"out":    {name: "out", value: linux.NF_BR_PRI_NAT_DST_OTHER, hooks: []Hook{Output}},
		"srcnat": {name: "srcnat", value: linux.NF_BR_PRI_NAT_SRC, hooks: []Hook{Postrouting}},
	},
	Netdev: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooks[Netdev]},
	},
}

// Used in the standardPriorityMatrix above.
// Note: IPv4 and Inet address families use the same standard priority names.
var spmIP = map[string]standardPriority{ // from uapi/linux/netfilter_ipv4.h
	"raw":      {name: "raw", value: linux.NF_IP_PRI_RAW, hooks: supportedHooks[IP]},
	"mangle":   {name: "mangle", value: linux.NF_IP_PRI_MANGLE, hooks: supportedHooks[IP]},
	"dstnat":   {name: "dstnat", value: linux.NF_IP_PRI_NAT_DST, hooks: []Hook{Prerouting}},
	"filter":   {name: "filter", value: linux.NF_IP_PRI_FILTER, hooks: supportedHooks[IP]},
	"security": {name: "security", value: linux.NF_IP_PRI_SECURITY, hooks: supportedHooks[IP]},
	"srcnat":   {name: "srcnat", value: linux.NF_IP_PRI_NAT_SRC, hooks: []Hook{Postrouting}},
}

// validateBaseChainInfo ensures the base chain info is valid by checking the
// compatibility of the set base chain type, hook, and priority, and the given
// address family.
// Note: errors if the provided base chain info is nil.
func validateBaseChainInfo(info *BaseChainInfo, family AddressFamily) error {
	if info == nil {
		return fmt.Errorf("base chain info is nil")
	}

	// Validates the hook.
	if err := validateHook(info.Hook, family); err != nil {
		return err
	}

	// Validates the base chain type.
	if info.BcType < 0 || info.BcType >= NumBaseChainTypes {
		return fmt.Errorf("invalid base chain type: %d", int(info.BcType))
	}
	if !slices.Contains(supportedAFsForBaseChainTypes[info.BcType], family) {
		return fmt.Errorf("base chain type %s is not valid for address family %s", info.BcType.String(), family.String())
	}
	if !slices.Contains(supportedHooksForBaseChainTypes[info.BcType], info.Hook) {
		return fmt.Errorf("base chain type %s is not valid for hook %s", info.BcType.String(), info.Hook.String())
	}

	// Priority assumed to be valid since it's a result of a constructor call.

	return nil
}

// Rule represents a single rule in a chain.
// TODO(b/345684870): More detailed public description after implementation.
type Rule struct {
	// Implement later
}

// Operation is an interface for all ops that can be performed on a packet.
type Operation interface {
	// Implement later
	Eval() Verdict
}

// Verdict represents verdict statements and are issued (returned) from tables,
// chains, and rules when processing packets to alter the control flow
// of the ruleset and determine the actions and modifications to be performed on
// packets.
type Verdict uint32

const (
	//
	// Absolute verdicts are issued from tables, chains, and rules. These are
	// called absolute because they terminate ruleset evaluation immediately.
	//

	// NftDrop, terminates evaluation and drops the packet, occurs instantly.
	NftDrop Verdict = iota

	// NftAccept, terminates evaluation and accepts the packet; the packet can
	// still be dropped later by another hook or another chain within same hook.
	NftAccept

	//
	// Internal verdicts are issued only for rules and continue/modify evaluation.
	//

	// NftQueue, terminates the current evaluation and queues packet to userspace.
	// Userspace must provide a Drop or Accept verdict. In the case Accept is
	// issued, processing resumes with the next base chain hook, not the rule
	// following the Queue verdict.
	NftQueue

	// NftContinue, continues evaluation with the next rule. This is the default
	// behavior if no verdict is issued.
	NftContinue

	// NftReturn, returns from the current chain and continues evaluation with the
	// next rule in the previous chain. If issued from a base chain (no previous
	// chain), the verdict issued is as specified by the base chain's policy.
	NftReturn

	// NftJump, continues evaluation at the first rule in the specified chain and
	// is set to continue evaluation back at the next rule in the current chain
	// after the specified chain is entirely evaluated or issues a Return (by
	// pushing the current position in the ruleset to a call stack). In the case
	// an absolute verdict is issued from the specified chain, ruleset evaluation
	// terminates immediately as normal.
	NftJump // chain required as argument

	// NftGoto, continues evaluation at the first rule in the specified chain
	// similar to NftJump but doesn't push the current position to a call stack so
	// evaluation doesn't resume at the current chain.
	NftGoto // chain required as argument

	// NumVerdicts is the number of verdicts supported by nftables.
	NumVerdicts
)

// String for Verdict prints names for the supported verdicts.
func (v Verdict) String() string {
	switch v {
	case NftDrop:
		return "Drop"
	case NftAccept:
		return "Accept"
	case NftQueue:
		return "Queue"
	case NftContinue:
		return "Continue"
	case NftReturn:
		return "Return"
	case NftJump:
		return "Jump"
	case NftGoto:
		return "Goto"
	default:
		panic(fmt.Sprintf("invalid verdict: %d", int(v)))
	}
}

// validateVerdict ensures the verdict is valid (can be absolute or internal).
func validateVerdict(verdict Verdict) error {
	// Note verdict is unsigned so it can't be less than 0.
	if verdict >= NumVerdicts {
		return fmt.Errorf("invalid verdict: %d", int(verdict))
	}
	return nil
}

// validateAbsoluteVerdict ensures an absolute verdict (Drop or Accept).
func validateAbsoluteVerdict(verdict Verdict) error {
	if verdict != NftDrop && verdict != NftAccept {
		return fmt.Errorf("invalid absolute verdict: %d", int(verdict))
	}
	return nil
}

//
// Top-Level NFTables Functions
// Note: Provides wrapper functions for the creation and deletion of tables,
// chains, and rules for convenience.
//

// NewNFTables creates a new NFTables object.
// Note: nothing needs to be initialized in the struct before use.
func NewNFTables() *NFTables {
	return &NFTables{}
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
func (nf *NFTables) GetTable(family AddressFamily, tableName string) (*Table, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Checks if the table map for the address family has been initialized.
	if nf.filters[family] == nil || nf.filters[family].tables == nil {
		return nil, fmt.Errorf("address family %s has no tables", family.String())
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables

	// Checks if a table with the name exists.
	t, exists := tableMap[tableName]
	if !exists {
		return nil, fmt.Errorf("table '%s' does not exists for address family %s", tableName, family.String())
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
	errorOnDuplicate bool) (*Table, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Initializes filter if first table for the address family.
	if nf.filters[family] == nil {
		nf.filters[family] = &addressFamilyFilter{
			family:   family,
			tables:   make(map[string]*Table),
			hfStacks: make(map[Hook]*hookFunctionStack),
		}
	}

	// Gets the corresponding table map for the address family.
	tableMap := nf.filters[family].tables

	// Checks if a table with the same name already exists. If so, returns the
	// existing table (unless errorOnDuplicate is true).
	if existingTable, exists := tableMap[name]; exists {
		if errorOnDuplicate {
			return nil, fmt.Errorf("table '%s' already exists in address family %s", name, family.String())
		}
		return existingTable, nil
	}

	// Creates the new table and add it to the table map.
	t := &Table{
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
func (nf *NFTables) CreateTable(family AddressFamily, name string, comment string) (*Table, error) {
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

// EvaluateHook evaluates a packet using the rules of the given hook for the
// given address family, returning an absolute Verdict and the resulting packet.
// Returns an error if address family or hook is invalid or they don't match.
// Note: if there is an error returned, Verdict is NftDrop and packet is nil.
func (nf *NFTables) EvaluateHook(family AddressFamily,
	hook Hook, pkt *stack.PacketBuffer) (Verdict, *stack.PacketBuffer, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return NftDrop, nil, err
	}

	// Ensures hook is valid.
	if err := validateHook(hook, family); err != nil {
		return NftDrop, nil, err
	}

	// Immediately accept if there are no base chains for the specified hook.
	if nf.filters[family] == nil || nf.filters[family].hfStacks[hook] == nil {
		return NftAccept, pkt, nil
	}

	// Evaluates packet through all base chains for given hook in priority order.
	for _, chain := range nf.filters[family].hfStacks[hook].baseChains {
		// Doesn't evaluate chain if it's table is flagged as dormant.
		if _, dormant := chain.table.flagSet[TableFlagDormant]; dormant {
			continue
		}
		// Note: chain.evaluate() returns an absolute verdict.
		newPkt, chainVerdict := chain.evaluate(pkt)
		// Returns immediately if the verdict is Drop.
		if chainVerdict == NftDrop {
			return NftDrop, nil, nil
		}
		pkt = newPkt
	}
	return NftAccept, pkt, nil
}

//
// Table Functions
//

// GetName returns the name of the table.
func (t *Table) GetName() string {
	return t.name
}

// GetAddressFamily returns the address family of the table.
func (t *Table) GetAddressFamily() AddressFamily {
	return t.afFilter.family
}

// GetComment returns the comment of the table.
func (t *Table) GetComment() string {
	return t.comment
}

// SetComment sets the comment of the table.
func (t *Table) SetComment(comment string) {
	t.comment = comment
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

// GetChain returns the chain with the specified name if it exists, error
// otherwise.
func (t *Table) GetChain(chainName string) (*Chain, error) {
	// Checks if a chain with the name exists.
	c, exists := t.chains[chainName]
	if !exists {
		return nil, fmt.Errorf("chain '%s' does not exists for table %s", chainName, t.GetName())
	}
	return c, nil
}

// AddChain makes a new chain for the table. Can return an error if a chain by
// the same name already exists if errorOnDuplicate is true.
func (t *Table) AddChain(name string, info *BaseChainInfo, comment string, errorOnDuplicate bool) (*Chain, error) {
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
		rules:         make([]*Rule, 0, defaultRuleCapacity),
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
			panic(fmt.Sprintf("failed to detach base chain %s from hook %s: %s", c.GetName(), c.baseChainInfo.Hook.String(), err))
		}
		if len(hfStack.baseChains) == 0 {
			delete(t.afFilter.hfStacks, c.baseChainInfo.Hook)
		}
	}

	// Deletes chain.
	delete(t.chains, name)
	return true
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

// GetTable returns the table that the chain belongs to.
func (c *Chain) GetTable() *Table {
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
	hfStack := hfStacks[info.Hook]
	if hfStack == nil {
		hfStack = &hookFunctionStack{
			hook:       info.Hook,
			baseChains: make([]*Chain, 0, defaultBaseChainCapacity),
		}
		hfStacks[info.Hook] = hfStack
	}

	// Sets the base chain info and attaches to the pipeline.
	c.baseChainInfo = info
	hfStack.attachBaseChain(c)

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

// AddRule adds a rule to the chain.
// TODO(b/345684870): Implement this and initialize the Rule in this func
// (i.e. change parameters)
func (c *Chain) AddRule(rule *Rule) {

	// Rules slice is guaranteed to be initialized
	c.rules = append(c.rules, rule)
}

// Chain.evaluate evaluates the packet through the chain's rules.
// Returns a Verdict and the packet (which may be modified).
func (c *Chain) evaluate(pkt *stack.PacketBuffer) (*stack.PacketBuffer, Verdict) {
	// TODO(b/345684870): Implement this by evaluating all rules in a chain in
	// sequential order.
	return pkt, NftAccept
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
		return fmt.Errorf("base chain '%s' does not exist for hook %s", name, hfStack.hook.String())
	}
	if len(hfStack.baseChains) < prevLen-1 {
		panic(fmt.Errorf("multiple base chains with name '%s' exist for hook %s", name, hfStack.hook.String()))
	}
	return nil
}
