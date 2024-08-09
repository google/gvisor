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
	registersByteSize = 64 // 4 16-byte registers or 16 4-byte registers.
	nestedJumpLimit   = 16 // Maximum number of nested jumps allowed,
	// corresponding to NFT_JUMP_STACK_SIZE in include/net/netfilter/nf_tables.h.
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

// Rule represents a single rule in a chain and is represented as a list of
// operations that are evaluated sequentially (on a packet).
// Rules must be registered to a chain to be used and evaluated, and rules that
// have been registered to a chain cannot be modified.
// Note: Empty rules should be created directly (via &Rule{}).
type Rule struct {
	chain *Chain
	ops   []Operation
}

// Operation represents a single operation in a rule.
type Operation interface {

	// TypeString returns the string representation of the type of the operation.
	TypeString() string

	// evaluate evaluates the operation on the given packet and register set,
	// changing the register set and possibly the packet in place.
	evaluate(regs *RegisterSet, pkt *stack.PacketBuffer)
}

// Ensures all operations implement the Operation interface at compile time.
var (
	_ Operation = (*Immediate)(nil)
	_ Operation = (*Comparison)(nil)
)

// Immediate is an operation that sets the data in a register.
type Immediate struct {
	data RegisterData // Data to set the destination register to.
	dreg uint8        // Number of the destination register.
}

// NewImmediate creates a new Immediate operation.
func NewImmediate(dreg uint8, data RegisterData) (*Immediate, error) {
	if err := data.ValidateRegister(dreg); err != nil {
		return nil, err
	}
	return &Immediate{dreg: dreg, data: data}, nil
}

// TypeString for Immediate returns "Immediate" as the string operation type.
func (op *Immediate) TypeString() string { return "Immediate" }

// evaluate for Immediate sets the data in the destination register.
func (op Immediate) evaluate(regs *RegisterSet, pkt *stack.PacketBuffer) {
	op.data.StoreData(regs, op.dreg)
}

// Comparison is an operation that compares the data in a register to a given
// value and breaks (by setting the verdict register to NFT_BREAK) from the rule
// if the comparison is false.
// Note: comparison operators are not supported for verdict registers.
type Comparison struct {
	data RegisterData // Data to compare the source register to.
	sreg uint8        // Number of the source register.
	cop  NftCmpOp     // Comparison operator.
}

// NftCmpOp is the comparison operator for a Comparison operation.
// Note: corresponds to enum nft_cmp_op from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type NftCmpOp int

// String for NftCmpOp returns the string representation of the comparison
// operator.
func (cop NftCmpOp) String() string {
	switch cop {
	case linux.NFT_CMP_EQ:
		return "=="
	case linux.NFT_CMP_NEQ:
		return "!="
	case linux.NFT_CMP_LT:
		return "<"
	case linux.NFT_CMP_LTE:
		return "<="
	case linux.NFT_CMP_GT:
		return ">"
	case linux.NFT_CMP_GTE:
		return ">="
	default:
		return fmt.Sprintf("%d", int(cop))
	}
}

// validateComparisonOp ensures the comparison operator is valid.
func validateComparisonOp(cop NftCmpOp) error {
	switch cop {
	case linux.NFT_CMP_EQ, linux.NFT_CMP_NEQ, linux.NFT_CMP_LT, linux.NFT_CMP_LTE, linux.NFT_CMP_GT, linux.NFT_CMP_GTE:
		return nil
	default:
		return fmt.Errorf("invalid comparison operator: %d", int(cop))
	}
}

// NewComparison creates a new Comparison operation.
func NewComparison(sreg uint8, cop NftCmpOp, data RegisterData) (*Comparison, error) {
	if sreg == linux.NFT_REG_VERDICT {
		return nil, fmt.Errorf("comparison operation cannot use verdict register as source")
	}
	if err := data.ValidateRegister(sreg); err != nil {
		return nil, err
	}
	if err := validateComparisonOp(cop); err != nil {
		return nil, err
	}
	return &Comparison{sreg: sreg, cop: cop, data: data}, nil
}

// TypeString for Comparison returns "Comparison" as the string operation type.
func (op *Comparison) TypeString() string { return "Comparison" }

// evaluate for Comparison compares the data in the source register to the given
// data and breaks from the rule if the comparison is false.
func (op Comparison) evaluate(regs *RegisterSet, pkt *stack.PacketBuffer) {
	// Gets the data to compare to.
	bytesData, ok := op.data.(BytesData)
	if !ok {
		panic("comparison operation data is not BytesData")
	}
	// Gets the data from the source register.
	regBuf := bytesData.getRegisterData(regs, op.sreg)

	// Compares from left to right in 4-byte chunks starting with the rightmost
	// byte of every 4-byte chunk since the data is little endian.
	// For example, 16-byte IPv6 address 2001:000a:130f:0000:0000:09c0:876a:130b
	// is represented as 0x0a000120 0x00000f13 0xc0090000 0x0b136a87 in operations
	// and as [0a|00|01|20|00|00|0f|13|c0|09|00|00|0b|13|6a|87] in the byte slice,
	// so we compare right to left in the first 4 bytes and then go to the next 4.
	dif := 0
	for i := 3; i < len(bytesData.data); {
		if regBuf[i] < bytesData.data[i] {
			dif = -1
			break
		}
		if regBuf[i] > bytesData.data[i] {
			dif = 1
			break
		}
		if i%4 == 0 {
			i += 8
		}
		i--
	}
	switch op.cop {
	case linux.NFT_CMP_EQ:
		if dif == 0 {
			return
		}
	case linux.NFT_CMP_NEQ:
		if dif != 0 {
			return
		}
	case linux.NFT_CMP_LT:
		if dif < 0 {
			return
		}
	case linux.NFT_CMP_LTE:
		if dif <= 0 {
			return
		}
	case linux.NFT_CMP_GT:
		if dif > 0 {
			return
		}
	case linux.NFT_CMP_GTE:
		if dif >= 0 {
			return
		}
	}
	// Comparison is false, so break from the rule.
	regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
}

//
// Register and Register-Related Implementations.
// Note: Registers are represented by type uint8 for the register number.
//

func isVerdictRegister(reg uint8) bool {
	return reg == linux.NFT_REG_VERDICT
}

func is16ByteRegister(reg uint8) bool {
	return reg >= linux.NFT_REG_1 && reg <= linux.NFT_REG_4
}

func is4ByteRegister(reg uint8) bool {
	return reg >= linux.NFT_REG32_00 && reg <= linux.NFT_REG32_15
}

func isRegister(reg uint8) bool {
	return isVerdictRegister(reg) || is16ByteRegister(reg) || is4ByteRegister(reg)
}

// RegisterDataType is the type of data to be set in a register.
type RegisterDataType int

const (
	// DataVerdict represents a verdict to be stored in a register.
	DataVerdict RegisterDataType = iota
	// Data4Bytes represents 4 bytes of data to be stored in a register.
	Data4Bytes
	// Data16Bytes represents 16 bytes of data to be stored in a register.
	Data16Bytes
)

// RegisterData represents the data to be set in a register.
type RegisterData interface {
	// String returns a string representation of the register data.
	String() string

	// Equal compares the register data to another.
	Equal(other RegisterData) bool

	// ValidateRegister ensures the register is compatible with the data type,
	// returning an error otherwise.
	ValidateRegister(reg uint8) error

	// StoreData sets the data in the destination register, panicking if the
	// register is not valid for the data type.
	// Note: assumes data is valid for register. This is used primarily during
	// operation evaluation and the data type/register compatibility should have
	// been checked during the operation init.
	StoreData(regs *RegisterSet, reg uint8)
}

// VerdictData represents a verdict as data to be stored in a register.
type VerdictData struct {
	data Verdict
}

// NewVerdictData creates a RegisterData for a verdict.
func NewVerdictData(verdict Verdict) RegisterData { return VerdictData{data: verdict} }

// String returns a string representation of the verdict data.
func (rd VerdictData) String() string {
	return rd.data.String()
}

// Equal compares the verdict data to another RegisterData object.
func (rd VerdictData) Equal(other RegisterData) bool {
	if other == nil {
		return false
	}
	otherVD, ok := other.(VerdictData)
	if !ok {
		return false
	}
	return rd.data == otherVD.data
}

// ValidateRegister ensures the register is compatible with VerdictData.
func (rd VerdictData) ValidateRegister(reg uint8) error {
	if !isVerdictRegister(reg) {
		return fmt.Errorf("verdict can only be stored in verdict register")
	}
	return nil
}

// StoreData sets the data in the destination register to the verdict.
func (rd VerdictData) StoreData(regs *RegisterSet, reg uint8) {
	if err := rd.ValidateRegister(reg); err != nil {
		panic(err)
	}
	regs.verdict = rd.data
}

// BytesData represents a 4 or 16 bytes of data to be stored in a register.
type BytesData struct {
	data []byte
}

// NewBytesData creates a RegisterData for 4 or 16 bytes of data.
func NewBytesData(bytes []byte) RegisterData {
	if len(bytes)%4 != 0 || len(bytes) > 16 {
		panic(fmt.Errorf("invalid byte data length: %d", len(bytes)))
	}
	return BytesData{data: bytes}
}

// String returns a string representation of the bytes data.
func (rd BytesData) String() string {
	return fmt.Sprintf("%x", rd.data)
}

// Equal compares the bytes data to another RegisterData object.
func (rd BytesData) Equal(other RegisterData) bool {
	if other == nil {
		return false
	}
	otherBD, ok := other.(BytesData)
	if !ok {
		return false
	}
	return slices.Equal(rd.data, otherBD.data)
}

// ValidateRegister ensures the register is compatible with Bytes4Data.
func (rd BytesData) ValidateRegister(reg uint8) error {
	if isVerdictRegister(reg) {
		return fmt.Errorf("data cannot be stored in verdict register")
	}
	if is4ByteRegister(reg) {
		if len(rd.data) != 4 {
			return fmt.Errorf("%d-byte data cannot be stored in 4-byte register", len(rd.data))
		}
	}
	// 16-byte register can be used for any data (guaranteed to be <= 16 bytes)
	return nil
}

// getRegisterData is a helper function that gets the appropriate slice of
// register data from the register set.
// Note: does not support verdict data and assumes the register is valid for the
// given data type.
func (rd BytesData) getRegisterData(regs *RegisterSet, reg uint8) []byte {
	// The entire 4-byte register (data must be exactly 4 bytes)
	if is4ByteRegister(reg) {
		start := (reg - linux.NFT_REG32_00) * linux.NFT_REG32_SIZE
		return regs.data[start : start+linux.NFT_REG32_SIZE]
	}
	// The appropriate (mod 4)-byte data in a 16-byte register
	// Leaves excess space on the left (bc the data is little endian).
	end := (int(reg)-linux.NFT_REG_1)*linux.NFT_REG_SIZE + linux.NFT_REG_SIZE
	return regs.data[end-len(rd.data) : end]
}

// StoreData sets the data in the destination register to the uint32.
func (rd BytesData) StoreData(regs *RegisterSet, reg uint8) {
	if err := rd.ValidateRegister(reg); err != nil {
		panic(err)
	}
	regBuf := rd.getRegisterData(regs, reg)
	copy(regBuf, rd.data)
}

// RegisterSet represents the set of registers supported by the kernel.
// Use RegisterData.StoreData to set data in the registers.
// Note: Corresponds to nft_regs from include/net/netfilter/nf_tables.h.
type RegisterSet struct {
	verdict Verdict                 // 16-byte verdict register
	data    [registersByteSize]byte // 4 16-byte registers or 16 4-byte registers
}

// NewRegisterSet creates a new RegisterSet with the Continue Verdict and all
// registers set to 0.
func NewRegisterSet() RegisterSet {
	return RegisterSet{
		verdict: Verdict{Code: VC(linux.NFT_CONTINUE)},
		data:    [registersByteSize]byte{0},
	}
}

// Verdict returns the verdict data.
func (regs *RegisterSet) Verdict() Verdict {
	return regs.verdict
}

//
// Verdict Implementation.
// There are two types of verdicts:
// 1. Netfilter (External) Verdicts: Drop, Accept, Stolen, Queue, Repeat, Stop
// 		These are terminal verdicts that are returned to the kernel.
// 2. Nftable (Internal) Verdicts:, Continue, Break, Jump, Goto, Return
// 		These are internal verdicts that only exist within the nftables library.
// Both share the same numeric space (uint32 Verdict Code).
//

// Verdict represents the result of evaluating a packet against a rule or chain.
type Verdict struct {
	// Code is the numeric code that represents the verdict issued.
	Code uint32

	// ChainName is the name of the chain to continue evaluation if the verdict is
	// Jump or Goto.
	// Note: the chain must be in the same table as the current chain.
	ChainName string
}

// String returns a string representation of the verdict.
func (v Verdict) String() string {
	out := VerdictCodeToString(v.Code)
	if v.ChainName != "" {
		out += fmt.Sprintf(" -> %s", v.ChainName)
	}
	return out
}

// VC converts a numeric code to a uint32 number representing the verdict.
func VC(v int32) uint32 {
	return uint32(v)
}

// VerdictCodeToString prints names for the supported verdicts.
func VerdictCodeToString(v uint32) string {
	switch v {
	// Netfilter (External) Verdicts:
	case VC(linux.NF_DROP):
		return "Drop"
	case VC(linux.NF_ACCEPT):
		return "Accept"
	case VC(linux.NF_STOLEN):
		return "Stolen"
	case VC(linux.NF_QUEUE):
		return "Queue"
	case VC(linux.NF_REPEAT):
		return "Repeat"
	case VC(linux.NF_STOP):
		return "Stop"
	// Nftable (Internal) Verdicts:
	case VC(linux.NFT_CONTINUE):
		return "Continue"
	case VC(linux.NFT_BREAK):
		return "Break"
	case VC(linux.NFT_JUMP):
		return "Jump"
	case VC(linux.NFT_GOTO):
		return "Goto"
	case VC(linux.NFT_RETURN):
		return "Return"
	default:
		panic(fmt.Sprintf("invalid verdict: %d", int(v)))
	}
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------

//
// Core Evaluation Functions
//

// EvaluateHook evaluates a packet using the rules of the given hook for the
// given address family, returning a netfilter verdict and modifying the packet
// in place.
// Returns an error if address family or hook is invalid or they don't match.
// TODO(b/345684870): Consider removing error case if we never return an error.
func (nf *NFTables) EvaluateHook(family AddressFamily, hook Hook, pkt *stack.PacketBuffer) (Verdict, error) {
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

	regs := NewRegisterSet()

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
func (c *Chain) evaluateFromRule(rIdx int, jumpDepth int, regs *RegisterSet, pkt *stack.PacketBuffer) error {
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
func (c *Chain) evaluate(regs *RegisterSet, pkt *stack.PacketBuffer) error {
	return c.evaluateFromRule(0, 0, regs, pkt)
}

// evaluate evaluates the rule on the given packet and register set, changing
// the register set and possibly the packet in place.
// The verdict in regs.Verdict() may be an nf table internal verdict or a
// netfilter terminal verdict.
func (r *Rule) evaluate(regs *RegisterSet, pkt *stack.PacketBuffer) error {
	for _, op := range r.ops {
		op.evaluate(regs, pkt)
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
func (c *Chain) RegisterRule(rule *Rule, index int) error {
	if rule.chain != nil {
		return fmt.Errorf("rule is already registered to a chain")
	}

	if index < -1 || index > len(c.rules) {
		return fmt.Errorf("invalid index %d for rule registration", index)
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
	if index == -1 || index == len(c.rules) {
		c.rules = append(c.rules, rule)
	} else {
		c.rules = slices.Insert(c.rules, index, rule)
	}
	return nil
}

// UnregisterRule removes the rule at the given index from the chain's rule list
// and unassigns the chain from the rule then returns the unregistered rule.
// Valid indices are -1 (pop) and [0, len-1]. Panics on invalid index.
func (c *Chain) UnregisterRule(index int) *Rule {
	rule, err := c.GetRule(index)
	if err != nil {
		panic(fmt.Sprintf("invalid index %d for rule registration", index))
	}
	if index == -1 {
		index = len(c.rules) - 1
	}
	c.rules = append(c.rules[:index], c.rules[index+1:]...)
	rule.chain = nil
	return rule
}

// GetRule returns the rule at the given index in the chain's rule list.
// Valid indices are -1 (last) and [0, len-1]. Errors on invalid index.
func (c *Chain) GetRule(index int) (*Rule, error) {
	if index < -1 || index > len(c.rules)-1 {
		return nil, fmt.Errorf("invalid index %d for rule retrieval", index)
	}
	if index == -1 {
		return c.rules[len(c.rules)-1], nil
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
func isJumpOrGotoOperation(op Operation) (bool, string) {
	imm, ok := op.(*Immediate)
	if !ok {
		return false, ""
	}
	verdictData, ok := imm.data.(VerdictData)
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

// AddOperation adds an operation to the rule. Adding operations is only allowed
// before the rule is registered to a chain. Returns an error if the operation
// is nil or if the rule is already registered to a chain.
func (r *Rule) AddOperation(op Operation) error {
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
		return fmt.Errorf("base chain '%s' does not exist for hook %s", name, hfStack.hook.String())
	}
	if len(hfStack.baseChains) < prevLen-1 {
		panic(fmt.Errorf("multiple base chains with name '%s' exist for hook %s", name, hfStack.hook.String()))
	}
	return nil
}
