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
// Inner Headers and Tunneling Headers are not supported.
//
// Finally, note that error checking for parameters/inputs is only guaranteed
// for public functions. Most private functions are assumed to have
// valid/prechecked inputs.
package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"slices"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TODO(b/345684870): Break this file up into multiple files by operation type.
// Each operation should get its own file.
// TODO(b/345684870): Make the nftables package thread-safe! Must be done before
// the package is used in production.

// Defines general constants for the nftables interpreter.
const (

	// Number of bytes for 4 16-byte registers or 16 4-byte registers.
	registersByteSize = 64

	// Maximum number of nested jumps allowed, corresponding to
	// NFT_JUMP_STACK_SIZE in include/net/netfilter/nf_tables.h.
	nestedJumpLimit = 16

	// Limit (exclusive) for number of buts that can be shifted for non-boolean
	// bitwise operations.
	bitshiftLimit = 32
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

// addressFamilyStrings maps address families to their string representation.
var addressFamilyStrings = map[AddressFamily]string{
	IP:     "IPv4",
	IP6:    "IPv6",
	Inet:   "Internet (Both IPv4/IPv6)",
	Arp:    "ARP",
	Bridge: "Bridge",
	Netdev: "Netdev",
}

// String for AddressFamily returns the name of the address family.
func (f AddressFamily) String() string {
	if af, ok := addressFamilyStrings[f]; ok {
		return af
	}
	panic(fmt.Sprintf("invalid address family: %d", int(f)))
}

// addressFamilyProtocols maps address families to their protocol number.
var addressFamilyProtocols = map[AddressFamily]uint8{
	IP:     linux.NFPROTO_INET,
	IP6:    linux.NFPROTO_IPV6,
	Inet:   linux.NFPROTO_IPV6,
	Arp:    linux.NFPROTO_ARP,
	Bridge: linux.NFPROTO_BRIDGE,
	Netdev: linux.NFPROTO_NETDEV,
}

// Protocol returns the protocol number for the address family.
func (f AddressFamily) Protocol() uint8 {
	if protocol, ok := addressFamilyProtocols[f]; ok {
		return protocol
	}
	panic(fmt.Sprintf("invalid address family: %d", int(f)))
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

// hookStrings maps hooks to their string representation.
var hookStrings = map[Hook]string{
	Prerouting:  "Prerouting",
	Input:       "Input",
	Forward:     "Forward",
	Output:      "Output",
	Postrouting: "Postrouting",
	Ingress:     "Ingress",
	Egress:      "Egress",
}

// String for Hook returns the name of the hook.
func (h Hook) String() string {
	if hook, ok := hookStrings[h]; ok {
		return hook
	}
	panic(fmt.Sprintf("invalid hook: %d", int(h)))
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

	return fmt.Errorf("hook %v is not valid for address family %v", hook, family)
}

// NFTables represents the nftables state for all address families.
// Note: unlike iptables, nftables doesn't start with any initialized tables.
type NFTables struct {
	filters   [NumAFs]*addressFamilyFilter // Filters for each address family.
	clock     tcpip.Clock                  // Clock for timing evaluations.
	startTime time.Time                    // Time NFTables object was created.
	rng       *rand.Rand                   // Random number generator.
}

// addressFamilyFilter represents the nftables state for a specific address
// family.
type addressFamilyFilter struct {
	// family is the address family of the filter.
	family AddressFamily

	// nftState is the NFTables object the filter belongs to.
	nftState *NFTables

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

// baseChainTypeStrings maps base chain types to their string representation.
var baseChainTypeStrings = map[BaseChainType]string{
	BaseChainTypeFilter: "filter",
	BaseChainTypeNat:    "nat",
	BaseChainTypeRoute:  "route",
}

// String for BaseChainType returns the name of the base chain type.
func (bcType BaseChainType) String() string {
	if bcTypeString, ok := baseChainTypeStrings[bcType]; ok {
		return bcTypeString
	}
	panic(fmt.Sprintf("invalid base chain type: %d", int(bcType)))
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
		return Priority{}, fmt.Errorf("standard priority names are not available for address family %v", family)
	}
	sp, exists := familyMatrix[name]
	if !exists {
		return Priority{}, fmt.Errorf("standard priority name '%s' is not compatible with address family %v", name, family)
	}

	// Checks for hook compatibility.
	if !slices.Contains(sp.hooks, hook) {
		return Priority{}, fmt.Errorf("standard priority %s is not compatible with hook %v", name, hook)
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
		return fmt.Errorf("base chain type %v is not valid for address family %v", info.BcType, family)
	}
	if !slices.Contains(supportedHooksForBaseChainTypes[info.BcType], info.Hook) {
		return fmt.Errorf("base chain type %v is not valid for hook %v", info.BcType, info.Hook)
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
	ops   []operation
}

// operation represents a single operation in a rule.
type operation interface {

	// evaluate evaluates the operation on the given packet and register set,
	// changing the register set and possibly the packet in place. We pass the
	// assigned rule to allow the operation to access parts of the NFTables state.
	evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule)
}

// Ensures all operations implement the Operation interface at compile time.
var (
	_ operation = (*immediate)(nil)
	_ operation = (*comparison)(nil)
	_ operation = (*ranged)(nil)
	_ operation = (*payloadLoad)(nil)
	_ operation = (*payloadSet)(nil)
	_ operation = (*bitwise)(nil)
	_ operation = (*counter)(nil)
	_ operation = (*last)(nil)
	_ operation = (*route)(nil)
	_ operation = (*byteorder)(nil)
	_ operation = (*metaLoad)(nil)
)

// immediate is an operation that sets the data in a register.
type immediate struct {
	data registerData // Data to set the destination register to.
	dreg uint8        // Number of the destination register.
}

// newImmediate creates a new immediate operation.
func newImmediate(dreg uint8, data registerData) (*immediate, error) {
	if err := data.validateRegister(dreg); err != nil {
		return nil, err
	}
	return &immediate{dreg: dreg, data: data}, nil
}

// evaluate for Immediate sets the data in the destination register.
func (op immediate) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	op.data.storeData(regs, op.dreg)
}

// comparison is an operation that compares the data in a register to a given
// value and breaks (by setting the verdict register to NFT_BREAK) from the rule
// if the comparison is false.
// Note: comparison operations are not supported for the verdict register.
type comparison struct {
	data bytesData // Data to compare the source register to.
	sreg uint8     // Number of the source register.
	cop  cmpOp     // Comparison operator.
}

// cmpOp is the comparison operator for a Comparison operation.
// Note: corresponds to enum nft_cmp_op from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type cmpOp int

// cmpOpStrings is a map of cmpOp to its string representation.
var cmpOpStrings = map[cmpOp]string{
	linux.NFT_CMP_EQ:  "==",
	linux.NFT_CMP_NEQ: "!=",
	linux.NFT_CMP_LT:  "<",
	linux.NFT_CMP_LTE: "<=",
	linux.NFT_CMP_GT:  ">",
	linux.NFT_CMP_GTE: ">=",
}

// String for cmpOp returns string representation of the comparison operator.
func (cop cmpOp) String() string {
	if copStr, ok := cmpOpStrings[cop]; ok {
		return copStr
	}
	panic(fmt.Sprintf("invalid comparison operator: %d", int(cop)))
}

// validateComparisonOp ensures the comparison operator is valid.
func validateComparisonOp(cop cmpOp) error {
	switch cop {
	case linux.NFT_CMP_EQ, linux.NFT_CMP_NEQ, linux.NFT_CMP_LT, linux.NFT_CMP_LTE, linux.NFT_CMP_GT, linux.NFT_CMP_GTE:
		return nil
	default:
		return fmt.Errorf("invalid comparison operator: %d", int(cop))
	}
}

// newComparison creates a new comparison operation.
func newComparison(sreg uint8, op int, data []byte) (*comparison, error) {
	if isVerdictRegister(sreg) {
		return nil, fmt.Errorf("comparison operation cannot use verdict register as source")
	}
	bytesData := newBytesData(data)
	if err := bytesData.validateRegister(sreg); err != nil {
		return nil, err
	}
	cop := cmpOp(op)
	if err := validateComparisonOp(cop); err != nil {
		return nil, err
	}
	return &comparison{sreg: sreg, cop: cop, data: bytesData}, nil
}

// evaluate for Comparison compares the data in the source register to the given
// data and breaks from the rule if the comparison is false.
func (op comparison) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the data to compare to.
	data := op.data.data

	// Gets the data from the source register.
	regBuf := getRegisterBuffer(regs, op.sreg)[:len(data)]

	// Compares bytes from left to right for all bytes in the comparison data.
	dif := bytes.Compare(regBuf, data)

	// Determines the comparison result depending on the operator.
	var result bool
	switch op.cop {
	case linux.NFT_CMP_EQ:
		result = dif == 0
	case linux.NFT_CMP_NEQ:
		result = dif != 0
	case linux.NFT_CMP_LT:
		result = dif < 0
	case linux.NFT_CMP_LTE:
		result = dif <= 0
	case linux.NFT_CMP_GT:
		result = dif > 0
	case linux.NFT_CMP_GTE:
		result = dif >= 0
	}
	if !result {
		// Comparison is false, so break from the rule.
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
	}
}

// ranged is an operation that checks whether the data in a register is between
// an inclusive range and breaks if the comparison is false.
// Note: ranged operations are not supported for the verdict register.
// Note: named "ranged" because "range" is a reserved keyword in Go.
type ranged struct {
	low  bytesData // Data to compare the source register to.
	high bytesData // Data to compare the source register to.
	sreg uint8     // Number of the source register.
	rop  rngOp     // Range operator.

	// Note: The linux kernel defines the range operation, but we have not been
	// able to observe it used by the nft binary. For any commands that may use
	// range, the nft binary seems to use two comparison operations instead. Thus,
	// there is no interpretation of the range operation via the nft binary debug
	// output, but the operation is fully supported and implemented.
}

// rngOp is the range operator for a Ranged operation.
// Note: corresponds to enum nft_range_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type rngOp int

// rngOpStrings is a map of rngOp to its string representation.
var rngOpStrings = map[rngOp]string{
	linux.NFT_RANGE_EQ:  "range ==",
	linux.NFT_RANGE_NEQ: "range !=",
}

// String for rngOp returns string representation of the range operator.
func (rop rngOp) String() string {
	if ropStr, ok := rngOpStrings[rop]; ok {
		return ropStr
	}
	panic(fmt.Sprintf("invalid range operator: %d", int(rop)))
}

// validateRangeOp ensures the range operator is valid.
func validateRangeOp(rop rngOp) error {
	switch rop {
	case linux.NFT_RANGE_EQ, linux.NFT_RANGE_NEQ:
		return nil
	default:
		return fmt.Errorf("invalid range operator: %d", int(rop))
	}
}

// newRanged creates a new ranged operation.
func newRanged(sreg uint8, op int, low, high []byte) (*ranged, error) {
	if isVerdictRegister(sreg) {
		return nil, fmt.Errorf("comparison operation cannot use verdict register as source")
	}
	if len(low) != len(high) {
		return nil, fmt.Errorf("upper and lower bounds for ranged operation must be the same length")
	}
	lowData := newBytesData(low)
	if err := lowData.validateRegister(sreg); err != nil {
		return nil, err
	}
	highData := newBytesData(high)
	if err := highData.validateRegister(sreg); err != nil {
		return nil, err
	}
	rop := rngOp(op)
	if err := validateRangeOp(rop); err != nil {
		return nil, err
	}
	return &ranged{sreg: sreg, rop: rop, low: lowData, high: highData}, nil
}

// evaluate for Ranged checks whether the source register data is within the
// specified inclusive range and breaks from the rule if comparison is false.
func (op ranged) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the upper and lower bounds as bytesData.
	low, high := op.low.data, op.high.data

	// Gets the data from the source register.
	regBuf := getRegisterBuffer(regs, op.sreg)[:len(low)]

	// Compares register data to both lower and upper bounds.
	d1 := bytes.Compare(regBuf, low)
	d2 := bytes.Compare(regBuf, high)

	// Determines the comparison result depending on the operator.
	if (d1 >= 0 && d2 <= 0) != (op.rop == linux.NFT_RANGE_EQ) {
		// Comparison is false, so break from the rule.
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
	}
}

// payloadLoad is an operation that loads data from the packet payload into a
// register.
// Note: payload operations are not supported for the verdict register.
type payloadLoad struct {
	base   payloadBase // Payload base to access data from.
	offset uint8       // Number of bytes to skip after the base.
	blen   uint8       // Number of bytes to load.
	dreg   uint8       // Number of the destination register.
}

// payloadBase is the header that determines the location of the packet data.
// Note: corresponds to enum nft_payload_bases from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type payloadBase int

// payloadBaseStrings is a map of payloadBase to its string representation.
var payloadBaseStrings = map[payloadBase]string{
	linux.NFT_PAYLOAD_LL_HEADER:        "Link Layer Header",
	linux.NFT_PAYLOAD_NETWORK_HEADER:   "Network Header",
	linux.NFT_PAYLOAD_TRANSPORT_HEADER: "Transport Header",
	linux.NFT_PAYLOAD_INNER_HEADER:     "Inner Header",
	linux.NFT_PAYLOAD_TUN_HEADER:       "Tunneling Header",
}

// String for payloadBase returns the string representation of the payload base.
func (base payloadBase) String() string {
	if baseStr, ok := payloadBaseStrings[base]; ok {
		return baseStr
	}
	panic(fmt.Sprintf("Invalid Payload Base: %d", int(base)))
}

// validatePayloadBase ensures the payload base is valid.
func validatePayloadBase(base payloadBase) error {
	switch base {
	// Supported payload bases.
	case linux.NFT_PAYLOAD_LL_HEADER, linux.NFT_PAYLOAD_NETWORK_HEADER, linux.NFT_PAYLOAD_TRANSPORT_HEADER:
		return nil
	// Unsupported payload bases.
	default:
		return fmt.Errorf("invalid payload base: %d", int(base))
	}
}

// getPayloadBuffer gets the data from the packet payload starting from the
// the beginning of the specified base header.
// Returns nil if the payload is not present or invalid.
func getPayloadBuffer(pkt *stack.PacketBuffer, base payloadBase) []byte {
	switch base {
	case linux.NFT_PAYLOAD_LL_HEADER:
		// Note: Assumes Mac Header is present and valid for necessary use cases.
		// Also, doesn't check VLAN tag because VLAN isn't supported by gVisor.
		return pkt.LinkHeader().Slice()
	case linux.NFT_PAYLOAD_NETWORK_HEADER:
		// No checks done in linux kernel.
		return pkt.NetworkHeader().Slice()
	case linux.NFT_PAYLOAD_TRANSPORT_HEADER:
		// Note: Assumes L4 protocol is present and valid for necessary use cases.

		// Errors if the packet is fragmented for IPv4 only.
		if net := pkt.NetworkHeader().Slice(); len(net) > 0 && pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			if h := header.IPv4(net); h.More() || h.FragmentOffset() != 0 {
				break // packet is fragmented
			}
		}
		return pkt.TransportHeader().Slice()
	}
	return nil
}

// newPayloadLoad creates a new payloadLoad operation.
func newPayloadLoad(base payloadBase, offset, blen, dreg uint8) (*payloadLoad, error) {
	if isVerdictRegister(dreg) {
		return nil, fmt.Errorf("payload load operation cannot use verdict register as destination")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && is4ByteRegister(dreg)) {
		return nil, fmt.Errorf("payload length %d is too long for destination register %d", blen, dreg)
	}
	if err := validatePayloadBase(base); err != nil {
		return nil, err
	}
	return &payloadLoad{base: base, offset: offset, blen: blen, dreg: dreg}, nil
}

// evaluate for PayloadLoad loads data from the packet payload into the
// destination register.
func (op payloadLoad) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the packet payload.
	payload := getPayloadBuffer(pkt, op.base)

	// Breaks if could not retrieve packet data.
	if payload == nil || len(payload) < int(op.offset+op.blen) {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Copies payload data into the specified register.
	data := newBytesData(payload[op.offset : op.offset+op.blen])
	data.storeData(regs, op.dreg)
}

// payloadSet is an operation that sets data in the packet payload to the value
// in a register.
// Note: payload operations are not supported for the verdict register.
type payloadSet struct {
	base       payloadBase // Payload base to access data from.
	offset     uint8       // Number of bytes to skip after the base for data.
	blen       uint8       // Number of bytes to load.
	sreg       uint8       // Number of the source register.
	csumType   uint8       // Type of checksum to use.
	csumOffset uint8       // Number of bytes to skip after the base for checksum.
	csumFlags  uint8       // Flags for checksum.

	// Note: the only flag defined for csumFlags is NFT_PAYLOAD_L4CSUM_PSEUDOHDR.
	// This flag is used to update L4 checksums whenever there has been a change
	// to a field that is part of the pseudo-header for the L4 checksum, not when
	// data within the L4 header is changed (instead setting csumType to
	// NFT_PAYLOAD_CSUM_INET suffices for that case).

	// For example, if any part of the L4 header is changed, csumType is set to
	// NFT_PAYLOAD_CSUM_INET and no flag is set for csumFlags since we only need
	// to update the checksum of the header specified by the payload base.
	// On the other hand, if data in the L3 header is changed that is part of
	// the pseudo-header for the L4 checksum (like saddr/daddr), csumType is set
	// to NFT_PAYLOAD_CSUM_INET and csumFlags to NFT_PAYLOAD_L4CSUM_PSEUDOHDR
	// because in addition to updating the checksum for the header specified by
	// the payload base, we need to separately locate and update the L4 checksum.
}

// validateChecksumType ensures the checksum type is valid.
func validateChecksumType(csumType uint8) error {
	switch csumType {
	case linux.NFT_PAYLOAD_CSUM_NONE:
		return nil
	case linux.NFT_PAYLOAD_CSUM_INET:
		return nil
	case linux.NFT_PAYLOAD_CSUM_SCTP:
		return fmt.Errorf("SCTP checksum not supported")
	default:
		return fmt.Errorf("invalid checksum type: %d", csumType)
	}
}

// newPayloadSet creates a new payloadSet operation.
func newPayloadSet(base payloadBase, offset, blen, sreg, csumType, csumOffset, csumFlags uint8) (*payloadSet, error) {
	if isVerdictRegister(sreg) {
		return nil, fmt.Errorf("payload set operation cannot use verdict register as destination")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && is4ByteRegister(sreg)) {
		return nil, fmt.Errorf("payload length %d is too long for destination register %d", blen, sreg)
	}
	if err := validatePayloadBase(base); err != nil {
		return nil, err
	}
	if err := validateChecksumType(csumType); err != nil {
		return nil, err
	}
	if csumFlags&^linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
		return nil, fmt.Errorf("invalid checksum flags: %d", csumFlags)
	}
	return &payloadSet{base: base, offset: offset, blen: blen, sreg: sreg,
		csumType: csumType, csumOffset: csumOffset, csumFlags: csumFlags}, nil
}

// evaluate for PayloadSet sets data in the packet payload to the value in the
// source register.
func (op payloadSet) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the packet payload.
	payload := getPayloadBuffer(pkt, op.base)

	// Breaks if could not retrieve packet data.
	if payload == nil || len(payload) < int(op.offset+op.blen) {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Gets the register data assumed to be in Big Endian.
	regData := getRegisterBuffer(regs, op.sreg)[:op.blen]

	// Returns early if the source data is the same as the existing payload data.
	if slices.Equal(regData, payload[op.offset:op.offset+op.blen]) {
		return
	}

	// Sets payload data to source register data after checksum updates.
	defer copy(payload[op.offset:op.offset+op.blen], regData)

	// Specifies no checksum updates.
	if op.csumType != linux.NFT_PAYLOAD_CSUM_INET && op.csumFlags == 0 {
		return
	}

	// Calculates partial checksums of old and new data.
	// Note: Checksums are done on 2-byte boundaries, so we must append the
	// surrounding bytes in our checksum calculations if the beginning or end
	// of the checksum is not aligned to a 2-byte boundary.
	begin := op.offset
	end := op.offset + op.blen
	if begin%2 != 0 {
		begin--
	}
	if end%2 != 0 && end != uint8(len(payload)) {
		end++
	}
	tempOld := make([]byte, end-begin)
	copy(tempOld, payload[begin:end])
	tempNew := make([]byte, end-begin)
	if begin != op.offset {
		tempNew[0] = payload[begin]
	}
	copy(tempNew[op.offset-begin:], regData)
	if end != op.offset+op.blen {
		tempNew[len(tempNew)-1] = payload[end-1]
	}
	oldDataCsum := checksum.Checksum(tempOld, 0)
	newDataCsum := checksum.Checksum(tempNew, 0)

	// Updates the checksum of the header specified by the payload base.
	if op.csumType == linux.NFT_PAYLOAD_CSUM_INET {
		// Reads the old checksum from the packet payload.
		oldTotalCsum := binary.BigEndian.Uint16(payload[op.csumOffset:])

		// New Total = Old Total - Old Data + New Data
		// Logic is very similar to checksum.checksumUpdate2ByteAlignedUint16
		// in gvisor/pkg/tcpip/header/checksum.go
		newTotalCsum := checksum.Combine(^oldTotalCsum, checksum.Combine(newDataCsum, ^oldDataCsum))
		checksum.Put(payload[op.csumOffset:], ^newTotalCsum)
	}

	// Separately updates the L4 checksum if the pseudo-header flag is set.
	// Note: it is possible to update the L4 checksum without updating the
	// checksum of the header specified by the payload base (ie type is NONE,
	// flag is pseudo-header). Specifically, IPv6 headers don't have their
	// own checksum calculations, but the L4 checksum is still updated for any
	// TCP/UDP headers following the IPv6 header.
	if op.csumFlags&linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
		if tBytes := pkt.TransportHeader().Slice(); pkt.TransportProtocolNumber != 0 && len(tBytes) > 0 {
			var transport header.Transport
			switch pkt.TransportProtocolNumber {
			case header.TCPProtocolNumber:
				transport = header.TCP(tBytes)
			case header.UDPProtocolNumber:
				transport = header.UDP(tBytes)
			case header.ICMPv4ProtocolNumber:
				transport = header.ICMPv4(tBytes)
			case header.ICMPv6ProtocolNumber:
				transport = header.ICMPv6(tBytes)
			case header.IGMPProtocolNumber:
				transport = header.IGMP(tBytes)
			}
			if transport != nil { // only updates if the transport header is present.
				// New Total = Old Total - Old Data + New Data (same as above)
				transport.SetChecksum(^checksum.Combine(^transport.Checksum(), checksum.Combine(newDataCsum, ^oldDataCsum)))
			}
		}
	}
}

// bitwiseOp is the bitwise operator for a bitwise operation.
// Note: corresponds to enum nft_bitwise_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type bitwiseOp int

// bitwiseOpStrings is a map of bitwiseOp to its string representation.
var bitwiseOpStrings = map[bitwiseOp]string{
	linux.NFT_BITWISE_BOOL:   "bitwise boolean",
	linux.NFT_BITWISE_LSHIFT: "bitwise <<",
	linux.NFT_BITWISE_RSHIFT: "bitwise >>",
}

// String for bitwiseOp returns the string representation of the bitwise
// operator.
func (bop bitwiseOp) String() string {
	if str, ok := bitwiseOpStrings[bop]; ok {
		return str
	}
	panic(fmt.Sprintf("invalid bitwise operator: %d", int(bop)))
}

// bitwise is an operation that performs bitwise math operations over data in
// a given register, storing the result in a destination register.
// Note: bitwise operations are not supported for the verdict register.
type bitwise struct {
	sreg  uint8     // Number of the source register.
	dreg  uint8     // Number of the destination register.
	bop   bitwiseOp // Bitwise operator to use.
	blen  uint8     // Number of bytes to apply bitwise operation to.
	mask  bytesData // Mask to apply bitwise & for boolean operations (before ^).
	xor   bytesData // Xor to apply bitwise ^ for boolean operations (after &).
	shift uint32    // Shift to apply bitwise <</>> for non-boolean operations.

	// Note: Technically, the linux kernel has defined bool, lshift, and rshift
	// as the 3 types of bitwise operations. However, we have not been able to
	// observe the lshift or rshift operations used by the nft binary. Thus, we
	// have no way to test the interpretation of these operations. Maintaining
	// consistency with the linux kernel, we have fully implemented lshift and
	// rshift, and We will leave the code here in case we are able to observe
	// their use in the future (perhaps outside the nft binary debug output).
}

// newBitwiseBool creates a new bitwise boolean operation.
func newBitwiseBool(sreg, dreg uint8, mask, xor []byte) (*bitwise, error) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, fmt.Errorf("bitwise operation cannot use verdict register as source or destination")
	}
	blen := len(mask)
	if blen != len(xor) {
		return nil, fmt.Errorf("bitwise boolean operation mask and xor must be the same length")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && (is4ByteRegister(sreg) || is4ByteRegister(dreg))) {
		return nil, fmt.Errorf("bitwise operation length %d is too long for source register %d, destination register %d", blen, sreg, dreg)
	}
	return &bitwise{sreg: sreg, dreg: dreg, bop: linux.NFT_BITWISE_BOOL, blen: uint8(blen), mask: newBytesData(mask), xor: newBytesData(xor)}, nil
}

// newBitwiseShift creates a new bitwise shift operation.
func newBitwiseShift(sreg, dreg, blen uint8, shift uint32, right bool) (*bitwise, error) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, fmt.Errorf("bitwise operation cannot use verdict register as source or destination")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && (is4ByteRegister(sreg) || is4ByteRegister(dreg))) {
		return nil, fmt.Errorf("bitwise operation length %d is too long for source register %d, destination register %d", blen, sreg, dreg)
	}
	if shift >= bitshiftLimit {
		return nil, fmt.Errorf("bitwise operation shift %d must be less than %d", shift, bitshiftLimit)
	}
	bop := bitwiseOp(linux.NFT_BITWISE_LSHIFT)
	if right {
		bop = linux.NFT_BITWISE_RSHIFT
	}
	return &bitwise{sreg: sreg, dreg: dreg, blen: blen, bop: bop, shift: shift}, nil
}

// evaluateBitwiseBool performs the bitwise boolean operation on the source register
// data and stores the result in the destination register.
func evaluateBitwiseBool(sregBuf, dregBuf, mask, xor []byte) {
	for i := 0; i < len(mask); i++ {
		dregBuf[i] = (sregBuf[i] & mask[i]) ^ xor[i]
	}
}

// evaluateBitwiseLshift performs the bitwise left shift operation on source
// register in 4 byte chunks and stores the result in the destination register.
func evaluateBitwiseLshift(sregBuf, dregBuf []byte, shift uint32) {
	carry := uint32(0)

	// Rounds down to nearest 4-byte multiple.
	for start := (len(sregBuf) - 1) & ^3; start >= 0; start -= 4 {
		// Extracts the 4-byte chunk from the source register, padding if necessary.
		var chunk uint32
		if start+4 <= len(sregBuf) {
			chunk = binary.BigEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.BigEndian.Uint32(padded[:])
		}

		// Does left shift, adds the carry, and calculates the new carry.
		res := (chunk << shift) | carry
		carry = chunk >> (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.BigEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.BigEndian.PutUint32(padded[:], res)
			copy(dregBuf[start:], padded[:])
		}
	}
}

// evaluateBitwiseRshift performs the bitwise right shift operation on source
// register in 4 byte chunks and stores the result in the destination register.
func evaluateBitwiseRshift(sregBuf, dregBuf []byte, shift uint32) {
	carry := uint32(0)

	for start := 0; start < len(sregBuf); start += 4 {
		// Extracts the 4-byte chunk from the source register, padding if necessary.
		var chunk uint32
		if start+4 <= len(sregBuf) {
			chunk = binary.BigEndian.Uint32(sregBuf[start:])
		} else {
			var padded [4]byte
			copy(padded[:], sregBuf[start:])
			chunk = binary.BigEndian.Uint32(padded[:])
		}

		// Does right shift, adds the carry, and calculates the new carry.
		res := carry | (chunk >> shift)
		carry = chunk << (bitshiftLimit - shift)

		// Stores the result in the destination register, using temporary buffer
		// if necessary.
		if start+4 <= len(dregBuf) {
			binary.BigEndian.PutUint32(dregBuf[start:], res)
		} else {
			var padded [4]byte
			binary.BigEndian.PutUint32(padded[:], res)
			copy(dregBuf[start:], padded[:])
		}
	}
}

// evaluate for bitwise performs the bitwise operation on the source register
// data and stores the result in the destination register.
func (op bitwise) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the specified buffers of the source and destination registers.
	sregBuf := getRegisterBuffer(regs, op.sreg)[:op.blen]
	dregBuf := getRegisterBuffer(regs, op.dreg)[:op.blen]

	if op.bop == linux.NFT_BITWISE_BOOL {
		evaluateBitwiseBool(sregBuf, dregBuf, op.mask.data, op.xor.data)
		return
	} else {
		if op.bop == linux.NFT_BITWISE_LSHIFT {
			evaluateBitwiseLshift(sregBuf, dregBuf, op.shift)
		} else {
			evaluateBitwiseRshift(sregBuf, dregBuf, op.shift)
		}
	}
}

// counter is an operation that increments a counter for the packets and number
// of bytes each time the operation is evaluated.
type counter struct {
	// Must be thread-safe because data stored here is updated for each evaluation
	// and evaluations can happen in parallel for processing multiple packets.

	bytes   atomic.Int64 // Number of bytes that have passed through counter.
	packets atomic.Int64 // Number of packets that have passed through counter.
}

// newCounter creates a new counter operation.
func newCounter(startBytes, startPackets int64) *counter {
	cntr := &counter{}
	cntr.bytes.Store(startBytes)
	cntr.packets.Store(startPackets)
	return cntr
}

// evaluate for counter increments the counter for the packet and bytes.
func (op *counter) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	op.bytes.Add(int64(pkt.Size()))
	op.packets.Add(1)
}

// last is an operation that records the last time the operation was evaluated
// for the purpose of tracking the last time the rule has matched a packet.
// Note: no explicit constructor bc no fields need to be set (use &last{}).
type last struct {
	// Must be thread-safe because data stored here is updated for each evaluation
	// and evaluations can happen in parallel for processing multiple packets.

	// timestampMS is the time of last evaluation as a millisecond unix time.
	// Milliseconds chosen as units because closest in magnitude to jiffies.
	timestampMS atomic.Int64

	// set is whether the operation has been evaluated at least once.
	set atomic.Bool

	// Note: The last operation has not been observed in the nft binary debug
	// output, so it has no interpretation, though it is fully implemented.
}

// evaluate for last records the last time the operation was evaluated and flags
// if this was the first time the operation was evaluated.
func (op *last) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	clock := rule.chain.table.afFilter.nftState.clock
	op.timestampMS.Store(clock.Now().UnixMilli())
	op.set.CompareAndSwap(false, true)
}

// route is an operation that loads specific route data into a register.
// Note: route operations are not supported for the verdict register.
type route struct {
	key  routeKey // Route key specifying what data to retrieve.
	dreg uint8    // Number of the destination register.

	// Route information is stored AS IS. If the data is a field stored by the
	// kernel, it is stored in host endian. If the data is from the packet, it
	// is stored in big endian (network order).
	// The nft binary handles the necessary endian conversions from user input.
	// For example, if the user wants to check if some kernel data == 123 vs
	// payload data == 123, the nft binary passes host endian register data for
	// the former and big endian register data for the latter.
}

// routeKey is the key that determines the specific route data to retrieve.
// Note: corresponds to enum nft_rt_keys from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type routeKey int

// routeKeyStrings is a map of route key to its string representation.
var routeKeyStrings = map[routeKey]string{
	linux.NFT_RT_CLASSID:  "Traffic Class ID",
	linux.NFT_RT_NEXTHOP4: "Next Hop IPv4",
	linux.NFT_RT_NEXTHOP6: "Next Hop IPv6",
	linux.NFT_RT_TCPMSS:   "TCP Maximum Segment Size (TCPMSS)",
	linux.NFT_RT_XFRM:     "IPsec Transformation",
}

// String for routeKey returns the string representation of the route key.
func (key routeKey) String() string {
	if keyStr, ok := routeKeyStrings[key]; ok {
		return keyStr
	}
	panic(fmt.Sprintf("invalid route key: %d", int(key)))
}

// validateRouteKey ensures the route key is valid.
func validateRouteKey(key routeKey) error {
	switch key {
	// Supported route keys.
	case linux.NFT_RT_NEXTHOP4, linux.NFT_RT_NEXTHOP6, linux.NFT_RT_TCPMSS:
		return nil
	// Unsupported route keys.
	case linux.NFT_RT_CLASSID:
		// Note: We can trivially support Traffic Class ID for IPv6, but we need to
		// do more work to support it for IPv4. For safety, we mark it as
		// unsupported since we don't know what packet type we're working with until
		// the time of evaluation. In the worst case, we don't want the user to
		// initialize a route with this key and then have it silently break and
		// yield a difficult-to-debug error.
		return fmt.Errorf("traffic class id not supported")
	case linux.NFT_RT_XFRM:
		return fmt.Errorf("xfrm transformation not supported")
	default:
		return fmt.Errorf("invalid route key: %d", int(key))
	}
}

// newRoute creates a new route operation.
func newRoute(key routeKey, dreg uint8) (*route, error) {
	if isVerdictRegister(dreg) {
		return nil, fmt.Errorf("route operation cannot use verdict register as destination")
	}
	if err := validateRouteKey(key); err != nil {
		return nil, err
	}

	return &route{key: key, dreg: dreg}, nil
}

// evaluate for Route loads specific routing data into the destination register.
func (op route) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the target data to be stored in the destination register.
	var target []byte
	switch op.key {

	// Retrieves next hop IPv4 address (restricted to IPv4).
	// Stores data in big endian network order.
	case linux.NFT_RT_NEXTHOP4:
		if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber {
			break
		}
		target = pkt.EgressRoute.NextHop.AsSlice()

	// Retrieves next hop IPv6 address (restricted to IPv6).
	// Stores data in big endian network order.
	case linux.NFT_RT_NEXTHOP6:
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			break
		}
		target = pkt.EgressRoute.NextHop.AsSlice()

	// Retrieves the TCP Maximum Segment Size (TCPMSS).
	// Stores data in host endian.
	case linux.NFT_RT_TCPMSS:
		tcpmss := pkt.GSOOptions.MSS
		target = binary.NativeEndian.AppendUint16(nil, tcpmss)
	}

	// Breaks if could not retrieve target data.
	if target == nil {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Stores the target data in the destination register.
	data := newBytesData(target)
	data.storeData(regs, op.dreg)
}

// byteorder is an operation that performs byte order operations on a register.
// Note: byteorder operations are not supported for the verdict register.
type byteorder struct {
	sreg uint8       // Number of the source register.
	dreg uint8       // Number of the destination register.
	bop  byteorderOp // Byte order operation to perform.
	blen uint8       // Number of total bytes to operate on.
	size uint8       // Granular size in bytes to operate on.
}

// byteorderOp is the byte order operator for a byteorder operation.
// Note: corresponds to enum nft_byteorder_ops from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type byteorderOp int

// byteorderOpStrings is a map of byteorder operator to its string
// representation.
var byteorderOpStrings = map[byteorderOp]string{
	linux.NFT_BYTEORDER_NTOH: "network to host",
	linux.NFT_BYTEORDER_HTON: "host to network",
}

// String for byteorderOp returns the string representation of the byteorder
// operator.
func (bop byteorderOp) String() string {
	if bopStr, ok := byteorderOpStrings[bop]; ok {
		return bopStr
	}
	panic(fmt.Sprintf("invalid byteorder operator: %d", int(bop)))
}

// validateByteorderOp ensures the byteorder operator is valid.
func validateByteorderOp(bop byteorderOp) error {
	switch bop {
	// Supported operators.
	case linux.NFT_BYTEORDER_NTOH, linux.NFT_BYTEORDER_HTON:
		return nil
	default:
		return fmt.Errorf("invalid byteorder operator: %d", int(bop))
	}
}

// newByteorder creates a new byteorder operation.
func newByteorder(sreg, dreg uint8, bop byteorderOp, blen, size uint8) (*byteorder, error) {
	if isVerdictRegister(sreg) || isVerdictRegister(dreg) {
		return nil, fmt.Errorf("byteorder operation cannot use verdict register")
	}
	if err := validateByteorderOp(bop); err != nil {
		return nil, err
	}
	if blen > linux.NFT_REG_SIZE {
		return nil, fmt.Errorf("byteorder operation cannot have length greater than the max register size of %d bytes", linux.NFT_REG_SIZE)
	}
	if (is4ByteRegister(sreg) || is4ByteRegister(dreg)) && blen > linux.NFT_REG32_SIZE {
		return nil, fmt.Errorf("byteorder operation cannot have length greater than the max register size of %d bytes", linux.NFT_REG32_SIZE)
	}
	if size > blen {
		return nil, fmt.Errorf("byteorder operation cannot have size greater than length")
	}
	if size != 2 && size != 4 && size != 8 {
		return nil, fmt.Errorf("byteorder operation size must be 2, 4, or 8 bytes")
	}
	return &byteorder{sreg: sreg, dreg: dreg, bop: bop, blen: blen, size: size}, nil
}

// evaluate for byteorder performs the byte order operation on the source
// register and stores the result in the destination register.
func (op byteorder) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the source and destination registers.
	src := getRegisterBuffer(regs, op.sreg)
	dst := getRegisterBuffer(regs, op.dreg)

	// Performs the byte order operations on the source register and stores the
	// result in as many bytes as are available in the destination register.
	switch op.size {
	case 8:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 8 {
				networkNum := binary.BigEndian.Uint64(src[i : i+8])
				binary.NativeEndian.PutUint64(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 8 {
				hostNum := binary.NativeEndian.Uint64(src[i : i+8])
				binary.BigEndian.PutUint64(dst[i:], hostNum)
			}
		}

	case 4:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 4 {
				networkNum := binary.BigEndian.Uint32(src[i : i+4])
				binary.NativeEndian.PutUint32(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 4 {
				hostNum := binary.NativeEndian.Uint32(src[i : i+4])
				binary.BigEndian.PutUint32(dst[i:], hostNum)
			}
		}

	case 2:
		switch op.bop {
		case linux.NFT_BYTEORDER_NTOH:
			for i := uint8(0); i < op.blen; i += 2 {
				networkNum := binary.BigEndian.Uint16(src[i : i+2])
				binary.NativeEndian.PutUint16(dst[i:], networkNum)
			}
		case linux.NFT_BYTEORDER_HTON:
			for i := uint8(0); i < op.blen; i += 2 {
				hostNum := binary.NativeEndian.Uint16(src[i : i+2])
				binary.BigEndian.PutUint16(dst[i:], hostNum)
			}
		}
	}

	// Zeroes out excess bytes of the destination register.
	// This is done since comparison can be done in multiples of 4 bytes.
	if rem := op.blen % 4; rem != 0 {
		clear(dst[op.blen : op.blen+4-rem])
	}
}

// metaLoad is an operation that loads specific meta data into a register.
// Note: meta operations are not supported for the verdict register.
// TODO(b/345684870): Support retrieving more meta fields for Meta Load.
type metaLoad struct {
	key  metaKey // Meta key specifying what data to retrieve.
	dreg uint8   // Number of the destination register.

	// Note: Similar to route, meta fields are stored AS IS. If the meta data is
	// a field stored by the kernel (i.e. length), it is stored in host endian. On
	// the contrary, if the meta data is data from the packet (i.e. protocol), it
	// is stored in big endian (network order).
	// The nft binary handles the necessary endian conversions from user input.
	// For example, if the user wants to check if meta len == 123 vs payload
	// data == 123, the nft binary passes host endian for the former and big
	// endian for the latter.
}

// metaKey is the key that determines the specific meta data to retrieve.
// Note: corresponds to enum nft_meta_keys from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type metaKey int

// metaKeyStrings is a map of meta key to its string representation.
var metaKeyStrings = map[metaKey]string{
	linux.NFT_META_LEN:           "NFT_META_LEN",
	linux.NFT_META_PROTOCOL:      "NFT_META_PROTOCOL",
	linux.NFT_META_PRIORITY:      "NFT_META_PRIORITY",
	linux.NFT_META_MARK:          "NFT_META_MARK",
	linux.NFT_META_IIF:           "NFT_META_IIF",
	linux.NFT_META_OIF:           "NFT_META_OIF",
	linux.NFT_META_IIFNAME:       "NFT_META_IIFNAME",
	linux.NFT_META_OIFNAME:       "NFT_META_OIFNAME",
	linux.NFT_META_IIFTYPE:       "NFT_META_IIFTYPE",
	linux.NFT_META_OIFTYPE:       "NFT_META_OIFTYPE",
	linux.NFT_META_SKUID:         "NFT_META_SKUID",
	linux.NFT_META_SKGID:         "NFT_META_SKGID",
	linux.NFT_META_NFTRACE:       "NFT_META_NFTRACE",
	linux.NFT_META_RTCLASSID:     "NFT_META_RTCLASSID",
	linux.NFT_META_SECMARK:       "NFT_META_SECMARK",
	linux.NFT_META_NFPROTO:       "NFT_META_NFPROTO",
	linux.NFT_META_L4PROTO:       "NFT_META_L4PROTO",
	linux.NFT_META_BRI_IIFNAME:   "NFT_META_BRI_IIFNAME",
	linux.NFT_META_BRI_OIFNAME:   "NFT_META_BRI_OIFNAME",
	linux.NFT_META_PKTTYPE:       "NFT_META_PKTTYPE",
	linux.NFT_META_CPU:           "NFT_META_CPU",
	linux.NFT_META_IIFGROUP:      "NFT_META_IIFGROUP",
	linux.NFT_META_OIFGROUP:      "NFT_META_OIFGROUP",
	linux.NFT_META_CGROUP:        "NFT_META_CGROUP",
	linux.NFT_META_PRANDOM:       "NFT_META_PRANDOM",
	linux.NFT_META_SECPATH:       "NFT_META_SECPATH",
	linux.NFT_META_IIFKIND:       "NFT_META_IIFKIND",
	linux.NFT_META_OIFKIND:       "NFT_META_OIFKIND",
	linux.NFT_META_BRI_IIFPVID:   "NFT_META_BRI_IIFPVID",
	linux.NFT_META_BRI_IIFVPROTO: "NFT_META_BRI_IIFVPROTO",
	linux.NFT_META_TIME_NS:       "NFT_META_TIME_NS",
	linux.NFT_META_TIME_DAY:      "NFT_META_TIME_DAY",
	linux.NFT_META_TIME_HOUR:     "NFT_META_TIME_HOUR",
	linux.NFT_META_SDIF:          "NFT_META_SDIF",
	linux.NFT_META_SDIFNAME:      "NFT_META_SDIFNAME",
	linux.NFT_META_BRI_BROUTE:    "NFT_META_BRI_BROUTE",
}

// String for metaKey returns the string representation of the meta key. This
// supports strings for supported and unsupported meta keys.
func (key metaKey) String() string {
	if keyStr, ok := metaKeyStrings[key]; ok {
		return keyStr
	}
	panic(fmt.Sprintf("invalid meta key: %d", int(key)))
}

// metaDataLengths holds the length in bytes for each supported meta key.
var metaDataLengths = map[metaKey]int{
	linux.NFT_META_LEN:       4,
	linux.NFT_META_PROTOCOL:  2,
	linux.NFT_META_NFPROTO:   1,
	linux.NFT_META_L4PROTO:   1,
	linux.NFT_META_SKUID:     4,
	linux.NFT_META_SKGID:     4,
	linux.NFT_META_RTCLASSID: 4,
	linux.NFT_META_PKTTYPE:   1,
	linux.NFT_META_PRANDOM:   4,
	linux.NFT_META_TIME_NS:   8,
	linux.NFT_META_TIME_DAY:  1,
	linux.NFT_META_TIME_HOUR: 4,
}

// validateMetaKey ensures the meta key is valid.
func validateMetaKey(key metaKey) error {
	switch key {
	case linux.NFT_META_LEN, linux.NFT_META_PROTOCOL, linux.NFT_META_NFPROTO,
		linux.NFT_META_L4PROTO, linux.NFT_META_SKUID, linux.NFT_META_SKGID,
		linux.NFT_META_RTCLASSID, linux.NFT_META_PKTTYPE, linux.NFT_META_PRANDOM,
		linux.NFT_META_TIME_NS, linux.NFT_META_TIME_DAY, linux.NFT_META_TIME_HOUR:
		return nil
	default:
		return fmt.Errorf("invalid meta key: %d", int(key))
	}
}

// newMetaLoad creates a new metaLoad operation.
func newMetaLoad(key metaKey, dreg uint8) (*metaLoad, error) {
	if isVerdictRegister(dreg) {
		return nil, fmt.Errorf("meta load operation cannot use verdict register as destination")
	}
	if err := validateMetaKey(key); err != nil {
		return nil, err
	}
	if metaDataLengths[key] > 4 && !is16ByteRegister(dreg) {
		return nil, fmt.Errorf("meta load operation cannot use 4-byte register as destination for key %s", key)
	}

	return &metaLoad{key: key, dreg: dreg}, nil
}

// evaluate for MetaLoad loads specific meta data into the destination register.
func (op metaLoad) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	var target []byte
	switch op.key {

	// Packet Length, in bytes (32-bit, host order).
	case linux.NFT_META_LEN:
		target = binary.NativeEndian.AppendUint32(nil, uint32(pkt.Size()))

	// Network EtherType Protocol (16-bit, network order).
	case linux.NFT_META_PROTOCOL:
		// Only valid if network header is present.
		if pkt.NetworkHeader().View() == nil {
			break
		}
		target = binary.BigEndian.AppendUint16(nil, uint16(pkt.NetworkProtocolNumber))

	// Netfilter (Family) Protocol (8-bit, single byte).
	case linux.NFT_META_NFPROTO:
		family := rule.chain.GetAddressFamily()
		target = []byte{family.Protocol()}

	// L4 Transport Layer Protocol (8-bit, single byte).
	case linux.NFT_META_L4PROTO:
		// Only valid if non-zero.
		if pkt.TransportProtocolNumber == 0 {
			break
		}
		target = []byte{uint8(pkt.TransportProtocolNumber)}

	// Originating Socket UID (32-bit, host order).
	case linux.NFT_META_SKUID:
		// Only valid if Owner is set (only set for locally generated packets).
		if pkt.Owner == nil {
			break
		}
		target = binary.NativeEndian.AppendUint32(nil, pkt.Owner.KUID())

	// Originating Socket GID (32-bit, host order).
	case linux.NFT_META_SKGID:
		// Only valid if Owner is set (only set for locally generated packets).
		if pkt.Owner == nil {
			break
		}
		target = binary.NativeEndian.AppendUint32(nil, pkt.Owner.KGID())

	// Route Traffic Class ID, same as Route equivalent (32-bit, host order).
	// Currently only implemented for IPv6, but should be for IPv4 as well.
	case linux.NFT_META_RTCLASSID:
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			break
		}
		if pkt.NetworkHeader().View() != nil {
			tcid, _ := pkt.Network().TOS()
			target = binary.NativeEndian.AppendUint32(nil, uint32(tcid))
		}

	// Packet Type (8-bit, single byte).
	case linux.NFT_META_PKTTYPE:
		target = []byte{uint8(pkt.PktType)}

	// Generated Pseudo-Random Number (32-bit, network order).
	case linux.NFT_META_PRANDOM:
		rng := rule.chain.table.afFilter.nftState.rng
		target = binary.BigEndian.AppendUint32(nil, uint32(rng.Uint32()))

	// Unix Time in Nanoseconds (64-bit, host order).
	case linux.NFT_META_TIME_NS:
		clock := rule.chain.table.afFilter.nftState.clock
		target = binary.NativeEndian.AppendUint64(nil, uint64(clock.Now().UnixNano()))

	// Day of Week (0 = Sunday, 6 = Saturday) (8-bit, single byte).
	case linux.NFT_META_TIME_DAY:
		clock := rule.chain.table.afFilter.nftState.clock
		target = []byte{uint8(clock.Now().Weekday())}

	// Hour of Day, in seconds (seconds since start of day) (32-bit, host order).
	case linux.NFT_META_TIME_HOUR:
		clock := rule.chain.table.afFilter.nftState.clock
		now := clock.Now()
		secs := now.Hour()*3600 + now.Minute()*60 + now.Second()
		target = binary.NativeEndian.AppendUint32(nil, uint32(secs))
	}

	// Breaks if could not retrieve meta data.
	if target == nil {
		regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Gets the destination register.
	dst := getRegisterBuffer(regs, op.dreg)
	// Zeroes out excess bytes of the destination register.
	// This is done since comparison can be done in multiples of 4 bytes.
	blen := metaDataLengths[op.key]
	if rem := blen % 4; rem != 0 {
		clear(dst[blen : blen+4-rem])
	}
	// Copies target data into the destination register.
	copy(dst, target)
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

// registerData represents the data to be set in a register.
type registerData interface {
	// String returns a string representation of the register data.
	String() string

	// equal compares the register data to another.
	equal(other registerData) bool

	// validateRegister ensures the register is compatible with the data type,
	// returning an error otherwise.
	validateRegister(reg uint8) error

	// storeData sets the data in the destination register, panicking if the
	// register is not valid for the data type.
	// Note: assumes data is valid for register. This is used primarily during
	// operation evaluation and the data type/register compatibility should have
	// been checked during the operation init.
	storeData(regs *registerSet, reg uint8)
}

// verdictData represents a verdict as data to be stored in a register.
type verdictData struct {
	data Verdict
}

// newVerdictData creates a registerData for a verdict.
func newVerdictData(verdict Verdict) verdictData { return verdictData{data: verdict} }

// String returns a string representation of the verdict data.
func (rd verdictData) String() string {
	return rd.data.String()
}

// equal compares the verdict data to another RegisterData object.
func (rd verdictData) equal(other registerData) bool {
	if other == nil {
		return false
	}
	otherVD, ok := other.(verdictData)
	if !ok {
		return false
	}
	return rd.data == otherVD.data
}

// validateRegister ensures the register is compatible with VerdictData.
func (rd verdictData) validateRegister(reg uint8) error {
	if !isVerdictRegister(reg) {
		return fmt.Errorf("verdict can only be stored in verdict register")
	}
	return nil
}

// storeData sets the data in the destination register to the verdict.
func (rd verdictData) storeData(regs *registerSet, reg uint8) {
	if err := rd.validateRegister(reg); err != nil {
		panic(err)
	}
	regs.verdict = rd.data
}

// bytesData represents <= 16 bytes of data to be stored in a register.
type bytesData struct {
	data []byte
}

// newBytesData creates a registerData for <= 16 bytes of data.
func newBytesData(bytes []byte) bytesData {
	if len(bytes) == 0 {
		panic("bytes data cannot be empty")
	}
	if len(bytes) > linux.NFT_REG_SIZE {
		panic(fmt.Errorf("bytes data cannot be more than %d bytes: %d", linux.NFT_REG_SIZE, len(bytes)))
	}
	return bytesData{data: bytes}
}

// String returns a string representation of the big endian bytes data.
func (rd bytesData) String() string {
	return fmt.Sprintf("%x", rd.data)
}

// equal compares the bytes data to another RegisterData object.
func (rd bytesData) equal(other registerData) bool {
	if other == nil {
		return false
	}
	otherBD, ok := other.(bytesData)
	if !ok {
		return false
	}
	return slices.Equal(rd.data, otherBD.data)
}

// validateRegister ensures the register is compatible with this bytes data.
func (rd bytesData) validateRegister(reg uint8) error {
	if isVerdictRegister(reg) {
		return fmt.Errorf("data cannot be stored in verdict register")
	}
	if is4ByteRegister(reg) && len(rd.data) > linux.NFT_REG32_SIZE {
		return fmt.Errorf("%d-byte data cannot be stored in %d-byte register", len(rd.data), linux.NFT_REG32_SIZE)
	}
	// 16-byte register can be used for any data (guaranteed to be <= 16 bytes)
	return nil
}

// getRegisterBuffer is a helper function that gets the appropriate slice of the
// register from the register set. The number of bytes returned is rounded up to
// the nearest 4-byte multiple.
// Note: does not support verdict data and assumes the register is valid for the
// given data type.
func getRegisterBuffer(regs *registerSet, reg uint8) []byte {
	// Returns the entire 4-byte register
	if is4ByteRegister(reg) {
		start := (reg - linux.NFT_REG32_00) * linux.NFT_REG32_SIZE
		return regs.data[start : start+linux.NFT_REG32_SIZE]
	}
	// Returns the entire 16-byte register
	start := (reg - linux.NFT_REG_1) * linux.NFT_REG_SIZE
	return regs.data[start : start+linux.NFT_REG_SIZE]
}

// storeData sets the data in the destination register to the bytes data.
func (rd bytesData) storeData(regs *registerSet, reg uint8) {
	if err := rd.validateRegister(reg); err != nil {
		panic(err)
	}
	copy(getRegisterBuffer(regs, reg), rd.data)
}

// registerSet represents the set of registers supported by the kernel.
// Use RegisterData.storeData to set data in the registers.
// Note: Corresponds to nft_regs from include/net/netfilter/nf_tables.h.
type registerSet struct {
	verdict Verdict                 // 16-byte verdict register
	data    [registersByteSize]byte // 4 16-byte registers or 16 4-byte registers
}

// newRegisterSet creates a new registerSet with the Continue Verdict and all
// registers set to 0.
func newRegisterSet() registerSet {
	return registerSet{
		verdict: Verdict{Code: VC(linux.NFT_CONTINUE)},
		data:    [registersByteSize]byte{0},
	}
}

// Verdict returns the verdict data.
func (regs *registerSet) Verdict() Verdict {
	return regs.verdict
}

func (regs *registerSet) String() string {
	return fmt.Sprintf("verdict: %v, data: %x", regs.verdict, regs.data)
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

// verdictCodeStrings is a map of verdict code to its string representation.
var verdictCodeStrings = map[uint32]string{
	// Netfilter (External) Verdicts:
	VC(linux.NF_DROP):   "Drop",
	VC(linux.NF_ACCEPT): "Accept",
	VC(linux.NF_STOLEN): "Stolen",
	VC(linux.NF_QUEUE):  "Queue",
	VC(linux.NF_REPEAT): "Repeat",
	VC(linux.NF_STOP):   "Stop",
	// Nftable (Internal) Verdicts:
	VC(linux.NFT_CONTINUE): "Continue",
	VC(linux.NFT_BREAK):    "Break",
	VC(linux.NFT_JUMP):     "Jump",
	VC(linux.NFT_GOTO):     "Goto",
	VC(linux.NFT_RETURN):   "Return",
}

// VerdictCodeToString prints names for the supported verdicts.
func VerdictCodeToString(v uint32) string {

	if vcStr, ok := verdictCodeStrings[v]; ok {
		return vcStr
	}
	return fmt.Sprintf("invalid verdict: %d", v)
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
func (c *Chain) evaluateFromRule(rIdx int, jumpDepth int, regs *registerSet, pkt *stack.PacketBuffer) error {
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
func (c *Chain) evaluate(regs *registerSet, pkt *stack.PacketBuffer) error {
	return c.evaluateFromRule(0, 0, regs, pkt)
}

// evaluate evaluates the rule on the given packet and register set, changing
// the register set and possibly the packet in place.
// The verdict in regs.Verdict() may be an nf table internal verdict or a
// netfilter terminal verdict.
func (r *Rule) evaluate(regs *registerSet, pkt *stack.PacketBuffer) error {
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
// TODO(b/345684870): Use a secure RNG.
func NewNFTables(clock tcpip.Clock, rng *rand.Rand) *NFTables {
	if clock == nil {
		panic("nftables state must be initialized with a non-nil clock")
	}
	if rng == nil {
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
func (nf *NFTables) GetTable(family AddressFamily, tableName string) (*Table, error) {
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
	errorOnDuplicate bool) (*Table, error) {
	// Ensures address family is valid.
	if err := validateAddressFamily(family); err != nil {
		return nil, err
	}

	// Initializes filter if first table for the address family.
	if nf.filters[family] == nil {
		nf.filters[family] = &addressFamilyFilter{
			family:   family,
			nftState: nf,
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
			return nil, fmt.Errorf("table '%s' already exists in address family %v", name, family)
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
func (c *Chain) UnregisterRule(index int) (*Rule, error) {
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
func (c *Chain) GetRule(index int) (*Rule, error) {
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
func (r *Rule) addOperation(op operation) error {
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
