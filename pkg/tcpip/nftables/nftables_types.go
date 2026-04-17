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
	"fmt"
	"slices"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TODO(b/345684870): Make the nftables package thread-safe! Must be done before
// the package is used in production.

// enableNFTables is a flag that indicates whether NFTables is enabled.
var enableNFTables atomicbitops.Bool

// EnableNFTables enables NFTables.
func EnableNFTables() {
	enableNFTables.Store(true)
}

// IsNFTablesEnabled returns true if NFTables is enabled.
func IsNFTablesEnabled() bool {
	return enableNFTables.Load()
}

// Defines general constants for the nftables interpreter.
const (

	// Total bytes for the registers in the nftables interpreter.
	registersByteSize = 64

	// Maximum number of nested jumps allowed, corresponding to
	// NFT_JUMP_STACK_SIZE in include/net/netfilter/nf_tables.h.
	nestedJumpLimit = 16

	// Limit (exclusive) for number of buts that can be shifted for non-boolean
	// bitwise operations.
	bitshiftLimit = 32
)

// addressFamilyProtocols maps address families to their protocol number.
var addressFamilyProtocols = map[stack.AddressFamily]uint8{
	stack.Unspec: linux.NFPROTO_UNSPEC,
	stack.IP:     linux.NFPROTO_IPV4,
	stack.IP6:    linux.NFPROTO_IPV6,
	stack.Inet:   linux.NFPROTO_INET,
	stack.Arp:    linux.NFPROTO_ARP,
	stack.Bridge: linux.NFPROTO_BRIDGE,
	stack.Netdev: linux.NFPROTO_NETDEV,
}

// AfProtocol returns the protocol number for the address family.
func AfProtocol(f stack.AddressFamily) uint8 {
	if protocol, ok := addressFamilyProtocols[f]; ok {
		return protocol
	}
	panic(fmt.Sprintf("invalid address family: %d", int(f)))
}

// validateAddressFamily ensures the family address is valid (within bounds).
func validateAddressFamily(family stack.AddressFamily) *syserr.AnnotatedError {
	// From net/netfilter/nf_tables_api.c:nf_tables_newtable
	if family < 0 || family >= stack.NumAFs {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("invalid address family: %d", int(family)))
	}

	return nil
}

// supportedHooks maps each address family to its supported hooks.
var supportedHooks [stack.NumAFs][stack.NFNumHooks]bool = [stack.NumAFs][stack.NFNumHooks]bool{
	stack.IP:     {true /*NFPrerouting*/, true /*NFInput*/, true /*NFForward*/, true /*NFOutput*/, true /*NFPostrouting*/, true /*NFIngress*/, false /*NFEgress*/},
	stack.IP6:    {true /*NFPrerouting*/, true /*NFInput*/, true /*NFForward*/, true /*NFOutput*/, true /*NFPostrouting*/, true /*NFIngress*/, false /*NFEgress*/},
	stack.Inet:   {true /*NFPrerouting*/, true /*NFInput*/, true /*NFForward*/, true /*NFOutput*/, true /*NFPostrouting*/, true /*NFIngress*/, false /*NFEgress*/},
	stack.Arp:    {false /*NFPrerouting*/, true /*NFInput*/, false /*NFForward*/, true /*NFOutput*/, false /*NFPostrouting*/, false /*NFIngress*/, false /*NFEgress*/},
	stack.Bridge: {true /*NFPrerouting*/, true /*NFInput*/, true /*NFForward*/, true /*NFOutput*/, true /*NFPostrouting*/, true /*NFIngress*/, false /*NFEgress*/},
	stack.Netdev: {false /*NFPrerouting*/, false /*NFInput*/, false /*NFForward*/, false /*NFOutput*/, false /*NFPostrouting*/, true /*NFIngress*/, true /*NFEgress*/},
}

// supportedLinuxHooks maps each address family to its supported hooks for each base chain type.
// From net/netfilter/nft_chain_filter.c, net/netfilter/nft_chain_nat.c, net/netfilter/nft_chain_route.c,
var supportedLinuxHooks = map[stack.AddressFamily]map[BaseChainType][]stack.NFHook{
	stack.IP: {
		BaseChainTypeFilter: {linux.NF_INET_LOCAL_IN, linux.NF_INET_LOCAL_OUT, linux.NF_INET_FORWARD, linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING},
		BaseChainTypeNat:    {linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING, linux.NF_INET_LOCAL_OUT, linux.NF_INET_LOCAL_IN},
		BaseChainTypeRoute:  {linux.NF_INET_LOCAL_OUT},
	},
	stack.IP6: {
		BaseChainTypeFilter: {linux.NF_INET_LOCAL_IN, linux.NF_INET_LOCAL_OUT, linux.NF_INET_FORWARD, linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING},
		BaseChainTypeNat:    {linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING, linux.NF_INET_LOCAL_OUT, linux.NF_INET_LOCAL_IN},
		BaseChainTypeRoute:  {linux.NF_INET_LOCAL_OUT},
	},
	stack.Inet: {
		BaseChainTypeFilter: {linux.NF_INET_LOCAL_IN, linux.NF_INET_LOCAL_OUT, linux.NF_INET_FORWARD, linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING},
		BaseChainTypeNat:    {linux.NF_INET_PRE_ROUTING, linux.NF_INET_POST_ROUTING, linux.NF_INET_LOCAL_OUT, linux.NF_INET_LOCAL_IN},
		BaseChainTypeRoute:  {linux.NF_INET_LOCAL_OUT},
	},
	stack.Arp: {
		BaseChainTypeFilter: {linux.NF_ARP_IN, linux.NF_ARP_OUT},
	},
	stack.Bridge: {
		BaseChainTypeFilter: {linux.NF_BR_PRE_ROUTING, linux.NF_BR_LOCAL_IN, linux.NF_BR_FORWARD, linux.NF_BR_LOCAL_OUT, linux.NF_BR_POST_ROUTING},
	},
	stack.Netdev: {
		BaseChainTypeFilter: {linux.NF_NETDEV_INGRESS, linux.NF_NETDEV_EGRESS},
	},
}

// validateHook ensures the hook is within bounds and supported for the given
// address family.
func validateHook(hook stack.NFHook, family stack.AddressFamily) *syserr.AnnotatedError {
	if hook >= stack.NFNumHooks {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid hook: %d", int(hook)))
	}
	if supportedHooks[family][hook] {
		return nil
	}

	// The hook is not supported for the given address family.
	return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("hook %d is not supported for address family %d", int(hook), int(family)))
}

// ValidLinuxHook ensures the hook is within bounds and supported for the
// given address family and base chain type.
func ValidLinuxHook(family stack.AddressFamily, bcType BaseChainType, hook uint32) bool {
	if hook >= linux.NFT_MAX_HOOKS {
		return false
	}

	typeToSupportedHooks, ok := supportedLinuxHooks[family]
	if !ok {
		return false
	}

	supportedHooks, ok := typeToSupportedHooks[bcType]
	if !ok {
		return false
	}

	return slices.Contains(supportedHooks, stack.NFHook(hook))
}

// FamilyHookKey is a struct that represents a stack.AddressFamily and linux hook pair.
type FamilyHookKey struct {
	Family stack.AddressFamily
	Hook   uint32
}

// linuxHookToStackHook maps the linux hook constants to the stack hook constants.
var linuxHookToStackHook = map[FamilyHookKey]stack.NFHook{
	{Family: stack.IP, Hook: linux.NF_INET_LOCAL_IN}:     stack.NFInput,
	{Family: stack.IP, Hook: linux.NF_INET_LOCAL_OUT}:    stack.NFOutput,
	{Family: stack.IP, Hook: linux.NF_INET_FORWARD}:      stack.NFForward,
	{Family: stack.IP, Hook: linux.NF_INET_PRE_ROUTING}:  stack.NFPrerouting,
	{Family: stack.IP, Hook: linux.NF_INET_POST_ROUTING}: stack.NFPostrouting,

	{Family: stack.IP6, Hook: linux.NF_INET_LOCAL_IN}:     stack.NFInput,
	{Family: stack.IP6, Hook: linux.NF_INET_LOCAL_OUT}:    stack.NFOutput,
	{Family: stack.IP6, Hook: linux.NF_INET_FORWARD}:      stack.NFForward,
	{Family: stack.IP6, Hook: linux.NF_INET_PRE_ROUTING}:  stack.NFPrerouting,
	{Family: stack.IP6, Hook: linux.NF_INET_POST_ROUTING}: stack.NFPostrouting,

	{Family: stack.Inet, Hook: linux.NF_INET_LOCAL_IN}:     stack.NFInput,
	{Family: stack.Inet, Hook: linux.NF_INET_LOCAL_OUT}:    stack.NFOutput,
	{Family: stack.Inet, Hook: linux.NF_INET_FORWARD}:      stack.NFForward,
	{Family: stack.Inet, Hook: linux.NF_INET_PRE_ROUTING}:  stack.NFPrerouting,
	{Family: stack.Inet, Hook: linux.NF_INET_POST_ROUTING}: stack.NFPostrouting,

	{Family: stack.Arp, Hook: linux.NF_ARP_IN}:  stack.NFInput,
	{Family: stack.Arp, Hook: linux.NF_ARP_OUT}: stack.NFOutput,

	{Family: stack.Bridge, Hook: linux.NF_BR_PRE_ROUTING}:  stack.NFPrerouting,
	{Family: stack.Bridge, Hook: linux.NF_BR_LOCAL_IN}:     stack.NFInput,
	{Family: stack.Bridge, Hook: linux.NF_BR_FORWARD}:      stack.NFForward,
	{Family: stack.Bridge, Hook: linux.NF_BR_LOCAL_OUT}:    stack.NFOutput,
	{Family: stack.Bridge, Hook: linux.NF_BR_POST_ROUTING}: stack.NFPostrouting,

	{Family: stack.Netdev, Hook: linux.NF_NETDEV_INGRESS}: stack.NFIngress,
	{Family: stack.Netdev, Hook: linux.NF_NETDEV_EGRESS}:  stack.NFEgress,
}

// StackHook returns the stack hook for the given linux hook.
func StackHook(family stack.AddressFamily, hook uint32) (stack.NFHook, *syserr.AnnotatedError) {
	if hook, ok := linuxHookToStackHook[FamilyHookKey{Family: family, Hook: hook}]; ok {
		return hook, nil
	}

	return stack.NFHook(0), syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid linux hook: %d", int(hook)))
}

// NFTables represents the nftables state for all address families.
// Note: unlike iptables, nftables doesn't start with any initialized tables.
type NFTables struct {
	filters            [stack.NumAFs]*addressFamilyFilter  // Filters for each address family.
	ip4InetBaseChains  [stack.NFNumHooks]hookFunctionStack // List of base chains for each hook in the IPv4-inet family.
	ip6InetBaseChains  [stack.NFNumHooks]hookFunctionStack // List of base chains for each hook in the IPv6-inet family.
	clock              tcpip.Clock                         // Clock for timing evaluations.
	startTime          time.Time                           // Time NFTables object was created.
	rng                rand.RNG                            // Random number generator.
	tableHandleCounter atomicbitops.Uint64                 // Table handle counter.
	Mu                 nfTablesRWMutex                     // Mutex for tableHandles.
	genid              uint32                              // Generation ID for nftables.
}

// Ensures NFTables implements the NFTablesInterface.
var _ stack.NFTablesInterface = (*NFTables)(nil)

// addressFamilyFilter represents the nftables state for a specific address
// family.
type addressFamilyFilter struct {
	// family is the address family of the filter.
	family stack.AddressFamily

	// nftState is the NFTables object the filter belongs to.
	nftState *NFTables

	// tables is a map of tables for each address family.
	tables map[string]*Table

	// tableHandles is a map of table handles (ids) to tables for a given address family.
	tableHandles map[uint64]*Table

	// hfStacks is a map of hook function stacks (slice of base chains for a
	// given hook ordered by priority).
	hfStacks map[stack.NFHook]*hookFunctionStack
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

	// chainHandles is a map of chain handles (ids) to chains for a given table.
	chainHandles map[uint64]*Chain

	// flagSet is the set of optional flags for the table.
	// Note: currently nftables only has the single Dormant flag.
	flagSet map[TableFlag]struct{}

	// handleCounter is the counter for chain and rule handles.
	handleCounter atomicbitops.Uint64

	// handle is the id of the table.
	handle uint64

	// owner is the port id of the table's owner, if it is specified.
	owner uint32

	// userData is the user-specified metadata for the table. This is not used
	// by the kernel, but rather userspace applications like nft binary.
	userData []byte
}

// TableInfo represents data between an AFfilter and a Table.
type TableInfo struct {
	Name   string
	Handle uint64
}

// HookInfo represents data retrieved from the NFTA_CHAIN_HOOK attribute.
type HookInfo struct {
	HookNum   uint32
	Priority  int32
	ChainType BaseChainType
}

// hookFunctionStack represents the list of base chains for a specific hook.
// The stack is ordered by priority and built as chains are added to tables.
type hookFunctionStack struct {
	baseChains    []*Chain
	natBaseChains []*Chain
}

// TableFlag is a flag for a table as supported by the nftables binary.
type TableFlag int

const (
	// TableFlagDormant is set if the table is dormant. Dormant tables are not
	// evaluated by the kernel.
	TableFlagDormant TableFlag = iota
	// TableFlagOwner is set if the table has an owner. The owner is the port
	// where the table is created.
	TableFlagOwner
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

	// handle is the id of the chain.
	handle uint64

	// flags is the set of optional flags for the chain.
	flags uint8

	// baseChainInfo is the base chain info for the chain if it is a base chain.
	// Otherwise, it is nil.
	baseChainInfo *BaseChainInfo

	// rules is a list of rules for the chain.
	rules []*Rule

	// handleToRule is a map of rule handles to rules for the chain.
	handleToRule map[uint64]*Rule

	// userData is the user-specified metadata for the chain. This is not used
	// by the kernel, but rather userspace applications like nft binary.
	userData []byte

	// TODO: b/421437663 - Increment the chainUse field when a jump or goto
	// instruction is encountered.
	// From net/netfilter/nf_tables_api.c: nft_data_hold
	// chainUse is the number of jump references to this chain.
	chainUse uint32

	// bound can only be set if the chain has the NFT_CHAIN_BINDING flag is set.
	// If bound is true, the chain is being jumped to by a specific chain in the same table.
	bound bool

	// comment is the optional comment for the table.
	comment string
}

// TODO(b/345684870): BaseChainInfo Implementation. Encode how bcType affects
// evaluation of a packet.

// BaseChainInfo stores hook-related info for attaching a chain to the pipeline.
type BaseChainInfo struct {
	// LINT.IfChange(base_chain_info)

	// BcType is the base chain type of the chain (filter, nat, route).
	BcType BaseChainType

	// Hook is the hook to attach the chain to in the netfilter pipeline
	Hook stack.NFHook

	// LinuxHookNum is the linux hook number for the hook. Used for filling out the information
	// for a retrieved base chain.
	LinuxHookNum uint32

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

	// LINT.ThenChange(:base_chain_info_copy)
}

// PolicyBoolToValue converts the policy drop boolean to a uint8.
func (bc *BaseChainInfo) PolicyBoolToValue() uint8 {
	if bc.PolicyDrop {
		return uint8(linux.NF_DROP)
	}
	return uint8(linux.NF_ACCEPT)
}

// NewBaseChainInfo creates a new BaseChainInfo object with the given values.
// The device and policyDrop parameters are optional in the nft binary and
// should be set to empty string and false if not needed.
func NewBaseChainInfo(bcType BaseChainType, hook stack.NFHook, priority Priority, device string, policyDrop bool) *BaseChainInfo {
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
var supportedAFsForBaseChainTypes [NumBaseChainTypes][]stack.AddressFamily = [NumBaseChainTypes][]stack.AddressFamily{
	BaseChainTypeFilter: {stack.IP, stack.IP6, stack.Inet, stack.Bridge, stack.Arp, stack.Netdev},
	BaseChainTypeNat:    {stack.IP, stack.IP6, stack.Inet},
	BaseChainTypeRoute:  {stack.IP, stack.IP6},
}

// supportedHooksForBaseChainTypes maps each base chain type to its supported
// hooks.
var supportedHooksForBaseChainTypes [NumBaseChainTypes][]stack.NFHook = [NumBaseChainTypes][]stack.NFHook{
	BaseChainTypeFilter: {stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress, stack.NFEgress},
	BaseChainTypeNat:    {stack.NFPrerouting, stack.NFInput, stack.NFOutput, stack.NFPostrouting},
	BaseChainTypeRoute:  {stack.NFOutput},
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
func NewStandardPriority(name string, family stack.AddressFamily, hook stack.NFHook) (Priority, *syserr.AnnotatedError) {
	// Validates address family and hook first.
	if err := validateAddressFamily(family); err != nil {
		return Priority{}, err
	}
	if err := validateHook(hook, family); err != nil {
		return Priority{}, err
	}

	// Ensures the standard priority name is set.
	if name == "" {
		return Priority{}, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "standard priority name cannot be empty")
	}

	// Looks up standard priority name in the standard priority matrix.
	familyMatrix, exists := standardPriorityMatrix[family]
	if !exists {
		return Priority{}, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("standard priority names are not available for address family %v", family))
	}
	sp, exists := familyMatrix[name]
	if !exists {
		return Priority{}, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("standard priority name %s not compatible for address family %s", name, family))
	}

	// Checks for hook compatibility.
	if !slices.Contains(sp.hooks, hook) {
		return Priority{}, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("hook %s is not compatible with standard priority %s", hook, name))
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
	hooks []stack.NFHook
}

// supportedHooksAsList converts the supported hooks array to a list of hooks.
func supportedHooksAsList(family stack.AddressFamily) []stack.NFHook {
	var ret []stack.NFHook
	for idx, ok := range supportedHooks[family] {
		if ok {
			ret = append(ret, stack.NFHook(idx))
		}
	}
	return ret
}

// standardPriorityMatrix is used to look up information for the predefined
// standard priority names.
// TODO: b/493710955 - Not used, clean up.
var standardPriorityMatrix = map[stack.AddressFamily](map[string]standardPriority){
	stack.IP: spmIP,
	// Note: IPv6 standard priorities constants currently have the same values as
	// IPv4's, but the definitions (in the linux kernel) may change in the future.
	stack.IP6: map[string]standardPriority{ // from uapi/linux/netfilter_ipv6.h
		"raw":      {name: "raw", value: linux.NF_IP6_PRI_RAW, hooks: supportedHooksAsList(stack.IP6)},
		"mangle":   {name: "mangle", value: linux.NF_IP6_PRI_MANGLE, hooks: supportedHooksAsList(stack.IP6)},
		"dstnat":   {name: "dstnat", value: linux.NF_IP6_PRI_NAT_DST, hooks: supportedHooksAsList(stack.IP6)},
		"filter":   {name: "filter", value: linux.NF_IP6_PRI_FILTER, hooks: supportedHooksAsList(stack.IP6)},
		"security": {name: "security", value: linux.NF_IP6_PRI_SECURITY, hooks: supportedHooksAsList(stack.IP6)},
		"srcnat":   {name: "srcnat", value: linux.NF_IP6_PRI_NAT_SRC, hooks: supportedHooksAsList(stack.IP6)},
	},
	stack.Inet: spmIP,
	stack.Arp: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooksAsList(stack.Arp)},
	},
	stack.Bridge: map[string]standardPriority{ // from uapi/linux/netfilter_bridge.h
		"dstnat": {name: "dstnat", value: linux.NF_BR_PRI_NAT_DST_BRIDGED, hooks: []stack.NFHook{stack.NFPrerouting}},
		"filter": {name: "filter", value: linux.NF_BR_PRI_FILTER_BRIDGED, hooks: supportedHooksAsList(stack.Bridge)},
		"out":    {name: "out", value: linux.NF_BR_PRI_NAT_DST_OTHER, hooks: []stack.NFHook{stack.NFOutput}},
		"srcnat": {name: "srcnat", value: linux.NF_BR_PRI_NAT_SRC, hooks: []stack.NFHook{stack.NFPostrouting}},
	},
	stack.Netdev: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooksAsList(stack.Netdev)},
	},
}

// Used in the standardPriorityMatrix above.
// Note: IPv4 and Inet address families use the same standard priority names.
// TODO: b/493710955 - Not used, clean up.
var spmIP = map[string]standardPriority{ // from uapi/linux/netfilter_ipv4.h
	"raw":      {name: "raw", value: linux.NF_IP_PRI_RAW, hooks: supportedHooksAsList(stack.IP)},
	"mangle":   {name: "mangle", value: linux.NF_IP_PRI_MANGLE, hooks: supportedHooksAsList(stack.IP)},
	"dstnat":   {name: "dstnat", value: linux.NF_IP_PRI_NAT_DST, hooks: []stack.NFHook{stack.NFPrerouting}},
	"filter":   {name: "filter", value: linux.NF_IP_PRI_FILTER, hooks: supportedHooksAsList(stack.IP)},
	"security": {name: "security", value: linux.NF_IP_PRI_SECURITY, hooks: supportedHooksAsList(stack.IP)},
	"srcnat":   {name: "srcnat", value: linux.NF_IP_PRI_NAT_SRC, hooks: supportedHooksAsList(stack.IP)},
}

// validateBaseChainInfo ensures the base chain info is valid by checking the
// compatibility of the set base chain type, hook, and priority, and the given
// address family.
// Note: errors if the provided base chain info is nil.
func validateBaseChainInfo(info *BaseChainInfo, family stack.AddressFamily) *syserr.AnnotatedError {
	if info == nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "base chain info is nil")
	}

	// Validates the hook.
	if err := validateHook(info.Hook, family); err != nil {
		return err
	}

	// Validates the base chain type.
	if info.BcType < 0 || info.BcType >= NumBaseChainTypes {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("base chain type %d is invalid", int(info.BcType)))
	}
	if !slices.Contains(supportedAFsForBaseChainTypes[info.BcType], family) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("base chain type %d is not supported for address family %v", int(info.BcType), family))
	}
	if !slices.Contains(supportedHooksForBaseChainTypes[info.BcType], info.Hook) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("base chain type %v is not valid for hook %v", info.BcType, info.Hook))
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
	chain  *Chain
	ops    []operation
	handle uint64
	udata  []byte
}

// ExprInfo represents the information for a single expression nested under
// NFTA_EXPRESSIONS.
type ExprInfo struct {
	ExprName string
	ExprData nlmsg.AttrsView
}

// operation represents a single operation in a rule.
type operation interface {
	// GetExprName returns the name of the expression.
	GetExprName() string
	// Dump dumps the parameters.
	Dump() ([]byte, *syserr.AnnotatedError)

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
	_ operation = (*metaSet)(nil)
)

// OpType represents the type of operation.
type OpType int

const (
	// OpTypeImmediate is the immediate operation type.
	OpTypeImmediate OpType = iota
	// OpTypeComparison is the comparison operation type.
	OpTypeComparison
	// OpTypeRanged is the ranged operation type.
	OpTypeRanged
	// OpTypePayload is the payload operation type.
	OpTypePayload
	// OpTypeBitwise is the bitwise operation type.
	OpTypeBitwise
	// OpTypeCounter is the counter operation type.
	OpTypeCounter
	// OpTypeLast is the last operation type.
	OpTypeLast
	// OpTypeRoute is the route operation type.
	OpTypeRoute
	// OpTypeByteorder is the byteorder operation type.
	OpTypeByteorder
	// OpTypeMeta is the meta operation type.
	OpTypeMeta
	// OpTypeNAT is the NAT operation type.
	OpTypeNAT
	// OpTypeUnknown is the unknown operation type.
	OpTypeUnknown
)

var opTypeStrings = []string{
	OpTypeImmediate:  "immediate",
	OpTypeComparison: "comparison",
	OpTypeRanged:     "ranged",
	OpTypePayload:    "payload",
	OpTypeBitwise:    "bitwise",
	OpTypeCounter:    "counter",
	OpTypeLast:       "last",
	OpTypeRoute:      "route",
	OpTypeByteorder:  "byteorder",
	OpTypeMeta:       "meta",
	OpTypeNAT:        "nat",
	OpTypeUnknown:    "unknown",
}

// String returns a string representation of the operation type.
func (o OpType) String() string {
	if o >= 0 && o < OpTypeUnknown {
		return opTypeStrings[o]
	}
	return "unknown"
}

// ToOpType converts a string to an operation type.
func ToOpType(s string) OpType {
	switch s {
	case "immediate":
		return OpTypeImmediate
	case "cmp":
		return OpTypeComparison
	case "ranged":
		return OpTypeRanged
	case "payload":
		return OpTypePayload
	case "bitwise":
		return OpTypeBitwise
	case "counter":
		return OpTypeCounter
	case "last":
		return OpTypeLast
	case "route":
		return OpTypeRoute
	case "byteorder":
		return OpTypeByteorder
	case "meta":
		return OpTypeMeta
	case "nat":
		return OpTypeNAT
	default:
		return OpTypeUnknown
	}
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

// registerSet represents the set of registers supported by the kernel.
// Use registerData.storeData to set data in the registers.
// Note: Corresponds to nft_regs from include/net/netfilter/nf_tables.h.
type registerSet struct {
	verdict stack.NFVerdict         // 16-byte verdict register
	data    [registersByteSize]byte // 4 16-byte registers or 16 4-byte registers
}

// newRegisterSet creates a new registerSet with the Continue Verdict and all
// registers set to 0.
func newRegisterSet() registerSet {
	return registerSet{
		verdict: stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)},
		data:    [registersByteSize]byte{0},
	}
}

// Verdict returns the verdict data.
func (regs *registerSet) Verdict() stack.NFVerdict {
	return regs.verdict
}

func (regs *registerSet) String() string {
	return fmt.Sprintf("verdict: %v, data: %x", regs.verdict, regs.data)
}

// NF Verdict Helper Functions

// VerdictString returns a string representation of the verdict.
func VerdictString(v stack.NFVerdict) string {
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

// netlinkAFToStackAF maps address families from linux/netfilter.h to their
// corresponding netfilter address families.
// From linux/include/uapi/linux/netfilter.h
var netlinkAFToStackAF = map[uint8]stack.AddressFamily{
	linux.NFPROTO_UNSPEC: stack.Unspec,
	linux.NFPROTO_INET:   stack.Inet,
	linux.NFPROTO_IPV4:   stack.IP,
	linux.NFPROTO_ARP:    stack.Arp,
	linux.NFPROTO_NETDEV: stack.Netdev,
	linux.NFPROTO_BRIDGE: stack.Bridge,
	linux.NFPROTO_IPV6:   stack.IP6,
}

// AFtoNetlinkAF converts a generic address family to a netfilter address family.
// On error, we simply cast it to be a stack.AddressFamily and return an error to allow netfilter
// sockets to handle it accordingly if needed.
func AFtoNetlinkAF(af uint8) (stack.AddressFamily, *syserr.Error) {
	naf, ok := netlinkAFToStackAF[af]
	if !ok {
		return stack.NumAFs, syserr.ErrNotSupported
	}
	return naf, nil
}

// parseVerdictAttrs parses and validates the verdict data from the data attributes.
func parseVerdictAttrs(tab *Table, dataAttrs map[uint16]nlmsg.BytesView) (stack.NFVerdict, *syserr.AnnotatedError) {
	v := stack.NFVerdict{}
	vBytes, ok := dataAttrs[linux.NFTA_DATA_VERDICT]
	if !ok {
		return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_DATA_VERDICT attribute is not found")
	}
	return validateVerdictData(tab, nlmsg.AttrsView(vBytes))
}

func parseDataAttrs(dataAttrs map[uint16]nlmsg.BytesView) ([]byte, *syserr.AnnotatedError) {
	vBytes, ok := dataAttrs[linux.NFTA_DATA_VALUE]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_DATA_VALUE attribute is not found")
	}
	return nlmsg.AttrsView(vBytes), nil
}

// validateDataRegister ensures that the data register and it's access is valid.
func validateDataRegister(regStartIdx int, dataSizeBytes int) *syserr.AnnotatedError {
	if dataSizeBytes == 0 {
		return syserr.NewAnnotatedError(syserr.ErrRange, "data size cannot be zero")
	}
	// Although this check is not needed as the next check will catch this,
	// added it just for readable error messages.
	if regStartIdx >= registersByteSize {
		return syserr.NewAnnotatedError(syserr.ErrRange, "register start index is invalid")
	}
	// Kernel code: net/netfilter/nf_tables_api.c:nft_validate_register_store
	endIdx := regStartIdx + dataSizeBytes - 1
	if endIdx >= registersByteSize {
		return syserr.NewAnnotatedError(syserr.ErrRange, "data is too large for register set")
	}
	return nil
}

// dumpDataAttr dumps the data attribute for the dump operation.
func dumpDataAttr(data []byte) ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_DATA_VALUE, primitive.AsByteSlice(data))
	return m.Buffer(), nil
}

// dumpVerdictDataAttr dumps the verdict data attribute for the dump operation.
func dumpVerdictDataAttr(verdict stack.NFVerdict) ([]byte, *syserr.AnnotatedError) {
	nestedAttr := nlmsg.NestedAttr{}
	nestedAttr.PutAttr(linux.NFTA_VERDICT_CODE, nlmsg.PutU32(uint32(verdict.Code)))
	if int32(verdict.Code) == linux.NFT_JUMP || int32(verdict.Code) == linux.NFT_GOTO {
		nestedAttr.PutAttrString(linux.NFTA_VERDICT_CHAIN, verdict.ChainName)
	}
	m := &nlmsg.Message{}
	m.PutNestedAttr(linux.NFTA_DATA_VERDICT, nestedAttr)
	return m.Buffer(), nil
}

// regNumToIdx converts a register number to an index for the registerSet.data.
// Also validates that the data register and it's access is valid.
func regNumToIdx(reg uint8, dataLenBytes int) (int, *syserr.AnnotatedError) {
	regIdx, ok := func() (int, bool) {
		if is4ByteRegister(reg) {
			return int((reg - linux.NFT_REG32_00) * linux.NFT_REG32_SIZE), true
		}
		if is16ByteRegister(reg) {
			return int((reg - linux.NFT_REG_1) * linux.NFT_REG_SIZE), true
		}
		return -1, false
	}()
	if !ok {
		return -1, syserr.NewAnnotatedError(syserr.ErrRange, fmt.Sprintf("Nftables: Unsupported register number: %d", reg))
	}
	if err := validateDataRegister(regIdx, dataLenBytes); err != nil {
		return -1, err
	}
	return regIdx, nil
}

// formatRegIdxForDump formats the register index for the dump operation.
// net/netfilter/nf_tables_api.c:nft_dump_register
func formatRegIdxForDump(regIdx int) uint32 {
	if regIdx >= registersByteSize {
		return 0
	}
	if regIdx%linux.NFT_REG_SIZE == 0 {
		return uint32(regIdx/linux.NFT_REG_SIZE) + linux.NFT_REG_1
	}
	if regIdx%linux.NFT_REG32_SIZE != 0 {
		return 0
	}
	return uint32(regIdx/linux.NFT_REG32_SIZE) + linux.NFT_REG32_00
}

// validateVerdictData validates the verdict data bytes and returns the data as a verdict.
func validateVerdictData(tab *Table, bytes nlmsg.AttrsView) (stack.NFVerdict, *syserr.AnnotatedError) {
	v := stack.NFVerdict{}
	verdictAttrs, ok := NfParse(bytes)
	if !ok {
		return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse verdict data")
	}

	verdictCodeBytes, ok := verdictAttrs[linux.NFTA_VERDICT_CODE]
	if !ok {
		return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_VERDICT_CODE attribute is not found")
	}

	verdictCode, ok := verdictCodeBytes.Uint32()
	if !ok {
		return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_VERDICT_CODE attribute cannot be parsed to a uint32")
	}

	verdictCode = nlmsg.NetToHostU32(verdictCode)
	switch int32(verdictCode) {
	case linux.NF_ACCEPT, linux.NF_DROP, linux.NF_QUEUE,
		linux.NFT_CONTINUE, linux.NFT_BREAK, linux.NFT_RETURN:

	case linux.NFT_JUMP, linux.NFT_GOTO:
		var chain *Chain
		var err *syserr.AnnotatedError
		if chainNameBytes, ok := verdictAttrs[linux.NFTA_VERDICT_CHAIN]; ok {
			if chain, err = tab.GetChain(chainNameBytes.String()); err != nil {
				return v, err
			}
		} else if _, ok := verdictAttrs[linux.NFTA_VERDICT_CHAIN_ID]; ok {
			// TODO - b/434243967: Add support for looking up chains via their transaction id.
			return v, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Looking up chains via their id is not supported")
		} else {
			return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Attributes for verdict data must contain a chain name or chain id")
		}

		if chain.IsBaseChain() {
			return v, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Nftables: Base chains are not supported as jump targets")
		}

		if chain.IsBound() {
			return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Already Bound chains cannot be jump targets")
		}

		if chain.GetFlags()&linux.NFT_CHAIN_BINDING != 0 {
			return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Chain binding must be set for chains to be used as jump targets")
		}

		if !chain.IncrementChainUse() {
			return v, syserr.NewAnnotatedError(syserr.ErrTooManyOpenFiles, fmt.Sprintf("Nftables: Chain use exceeds the maximum number of chains that can jump to chain %s", chain.GetName()))
		}

		v.ChainName = chain.name
	default:
		return v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("Nftables: Unsupported verdict code: %d", verdictCode))
	}

	// TODO - b/345684870: Potentially modify this to take a pointer to the chain it is jumping to.
	// Would need to ensure that the chain cannot be removed while it is being pointed to (using use field).
	v.Code = verdictCode
	return v, nil
}

// deepCopyRule returns a deep copy of the Rule struct.
func deepCopyRule(rule *Rule, chainCopy *Chain) *Rule {
	return &Rule{
		chain: chainCopy,
		// Because the underlying op data within the slice cannot be
		// modified, creating a shallow copy is sufficient. Even if the
		// original struct is modified and an operation is dropped,
		// the copy will hold a reference to the original operation,
		// preventing it from being destroyed.
		ops:    slices.Clone(rule.ops),
		handle: rule.handle,
		udata:  slices.Clone(rule.udata),
	}
}

// deepCopyChain returns a deep copy of the Chain struct.
func deepCopyChain(chain *Chain, tableCopy *Table) *Chain {
	chainCopy := &Chain{
		name:         chain.name,
		table:        tableCopy,
		handle:       chain.handle,
		flags:        chain.flags,
		handleToRule: make(map[uint64]*Rule),
		userData:     slices.Clone(chain.userData),
		chainUse:     chain.chainUse,
		bound:        chain.bound,
		comment:      chain.comment,
	}

	// LINT.IfChange(base_chain_info_copy)

	// BaseChainInfo is immutable after creation and it only contains
	// primitives, so we can safely copy it.
	if chain.baseChainInfo != nil {
		chainCopy.baseChainInfo = &BaseChainInfo{}
		*chainCopy.baseChainInfo = *chain.baseChainInfo
	}

	// LINT.ThenChange()

	for _, rule := range chain.rules {
		ruleCopy := deepCopyRule(rule, chainCopy)
		chainCopy.rules = append(chainCopy.rules, ruleCopy)
		chainCopy.handleToRule[ruleCopy.handle] = ruleCopy
	}
	return chainCopy
}

// deepCopyTable returns a deep copy of the Table struct.
func deepCopyTable(table *Table, afFilter *addressFamilyFilter) *Table {
	tableCopy := &Table{
		name:         table.name,
		afFilter:     afFilter,
		chains:       make(map[string]*Chain),
		chainHandles: make(map[uint64]*Chain),
		flagSet:      make(map[TableFlag]struct{}),
		handle:       table.handle,
		owner:        table.owner,
		userData:     slices.Clone(table.userData),
	}
	tableCopy.handleCounter.Store(table.handleCounter.Load())

	for flag := range table.flagSet {
		tableCopy.flagSet[flag] = struct{}{}
	}

	for chainName, chain := range table.chains {
		chainCopy := deepCopyChain(chain, tableCopy)
		tableCopy.chains[chainName] = chainCopy
		tableCopy.chainHandles[chainCopy.handle] = chainCopy
	}
	return tableCopy
}

// DeepCopy returns a deep copy of the NFTables struct.
// Assumes that the caller has already locked the mutex.
// **********************************************************************
// TODO: b/436922484: Add a transaction system to avoid deep copying the entire
// NFTables structure.
// **********************************************************************
func (nf *NFTables) DeepCopy() *NFTables {
	nftCopy := &NFTables{
		clock:              nf.clock,
		startTime:          nf.startTime,
		rng:                nf.rng,
		tableHandleCounter: atomicbitops.Uint64{},
	}

	nftCopy.tableHandleCounter.Store(nf.tableHandleCounter.Load())
	for i, filter := range nf.filters {
		if filter == nil {
			continue
		}

		nftCopy.filters[i] = &addressFamilyFilter{
			family:       filter.family,
			nftState:     nftCopy,
			tables:       make(map[string]*Table),
			tableHandles: make(map[uint64]*Table),
			hfStacks:     make(map[stack.NFHook]*hookFunctionStack),
		}

		for tableName, table := range filter.tables {
			tableCopy := deepCopyTable(table, nftCopy.filters[i])
			nftCopy.filters[i].tables[tableName] = tableCopy
			nftCopy.filters[i].tableHandles[tableCopy.handle] = tableCopy
		}

		for hook, hfStack := range filter.hfStacks {
			hfStackCopy := &hookFunctionStack{}
			for _, chain := range hfStack.baseChains {
				chainCopy := nftCopy.filters[i].tables[chain.table.name].chains[chain.name]
				hfStackCopy.baseChains = append(hfStackCopy.baseChains, chainCopy)
				nftCopy.addChainToCache(chainCopy)
			}
			for _, chain := range hfStack.natBaseChains {
				chainCopy := nftCopy.filters[i].tables[chain.table.name].chains[chain.name]
				hfStackCopy.natBaseChains = append(hfStackCopy.natBaseChains, chainCopy)
				nftCopy.addChainToCache(chainCopy)
			}
			nftCopy.filters[i].hfStacks[hook] = hfStackCopy
		}
	}
	return nftCopy
}

// ReplaceNFTables replaces the tables of the NFTables struct
// with the tables of the passed in NFTables struct.
func (nf *NFTables) ReplaceNFTables(nftCopy *NFTables) {
	nf.filters = nftCopy.filters
	nf.ip4InetBaseChains = nftCopy.ip4InetBaseChains
	nf.ip6InetBaseChains = nftCopy.ip6InetBaseChains
	nf.genid++
}
