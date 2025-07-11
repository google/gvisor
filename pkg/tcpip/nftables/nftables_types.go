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
	"gvisor.dev/gvisor/pkg/rand"
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

	// Number of bytes for 4 16-byte registers or 16 4-byte registers.
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
	stack.IP:     linux.NFPROTO_INET,
	stack.IP6:    linux.NFPROTO_IPV6,
	stack.Inet:   linux.NFPROTO_IPV6,
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
var supportedHooks [stack.NumAFs][]stack.NFHook = [stack.NumAFs][]stack.NFHook{
	stack.IP:     {stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress},
	stack.IP6:    {stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress},
	stack.Inet:   {stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress},
	stack.Arp:    {stack.NFInput, stack.NFOutput},
	stack.Bridge: {stack.NFPrerouting, stack.NFInput, stack.NFForward, stack.NFOutput, stack.NFPostrouting, stack.NFIngress},
	stack.Netdev: {stack.NFIngress, stack.NFEgress},
}

// validateHook ensures the hook is within bounds and supported for the given
// address family.
func validateHook(hook stack.NFHook, family stack.AddressFamily) *syserr.AnnotatedError {
	if hook >= stack.NFNumHooks {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid hook: %d", int(hook)))
	}
	if slices.Contains(supportedHooks[family], hook) {
		return nil
	}

	// The hook is not supported for the given address family.
	return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("hook %d is not supported for address family %d", int(hook), int(family)))
}

// NFTables represents the nftables state for all address families.
// Note: unlike iptables, nftables doesn't start with any initialized tables.
type NFTables struct {
	filters            [stack.NumAFs]*addressFamilyFilter // Filters for each address family.
	clock              tcpip.Clock                        // Clock for timing evaluations.
	startTime          time.Time                          // Time NFTables object was created.
	rng                rand.RNG                           // Random number generator.
	tableHandleCounter atomicbitops.Uint64                // Table handle counter.
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

	// flagSet is the set of optional flags for the table.
	// Note: currently nftables only has the single Dormant flag.
	flagSet map[TableFlag]struct{}

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

// hookFunctionStack represents the list of base chains for a specific hook.
// The stack is ordered by priority and built as chains are added to tables.
type hookFunctionStack struct {
	hook       stack.NFHook
	baseChains []*Chain
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
	Hook stack.NFHook

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
		return Priority{}, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("standard priority name cannot be empty"))
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

// standardPriorityMatrix is used to look up information for the predefined
// standard priority names.
var standardPriorityMatrix = map[stack.AddressFamily](map[string]standardPriority){
	stack.IP: spmIP,
	// Note: IPv6 standard priorities constants currently have the same values as
	// IPv4's, but the definitions (in the linux kernel) may change in the future.
	stack.IP6: map[string]standardPriority{ // from uapi/linux/netfilter_ipv6.h
		"raw":      {name: "raw", value: linux.NF_IP6_PRI_RAW, hooks: supportedHooks[stack.IP6]},
		"mangle":   {name: "mangle", value: linux.NF_IP6_PRI_MANGLE, hooks: supportedHooks[stack.IP6]},
		"dstnat":   {name: "dstnat", value: linux.NF_IP6_PRI_NAT_DST, hooks: []stack.NFHook{stack.NFPrerouting}},
		"filter":   {name: "filter", value: linux.NF_IP6_PRI_FILTER, hooks: supportedHooks[stack.IP6]},
		"security": {name: "security", value: linux.NF_IP6_PRI_SECURITY, hooks: supportedHooks[stack.IP6]},
		"srcnat":   {name: "srcnat", value: linux.NF_IP6_PRI_NAT_SRC, hooks: []stack.NFHook{stack.NFPostrouting}},
	},
	stack.Inet: spmIP,
	stack.Arp: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooks[stack.Arp]},
	},
	stack.Bridge: map[string]standardPriority{ // from uapi/linux/netfilter_bridge.h
		"dstnat": {name: "dstnat", value: linux.NF_BR_PRI_NAT_DST_BRIDGED, hooks: []stack.NFHook{stack.NFPrerouting}},
		"filter": {name: "filter", value: linux.NF_BR_PRI_FILTER_BRIDGED, hooks: supportedHooks[stack.Bridge]},
		"out":    {name: "out", value: linux.NF_BR_PRI_NAT_DST_OTHER, hooks: []stack.NFHook{stack.NFOutput}},
		"srcnat": {name: "srcnat", value: linux.NF_BR_PRI_NAT_SRC, hooks: []stack.NFHook{stack.NFPostrouting}},
	},
	stack.Netdev: map[string]standardPriority{ // defined as same as IP filter priority
		"filter": {name: "filter", value: spmIP["filter"].value, hooks: supportedHooks[stack.Netdev]},
	},
}

// Used in the standardPriorityMatrix above.
// Note: IPv4 and Inet address families use the same standard priority names.
var spmIP = map[string]standardPriority{ // from uapi/linux/netfilter_ipv4.h
	"raw":      {name: "raw", value: linux.NF_IP_PRI_RAW, hooks: supportedHooks[stack.IP]},
	"mangle":   {name: "mangle", value: linux.NF_IP_PRI_MANGLE, hooks: supportedHooks[stack.IP]},
	"dstnat":   {name: "dstnat", value: linux.NF_IP_PRI_NAT_DST, hooks: []stack.NFHook{stack.NFPrerouting}},
	"filter":   {name: "filter", value: linux.NF_IP_PRI_FILTER, hooks: supportedHooks[stack.IP]},
	"security": {name: "security", value: linux.NF_IP_PRI_SECURITY, hooks: supportedHooks[stack.IP]},
	"srcnat":   {name: "srcnat", value: linux.NF_IP_PRI_NAT_SRC, hooks: []stack.NFHook{stack.NFPostrouting}},
}

// validateBaseChainInfo ensures the base chain info is valid by checking the
// compatibility of the set base chain type, hook, and priority, and the given
// address family.
// Note: errors if the provided base chain info is nil.
func validateBaseChainInfo(info *BaseChainInfo, family stack.AddressFamily) *syserr.AnnotatedError {
	if info == nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("base chain info is nil"))
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
	validateRegister(reg uint8) *syserr.AnnotatedError

	// storeData sets the data in the destination register, panicking if the
	// register is not valid for the data type.
	// Note: assumes data is valid for register. This is used primarily during
	// operation evaluation and the data type/register compatibility should have
	// been checked during the operation init.
	storeData(regs *registerSet, reg uint8)
}

// verdictData represents a verdict as data to be stored in a register.
type verdictData struct {
	data stack.NFVerdict
}

// newVerdictData creates a registerData for a verdict.
func newVerdictData(verdict stack.NFVerdict) verdictData { return verdictData{data: verdict} }

// String returns a string representation of the verdict data.
func (rd verdictData) String() string {
	return VerdictString(rd.data)
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
func (rd verdictData) validateRegister(reg uint8) *syserr.AnnotatedError {
	if !isVerdictRegister(reg) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("verdict can only be stored in verdict register"))
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
func (rd bytesData) validateRegister(reg uint8) *syserr.AnnotatedError {
	if isVerdictRegister(reg) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("data cannot be stored in verdict register"))
	}
	if is4ByteRegister(reg) && len(rd.data) > linux.NFT_REG32_SIZE {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("%d-byte data cannot be stored in %d-byte register", len(rd.data), linux.NFT_REG32_SIZE))
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

// netlinkAFToStackAF maps address families from linux/socket.h to their corresponding
// netfilter address families.
// From linux/include/uapi/linux/netfilter.h
var netlinkAFToStackAF = map[uint8]stack.AddressFamily{
	linux.AF_UNSPEC:    stack.Unspec,
	linux.AF_UNIX:      stack.Inet,
	linux.AF_INET:      stack.IP,
	linux.AF_AX25:      stack.Arp,
	linux.AF_APPLETALK: stack.Netdev,
	linux.AF_BRIDGE:    stack.Bridge,
	linux.AF_INET6:     stack.IP6,
}

// AFtoNetlinkAF converts a generic address family to a netfilter address family.
// On error, we simply return stack.NumAFs, which will fail validate address family checks later
// on. This is done because Linux does not check these address families for all nftables functions,
// only for certain ones.
func AFtoNetlinkAF(af uint8) stack.AddressFamily {
	naf, ok := netlinkAFToStackAF[af]
	if !ok {
		return stack.NumAFs
	}
	return naf
}
