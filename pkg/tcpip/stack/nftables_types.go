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
)

// NFTablesInterface is an interface for evaluating chains.
type NFTablesInterface interface {
	CheckPrerouting(pkt *PacketBuffer, af AddressFamily) bool
	CheckInput(pkt *PacketBuffer, af AddressFamily) bool
	CheckForward(pkt *PacketBuffer, af AddressFamily) bool
	CheckOutput(pkt *PacketBuffer, af AddressFamily) bool
	CheckPostrouting(pkt *PacketBuffer, af AddressFamily) bool
	CheckIngress(pkt *PacketBuffer, af AddressFamily) bool
	CheckEgress(pkt *PacketBuffer, af AddressFamily) bool
}

// NFHook describes specific points in the pipeline where chains can be attached.
// Each address family has its own set of hooks (defined in supportedHooks).
// For IPv4/IPv6/Inet and Bridge, there are two possible pipelines:
// 1. Prerouting -> Input -> ~Local Process~ -> Output -> Postrouting
// 2. Prerouting -> Forward -> Postrouting
type NFHook uint16

const (
	// NFPrerouting Hook is supported by IPv4/IPv6/Inet, Bridge Families.
	// Prerouting is evaluated before a packet is routed to applications or forwarded.
	NFPrerouting NFHook = iota

	// NFInput Hook is supported by IPv4/IPv6/Inet, Bridge, ARP Families.
	// Input is evaluated before a packet reaches an application.
	NFInput

	// NFForward Hook is supported by IPv4/IPv6/Inet, Bridge Families.
	// Forward is evaluated once it's decided that a packet should be forwarded to another host.
	NFForward

	// NFOutput Hook is supported by IPv4/IPv6/Inet, Bridge, ARP Families.
	// Output is evaluated after a packet is written by an application to be sent out.
	NFOutput

	// NFPostrouting Hook is supported by IPv4/IPv6/Inet, Bridge Families.
	// Postrouting is evaluated just before a packet goes out on the wire.
	NFPostrouting

	// NFIngress Hook is supported by IPv4/IPv6/Inet, Bridge, Netdev Families.
	// Ingress is the first hook evaluated, even before prerouting.
	NFIngress

	// NFEgress Hook is supported by Netdev Family only.
	// Egress is the last hook evaluated, after the packet has been processed by the
	// application and is being prepared for transmission out of the network interface.
	NFEgress

	// NFNumHooks is the number of hooks supported by nftables.
	NFNumHooks
)

// hookStrings maps hooks to their string representation.
var hookStrings = map[NFHook]string{
	NFPrerouting:  "Prerouting",
	NFInput:       "Input",
	NFForward:     "Forward",
	NFOutput:      "Output",
	NFPostrouting: "Postrouting",
	NFIngress:     "Ingress",
	NFEgress:      "Egress",
}

// String for Hook returns the name of the hook.
func (h NFHook) String() string {
	if hook, ok := hookStrings[h]; ok {
		return hook
	}
	panic(fmt.Sprintf("invalid NFHook: %d", int(h)))
}

// AddressFamily describes the 6 address families supported by nftables.
// The address family determines the type of packets processed, and each family
// contains hooks at specific stages of the packet processing pipeline.
type AddressFamily int

const (
	// Unspec represents an unspecified address family.
	Unspec AddressFamily = iota

	// IP     represents IPv4 Family.
	IP

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

// AddressFamilyStrings maps address families to their string representation.
var AddressFamilyStrings = map[AddressFamily]string{
	Unspec: "UNSPEC",
	IP:     "IPv4",
	IP6:    "IPv6",
	Inet:   "Internet (Both IPv4/IPv6)",
	Arp:    "ARP",
	Bridge: "Bridge",
	Netdev: "Netdev",
}

// ValidateAddressFamily ensures the family address is valid (within bounds).
// Unspecified address family is not valid. It is only used to reference all address families.
func ValidateAddressFamily(family AddressFamily) error {
	if family < 1 || family >= NumAFs {
		return fmt.Errorf("invalid address family: %d", int(family))
	}
	return nil
}

// String for AddressFamily returns the name of the address family.
func (f AddressFamily) String() string {
	if af, ok := AddressFamilyStrings[f]; ok {
		return af
	}
	panic(fmt.Sprintf("invalid address family: %d", int(f)))
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

// NFVerdict represents the result of evaluating a packet against a rule or chain.
type NFVerdict struct {
	// Code is the numeric code that represents the verdict issued.
	Code uint32

	// ChainName is the name of the chain to continue evaluation if the verdict is
	// Jump or Goto.
	// Note: the chain must be in the same table as the current chain.
	ChainName string
}
