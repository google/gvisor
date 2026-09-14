// Copyright 2026 The gVisor Authors.
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

package boot

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// savedNetworkInterfacesKey is the metadata key for the saved network interfaces JSON.
	savedNetworkInterfacesKey = "saved_network_interfaces"
)

// SavedInterfaceAddress represents an IP address and prefix length for a saved interface.
type SavedInterfaceAddress struct {
	Address   string `json:"address"`
	PrefixLen int    `json:"prefix_len,omitempty"`
	Family    string `json:"family"` // "ipv4" or "ipv6"
}

// SavedInterfaceInfo represents a network interface saved during checkpoint.
type SavedInterfaceInfo struct {
	Name      string                  `json:"name"`
	Addresses []SavedInterfaceAddress `json:"addresses"`
}

// addrEntry is one address belonging to a single interface, used while
// pairing the saved side against the restored side.
type addrEntry struct {
	ip     string
	prefix int
}

// isRemappableAddr reports whether ip is an address that is meaningful to
// remap across a checkpoint/restore boundary.
//
// Link-local addresses (IPv6 fe80::/10 and IPv4 169.254.0.0/16) are excluded
// because they are derived from the interface's hardware address rather than
// assigned by the network. The restored value is therefore unrelated to the
// saved one, and pairing them yields entries that are at best noise and at
// worst displace a real address during matching. Loopback and multicast
// addresses are excluded for the same reason.
func isRemappableAddr(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	return true
}

// sameSubnet reports whether a and b share an identical network prefix. Used
// to pair a saved address with the restored address that replaced it when an
// interface keeps its subnet but changes host address.
func sameSubnet(a, b addrEntry) bool {
	if a.prefix <= 0 || b.prefix <= 0 || a.prefix != b.prefix {
		return false
	}
	ipA, ipB := net.ParseIP(a.ip), net.ParseIP(b.ip)
	if ipA == nil || ipB == nil {
		return false
	}
	if v4 := ipA.To4(); v4 != nil {
		ipA = v4
	}
	if v4 := ipB.To4(); v4 != nil {
		ipB = v4
	}
	if len(ipA) != len(ipB) {
		return false
	}
	mask := net.CIDRMask(a.prefix, len(ipA)*8)
	if mask == nil {
		return false
	}
	return ipA.Mask(mask).Equal(ipB.Mask(mask))
}

// pairAddresses maps saved addresses onto restored addresses for a single
// interface and a single address family, recording results in remap.
//
// Pairing runs in three passes so that the outcome does not depend on the
// order in which either side happens to enumerate its addresses. This matters
// because the two orderings come from unrelated sources: the saved side is
// netstack's insertion-ordered primary address list, while the restored side
// is whatever order the kernel reports over netlink.
//
//  1. Identity. An address present on both sides is pinned to itself and
//     removed from both pools, contributing no remap entry. Without this an
//     unchanged address could be paired with an unrelated new one purely
//     because of position.
//  2. Same prefix. Remaining addresses sharing a subnet are paired, which is
//     the correct reading when a NIC keeps its subnet but changes host.
//  3. Positional. Anything still unmatched is paired in sorted order. That is
//     unambiguous when a single address remains on each side; beyond that it
//     is a guess, so a warning is logged directing the operator to --ip-remap.
func pairAddresses(ifaceName, family string, saved, restored []addrEntry, remap map[string]string) {
	// Pass 1: drop addresses that appear unchanged on both sides.
	savedSet := make(map[string]bool, len(saved))
	for _, s := range saved {
		savedSet[s.ip] = true
	}
	restoredSet := make(map[string]bool, len(restored))
	for _, r := range restored {
		restoredSet[r.ip] = true
	}
	var sPool, rPool []addrEntry
	for _, s := range saved {
		if !restoredSet[s.ip] {
			sPool = append(sPool, s)
		}
	}
	for _, r := range restored {
		if !savedSet[r.ip] {
			rPool = append(rPool, r)
		}
	}

	// Pass 2: pair addresses that share a subnet.
	usedR := make([]bool, len(rPool))
	var sLeft []addrEntry
	for _, s := range sPool {
		matched := -1
		for i, r := range rPool {
			if usedR[i] {
				continue
			}
			if sameSubnet(s, r) {
				matched = i
				break
			}
		}
		if matched >= 0 {
			usedR[matched] = true
			remap[s.ip] = rPool[matched].ip
			continue
		}
		sLeft = append(sLeft, s)
	}
	var rLeft []addrEntry
	for i, r := range rPool {
		if !usedR[i] {
			rLeft = append(rLeft, r)
		}
	}
	if len(sLeft) == 0 || len(rLeft) == 0 {
		return
	}

	// Pass 3: sorted positional pairing for the remainder.
	sort.Slice(sLeft, func(i, j int) bool { return sLeft[i].ip < sLeft[j].ip })
	sort.Slice(rLeft, func(i, j int) bool { return rLeft[i].ip < rLeft[j].ip })
	if len(sLeft) > 1 || len(rLeft) > 1 {
		log.Warningf("computeAutoLocalRemap: interface %q has %d unmatched saved and %d unmatched restored %s address(es) that share no subnet; pairing them in sorted order, which is a guess. Pass --ip-remap explicitly if this mapping is wrong.",
			ifaceName, len(sLeft), len(rLeft), family)
	}
	for i := 0; i < len(sLeft) && i < len(rLeft); i++ {
		remap[sLeft[i].ip] = rLeft[i].ip
	}
}

// splitFamilies partitions addrs into IPv4 and IPv6 buckets, discarding any
// address that is not meaningful to remap.
func splitFamilies(addrs []addrEntry) (v4, v6 []addrEntry) {
	for _, a := range addrs {
		ip := net.ParseIP(a.ip)
		if !isRemappableAddr(ip) {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// setNetworkInterfaceMetadata records the network interface names and IP addresses
// into saveOpts.Metadata so that at restore time, the local network interface IP addresses
// can be automatically remapped without requiring explicit user-provided IP mappings.
func (l *Loader) setNetworkInterfaceMetadata(saveOpts *state.SaveOpts) error {
	netns := l.k.RootNetworkNamespace()
	if netns == nil {
		log.Infof("setNetworkInterfaceMetadata: RootNetworkNamespace is nil")
		return nil
	}
	st := netns.Stack()
	if st == nil {
		log.Infof("setNetworkInterfaceMetadata: netns.Stack is nil")
		return nil
	}
	eps, ok := st.(*netstack.Stack)
	if !ok || eps.Stack == nil {
		log.Infof("setNetworkInterfaceMetadata: stack is not *netstack.Stack: %T", st)
		return nil
	}
	var savedIfaces []SavedInterfaceInfo
	nicInfos := eps.Stack.NICInfo()
	log.Infof("setNetworkInterfaceMetadata: found %d NICs in stack", len(nicInfos))
	for nicID, iface := range nicInfos {
		log.Infof("setNetworkInterfaceMetadata: NIC %d: name=%s, loopback=%v, addrs=%d", nicID, iface.Name, iface.Flags.Loopback, len(iface.ProtocolAddresses))
		if iface.Flags.Loopback {
			continue
		}
		var addrs []SavedInterfaceAddress
		for _, protoAddr := range iface.ProtocolAddresses {
			addrStr := protoAddr.AddressWithPrefix.Address.String()
			if addrStr == "" {
				continue
			}
			// Skip addresses that cannot meaningfully be remapped, most
			// notably IPv6 link-local addresses, which netstack generates
			// from the link address and which therefore differ arbitrarily
			// between the saved and restored sandbox.
			if !isRemappableAddr(net.ParseIP(addrStr)) {
				log.Infof("setNetworkInterfaceMetadata: skipping non-remappable address %s on NIC %s", addrStr, iface.Name)
				continue
			}
			family := "ipv4"
			if protoAddr.Protocol == header.IPv6ProtocolNumber {
				family = "ipv6"
			}
			addrs = append(addrs, SavedInterfaceAddress{
				Address:   addrStr,
				PrefixLen: protoAddr.AddressWithPrefix.PrefixLen,
				Family:    family,
			})
		}
		if len(addrs) == 0 {
			continue
		}
		// Sort addresses so the serialized form is stable across checkpoints.
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Address < addrs[j].Address })
		savedIfaces = append(savedIfaces, SavedInterfaceInfo{
			Name:      iface.Name,
			Addresses: addrs,
		})
	}
	if len(savedIfaces) == 0 {
		log.Infof("setNetworkInterfaceMetadata: No non-loopback network interfaces to save")
		return nil
	}
	// NICInfo() returns a map, so iteration order is randomized. Sort by name
	// to keep the saved metadata byte-for-byte reproducible.
	sort.Slice(savedIfaces, func(i, j int) bool { return savedIfaces[i].Name < savedIfaces[j].Name })
	data, err := json.Marshal(savedIfaces)
	if err != nil {
		return fmt.Errorf("failed to marshal saved network interfaces: %w", err)
	}
	saveOpts.Metadata[savedNetworkInterfacesKey] = string(data)
	log.Infof("setNetworkInterfaceMetadata: Saved %d network interfaces in metadata: %s", len(savedIfaces), string(data))
	return nil
}

// computeAutoLocalRemap derives an IP remapping table by comparing the saved network interfaces
// (from checkpoint metadata) with the new network interfaces (scraped from the target network namespace).
//
// Interfaces are matched by name (eth0 to eth0, eth1 to eth1), not by position,
// because both sides ultimately derive their name from the same host interface:
// the saved side through stack.NICOptions.Name and the restored side through the
// netns scrape. Positional matching is used only as a fallback when exactly one
// non-loopback interface exists on each side, where position is unambiguous.
func computeAutoLocalRemap(savedIfacesJSON string, args *CreateLinksAndRoutesArgs) map[string]string {
	log.Infof("computeAutoLocalRemap: savedIfacesJSON=%q, args=%+v", savedIfacesJSON, args)
	if savedIfacesJSON == "" || args == nil {
		return nil
	}
	var savedIfaces []SavedInterfaceInfo
	if err := json.Unmarshal([]byte(savedIfacesJSON), &savedIfaces); err != nil {
		log.Warningf("Failed to unmarshal saved network interfaces: %v", err)
		return nil
	}

	type restoredIface struct {
		name  string
		addrs []addrEntry
	}
	var restoredIfaces []restoredIface
	collect := func(name string, addresses []IPWithPrefix) {
		r := restoredIface{name: name}
		for _, addr := range addresses {
			if addr.Address == nil {
				continue
			}
			r.addrs = append(r.addrs, addrEntry{ip: addr.Address.String(), prefix: addr.PrefixLen})
		}
		restoredIfaces = append(restoredIfaces, r)
	}
	for _, link := range args.FDBasedLinks {
		collect(link.Name, link.Addresses)
	}
	for _, link := range args.XDPLinks {
		collect(link.Name, link.Addresses)
	}

	remap := make(map[string]string)

	savedAddrs := func(s SavedInterfaceInfo) []addrEntry {
		var out []addrEntry
		for _, a := range s.Addresses {
			out = append(out, addrEntry{ip: a.Address, prefix: a.PrefixLen})
		}
		return out
	}

	pairIface := func(name string, saved, restored []addrEntry) {
		sV4, sV6 := splitFamilies(saved)
		rV4, rV6 := splitFamilies(restored)
		pairAddresses(name, "IPv4", sV4, rV4, remap)
		pairAddresses(name, "IPv6", sV6, rV6, remap)
	}

	// 1. Match interfaces by name (e.g. eth0 -> eth0, eth1 -> eth1).
	restoredByName := make(map[string]restoredIface, len(restoredIfaces))
	for _, r := range restoredIfaces {
		restoredByName[r.name] = r
	}
	matchedByName := 0
	for _, sIface := range savedIfaces {
		rIface, ok := restoredByName[sIface.Name]
		if !ok {
			continue
		}
		matchedByName++
		pairIface(sIface.Name, savedAddrs(sIface), rIface.addrs)
	}

	// 2. Fallback: no interface name matched, but there is exactly one
	// non-loopback interface on each side, so the pairing is unambiguous.
	if matchedByName == 0 && len(savedIfaces) == 1 && len(restoredIfaces) == 1 {
		log.Infof("computeAutoLocalRemap: no interface name matched; falling back to positional matching of the single saved interface %q onto restored interface %q",
			savedIfaces[0].Name, restoredIfaces[0].name)
		pairIface(savedIfaces[0].Name, savedAddrs(savedIfaces[0]), restoredIfaces[0].addrs)
	}

	// Surface the case where metadata was present but nothing could be
	// derived. Left silent, this manifests much later as connections that
	// restore with stale local addresses and then fail with no explanation.
	if len(savedIfaces) > 0 && len(remap) == 0 {
		savedNames := make([]string, 0, len(savedIfaces))
		for _, s := range savedIfaces {
			savedNames = append(savedNames, s.Name)
		}
		restoredNames := make([]string, 0, len(restoredIfaces))
		for _, r := range restoredIfaces {
			restoredNames = append(restoredNames, r.name)
		}
		log.Warningf("computeAutoLocalRemap: derived no local IP remappings. Saved interfaces %v, restored interfaces %v, matched by name: %d. If the local addresses did change, connections will restore with stale addresses; pass --ip-remap explicitly.",
			savedNames, restoredNames, matchedByName)
	}

	log.Infof("computeAutoLocalRemap: derived auto-local remap table: %+v", remap)
	return remap
}
