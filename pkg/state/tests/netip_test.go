// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"bytes"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func TestNetipValues(t *testing.T) {
	addresses := []netip.Addr{
		{},
		netip.IPv4Unspecified(),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.IPv6Unspecified(),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("fe80::1%eth0"),
	}
	prefixes := []netip.Prefix{
		{},
		netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 33),
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 24),
		netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 32),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		netip.PrefixFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 120),
		netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 64),
		netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 128),
	}
	addressPorts := []netip.AddrPort{
		{},
		netip.AddrPortFrom(netip.Addr{}, 80),
		netip.MustParseAddrPort("0.0.0.0:80"),
		netip.MustParseAddrPort("192.0.2.1:65535"),
		netip.MustParseAddrPort("[::ffff:192.0.2.1]:80"),
		netip.MustParseAddrPort("[::]:0"),
		netip.MustParseAddrPort("[2001:db8::1]:80"),
		netip.MustParseAddrPort("[fe80::1%eth0]:80"),
	}
	original := netipContainer{
		address:       netip.MustParseAddr("fe80::1%eth0"),
		prefix:        netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 64),
		addressPort:   netip.MustParseAddrPort("[fe80::1%eth0]:80"),
		addresses:     addresses,
		prefixes:      prefixes,
		addressPorts:  addressPorts,
		byAddress:     make(map[netip.Addr]int, len(addresses)),
		byPrefix:      make(map[netip.Prefix]int, len(prefixes)),
		byAddressPort: make(map[netip.AddrPort]int, len(addressPorts)),
	}
	original.addressPointer = &original.address
	original.prefixPointer = &original.prefix
	original.addrPortPointer = &original.addressPort
	for i, a := range addresses {
		original.byAddress[a] = i
		original.values = append(original.values, a)
	}
	for i, p := range prefixes {
		original.byPrefix[p] = i
		original.values = append(original.values, p)
	}
	for i, ap := range addressPorts {
		original.byAddressPort[ap] = i
		original.values = append(original.values, ap)
	}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var restored netipContainer
	if _, err := state.Load(t.Context(), &buf, &restored); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Use equality and map lookups, not reflect.DeepEqual: distinct interned
	// handles can contain deeply equal contents but remain different map keys.
	if restored.address != original.address || restored.prefix != original.prefix || restored.addressPort != original.addressPort {
		t.Errorf("fields = (%v, %v, %v), want (%v, %v, %v)", restored.address, restored.prefix, restored.addressPort, original.address, original.prefix, original.addressPort)
	}
	if restored.addressPointer != &restored.address {
		t.Errorf("addressPointer = %p, want alias %p", restored.addressPointer, &restored.address)
	}
	if restored.prefixPointer != &restored.prefix {
		t.Errorf("prefixPointer = %p, want alias %p", restored.prefixPointer, &restored.prefix)
	}
	if restored.addrPortPointer != &restored.addressPort {
		t.Errorf("addrPortPointer = %p, want alias %p", restored.addrPortPointer, &restored.addressPort)
	}
	if !slices.Equal(restored.addresses, addresses) {
		t.Errorf("addresses = %v, want %v", restored.addresses, addresses)
	}
	if !slices.Equal(restored.prefixes, prefixes) {
		t.Errorf("prefixes = %v, want %v", restored.prefixes, prefixes)
	}
	if !slices.Equal(restored.addressPorts, addressPorts) {
		t.Errorf("addressPorts = %v, want %v", restored.addressPorts, addressPorts)
	}
	if !maps.Equal(restored.byAddress, original.byAddress) {
		t.Errorf("byAddress = %v, want %v", restored.byAddress, original.byAddress)
	}
	if !maps.Equal(restored.byPrefix, original.byPrefix) {
		t.Errorf("byPrefix = %v, want %v", restored.byPrefix, original.byPrefix)
	}
	if !maps.Equal(restored.byAddressPort, original.byAddressPort) {
		t.Errorf("byAddressPort = %v, want %v", restored.byAddressPort, original.byAddressPort)
	}
	if !slices.Equal(restored.values, original.values) {
		t.Errorf("interfaces = %v, want %v", restored.values, original.values)
	}
}
