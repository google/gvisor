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
	"net"
	"reflect"
	"testing"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	return string(b)
}

func TestComputeAutoLocalRemap_MultiNIC(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.88.1.170", Family: "ipv4"},
			},
		},
		{
			Name: "eth1",
			Addresses: []SavedInterfaceAddress{
				{Address: "192.168.100.170", Family: "ipv4"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "eth0",
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("10.88.1.186"), PrefixLen: 24},
				},
			},
			{
				Name: "eth1",
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("192.168.100.186"), PrefixLen: 24},
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{
		"10.88.1.170":     "10.88.1.186",
		"192.168.100.170": "192.168.100.186",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v", got, want)
	}
}

func TestComputeAutoLocalRemap_SingleNIC_Fallback(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.0.0.1", Family: "ipv4"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "net0", // name differs, triggers fallback
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("10.1.0.1"), PrefixLen: 24},
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{
		"10.0.0.1": "10.1.0.1",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v", got, want)
	}
}

func TestComputeAutoLocalRemap_DualStack(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.0.0.1", Family: "ipv4"},
				{Address: "2001:db8::1", Family: "ipv6"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "eth0",
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("10.0.0.2"), PrefixLen: 24},
					{Address: net.ParseIP("2001:db8::2"), PrefixLen: 64},
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{
		"10.0.0.1":    "10.0.0.2",
		"2001:db8::1": "2001:db8::2",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v", got, want)
	}
}

// TestComputeAutoLocalRemap_NoMetadata covers restoring a checkpoint taken by
// a runsc build that predates the saved_network_interfaces metadata. No
// mappings can be derived and the caller must fall back to --ip-remap alone.
func TestComputeAutoLocalRemap_NoMetadata(t *testing.T) {
	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name:      "eth0",
				Addresses: []IPWithPrefix{{Address: net.ParseIP("10.0.0.2"), PrefixLen: 24}},
			},
		},
	}
	if got := computeAutoLocalRemap("", newArgs); got != nil {
		t.Errorf("computeAutoLocalRemap(\"\", args) = %v, want nil", got)
	}
	if got := computeAutoLocalRemap("not valid json", newArgs); got != nil {
		t.Errorf("computeAutoLocalRemap(invalid, args) = %v, want nil", got)
	}
	saved := []SavedInterfaceInfo{{Name: "eth0", Addresses: []SavedInterfaceAddress{{Address: "10.0.0.1", Family: "ipv4"}}}}
	if got := computeAutoLocalRemap(mustJSON(t, saved), nil); got != nil {
		t.Errorf("computeAutoLocalRemap(saved, nil) = %v, want nil", got)
	}
}

// TestComputeAutoLocalRemap_SkipsLinkLocal verifies that IPv6 link-local
// addresses are excluded. They are derived from the link address, so the saved
// and restored values are unrelated and pairing them is meaningless.
func TestComputeAutoLocalRemap_SkipsLinkLocal(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.0.0.1", PrefixLen: 24, Family: "ipv4"},
				{Address: "fe80::aaaa", PrefixLen: 64, Family: "ipv6"},
				{Address: "169.254.7.7", PrefixLen: 16, Family: "ipv4"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "eth0",
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("10.0.0.9"), PrefixLen: 24},
					{Address: net.ParseIP("fe80::bbbb"), PrefixLen: 64},
					{Address: net.ParseIP("169.254.9.9"), PrefixLen: 16},
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{"10.0.0.1": "10.0.0.9"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v (link-local must be skipped)", got, want)
	}
}

// TestComputeAutoLocalRemap_AddressOrderIndependent is the regression test for
// the index-pairing hazard. The restored side lists its addresses in the
// opposite order from the saved side; matching must follow the subnet, not the
// position. Naive index pairing would produce the cross-mapped result.
func TestComputeAutoLocalRemap_AddressOrderIndependent(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.0.0.5", PrefixLen: 24, Family: "ipv4"},
				{Address: "10.0.1.5", PrefixLen: 24, Family: "ipv4"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "eth0",
				Addresses: []IPWithPrefix{
					// Deliberately reversed relative to the saved ordering.
					{Address: net.ParseIP("10.0.1.9"), PrefixLen: 24},
					{Address: net.ParseIP("10.0.0.9"), PrefixLen: 24},
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{
		"10.0.0.5": "10.0.0.9",
		"10.0.1.5": "10.0.1.9",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v (must pair by subnet, not index)", got, want)
	}
}

// TestComputeAutoLocalRemap_UnchangedAddressPinned verifies that an address
// carried over unchanged is pinned to itself and does not absorb the mapping
// intended for a different address on the same interface.
func TestComputeAutoLocalRemap_UnchangedAddressPinned(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{
			Name: "eth0",
			Addresses: []SavedInterfaceAddress{
				{Address: "10.0.0.1", PrefixLen: 24, Family: "ipv4"},
				{Address: "10.0.0.2", PrefixLen: 24, Family: "ipv4"},
			},
		},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{
				Name: "eth0",
				Addresses: []IPWithPrefix{
					{Address: net.ParseIP("10.0.0.2"), PrefixLen: 24}, // unchanged
					{Address: net.ParseIP("10.0.0.7"), PrefixLen: 24}, // replaces .1
				},
			},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{"10.0.0.1": "10.0.0.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v (unchanged address must be pinned)", got, want)
	}
}

// TestComputeAutoLocalRemap_NICOrderIndependent is the unit-level analogue of
// the swapped-subnet restore scenario: the restored links are enumerated in a
// different order than the saved interfaces, and the subnets attached to eth0
// and eth1 are exchanged. Name-based matching must still map each interface to
// its own successor.
func TestComputeAutoLocalRemap_NICOrderIndependent(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{Name: "eth0", Addresses: []SavedInterfaceAddress{{Address: "10.0.0.1", PrefixLen: 24, Family: "ipv4"}}},
		{Name: "eth1", Addresses: []SavedInterfaceAddress{{Address: "192.168.0.1", PrefixLen: 24, Family: "ipv4"}}},
	}

	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			// Reverse order, and each interface now carries the other's subnet.
			{Name: "eth1", Addresses: []IPWithPrefix{{Address: net.ParseIP("10.0.0.9"), PrefixLen: 24}}},
			{Name: "eth0", Addresses: []IPWithPrefix{{Address: net.ParseIP("192.168.0.9"), PrefixLen: 24}}},
		},
	}

	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	want := map[string]string{
		"10.0.0.1":    "192.168.0.9", // eth0 -> eth0
		"192.168.0.1": "10.0.0.9",    // eth1 -> eth1
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("computeAutoLocalRemap() = %v, want %v (must match by NIC name, not position)", got, want)
	}
}

// TestComputeAutoLocalRemap_UnchangedAddressesYieldNothing confirms that a
// restore into an identical network produces an empty table rather than
// self-mappings.
func TestComputeAutoLocalRemap_UnchangedAddressesYieldNothing(t *testing.T) {
	saved := []SavedInterfaceInfo{
		{Name: "eth0", Addresses: []SavedInterfaceAddress{{Address: "10.0.0.1", PrefixLen: 24, Family: "ipv4"}}},
	}
	newArgs := &CreateLinksAndRoutesArgs{
		FDBasedLinks: []FDBasedLink{
			{Name: "eth0", Addresses: []IPWithPrefix{{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24}}},
		},
	}
	got := computeAutoLocalRemap(mustJSON(t, saved), newArgs)
	if len(got) != 0 {
		t.Errorf("computeAutoLocalRemap() = %v, want empty", got)
	}
}

func TestSameSubnet(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b addrEntry
		want bool
	}{
		{"same v4 /24", addrEntry{"10.0.0.1", 24}, addrEntry{"10.0.0.9", 24}, true},
		{"different v4 /24", addrEntry{"10.0.0.1", 24}, addrEntry{"10.0.1.9", 24}, false},
		{"mismatched prefix", addrEntry{"10.0.0.1", 24}, addrEntry{"10.0.0.9", 16}, false},
		{"zero prefix", addrEntry{"10.0.0.1", 0}, addrEntry{"10.0.0.9", 0}, false},
		{"same v6 /64", addrEntry{"2001:db8::1", 64}, addrEntry{"2001:db8::9", 64}, true},
		{"different v6 /64", addrEntry{"2001:db8:1::1", 64}, addrEntry{"2001:db8:2::9", 64}, false},
		{"cross family", addrEntry{"10.0.0.1", 24}, addrEntry{"2001:db8::9", 24}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameSubnet(tc.a, tc.b); got != tc.want {
				t.Errorf("sameSubnet(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestIsRemappableAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.5", true},
		{"2001:db8::1", true},
		{"fe80::1", false},     // IPv6 link-local
		{"169.254.1.1", false}, // IPv4 link-local
		{"127.0.0.1", false},   // loopback
		{"::1", false},         // IPv6 loopback
		{"224.0.0.1", false},   // multicast
		{"ff02::1", false},     // IPv6 link-local multicast
		{"0.0.0.0", false},     // unspecified
	} {
		t.Run(tc.addr, func(t *testing.T) {
			if got := isRemappableAddr(net.ParseIP(tc.addr)); got != tc.want {
				t.Errorf("isRemappableAddr(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
	if isRemappableAddr(nil) {
		t.Error("isRemappableAddr(nil) = true, want false")
	}
}
