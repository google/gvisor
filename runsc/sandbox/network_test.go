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


package sandbox

import (
	"cmp"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/boot"
)

func routeKey(r boot.Route) string {
	return r.Destination.String() + "-" + r.Gateway.String()
}

func sortRoutes(routes []boot.Route) []boot.Route {
	result := make([]boot.Route, len(routes))
	copy(result, routes)
	slices.SortFunc(result, func(a, b boot.Route) int {
		return cmp.Compare(routeKey(a), routeKey(b))
	})
	return result
}

func routesEqual(a, b []boot.Route) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := sortRoutes(a)
	sortedB := sortRoutes(b)
	for i := range sortedA {
		if !routeEqual(sortedA[i], sortedB[i]) {
			return false
		}
	}
	return true
}

func routeEqual(a, b boot.Route) bool {
	return a.Destination.String() == b.Destination.String() &&
		a.Gateway.Equal(b.Gateway) &&
		a.MTU == b.MTU
}

func routePtrEqual(a, b *boot.Route) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return routeEqual(*a, *b)
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: must run as root")
	}
}

// setupTestNamespace creates a new network namespace for testing.
// The cleanup to restore the original namespace is automatically registered with t.Cleanup.
func setupTestNamespace(t *testing.T) error {
	t.Helper()

	origNs, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to get current netns: %v", err)
	}

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		unix.Close(origNs)
		return fmt.Errorf("failed to unshare netns: %v", err)
	}

	// Lock the OS thread to ensure we stay in the new namespace
	runtime.LockOSThread()

	t.Cleanup(func() {
		if err := unix.Setns(origNs, unix.CLONE_NEWNET); err != nil {
			t.Errorf("Failed to restore original netns: %v", err)
		}
		runtime.UnlockOSThread()
		unix.Close(origNs)
	})

	return nil
}

func createVethPair(t *testing.T, name string) (netlink.Link, error) {
	t.Helper()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		PeerName: name + "-peer",
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("failed to create veth pair: %v", err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		netlink.LinkDel(veth)
		return nil, fmt.Errorf("failed to get veth link: %v", err)
	}

	t.Cleanup(func() {
		if err := netlink.LinkDel(veth); err != nil {
			t.Errorf("Failed to delete veth pair: %v", err)
		}
	})

	return link, nil
}

// setupVethInterface is a helper that creates a network namespace,
// a veth pair, brings the link up, assigns an IP address, and returns the
// corresponding net.Interface.
func setupVethInterface(t *testing.T, name, ip string, prefixLen, addrBits int) *net.Interface {
	t.Helper()

	if err := setupTestNamespace(t); err != nil {
		t.Fatalf("Failed to setup test namespace: %v", err)
	}

	link, err := createVethPair(t, name)
	if err != nil {
		t.Fatalf("Failed to create veth pair: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(ip),
			Mask: net.CIDRMask(prefixLen, addrBits),
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("Failed to get interface: %v", err)
	}
	return iface
}

func addRoute(t *testing.T, dst *net.IPNet, gw net.IP) {
	t.Helper()
	route := &netlink.Route{Dst: dst, Gw: gw}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatalf("Failed to add route (dst=%v, gw=%v): %v", dst, gw, err)
	}
}

func parseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("Failed to parse CIDR %s: %v", cidr, err)
	}
	return ipNet
}

func TestRoutesForIface_CustomRoute(t *testing.T) {
	requireRoot(t)

	iface := setupVethInterface(t, "testveth0", "10.0.0.1", 24, 32)

	addRoute(t, nil, net.ParseIP("10.0.0.254"))
	addRoute(t, parseCIDR(t, "192.168.1.0/24"), net.ParseIP("10.0.0.2"))

	routes, defv4, defv6, err := routesForIface(*iface, false)
	if err != nil {
		t.Fatalf("routesForIface failed: %v", err)
	}

	wantDefv4 := &boot.Route{
		Destination: net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPMask(net.IPv4zero),
		},
		Gateway: net.ParseIP("10.0.0.254"),
	}
	if !routePtrEqual(defv4, wantDefv4) {
		t.Errorf("defv4 = %+v, want %+v", defv4, wantDefv4)
	}

	if defv6 != nil {
		t.Error("Expected no default IPv6 route")
	}

	wantRoutes := []boot.Route{
		{
			Destination: net.IPNet{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(24, 32),
			},
			Gateway: nil,
		},
		{
			Destination: net.IPNet{
				IP:   net.ParseIP("192.168.1.0"),
				Mask: net.CIDRMask(24, 32),
			},
			Gateway: net.ParseIP("10.0.0.2"),
		},
	}

	if !routesEqual(routes, wantRoutes) {
		t.Errorf("routes mismatch:\ngot  %+v\nwant %+v", sortRoutes(routes), sortRoutes(wantRoutes))
	}
}

func TestRoutesForIface_IPv6(t *testing.T) {
	requireRoot(t)

	iface := setupVethInterface(t, "testveth2", "2001:db8::1", 64, 128)

	addRoute(t, nil, net.ParseIP("2001:db8::ffff"))

	routes, defv4, defv6, err := routesForIface(*iface, false)
	if err != nil {
		t.Fatalf("routesForIface failed: %v", err)
	}

	if defv4 != nil {
		t.Error("Expected no default IPv4 route")
	}

	wantDefv6 := &boot.Route{
		Destination: net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.IPMask(net.IPv6zero),
		},
		Gateway: net.ParseIP("2001:db8::ffff"),
	}
	if !routePtrEqual(defv6, wantDefv6) {
		t.Errorf("defv6 = %+v, want %+v", defv6, wantDefv6)
	}

	wantRoutes := []boot.Route{
		{
			Destination: net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(64, 128),
			},
			Gateway: nil,
		},
	}

	if !routesEqual(routes, wantRoutes) {
		t.Errorf("routes mismatch:\ngot  %+v\nwant %+v", sortRoutes(routes), sortRoutes(wantRoutes))
	}
}

func TestRoutesForIface_IPv6Disabled(t *testing.T) {
	requireRoot(t)

	iface := setupVethInterface(t, "testveth3", "2001:db8::1", 64, 128)

	addRoute(t, nil, net.ParseIP("2001:db8::ffff"))

	routes, defv4, defv6, err := routesForIface(*iface, true)
	if err != nil {
		t.Fatalf("routesForIface failed: %v", err)
	}

	if defv4 != nil {
		t.Error("Expected no default IPv4 route when disabled")
	}

	if defv6 != nil {
		t.Error("Expected no default IPv6 route when disabled")
	}

	if !routesEqual(routes, []boot.Route{}) {
		t.Errorf("routes mismatch:\ngot  %+v\nwant %+v", routes, []boot.Route{})
	}
}

func TestRoutesForIface_CustomRouteIPv6(t *testing.T) {
	requireRoot(t)

	iface := setupVethInterface(t, "testveth4", "2001:db8::1", 64, 128)

	addRoute(t, nil, net.ParseIP("2001:db8::ffff"))
	addRoute(t, parseCIDR(t, "fd00:abcd::/48"), net.ParseIP("2001:db8::2"))

	routes, defv4, defv6, err := routesForIface(*iface, false)
	if err != nil {
		t.Fatalf("routesForIface failed: %v", err)
	}

	if defv4 != nil {
		t.Error("Expected no default IPv4 route")
	}

	wantDefv6 := &boot.Route{
		Destination: net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.IPMask(net.IPv6zero),
		},
		Gateway: net.ParseIP("2001:db8::ffff"),
	}
	if !routePtrEqual(defv6, wantDefv6) {
		t.Errorf("defv6 = %+v, want %+v", defv6, wantDefv6)
	}

	wantRoutes := []boot.Route{
		{
			Destination: net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(64, 128),
			},
			Gateway: nil,
		},
		{
			Destination: net.IPNet{
				IP:   net.ParseIP("fd00:abcd::"),
				Mask: net.CIDRMask(48, 128),
			},
			Gateway: net.ParseIP("2001:db8::2"),
		},
	}

	if !routesEqual(routes, wantRoutes) {
		t.Errorf("routes mismatch:\ngot  %+v\nwant %+v", sortRoutes(routes), sortRoutes(wantRoutes))
	}
}

