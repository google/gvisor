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

package sandbox

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

func init() {
	// Reserve the initial thread for main so namespace tests use threads that
	// can exit if namespace restoration fails. Locking during init pins main
	// to this thread: https://pkg.go.dev/runtime#LockOSThread.
	runtime.LockOSThread()
}

func fdbasedLinkEqual(a, b sentryapi.FDBasedLink) bool {
	if a.Name != b.Name {
		return false
	}
	if a.MTU != b.MTU {
		return false
	}
	if a.QDisc != b.QDisc {
		return false
	}
	// LinkAddress is randomly assigned for veth pairs, so compare lengths.
	if len(a.LinkAddress) != len(b.LinkAddress) {
		return false
	}
	if len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i := range a.Addresses {
		if !a.Addresses[i].Address.Equal(b.Addresses[i].Address) {
			return false
		}
		if a.Addresses[i].PrefixLen != b.Addresses[i].PrefixLen {
			return false
		}
	}
	if len(a.Routes) != len(b.Routes) {
		return false
	}
	for i := range a.Routes {
		if a.Routes[i].Destination.String() != b.Routes[i].Destination.String() {
			return false
		}
		if !a.Routes[i].Gateway.Equal(b.Routes[i].Gateway) {
			return false
		}
	}
	if len(a.Neighbors) != len(b.Neighbors) {
		return false
	}
	for i := range a.Neighbors {
		if !a.Neighbors[i].IP.Equal(b.Neighbors[i].IP) {
			return false
		}
		if a.Neighbors[i].HardwareAddr.String() != b.Neighbors[i].HardwareAddr.String() {
			return false
		}
	}
	return true
}

func fdbasedLinksEqual(a, b []sentryapi.FDBasedLink) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !fdbasedLinkEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func defaultRouteEqual(a, b sentryapi.DefaultRoute) bool {
	if a.Name != b.Name {
		return false
	}
	if a.Route.Destination.String() != b.Route.Destination.String() {
		return false
	}
	if !a.Route.Gateway.Equal(b.Route.Gateway) {
		return false
	}
	return true
}

func loopbackLinksEqual(a, b []sentryapi.LoopbackLink) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
		if len(a[i].Addresses) != len(b[i].Addresses) {
			return false
		}
		for j := range a[i].Addresses {
			if !a[i].Addresses[j].Address.Equal(b[i].Addresses[j].Address) {
				return false
			}
			if a[i].Addresses[j].PrefixLen != b[i].Addresses[j].PrefixLen {
				return false
			}
		}
		if len(a[i].Routes) != len(b[i].Routes) {
			return false
		}
		for j := range a[i].Routes {
			if a[i].Routes[j].Destination.String() != b[i].Routes[j].Destination.String() {
				return false
			}
			if !a[i].Routes[j].Gateway.Equal(b[i].Routes[j].Gateway) {
				return false
			}
		}
	}
	return true
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: must run as root")
	}
}

func setupTestNamespace(t *testing.T) {
	t.Helper()

	// Network namespaces are per-thread. Pin before saving or changing one.
	runtime.LockOSThread()
	restoreFailed := false
	t.Cleanup(func() {
		if !restoreFailed {
			runtime.UnlockOSThread()
		}
	})
	origNs, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("Failed to get current netns: %v", err)
	}

	t.Cleanup(func() { unix.Close(origNs) })

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("Failed to unshare netns: %v", err)
	}

	t.Cleanup(func() {
		if err := unix.Setns(origNs, unix.CLONE_NEWNET); err != nil {
			// Let the test goroutine exit with the thread locked rather than
			// returning a thread in the wrong namespace to the runtime.
			restoreFailed = true
			t.Errorf("Failed to restore original netns: %v", err)
		}
	})
}

func createVethPair(t *testing.T, name string) netlink.Link {
	t.Helper()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		PeerName: name + "-peer",
	}

	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("Failed to create veth pair: %v", err)
	}
	t.Cleanup(func() {
		if err := netlink.LinkDel(veth); err != nil {
			t.Errorf("Failed to delete veth pair: %v", err)
		}
	})

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("Failed to get veth link: %v", err)
	}
	return link
}

func setupVethInterface(t *testing.T, name, ip string, prefixLen, addrBits int) netlink.Link {
	t.Helper()

	setupTestNamespace(t)
	link := createVethPair(t, name)

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

	return link
}

func addRoute(t *testing.T, dst *net.IPNet, gw net.IP) {
	t.Helper()
	route := &netlink.Route{Dst: dst, Gw: gw}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatalf("Failed to add route (dst=%v, gw=%v): %v", dst, gw, err)
	}
}

func addNeighbor(t *testing.T, link netlink.Link, ip net.IP, hwAddr string) {
	t.Helper()
	hw, err := net.ParseMAC(hwAddr)
	if err != nil {
		t.Fatalf("Failed to parse MAC %s: %v", hwAddr, err)
	}
	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           ip,
		HardwareAddr: hw,
		State:        netlink.NUD_PERMANENT,
	}
	if err := netlink.NeighAdd(neigh); err != nil {
		t.Fatalf("Failed to add neighbor: %v", err)
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

func setupLoopback(t *testing.T) {
	t.Helper()
	loLink, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("Failed to get lo link: %v", err)
	}
	if err := netlink.LinkSetUp(loLink); err != nil {
		t.Fatalf("Failed to bring up lo: %v", err)
	}
	err = netlink.AddrAdd(loLink, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
	})
	if err != nil && err != unix.EEXIST {
		t.Fatalf("Failed to add address to lo: %v", err)
	}
}

// defaultLoopbackLinks returns the expected loopback links for a standard
// loopback interface with 127.0.0.1/8 and ::1/128.
func defaultLoopbackLinks() []sentryapi.LoopbackLink {
	return []sentryapi.LoopbackLink{
		{
			Name: "lo",
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("127.0.0.1"), PrefixLen: 8},
				{Address: net.ParseIP("::1"), PrefixLen: 128},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{127, 0, 0, 0},
						Mask: net.IPMask{255, 0, 0, 0},
					},
				},
				{
					Destination: net.IPNet{
						IP:   net.ParseIP("::1"),
						Mask: net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
					},
				},
			},
		},
	}
}

func TestCollectLinksAndRoutes_SingleInterface(t *testing.T) {
	requireRoot(t)
	link := setupVethInterface(t, "testveth0", "10.0.0.1", 24, 32)
	setupLoopback(t)
	addRoute(t, nil, net.ParseIP("10.0.0.254"))
	addRoute(t, parseCIDR(t, "192.168.1.0/24"), net.ParseIP("10.0.0.2"))
	addNeighbor(t, link, net.ParseIP("10.0.0.2"), "00:11:22:33:44:55")

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, false)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	wantFDLinks := []sentryapi.FDBasedLink{
		{
			Name:        "testveth0",
			MTU:         1500,
			LinkAddress: link.Attrs().HardwareAddr,
			QDisc:       config.QDiscNone,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24},
			},
			Routes: []sentryapi.Route{
				{Destination: *parseCIDR(t, "0.0.0.0/0"), Gateway: net.ParseIP("10.0.0.254")},
				{
					Destination: net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
				},
				{
					Destination: net.IPNet{
						IP:   net.IP{192, 168, 1, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
					Gateway: net.ParseIP("10.0.0.2"),
				},
			},
			Neighbors: []sentryapi.Neighbor{
				{IP: net.ParseIP("10.0.0.2"), HardwareAddr: mustParseMAC("00:11:22:33:44:55")},
			},
		},
	}

	if !fdbasedLinksEqual(args.FDBasedLinks, wantFDLinks) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant %+v", args.FDBasedLinks, wantFDLinks)
	}

	// The pinned netlink decoder returns explicit /0 routes in the link list.
	wantGW := sentryapi.DefaultRoute{}
	if !defaultRouteEqual(args.Defaultv4Gateway, wantGW) {
		t.Errorf("Defaultv4Gateway mismatch:\ngot  %+v\nwant %+v", args.Defaultv4Gateway, wantGW)
	}

	if !loopbackLinksEqual(args.LoopbackLinks, defaultLoopbackLinks()) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant %+v", args.LoopbackLinks, defaultLoopbackLinks())
	}
}

func mustParseMAC(s string) net.HardwareAddr {
	hw, _ := net.ParseMAC(s)
	return hw
}

func TestCollectLinksAndRoutes_LoopbackOnly(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)
	setupLoopback(t)

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, false)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	wantLoopbackLinks := []sentryapi.LoopbackLink{
		{
			Name: "lo",
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("127.0.0.1"), PrefixLen: 8},
				{Address: net.ParseIP("::1"), PrefixLen: 128},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{127, 0, 0, 0},
						Mask: net.IPMask{255, 0, 0, 0},
					},
				},
				{
					Destination: net.IPNet{
						IP:   net.ParseIP("::1"),
						Mask: net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
					},
				},
			},
		},
	}
	if !loopbackLinksEqual(args.LoopbackLinks, wantLoopbackLinks) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant %+v", args.LoopbackLinks, wantLoopbackLinks)
	}

	if !fdbasedLinksEqual(args.FDBasedLinks, nil) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant nil", args.FDBasedLinks)
	}
}

func TestCollectLinksAndRoutes_MultipleInterfaces(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)
	setupLoopback(t)

	veth0Link := createVethPair(t, "testveth0")
	veth1Link := createVethPair(t, "testveth1")
	if err := netlink.LinkSetUp(veth0Link); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}
	if err := netlink.LinkSetUp(veth1Link); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}
	if err := netlink.AddrAdd(veth0Link, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}
	if err := netlink.AddrAdd(veth1Link, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	addRoute(t, nil, net.ParseIP("10.0.0.254"))

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, false)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	wantFDLinks := []sentryapi.FDBasedLink{
		{
			Name:        "testveth0",
			MTU:         1500,
			LinkAddress: veth0Link.Attrs().HardwareAddr,
			QDisc:       config.QDiscNone,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24},
			},
			Routes: []sentryapi.Route{
				{Destination: *parseCIDR(t, "0.0.0.0/0"), Gateway: net.ParseIP("10.0.0.254")},
				{
					Destination: net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
				},
			},
		},
		{
			Name:        "testveth1",
			MTU:         1500,
			LinkAddress: veth1Link.Attrs().HardwareAddr,
			QDisc:       config.QDiscNone,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("192.168.1.1"), PrefixLen: 24},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{192, 168, 1, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
				},
			},
		},
	}
	if !fdbasedLinksEqual(args.FDBasedLinks, wantFDLinks) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant %+v", args.FDBasedLinks, wantFDLinks)
	}

	// The pinned netlink decoder returns explicit /0 routes in the link list.
	wantGW := sentryapi.DefaultRoute{}
	if !defaultRouteEqual(args.Defaultv4Gateway, wantGW) {
		t.Errorf("Defaultv4Gateway mismatch:\ngot  %+v\nwant %+v", args.Defaultv4Gateway, wantGW)
	}

	if name, err := primaryInterface(&args); err != nil || name != "testveth0" {
		t.Errorf("primaryInterface = (%q, %v), want (testveth0, nil)", name, err)
	}

	if !loopbackLinksEqual(args.LoopbackLinks, defaultLoopbackLinks()) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant %+v", args.LoopbackLinks, defaultLoopbackLinks())
	}
}

func TestCollectLinksAndRoutes_IPv6Disabled(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)
	setupLoopback(t)

	veth0Link := createVethPair(t, "testveth0")
	if err := netlink.LinkSetUp(veth0Link); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}
	if err := netlink.AddrAdd(veth0Link, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}
	if err := netlink.AddrAdd(veth0Link, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	addRoute(t, nil, net.ParseIP("10.0.0.254"))
	addRoute(t, nil, net.ParseIP("2001:db8::ffff"))

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, true)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	wantFDLinks := []sentryapi.FDBasedLink{
		{
			Name:        "testveth0",
			MTU:         1500,
			LinkAddress: veth0Link.Attrs().HardwareAddr,
			QDisc:       config.QDiscNone,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24},
			},
			Routes: []sentryapi.Route{
				{Destination: *parseCIDR(t, "0.0.0.0/0"), Gateway: net.ParseIP("10.0.0.254")},
				{
					Destination: net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
				},
			},
		},
	}

	if !fdbasedLinksEqual(args.FDBasedLinks, wantFDLinks) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant %+v", args.FDBasedLinks, wantFDLinks)
	}

	if !args.Defaultv6Gateway.Route.Empty() {
		t.Errorf("Defaultv6Gateway.Route should be empty, got %+v", args.Defaultv6Gateway.Route)
	}

	wantLoopbackLinks := []sentryapi.LoopbackLink{
		{
			Name: "lo",
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("127.0.0.1"), PrefixLen: 8},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{127, 0, 0, 0},
						Mask: net.IPMask{255, 0, 0, 0},
					},
				},
			},
		},
	}
	if !loopbackLinksEqual(args.LoopbackLinks, wantLoopbackLinks) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant %+v", args.LoopbackLinks, wantLoopbackLinks)
	}
}

func TestCollectLinksAndRoutes_DownInterface(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)

	createVethPair(t, "testveth0")

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, false)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	if !fdbasedLinksEqual(args.FDBasedLinks, nil) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant nil", args.FDBasedLinks)
	}

	if !loopbackLinksEqual(args.LoopbackLinks, nil) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant nil", args.LoopbackLinks)
	}
}

func TestCollectLinksAndRoutes_NoUsableAddresses(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)

	veth0Link := createVethPair(t, "testveth0")
	if err := netlink.LinkSetUp(veth0Link); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}
	if err := netlink.AddrAdd(veth0Link, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, true)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	if !fdbasedLinksEqual(args.FDBasedLinks, nil) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant nil", args.FDBasedLinks)
	}

	if !loopbackLinksEqual(args.LoopbackLinks, nil) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant nil", args.LoopbackLinks)
	}
}

func TestCollectLinksAndRoutes_LoopbackExtraRoutes(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)
	setupLoopback(t)

	vethLink := createVethPair(t, "testveth0")
	if err := netlink.LinkSetUp(vethLink); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}
	if err := netlink.AddrAdd(vethLink, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
	}); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	// Add a custom route pointing to the loopback interface.
	// This simulates routes added by e.g. podman-network-create --route.
	loLink, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("Failed to get lo link: %v", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       parseCIDR(t, "10.88.0.0/16"),
		LinkIndex: loLink.Attrs().Index,
	}); err != nil {
		t.Fatalf("Failed to add route to lo: %v", err)
	}

	conf := &config.Config{
		XDP: config.XDP{Mode: config.XDPModeOff},
	}

	args, err := collectLinksAndRoutes(conf, false)
	if err != nil {
		t.Fatalf("collectLinksAndRoutes failed: %v", err)
	}

	wantLoopbackLinks := []sentryapi.LoopbackLink{
		{
			Name: "lo",
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("127.0.0.1"), PrefixLen: 8},
				{Address: net.IPv6loopback, PrefixLen: 128},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{127, 0, 0, 0},
						Mask: net.IPMask{255, 0, 0, 0},
					},
				},
				{
					Destination: net.IPNet{
						IP:   net.IPv6loopback,
						Mask: net.CIDRMask(128, 128),
					},
				},
				{
					Destination: net.IPNet{
						IP:   net.IP{10, 88, 0, 0},
						Mask: net.IPMask{255, 255, 0, 0},
					},
				},
			},
		},
	}

	if !loopbackLinksEqual(args.LoopbackLinks, wantLoopbackLinks) {
		t.Errorf("LoopbackLinks mismatch:\ngot  %+v\nwant %+v", args.LoopbackLinks, wantLoopbackLinks)
	}

	wantFDLinks := []sentryapi.FDBasedLink{
		{
			Name:        "testveth0",
			MTU:         1500,
			LinkAddress: vethLink.Attrs().HardwareAddr,
			QDisc:       config.QDiscNone,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24},
			},
			Routes: []sentryapi.Route{
				{
					Destination: net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPMask{255, 255, 255, 0},
					},
				},
			},
		},
	}
	if !fdbasedLinksEqual(args.FDBasedLinks, wantFDLinks) {
		t.Errorf("FDBasedLinks mismatch:\ngot  %+v\nwant %+v", args.FDBasedLinks, wantFDLinks)
	}
}

func TestDialExternalUDS(t *testing.T) {
	// The peer listens on SOCK_SEQPACKET, as an external network proxy must.
	dir := t.TempDir()
	path := filepath.Join(dir, "netproxy.sock")
	ln, err := net.Listen("unixpacket", path)
	if err != nil {
		t.Fatalf(`net.Listen("unixpacket", %q) failed: %v`, path, err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()

	f, err := dialExternalUDS(path)
	if err != nil {
		t.Fatalf("dialExternalUDS(%q) failed: %v", path, err)
	}
	defer f.Close()

	for _, opt := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
		sz, err := unix.GetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, opt)
		if err != nil {
			t.Fatalf("GetsockoptInt(%d) failed: %v", opt, err)
		}
		if sz <= 0 {
			t.Errorf("GetsockoptInt(%d) = %d, want > 0", opt, sz)
		}
	}

	var peer net.Conn
	select {
	case peer = <-accepted:
		if peer == nil {
			t.Fatal("ln.Accept() failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the peer to accept the connection")
	}
	defer peer.Close()

	// Message boundaries must be preserved in both directions: the sentry and
	// the external proxy exchange one IP packet per datagram.
	wantOutbound := []byte("outbound-packet")
	if _, err := f.Write(wantOutbound); err != nil {
		t.Fatalf("f.Write(%q) failed: %v", wantOutbound, err)
	}
	got := make([]byte, 64)
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("peer.SetReadDeadline() failed: %v", err)
	}
	n, err := peer.Read(got)
	if err != nil {
		t.Fatalf("peer.Read() failed: %v", err)
	}
	if !bytes.Equal(got[:n], wantOutbound) {
		t.Errorf("peer.Read() = %q, want %q", got[:n], wantOutbound)
	}

	wantInbound := []byte("inbound-packet")
	if _, err := peer.Write(wantInbound); err != nil {
		t.Fatalf("peer.Write(%q) failed: %v", wantInbound, err)
	}
	n, err = f.Read(got)
	if err != nil {
		t.Fatalf("f.Read() failed: %v", err)
	}
	if !bytes.Equal(got[:n], wantInbound) {
		t.Errorf("f.Read() = %q, want %q", got[:n], wantInbound)
	}
}

func TestConfigureProxyLink(t *testing.T) {
	link := sentryapi.FDBasedLink{
		Name:              "eth0",
		NumChannels:       4,
		TXChecksumOffload: true,
		RXChecksumOffload: false,
	}
	configureProxyLink(&link)
	if !link.IsProxy {
		t.Errorf("configureProxyLink() IsProxy = false, want true")
	}
	if link.NumChannels != 1 {
		t.Errorf("configureProxyLink() NumChannels = %d, want 1", link.NumChannels)
	}
	if !link.RXChecksumOffload {
		t.Errorf("configureProxyLink() RXChecksumOffload = false, want true")
	}
}

func TestDialExternalUDSRejectsStreamPeer(t *testing.T) {
	// A SOCK_STREAM peer provides no message boundaries and must be rejected by
	// the kernel with EPROTOTYPE.
	dir := t.TempDir()
	path := filepath.Join(dir, "stream.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf(`net.Listen("unix", %q) failed: %v`, path, err)
	}
	defer ln.Close()

	f, err := dialExternalUDS(path)
	if err == nil {
		_ = f.Close()
		t.Fatalf("dialExternalUDS(%q) succeeded against a SOCK_STREAM listener, want error", path)
	}
	if !errors.Is(err, unix.EPROTOTYPE) {
		t.Errorf("dialExternalUDS(%q) = %v, want EPROTOTYPE", path, err)
	}
}

func TestDialExternalUDSMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.sock")
	f, err := dialExternalUDS(path)
	if err == nil {
		_ = f.Close()
		t.Fatalf("dialExternalUDS(%q) succeeded for a nonexistent socket, want error", path)
	}
	if !errors.Is(err, unix.ENOENT) {
		t.Errorf("dialExternalUDS(%q) = %v, want ENOENT", path, err)
	}
}

func TestPrimaryInterface(t *testing.T) {
	testCases := []struct {
		name    string
		args    *sentryapi.CreateLinksAndRoutesArgs
		want    string
		wantErr bool
	}{
		{
			name:    "nil args",
			args:    nil,
			wantErr: true,
		},
		{
			name: "v4 gateway in fdbased",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "eth1"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			want: "eth1",
		},
		{
			name: "v4 gateway not in fdbased rejects eth0 fallback",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "other0"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			wantErr: true,
		},
		{
			name: "v6 gateway in fdbased",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv6Gateway: sentryapi.DefaultRoute{Name: "eth2"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth1"}, {Name: "eth2"}},
			},
			want: "eth2",
		},
		{
			name: "v6 gateway not in fdbased rejects single link fallback",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv6Gateway: sentryapi.DefaultRoute{Name: "other0"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "myif0"}},
			},
			wantErr: true,
		},
		{
			name: "v4 and v6 gateways match same fdbased link",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "eth1"},
				Defaultv6Gateway: sentryapi.DefaultRoute{Name: "eth1"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			want: "eth1",
		},
		{
			name: "v4 and v6 gateways differ",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "eth0"},
				Defaultv6Gateway: sentryapi.DefaultRoute{Name: "eth1"},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			wantErr: true,
		},
		{
			name: "no gateway with eth0 fallback",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			want: "eth0",
		},
		{
			name: "single link in fdbased",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				FDBasedLinks: []sentryapi.FDBasedLink{{Name: "tap0"}},
			},
			want: "tap0",
		},
		{
			name: "multiple links with no gateway and no eth0",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				FDBasedLinks: []sentryapi.FDBasedLink{{Name: "tap0"}, {Name: "tap1"}},
			},
			wantErr: true,
		},
		{
			// The gateway resolves to an XDP link, which cannot be proxied over
			// UDS. primaryInterface() must reject it rather than falling back or
			// returning a name that has no corresponding FDBasedLink.
			name: "v4 gateway matches an XDP link only",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "xdp0"},
				XDPLinks:         []sentryapi.XDPLink{{Name: "xdp0"}},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "tap0"}, {Name: "tap1"}},
			},
			wantErr: true,
		},
		{
			// Even when eth0 is present in FDBasedLinks, a default gateway on an
			// XDP link must fail rather than silently routing default traffic
			// around the UDS proxy.
			name: "v4 gateway matches an XDP link rejects eth0 fallback",
			args: &sentryapi.CreateLinksAndRoutesArgs{
				Defaultv4Gateway: sentryapi.DefaultRoute{Name: "xdp0"},
				XDPLinks:         []sentryapi.XDPLink{{Name: "xdp0"}},
				FDBasedLinks:     []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1"}},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := primaryInterface(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("primaryInterface(%+v) error = %v, wantErr %v", tc.args, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("primaryInterface(%+v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestLoopbackLinkDefaultRoute(t *testing.T) {
	requireRoot(t)
	setupTestNamespace(t)
	setupLoopback(t)
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	gateway := net.ParseIP("127.0.0.2")
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: iface.Index,
		Dst:       parseCIDR(t, "0.0.0.0/0"),
		Gw:        gateway,
		MTU:       1420,
	}); err != nil {
		t.Fatal(err)
	}
	link, err := loopbackLink(&config.Config{}, *iface, addrs, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range link.Routes {
		if r.Destination.String() == "0.0.0.0/0" && r.Gateway.Equal(gateway) && r.MTU == 1420 {
			return
		}
	}
	t.Fatalf("loopback default route was lost: %+v", link.Routes)
}

func TestPrimaryInterfacePerLinkDefaults(t *testing.T) {
	route := func(cidr string) sentryapi.Route { return sentryapi.Route{Destination: *parseCIDR(t, cidr)} }
	v4, v6 := route("0.0.0.0/0"), route("::/0")
	for _, tc := range []struct {
		name        string
		args        sentryapi.CreateLinksAndRoutesArgs
		want        string
		wantErr     bool
		errContains string
	}{
		{name: "IPv4 overrides eth0 fallback", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1", Routes: []sentryapi.Route{v4}}}}, want: "eth1"},
		{name: "IPv6 overrides eth0 fallback", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1", Routes: []sentryapi.Route{v6}}}}, want: "eth1"},
		{name: "gatewayless first default wins", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "first", Routes: []sentryapi.Route{v4}}, {Name: "second", Routes: []sentryapi.Route{{Destination: v4.Destination, Gateway: net.ParseIP("10.0.0.254")}}}}}, want: "first"},
		{name: "per-link default precedes appended default", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "first", Routes: []sentryapi.Route{v4}}, {Name: "second"}}, Defaultv4Gateway: sentryapi.DefaultRoute{Name: "second", Route: v4}}, want: "first"},
		{name: "dual stack same link", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "first"}, {Name: "second", Routes: []sentryapi.Route{v4, v6}}}}, want: "second"},
		{name: "dual stack split rejects fallback", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0", Routes: []sentryapi.Route{v4}}, {Name: "eth1", Routes: []sentryapi.Route{v6}}}}, wantErr: true},
		{name: "loopback precedes FD", args: sentryapi.CreateLinksAndRoutesArgs{LoopbackLinks: []sentryapi.LoopbackLink{{Name: "lo", Routes: []sentryapi.Route{v4}}}, FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0", Routes: []sentryapi.Route{v4}}}}, wantErr: true},
		{name: "XDP default is not proxyable", errContains: "xdp0", args: sentryapi.CreateLinksAndRoutesArgs{XDPLinks: []sentryapi.XDPLink{{Name: "xdp0", Routes: []sentryapi.Route{v6}}}}, wantErr: true},
		{name: "FD links take precedence over unused XDP links", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0", Routes: []sentryapi.Route{v4}}}, XDPLinks: []sentryapi.XDPLink{{Name: "xdp0", Routes: []sentryapi.Route{v6}}}}, want: "eth0"},
		{name: "zero networks are not defaults", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1", Routes: []sentryapi.Route{route("0.0.0.0/8"), route("::/64")}}}}, want: "eth0"},
		{name: "empty and invalid masks are not defaults", args: sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{{Name: "eth0"}, {Name: "eth1", Routes: []sentryapi.Route{{Destination: net.IPNet{IP: net.IPv4zero}}, {Destination: net.IPNet{IP: net.IPv4zero, Mask: net.IPMask{0, 255, 0, 0}}}}}}}, want: "eth0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// These selection cases model dual-stack links. Address-family
			// eligibility is covered separately below.
			addresses := []sentryapi.IPWithPrefix{{Address: net.ParseIP("10.0.0.1"), PrefixLen: 24}, {Address: net.ParseIP("2001:db8::1"), PrefixLen: 64}}
			for i := range tc.args.FDBasedLinks {
				tc.args.FDBasedLinks[i].Addresses = addresses
			}
			for i := range tc.args.LoopbackLinks {
				tc.args.LoopbackLinks[i].Addresses = addresses
			}
			for i := range tc.args.XDPLinks {
				tc.args.XDPLinks[i].Addresses = addresses
			}
			got, err := primaryInterface(&tc.args)
			if tc.errContains != "" && (err == nil || !strings.Contains(err.Error(), tc.errContains)) {
				t.Fatalf("error = %v, want it to name %q", err, tc.errContains)
			}
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("primaryInterface = (%q, %v), want (%q, error=%t)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestRouteCollectionPreservesDefaults(t *testing.T) {
	requireRoot(t)
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		for _, kind := range []string{"gateway", "on-link", "mixed", "two-gateways"} {
			for _, disabled := range []bool{false, true} {
				if disabled && !ipv6 {
					continue
				}
				name := family + "/" + kind
				if disabled {
					name += "/disabled"
				}
				t.Run(name, func(t *testing.T) {
					address, gateway, otherGateway, cidr, prefix, bits := "10.0.0.1", "10.0.0.254", "10.0.0.253", "0.0.0.0/0", 24, 32
					if ipv6 {
						address, gateway, otherGateway, cidr, prefix, bits = "2001:db8::1", "2001:db8::ffff", "2001:db8::fffe", "::/0", 64, 128
					}
					link := setupVethInterface(t, "testroute0", address, prefix, bits)
					if disabled {
						// Retain the link when IPv6 is disabled, so the test
						// exercises route filtering rather than skipping it.
						if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}); err != nil {
							t.Fatal(err)
						}
					}
					setupLoopback(t)
					preferred := netlink.Route{LinkIndex: link.Attrs().Index, Dst: parseCIDR(t, cidr), Gw: net.ParseIP(gateway), Priority: 10, MTU: 1420}
					if kind == "on-link" {
						preferred.Gw = nil
						preferred.Scope = netlink.SCOPE_LINK
					}
					wantGateways := []net.IP{preferred.Gw}
					if kind == "mixed" || kind == "two-gateways" {
						// Add the less preferred route FIRST to distinguish metric
						// precedence from insertion order in the kernel dump.
						other := preferred
						other.Priority, other.MTU = 100, 1400
						if kind == "mixed" {
							other.Gw = nil
							other.Scope = netlink.SCOPE_LINK
						} else {
							other.Gw = net.ParseIP(otherGateway)
						}
						if err := netlink.RouteAdd(&other); err != nil {
							t.Fatal(err)
						}
						wantGateways = append(wantGateways, other.Gw)
					}
					if err := netlink.RouteAdd(&preferred); err != nil {
						t.Fatal(err)
					}
					args, err := collectLinksAndRoutes(&config.Config{}, disabled)
					if err != nil {
						t.Fatal(err)
					}
					if len(args.FDBasedLinks) != 1 || args.FDBasedLinks[0].Name != "testroute0" {
						t.Fatalf("test link was not retained: %+v", args.FDBasedLinks)
					}
					if !args.Defaultv4Gateway.Route.Empty() || !args.Defaultv6Gateway.Route.Empty() {
						t.Fatal("collection extracted defaults from their per-link positions")
					}
					if disabled {
						wantGateways = nil
					}
					var defaults []sentryapi.Route
					for _, l := range args.FDBasedLinks {
						for _, r := range l.Routes {
							if r.Destination.String() == cidr {
								defaults = append(defaults, r)
							}
						}
					}
					if len(defaults) != len(wantGateways) {
						t.Fatalf("defaults = %+v, want %d routes", defaults, len(wantGateways))
					}
					for i, r := range defaults {
						mtu := uint32(1420)
						if i == 1 {
							mtu = 1400
						}
						if !r.Gateway.Equal(wantGateways[i]) || r.MTU != mtu {
							t.Errorf("default %d = %+v, want gateway %s MTU %d", i, r, wantGateways[i], mtu)
						}
					}
					if !disabled {
						if name, err := primaryInterface(&args); err != nil || name != "testroute0" {
							t.Errorf("primaryInterface = (%q, %v)", name, err)
						}
					}
				})
			}
		}
	}
}

func TestCollectedDefaultsAcrossInterfaces(t *testing.T) {
	requireRoot(t)
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		for _, kind := range []string{"gateway-first", "on-link-first", "two-gateways"} {
			t.Run(family+"/"+kind, func(t *testing.T) {
				address, address2, gateway, gateway2, cidr, prefix, bits := "10.0.0.1", "10.1.0.1", "10.0.0.254", "10.1.0.254", "0.0.0.0/0", 24, 32
				if ipv6 {
					address, address2, gateway, gateway2, cidr, prefix, bits = "2001:db8::1", "2001:db8:1::1", "2001:db8::ffff", "2001:db8:1::ffff", "::/0", 64, 128
				}
				first := setupVethInterface(t, "testfirst", address, prefix, bits)
				setupLoopback(t)
				second := createVethPair(t, "testsecond")
				if err := netlink.LinkSetUp(second); err != nil {
					t.Fatal(err)
				}
				if err := netlink.AddrAdd(second, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(address2), Mask: net.CIDRMask(prefix, bits)}}); err != nil {
					t.Fatal(err)
				}
				routes := []netlink.Route{
					{LinkIndex: first.Attrs().Index, Dst: parseCIDR(t, cidr), Gw: net.ParseIP(gateway), Priority: 100, MTU: 1420},
					{LinkIndex: second.Attrs().Index, Dst: parseCIDR(t, cidr), Gw: net.ParseIP(gateway2), Priority: 10, MTU: 1400},
				}
				if kind == "gateway-first" {
					routes[1].Gw = nil
					routes[1].Scope = netlink.SCOPE_LINK
				}
				if kind == "on-link-first" {
					routes[0].Gw = nil
					routes[0].Scope = netlink.SCOPE_LINK
				}
				for i := len(routes) - 1; i >= 0; i-- {
					if err := netlink.RouteAdd(&routes[i]); err != nil {
						t.Fatal(err)
					}
				}
				args, err := collectLinksAndRoutes(&config.Config{}, false)
				if err != nil {
					t.Fatal(err)
				}
				if len(args.FDBasedLinks) != 2 {
					t.Fatalf("FD links = %+v", args.FDBasedLinks)
				}
				if !args.Defaultv4Gateway.Route.Empty() || !args.Defaultv6Gateway.Route.Empty() {
					t.Fatal("default routes were extracted")
				}
				for i, link := range args.FDBasedLinks {
					wantName := "testfirst"
					if i == 1 {
						wantName = "testsecond"
					}
					if link.Name != wantName {
						t.Fatalf("link %d = %s, want %s", i, link.Name, wantName)
					}
					found := 0
					for _, r := range link.Routes {
						if r.Destination.String() == cidr {
							found++
							if !r.Gateway.Equal(routes[i].Gw) || r.MTU != uint32(routes[i].MTU) {
								t.Errorf("default on %s changed: %+v", link.Name, r)
							}
						}
					}
					if found != 1 {
						t.Fatalf("default count on %s = %d, want 1", link.Name, found)
					}
				}
				// Boot installs per-interface routes in interface order. It does
				// not compare metrics across interfaces, even with reverse insertion.
				if name, err := primaryInterface(&args); err != nil || name != "testfirst" {
					t.Fatalf("primaryInterface = (%q, %v), want testfirst", name, err)
				}
			})
		}
	}
}

// checkPrimaryAgainstNetstack validates unbound route selection without sending
// packets. Install collected FD routes and addresses in their existing order.
func checkPrimaryAgainstNetstack(t *testing.T, args *sentryapi.CreateLinksAndRoutesArgs, destination, want string) {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}})
	defer s.Close()
	address := func(ip net.IP) tcpip.Address {
		if v4 := ip.To4(); v4 != nil {
			return tcpip.AddrFromSlice(v4)
		}
		return tcpip.AddrFromSlice(ip.To16())
	}
	var routes []tcpip.Route
	names := make(map[tcpip.NICID]string)
	for i, link := range args.FDBasedLinks {
		id := tcpip.NICID(i + 1)
		names[id] = link.Name
		if err := s.CreateNIC(id, channel.New(1, 1500, "")); err != nil {
			t.Fatal(err)
		}
		for _, a := range link.Addresses {
			proto := ipv6.ProtocolNumber
			if a.Address.To4() != nil {
				proto = ipv4.ProtocolNumber
			}
			if err := s.AddProtocolAddress(id, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: address(a.Address), PrefixLen: a.PrefixLen}}, stack.AddressProperties{}); err != nil {
				t.Fatal(err)
			}
		}
		for _, r := range link.Routes {
			subnet, err := tcpip.NewSubnet(address(r.Destination.IP), tcpip.MaskFromBytes(r.Destination.Mask))
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, tcpip.Route{Destination: subnet, Gateway: address(r.Gateway), NIC: id, MTU: r.MTU})
		}
	}
	s.SetRouteTable(routes)
	remote := net.ParseIP(destination)
	proto := ipv6.ProtocolNumber
	if remote.To4() != nil {
		proto = ipv4.ProtocolNumber
	}
	r, err := s.FindRoute(0, tcpip.Address{}, address(remote), proto, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	actual := names[r.NICID()]
	if actual != want {
		t.Fatalf("netstack selected %q, want %q", actual, want)
	}
	if got, err := primaryInterface(args); err != nil || got != actual {
		t.Fatalf("primaryInterface = (%q, %v), netstack selected %q", got, err, actual)
	}
}

func TestPrimaryInterfaceAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name, unsupported, supported, cidr, remote string
		unsupportedBits, supportedBits             int
	}{
		{"IPv4", "2001:db8::1", "10.0.0.1", "0.0.0.0/0", "198.51.100.1", 64, 24},
		{"IPv6", "10.0.0.1", "2001:db8::1", "::/0", "2001:db8:ffff::1", 24, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &sentryapi.CreateLinksAndRoutesArgs{FDBasedLinks: []sentryapi.FDBasedLink{
				{Name: "wrongfamily", Addresses: []sentryapi.IPWithPrefix{{Address: net.ParseIP(tc.unsupported), PrefixLen: tc.unsupportedBits}}, Routes: []sentryapi.Route{{Destination: *parseCIDR(t, tc.cidr)}}},
				{Name: "eth0", Addresses: []sentryapi.IPWithPrefix{{Address: net.ParseIP(tc.supported), PrefixLen: tc.supportedBits}}, Routes: []sentryapi.Route{{Destination: *parseCIDR(t, tc.cidr)}}},
			}}
			checkPrimaryAgainstNetstack(t, args, tc.remote, "eth0")
		})
	}
}

func TestCollectedDefaultWithoutFamilyAddress(t *testing.T) {
	requireRoot(t)
	first := setupVethInterface(t, "v6only", "2001:db8::1", 64, 128)
	setupLoopback(t)
	second := createVethPair(t, "eth0")
	if err := netlink.LinkSetUp(second); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(second, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []netlink.Route{
		{LinkIndex: first.Attrs().Index, Dst: parseCIDR(t, "0.0.0.0/0"), Scope: netlink.SCOPE_LINK, Priority: 10},
		{LinkIndex: second.Attrs().Index, Dst: parseCIDR(t, "0.0.0.0/0"), Gw: net.ParseIP("10.0.0.254"), Priority: 100},
	} {
		if err := netlink.RouteAdd(&r); err != nil {
			t.Fatal(err)
		}
	}
	args, err := collectLinksAndRoutes(&config.Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(args.FDBasedLinks) != 2 || args.FDBasedLinks[0].Name != "v6only" {
		t.Fatalf("unexpected link order: %+v", args.FDBasedLinks)
	}
	checkPrimaryAgainstNetstack(t, &args, "198.51.100.1", "eth0")
}
