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

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const setupUDPArg = "--setup-udp-network"

// Linux sock_setsockopt in net/core/sock.c requires CAP_NET_ADMIN in the initial
// user namespace to force larger buffers. The UDP link can use the reported size.
var udpBufferWarning = regexp.MustCompile(`^W[0-9]{4} [0-9:.]+ +[0-9]+ network\.go:[0-9]+\] Failed to increase (rcv|snd) buffer to 4194304 on SOCK_RAW on eth0\. Current buffer [1-9][0-9]*: operation not permitted$`)

func runWithUDPNetwork(path string, args []string) error {
	// Network namespaces belong to threads. Keep this thread through exec and
	// open every network socket after unshare, including on direct invocation.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare network namespace: %w", err)
	}
	if err := configureUDPNetwork(); err != nil {
		return err
	}
	return unix.Exec(path, args, os.Environ())
}

func configureUDPNetwork() error {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open routing socket: %w", err)
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bring up loopback: %w", err)
	}
	eth := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Flags: net.FlagUp | net.FlagMulticast}}
	if err := h.LinkAdd(eth); err != nil {
		return fmt.Errorf("create bridge eth0: %w", err)
	}
	ipNet := func(s string) *net.IPNet {
		p := netip.MustParsePrefix(s)
		return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	}
	for _, addr := range []netlink.Addr{
		{IPNet: ipNet("192.0.2.1/24"), Broadcast: net.IPv4(192, 0, 2, 255)},
		{IPNet: ipNet("2001:db8::1/64"), Flags: unix.IFA_F_NODAD},
	} {
		if err := h.AddrAdd(eth, &addr); err != nil {
			return fmt.Errorf("address eth0 with %v: %w", addr.IPNet, err)
		}
	}
	// Neither a peer nor a default route is needed for local UDP delivery.
	// The IPv6 tests join ff05::1234 on loopback.
	for _, route := range []netlink.Route{
		{LinkIndex: eth.Index, Dst: ipNet("224.0.0.0/4"), Scope: netlink.SCOPE_LINK},
		{LinkIndex: eth.Index, Dst: ipNet("255.255.255.255/32"), Scope: netlink.SCOPE_LINK},
		{LinkIndex: lo.Attrs().Index, Dst: ipNet("ff05::1234/128"), Type: unix.RTN_LOCAL, Table: unix.RT_TABLE_MAIN},
	} {
		if err := h.RouteAdd(&route); err != nil {
			return fmt.Errorf("route %s: %w", route.Dst, err)
		}
	}
	return nil
}
