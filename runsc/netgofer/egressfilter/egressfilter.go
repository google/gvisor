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

// Package egressfilter validates outbound traffic destinations for netgofer,
// enforcing invariants such as loopback, multicast, link-local, broadcast,
// and host network interface protection.
package egressfilter

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Options configures an egress Filter.
type Options struct {
	// AllowLoopback determines whether destinations on loopback addresses
	// (127.0.0.0/8 and ::1) are permitted.
	AllowLoopback bool

	// LocalAddrs overrides the set of host interface addresses rejected by the
	// filter. If nil, New queries the host network interfaces using
	// net.InterfaceAddrs(). This query must be performed before seccomp filters
	// are installed.
	LocalAddrs []net.IP
}

// Filter validates whether a destination is permitted for outbound traffic.
type Filter struct {
	allowLoopback bool
	localAddrs    map[tcpip.Address]struct{}
}

// New creates a new Filter with the given options.
func New(opts Options) (*Filter, error) {
	localAddrs := make(map[tcpip.Address]struct{})
	if opts.LocalAddrs != nil {
		for _, ip := range opts.LocalAddrs {
			recordLocalIP(localAddrs, ip)
		}
	} else {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil, fmt.Errorf("querying interface addresses: %w", err)
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			recordLocalIP(localAddrs, ip)
		}
	}
	return &Filter{
		allowLoopback: opts.AllowLoopback,
		localAddrs:    localAddrs,
	}, nil
}

func recordLocalIP(m map[tcpip.Address]struct{}, ip net.IP) {
	if ip == nil || ip.IsLoopback() {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		m[tcpip.AddrFrom4Slice(ip4)] = struct{}{}
	} else if ip16 := ip.To16(); ip16 != nil {
		m[tcpip.AddrFrom16Slice(ip16)] = struct{}{}
	}
}

// Allows reports whether the destination (addr, port) is permitted.
func (f *Filter) Allows(addr tcpip.Address, port uint16) bool {
	if f == nil || port == 0 {
		return false
	}
	ip := net.IP(addr.AsSlice())
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		addr = tcpip.AddrFrom4Slice(ip4)
	}
	if _, isLocal := f.localAddrs[addr]; isLocal {
		return false
	}
	if ip.IsLoopback() {
		return f.allowLoopback
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if addr == header.IPv4Broadcast || header.IPv4CurrentNetworkSubnet.Contains(addr) {
		return false
	}
	return true
}

// AllowsLoopback reports whether loopback destinations are permitted.
func (f *Filter) AllowsLoopback() bool {
	if f == nil {
		return false
	}
	return f.allowLoopback
}
