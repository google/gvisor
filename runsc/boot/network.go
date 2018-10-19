// Copyright 2018 Google LLC
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
	"fmt"
	"math/rand"
	"net"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/loopback"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/arp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
)

// Network exposes methods that can be used to configure a network stack.
type Network struct {
	Stack *stack.Stack
}

// Route represents a route in the network stack.
type Route struct {
	Destination net.IP
	Mask        net.IPMask
	Gateway     net.IP
}

// DefaultRoute represents a catch all route to the default gateway.
type DefaultRoute struct {
	Route Route
	Name  string
}

// FDBasedLink configures an fd-based link.
type FDBasedLink struct {
	Name      string
	MTU       int
	Addresses []net.IP
	Routes    []Route
}

// LoopbackLink configures a loopback li nk.
type LoopbackLink struct {
	Name      string
	Addresses []net.IP
	Routes    []Route
}

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs struct {
	// FilePayload contains the fds associated with the FDBasedLinks.  The
	// two slices must have the same length.
	urpc.FilePayload

	LoopbackLinks []LoopbackLink
	FDBasedLinks  []FDBasedLink

	DefaultGateway DefaultRoute
}

// Empty returns true if route hasn't been set.
func (r *Route) Empty() bool {
	return r.Destination == nil && r.Mask == nil && r.Gateway == nil
}

func (r *Route) toTcpipRoute(id tcpip.NICID) tcpip.Route {
	return tcpip.Route{
		Destination: ipToAddress(r.Destination),
		Gateway:     ipToAddress(r.Gateway),
		Mask:        ipToAddressMask(net.IP(r.Mask)),
		NIC:         id,
	}
}

// CreateLinksAndRoutes creates links and routes in a network stack.  It should
// only be called once.
func (n *Network) CreateLinksAndRoutes(args *CreateLinksAndRoutesArgs, _ *struct{}) error {
	if len(args.FilePayload.Files) != len(args.FDBasedLinks) {
		return fmt.Errorf("FilePayload must be same length at FDBasedLinks")
	}

	var nicID tcpip.NICID
	nicids := make(map[string]tcpip.NICID)

	// Collect routes from all links.
	var routes []tcpip.Route

	// Loopback normally appear before other interfaces.
	for _, link := range args.LoopbackLinks {
		nicID++
		nicids[link.Name] = nicID

		linkEP := loopback.New()

		log.Infof("Enabling loopback interface %q with id %d on addresses %+v", link.Name, nicID, link.Addresses)
		if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
			return err
		}

		// Collect the routes from this link.
		for _, r := range link.Routes {
			routes = append(routes, r.toTcpipRoute(nicID))
		}
	}

	for i, link := range args.FDBasedLinks {
		nicID++
		nicids[link.Name] = nicID

		// Copy the underlying FD.
		oldFD := args.FilePayload.Files[i].Fd()
		newFD, err := syscall.Dup(int(oldFD))
		if err != nil {
			return fmt.Errorf("failed to dup FD %v: %v", oldFD, err)
		}

		mac := tcpip.LinkAddress(generateRndMac())
		linkEP := fdbased.New(&fdbased.Options{
			FD:             newFD,
			MTU:            uint32(link.MTU),
			EthernetHeader: true,
			HandleLocal:    true,
			Address:        mac,
		})

		log.Infof("Enabling interface %q with id %d on addresses %+v (%v)", link.Name, nicID, link.Addresses, mac)
		if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
			return err
		}

		// Collect the routes from this link.
		for _, r := range link.Routes {
			routes = append(routes, r.toTcpipRoute(nicID))
		}
	}

	if !args.DefaultGateway.Route.Empty() {
		nicID, ok := nicids[args.DefaultGateway.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", args.DefaultGateway.Name)
		}
		routes = append(routes, args.DefaultGateway.Route.toTcpipRoute(nicID))
	}

	log.Infof("Setting routes %+v", routes)
	n.Stack.SetRouteTable(routes)
	return nil
}

// createNICWithAddrs creates a NIC in the network stack and adds the given
// addresses.
func (n *Network) createNICWithAddrs(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID, addrs []net.IP) error {
	if err := n.Stack.CreateNamedNIC(id, name, sniffer.New(linkEP)); err != nil {
		return fmt.Errorf("CreateNamedNIC(%v, %v, %v) failed: %v", id, name, linkEP, err)
	}

	// Always start with an arp address for the NIC.
	if err := n.Stack.AddAddress(id, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		return fmt.Errorf("AddAddress(%v, %v, %v) failed: %v", id, arp.ProtocolNumber, arp.ProtocolAddress, err)
	}

	for _, addr := range addrs {
		proto, tcpipAddr := ipToAddressAndProto(addr)
		if err := n.Stack.AddAddress(id, proto, tcpipAddr); err != nil {
			return fmt.Errorf("AddAddress(%v, %v, %v) failed: %v", id, proto, tcpipAddr, err)
		}
	}
	return nil
}

// ipToAddressAndProto converts IP to tcpip.Address and a protocol number.
//
// Note: don't use 'len(ip)' to determine IP version because length is always 16.
func ipToAddressAndProto(ip net.IP) (tcpip.NetworkProtocolNumber, tcpip.Address) {
	if i4 := ip.To4(); i4 != nil {
		return ipv4.ProtocolNumber, tcpip.Address(i4)
	}
	return ipv6.ProtocolNumber, tcpip.Address(ip)
}

// ipToAddress converts IP to tcpip.Address, ignoring the protocol.
func ipToAddress(ip net.IP) tcpip.Address {
	_, addr := ipToAddressAndProto(ip)
	return addr
}

// ipToAddressMask converts IP to tcpip.AddressMask, ignoring the protocol.
func ipToAddressMask(ip net.IP) tcpip.AddressMask {
	_, addr := ipToAddressAndProto(ip)
	return tcpip.AddressMask(addr)
}

// generateRndMac returns a random local MAC address.
// Copied from eth_random_addr() (include/linux/etherdevice.h)
func generateRndMac() net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	rand.Read(mac)
	mac[0] &^= 0x1 // clear multicast bit
	mac[0] |= 0x2  // set local assignment bit (IEEE802)
	return mac
}
