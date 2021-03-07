// Copyright 2018 The gVisor Authors.
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
	"net"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/packetsocket"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
)

var (
	// DefaultLoopbackLink contains IP addresses and routes of "127.0.0.1/8" and
	// "::1/8" on "lo" interface.
	DefaultLoopbackLink = LoopbackLink{
		Name: "lo",
		Addresses: []IPWithPrefix{
			{Address: net.IP("\x7f\x00\x00\x01"), PrefixLen: 8},
			{Address: net.IPv6loopback, PrefixLen: 128},
		},
		Routes: []Route{
			{
				Destination: net.IPNet{
					IP:   net.IPv4(0x7f, 0, 0, 0),
					Mask: net.IPv4Mask(0xff, 0, 0, 0),
				},
			},
			{
				Destination: net.IPNet{
					IP:   net.IPv6loopback,
					Mask: net.IPMask(strings.Repeat("\xff", net.IPv6len)),
				},
			},
		},
	}
)

// Network exposes methods that can be used to configure a network stack.
type Network struct {
	Stack *stack.Stack
}

// Route represents a route in the network stack.
type Route struct {
	Destination net.IPNet
	Gateway     net.IP
}

// DefaultRoute represents a catch all route to the default gateway.
type DefaultRoute struct {
	Route Route
	Name  string
}

// FDBasedLink configures an fd-based link.
type FDBasedLink struct {
	Name               string
	MTU                int
	Addresses          []IPWithPrefix
	Routes             []Route
	GSOMaxSize         uint32
	SoftwareGSOEnabled bool
	TXChecksumOffload  bool
	RXChecksumOffload  bool
	LinkAddress        net.HardwareAddr
	QDisc              config.QueueingDiscipline

	// NumChannels controls how many underlying FD's are to be used to
	// create this endpoint.
	NumChannels int
}

// LoopbackLink configures a loopback li nk.
type LoopbackLink struct {
	Name      string
	Addresses []IPWithPrefix
	Routes    []Route
}

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs struct {
	// FilePayload contains the fds associated with the FDBasedLinks. The
	// number of fd's should match the sum of the NumChannels field of the
	// FDBasedLink entries below.
	urpc.FilePayload

	LoopbackLinks []LoopbackLink
	FDBasedLinks  []FDBasedLink

	Defaultv4Gateway DefaultRoute
	Defaultv6Gateway DefaultRoute
}

// IPWithPrefix is an address with its subnet prefix length.
type IPWithPrefix struct {
	// Address is a network address.
	Address net.IP

	// PrefixLen is the subnet prefix length.
	PrefixLen int
}

func (ip IPWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", ip.Address, ip.PrefixLen)
}

// Empty returns true if route hasn't been set.
func (r *Route) Empty() bool {
	return r.Destination.IP == nil && r.Destination.Mask == nil && r.Gateway == nil
}

func (r *Route) toTcpipRoute(id tcpip.NICID) (tcpip.Route, error) {
	subnet, err := tcpip.NewSubnet(ipToAddress(r.Destination.IP), ipMaskToAddressMask(r.Destination.Mask))
	if err != nil {
		return tcpip.Route{}, err
	}
	return tcpip.Route{
		Destination: subnet,
		Gateway:     ipToAddress(r.Gateway),
		NIC:         id,
	}, nil
}

// CreateLinksAndRoutes creates links and routes in a network stack.  It should
// only be called once.
func (n *Network) CreateLinksAndRoutes(args *CreateLinksAndRoutesArgs, _ *struct{}) error {
	wantFDs := 0
	for _, l := range args.FDBasedLinks {
		wantFDs += l.NumChannels
	}
	if got := len(args.FilePayload.Files); got != wantFDs {
		return fmt.Errorf("args.FilePayload.Files has %d FD's but we need %d entries based on FDBasedLinks", got, wantFDs)
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
			route, err := r.toTcpipRoute(nicID)
			if err != nil {
				return err
			}
			routes = append(routes, route)
		}
	}

	fdOffset := 0
	for _, link := range args.FDBasedLinks {
		nicID++
		nicids[link.Name] = nicID

		FDs := []int{}
		for j := 0; j < link.NumChannels; j++ {
			// Copy the underlying FD.
			oldFD := args.FilePayload.Files[fdOffset].Fd()
			newFD, err := unix.Dup(int(oldFD))
			if err != nil {
				return fmt.Errorf("failed to dup FD %v: %v", oldFD, err)
			}
			FDs = append(FDs, newFD)
			fdOffset++
		}

		mac := tcpip.LinkAddress(link.LinkAddress)
		log.Infof("gso max size is: %d", link.GSOMaxSize)

		linkEP, err := fdbased.New(&fdbased.Options{
			FDs:                FDs,
			MTU:                uint32(link.MTU),
			EthernetHeader:     true,
			Address:            mac,
			PacketDispatchMode: fdbased.RecvMMsg,
			GSOMaxSize:         link.GSOMaxSize,
			SoftwareGSOEnabled: link.SoftwareGSOEnabled,
			TXChecksumOffload:  link.TXChecksumOffload,
			RXChecksumOffload:  link.RXChecksumOffload,
		})
		if err != nil {
			return err
		}

		switch link.QDisc {
		case config.QDiscNone:
		case config.QDiscFIFO:
			log.Infof("Enabling FIFO QDisc on %q", link.Name)
			linkEP = fifo.New(linkEP, runtime.GOMAXPROCS(0), 1000)
		}

		// Enable support for AF_PACKET sockets to receive outgoing packets.
		linkEP = packetsocket.New(linkEP)

		log.Infof("Enabling interface %q with id %d on addresses %+v (%v) w/ %d channels", link.Name, nicID, link.Addresses, mac, link.NumChannels)
		if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
			return err
		}

		// Collect the routes from this link.
		for _, r := range link.Routes {
			route, err := r.toTcpipRoute(nicID)
			if err != nil {
				return err
			}
			routes = append(routes, route)
		}
	}

	if !args.Defaultv4Gateway.Route.Empty() {
		nicID, ok := nicids[args.Defaultv4Gateway.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", args.Defaultv4Gateway.Name)
		}
		route, err := args.Defaultv4Gateway.Route.toTcpipRoute(nicID)
		if err != nil {
			return err
		}
		routes = append(routes, route)
	}

	if !args.Defaultv6Gateway.Route.Empty() {
		nicID, ok := nicids[args.Defaultv6Gateway.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", args.Defaultv6Gateway.Name)
		}
		route, err := args.Defaultv6Gateway.Route.toTcpipRoute(nicID)
		if err != nil {
			return err
		}
		routes = append(routes, route)
	}

	log.Infof("Setting routes %+v", routes)
	n.Stack.SetRouteTable(routes)
	return nil
}

// createNICWithAddrs creates a NIC in the network stack and adds the given
// addresses.
func (n *Network) createNICWithAddrs(id tcpip.NICID, name string, ep stack.LinkEndpoint, addrs []IPWithPrefix) error {
	opts := stack.NICOptions{Name: name}
	if err := n.Stack.CreateNICWithOptions(id, sniffer.New(ep), opts); err != nil {
		return fmt.Errorf("CreateNICWithOptions(%d, _, %+v) failed: %v", id, opts, err)
	}

	for _, addr := range addrs {
		proto, tcpipAddr := ipToAddressAndProto(addr.Address)
		ap := tcpip.AddressWithPrefix{
			Address:   tcpipAddr,
			PrefixLen: addr.PrefixLen,
		}
		if err := n.Stack.AddAddressWithPrefix(id, proto, ap); err != nil {
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

// ipMaskToAddressMask converts IPMask to tcpip.AddressMask, ignoring the
// protocol.
func ipMaskToAddressMask(ipMask net.IPMask) tcpip.AddressMask {
	return tcpip.AddressMask(ipToAddress(net.IP(ipMask)))
}
