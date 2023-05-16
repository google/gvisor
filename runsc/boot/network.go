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
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostos"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/packetsocket"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/xdp"
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

type Neighbor struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

// FDBasedLink configures an fd-based link.
type FDBasedLink struct {
	Name              string
	InterfaceIndex    int
	MTU               int
	Addresses         []IPWithPrefix
	Routes            []Route
	GSOMaxSize        uint32
	GvisorGSOEnabled  bool
	GvisorGROTimeout  time.Duration
	TXChecksumOffload bool
	RXChecksumOffload bool
	LinkAddress       net.HardwareAddr
	QDisc             config.QueueingDiscipline
	Neighbors         []Neighbor

	// NumChannels controls how many underlying FDs are to be used to
	// create this endpoint.
	NumChannels int
}

// XDPLink configures an XDP link.
type XDPLink struct {
	Name              string
	InterfaceIndex    int
	MTU               int
	Addresses         []IPWithPrefix
	Routes            []Route
	TXChecksumOffload bool
	RXChecksumOffload bool
	LinkAddress       net.HardwareAddr
	QDisc             config.QueueingDiscipline
	Neighbors         []Neighbor
	GvisorGROTimeout  time.Duration

	// NumChannels controls how many underlying FDs are to be used to
	// create this endpoint.
	NumChannels int
}

// LoopbackLink configures a loopback link.
type LoopbackLink struct {
	Name             string
	Addresses        []IPWithPrefix
	Routes           []Route
	GvisorGROTimeout time.Duration
}

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs struct {
	// FilePayload contains the fds associated with the FDBasedLinks. The
	// number of fd's should match the sum of the NumChannels field of the
	// FDBasedLink entries below.
	urpc.FilePayload

	LoopbackLinks []LoopbackLink
	FDBasedLinks  []FDBasedLink
	XDPLinks      []XDPLink

	Defaultv4Gateway DefaultRoute
	Defaultv6Gateway DefaultRoute

	// PCAP indicates that FilePayload also contains a PCAP log file.
	PCAP bool
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
	if len(args.FDBasedLinks) > 0 && len(args.XDPLinks) > 0 {
		return fmt.Errorf("received both fdbased and XDP links, but only one can be used at a time")
	}
	wantFDs := 0
	for _, l := range args.FDBasedLinks {
		wantFDs += l.NumChannels
	}
	if len(args.XDPLinks) > 0 {
		wantFDs += 4
	}
	if args.PCAP {
		wantFDs++
	}
	if got := len(args.FilePayload.Files); got != wantFDs {
		return fmt.Errorf("args.FilePayload.Files has %d FDs but we need %d entries based on FDBasedLinks, XDPLinks, and PCAP", got, wantFDs)
	}

	var nicID tcpip.NICID
	nicids := make(map[string]tcpip.NICID)

	// Collect routes from all links.
	var routes []tcpip.Route

	// Loopback normally appear before other interfaces.
	for _, link := range args.LoopbackLinks {
		nicID++
		nicids[link.Name] = nicID

		linkEP := packetsocket.New(ethernet.New(loopback.New()))

		log.Infof("Enabling loopback interface %q with id %d on addresses %+v", link.Name, nicID, link.Addresses)
		opts := stack.NICOptions{
			Name:       link.Name,
			GROTimeout: link.GvisorGROTimeout,
		}
		if err := n.createNICWithAddrs(nicID, linkEP, opts, link.Addresses); err != nil {
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

	// Setup fdbased or XDP links.
	if len(args.FDBasedLinks) > 0 {
		// Choose a dispatch mode.
		dispatchMode := fdbased.RecvMMsg
		version, err := hostos.KernelVersion()
		if err != nil {
			return err
		}
		if version.AtLeast(5, 6) {
			dispatchMode = fdbased.PacketMMap
		} else {
			log.Infof("Host kernel version < 5.6, falling back to RecvMMsg dispatch")
		}

		fdOffset := 0
		for _, link := range args.FDBasedLinks {
			nicID++
			nicids[link.Name] = nicID

			FDs := make([]int, 0, link.NumChannels)
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
				EthernetHeader:     mac != "",
				Address:            mac,
				PacketDispatchMode: dispatchMode,
				GSOMaxSize:         link.GSOMaxSize,
				GvisorGSOEnabled:   link.GvisorGSOEnabled,
				TXChecksumOffload:  link.TXChecksumOffload,
				RXChecksumOffload:  link.RXChecksumOffload,
			})
			if err != nil {
				return err
			}

			// Wrap linkEP in a sniffer to enable packet logging.
			sniffEP := sniffer.New(packetsocket.New(linkEP))

			var qDisc stack.QueueingDiscipline
			switch link.QDisc {
			case config.QDiscNone:
			case config.QDiscFIFO:
				log.Infof("Enabling FIFO QDisc on %q", link.Name)
				qDisc = fifo.New(sniffEP, runtime.GOMAXPROCS(0), 1000)
			}

			log.Infof("Enabling interface %q with id %d on addresses %+v (%v) w/ %d channels", link.Name, nicID, link.Addresses, mac, link.NumChannels)
			opts := stack.NICOptions{
				Name:       link.Name,
				QDisc:      qDisc,
				GROTimeout: link.GvisorGROTimeout,
			}
			if err := n.createNICWithAddrs(nicID, sniffEP, opts, link.Addresses); err != nil {
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

			for _, neigh := range link.Neighbors {
				proto, tcpipAddr := ipToAddressAndProto(neigh.IP)
				n.Stack.AddStaticNeighbor(nicID, proto, tcpipAddr, tcpip.LinkAddress(neigh.HardwareAddr))
			}
		}
	} else if len(args.XDPLinks) > 0 {
		if nlinks := len(args.XDPLinks); nlinks > 1 {
			return fmt.Errorf("XDP only supports one link device, but got %d", nlinks)
		}
		link := args.XDPLinks[0]
		nicID++
		nicids[link.Name] = nicID

		// Get the AF_XDP socket.
		fdOffset := 0
		oldFD := args.FilePayload.Files[fdOffset].Fd()
		fd, err := unix.Dup(int(oldFD))
		if err != nil {
			return fmt.Errorf("failed to dup AF_XDP fd %v: %v", oldFD, err)
		}
		fdOffset++

		// The parent process sends several other FDs in order
		// to keep them open and alive. These are for BPF
		// programs and maps that, if closed, will break the
		// dispatcher.
		for _, fdName := range []string{"program-fd", "sockmap-fd", "link-fd"} {
			oldFD := args.FilePayload.Files[fdOffset].Fd()
			if _, err := unix.Dup(int(oldFD)); err != nil {
				return fmt.Errorf("failed to dup %s with FD %d: %v", fdName, oldFD, err)
			}
			fdOffset++
		}

		mac := tcpip.LinkAddress(link.LinkAddress)
		linkEP, err := xdp.New(&xdp.Options{
			FD:                fd,
			Address:           mac,
			TXChecksumOffload: link.TXChecksumOffload,
			RXChecksumOffload: link.RXChecksumOffload,
			InterfaceIndex:    link.InterfaceIndex,
		})
		if err != nil {
			return err
		}

		// Wrap linkEP in a sniffer to enable packet logging.
		var sniffEP stack.LinkEndpoint
		if args.PCAP {
			newFD, err := unix.Dup(int(args.FilePayload.Files[fdOffset].Fd()))
			if err != nil {
				return fmt.Errorf("failed to dup pcap FD: %v", err)
			}
			const packetTruncateSize = 4096
			sniffEP, err = sniffer.NewWithWriter(packetsocket.New(linkEP), os.NewFile(uintptr(newFD), "pcap-file"), packetTruncateSize)
			if err != nil {
				return fmt.Errorf("failed to create PCAP logger: %v", err)
			}
			fdOffset++
		} else {
			sniffEP = sniffer.New(packetsocket.New(linkEP))
		}

		var qDisc stack.QueueingDiscipline
		switch link.QDisc {
		case config.QDiscNone:
		case config.QDiscFIFO:
			log.Infof("Enabling FIFO QDisc on %q", link.Name)
			qDisc = fifo.New(sniffEP, runtime.GOMAXPROCS(0), 1000)
		}

		log.Infof("Enabling interface %q with id %d on addresses %+v (%v) w/ %d channels", link.Name, nicID, link.Addresses, mac, link.NumChannels)
		opts := stack.NICOptions{
			Name:       link.Name,
			QDisc:      qDisc,
			GROTimeout: link.GvisorGROTimeout,
		}
		if err := n.createNICWithAddrs(nicID, sniffEP, opts, link.Addresses); err != nil {
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

		for _, neigh := range link.Neighbors {
			proto, tcpipAddr := ipToAddressAndProto(neigh.IP)
			n.Stack.AddStaticNeighbor(nicID, proto, tcpipAddr, tcpip.LinkAddress(neigh.HardwareAddr))
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
func (n *Network) createNICWithAddrs(id tcpip.NICID, ep stack.LinkEndpoint, opts stack.NICOptions, addrs []IPWithPrefix) error {
	if err := n.Stack.CreateNICWithOptions(id, ep, opts); err != nil {
		return fmt.Errorf("CreateNICWithOptions(%d, _, %+v) failed: %v", id, opts, err)
	}

	for _, addr := range addrs {
		proto, tcpipAddr := ipToAddressAndProto(addr.Address)
		protocolAddr := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpipAddr,
				PrefixLen: addr.PrefixLen,
			},
		}
		if err := n.Stack.AddProtocolAddress(id, protocolAddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("AddProtocolAddress(%d, %+v, {}) failed: %s", id, protocolAddr, err)
		}
	}
	return nil
}

// ipToAddressAndProto converts IP to tcpip.Address and a protocol number.
//
// Note: don't use 'len(ip)' to determine IP version because length is always 16.
func ipToAddressAndProto(ip net.IP) (tcpip.NetworkProtocolNumber, tcpip.Address) {
	if i4 := ip.To4(); i4 != nil {
		return ipv4.ProtocolNumber, tcpip.AddrFromSlice(i4)
	}
	return ipv6.ProtocolNumber, tcpip.AddrFromSlice(ip)
}

// ipToAddress converts IP to tcpip.Address, ignoring the protocol.
func ipToAddress(ip net.IP) tcpip.Address {
	_, addr := ipToAddressAndProto(ip)
	return addr
}

// ipMaskToAddressMask converts IPMask to tcpip.AddressMask, ignoring the
// protocol.
func ipMaskToAddressMask(ipMask net.IPMask) tcpip.AddressMask {
	addr := ipToAddress(net.IP(ipMask))
	return tcpip.MaskFromBytes(addr.AsSlice())
}
