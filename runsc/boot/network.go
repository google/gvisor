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
	"io"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/gomaxprocs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/tbf"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/xdp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

// Network exposes methods that can be used to configure a network stack.
type Network struct {
	Stack  *stack.Stack
	Kernel *kernel.Kernel

	// PluginStack is a third-party network stack to use in place of
	// netstack when non-nil.
	PluginStack plugin.PluginStack
}

func toTcpipRoute(r *sentryapi.Route, id tcpip.NICID) (tcpip.Route, error) {
	subnet, err := tcpip.NewSubnet(ipToAddress(r.Destination.IP), ipMaskToAddressMask(r.Destination.Mask))
	if err != nil {
		return tcpip.Route{}, err
	}
	return tcpip.Route{
		Destination: subnet,
		Gateway:     ipToAddress(r.Gateway),
		NIC:         id,
		MTU:         r.MTU,
	}, nil
}

// InitPluginStack initializes plugin network stack.
// It will invoke Init() that is registered by current plugin stack.
func (n *Network) InitPluginStack(args *sentryapi.InitPluginStackArgs, _ *struct{}) error {
	pluginStack := n.PluginStack
	if pluginStack == nil {
		return fmt.Errorf("plugin stack is not registered")
	}

	fdNum := len(args.FilePayload.Files)
	fds := make([]int, fdNum)
	for i := 0; i < fdNum; i++ {
		oldFD := args.FilePayload.Files[i].Fd()
		if newFD, err := syscall.Dup(int(oldFD)); err != nil {
			return fmt.Errorf("failed to dup FD")
		} else {
			fds[i] = newFD
		}
	}

	return pluginStack.Init(&plugin.InitStackArgs{
		InitStr: args.InitStr,
		FDs:     fds,
	})
}

// CreateLinksAndRoutes creates links and routes in a network stack. It should
// only be called once.
func (n *Network) CreateLinksAndRoutes(args *sentryapi.CreateLinksAndRoutesArgs, _ *struct{}) error {
	files, err := splitNetworkFiles(args)
	if err != nil {
		return err
	}
	setup := networkSetup{
		network:     n,
		nicIDs:      make(map[string]tcpip.NICID),
		captureFile: files.pcap,
		logPackets:  args.LogPackets,
	}

	// Loopback normally appears before other interfaces. Only external links
	// write to the PCAP file.
	for _, link := range args.LoopbackLinks {
		var ep stack.LinkEndpoint = ethernet.New(loopback.New())
		if args.LogPackets {
			ep = sniffer.New(ep)
		}
		if _, err := setup.addNIC(ep, link.Name, link.Addresses, link.Routes, nil); err != nil {
			return err
		}
	}

	for _, link := range args.FDBasedLinks {
		channels := files.links[:link.NumChannels]
		files.links = files.links[link.NumChannels:]
		ep, err := newFDBasedEndpoint(link, channels)
		if err != nil {
			return err
		}
		neighbors := link.Neighbors
		if link.IsProxy {
			// A proxy carries bare IP packets and has no neighbor table.
			neighbors = nil
		}
		if err := setup.addExternalNIC(ep, externalNIC{
			name:      link.Name,
			addresses: link.Addresses,
			routes:    link.Routes,
			neighbors: neighbors,
			qdisc:     link.QDisc,
			rate:      link.TBFRate,
			burst:     link.TBFBurst,
		}); err != nil {
			return err
		}
	}
	for _, link := range args.XDPLinks {
		ep, err := newXDPEndpoint(link, files.links)
		if err != nil {
			return err
		}
		if err := setup.addExternalNIC(ep, externalNIC{
			name:      link.Name,
			addresses: link.Addresses,
			routes:    link.Routes,
			neighbors: link.Neighbors,
			qdisc:     link.QDisc,
			rate:      link.TBFRate,
			burst:     link.TBFBurst,
		}); err != nil {
			return err
		}
	}

	for _, gw := range []sentryapi.DefaultRoute{args.Defaultv4Gateway, args.Defaultv6Gateway} {
		if gw.Route.Empty() {
			continue
		}
		nicID, ok := setup.nicIDs[gw.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", gw.Name)
		}
		route, err := toTcpipRoute(&gw.Route, nicID)
		if err != nil {
			return err
		}
		setup.routes = append(setup.routes, route)
	}
	log.Infof("Setting routes %+v", setup.routes)
	n.Stack.SetRouteTable(setup.routes)

	if files.nat != nil {
		log.Infof("Replacing NAT table")
		iptReplaceBlob, err := io.ReadAll(files.nat)
		if err != nil {
			return fmt.Errorf("failed to read iptables blob: %v", err)
		}
		if err := netfilter.SetEntries(n.Kernel.RootUserNamespace(), n.Stack, iptReplaceBlob, false); err != nil {
			return fmt.Errorf("failed to SetEntries: %v", err)
		}
	}

	if args.PauseExternalNetworking {
		n.Stack.DisableAllNonLoopbackNICs()
	}
	n.Stack.SetAllowConnectedOnSave(args.AllowConnectedOnSave)
	return nil
}

// networkFiles names the three parts of the CreateLinksAndRoutes file payload.
type networkFiles struct {
	links []*os.File
	pcap  *os.File
	nat   *os.File
}

func splitNetworkFiles(args *sentryapi.CreateLinksAndRoutesArgs) (networkFiles, error) {
	if len(args.FDBasedLinks) > 0 && len(args.XDPLinks) > 0 {
		return networkFiles{}, fmt.Errorf("received both fdbased and XDP links, but only one can be used at a time")
	}
	if n := len(args.XDPLinks); n > 1 {
		return networkFiles{}, fmt.Errorf("XDP only supports one link device, but got %d", n)
	}
	var files networkFiles
	// The sender appends the optional files after the link descriptors.
	linkFiles := args.FilePayload.Files
	if args.NATBlob {
		if len(linkFiles) == 0 {
			return networkFiles{}, fmt.Errorf("missing NAT file")
		}
		files.nat = linkFiles[len(linkFiles)-1]
		linkFiles = linkFiles[:len(linkFiles)-1]
	}
	if args.PCAP {
		if len(linkFiles) == 0 {
			return networkFiles{}, fmt.Errorf("missing PCAP file")
		}
		files.pcap = linkFiles[len(linkFiles)-1]
		linkFiles = linkFiles[:len(linkFiles)-1]
	}
	want := 0
	for _, link := range args.FDBasedLinks {
		if link.NumChannels < 0 || link.NumChannels > len(linkFiles)-want {
			return networkFiles{}, fmt.Errorf("interface %q requires %d channel FDs, have %d", link.Name, link.NumChannels, len(linkFiles)-want)
		}
		want += link.NumChannels
	}
	for _, link := range args.XDPLinks {
		switch link.Bind {
		case sentryapi.BindSentry:
			want = 4 // AF_XDP socket, program, socket map, and link.
		case sentryapi.BindRunsc:
			want = 1 // runsc keeps the BPF resources alive.
		default:
			return networkFiles{}, fmt.Errorf("unknown bind value: %d", link.Bind)
		}
	}
	if got := len(linkFiles); got != want {
		return networkFiles{}, fmt.Errorf("received %d link FDs, want %d", got, want)
	}
	files.links = linkFiles
	return files, nil
}

func openPacketCapture(f *os.File) (*sniffer.PCAP, error) {
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("duplicating PCAP file: %w", err)
	}
	file := os.NewFile(uintptr(fd), "pcap-file")
	const packetTruncateSize = 4096
	capture, err := sniffer.NewPCAP(file, packetTruncateSize)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("writing PCAP header: %w", err)
	}
	return capture, nil
}

// The RPC closes its files on return. Each endpoint needs its descriptors
// for the lifetime of the sandbox.
func dupLinkFDs(files []*os.File) ([]int, error) {
	fds := make([]int, 0, len(files))
	for _, file := range files {
		fd, err := unix.Dup(int(file.Fd()))
		if err != nil {
			closeLinkFDs(fds)
			return nil, fmt.Errorf("duplicating link FD %d: %w", file.Fd(), err)
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

func closeLinkFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

func newFDBasedEndpoint(link sentryapi.FDBasedLink, channels []*os.File) (stack.LinkEndpoint, error) {
	fds, err := dupLinkFDs(channels)
	if err != nil {
		return nil, err
	}
	// Testing has shown that RecvMMsg is the fastest. Attempts to use
	// the PacketMMap dispatcher have failed to result in higher throughput.
	dispatchMode := fdbased.RecvMMsg
	if link.IsProxy {
		// Use Readv for a SOCK_SEQPACKET UDS proxy link so a peer EOF (0-byte
		// read) stops the dispatcher cleanly instead of busy-spinning in
		// RecvMMsg.
		dispatchMode = fdbased.Readv
	}
	mac := tcpip.LinkAddress(link.LinkAddress)
	log.Infof("Creating FD-based link %q (%v) with %d channels", link.Name, mac, link.NumChannels)
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                  fds,
		MTU:                  uint32(link.MTU),
		EthernetHeader:       mac != "" && !link.IsProxy,
		Address:              mac,
		PacketDispatchMode:   dispatchMode,
		GSOMaxSize:           link.GSOMaxSize,
		GVisorGSOEnabled:     link.GVisorGSOEnabled,
		TXChecksumOffload:    link.TXChecksumOffload,
		RXChecksumOffload:    link.RXChecksumOffload,
		GRO:                  link.GVisorGRO,
		ProcessorsPerChannel: link.ProcessorsPerChannel,
		IsPacketSocket:       link.IsPacket,
		PreConfigured:        link.PreConfigured,
	})
	if err != nil {
		closeLinkFDs(fds)
	}
	return ep, err
}

func newXDPEndpoint(link sentryapi.XDPLink, files []*os.File) (stack.LinkEndpoint, error) {
	// When the sentry binds the socket, the remaining FDs keep its BPF
	// program, socket map, and link alive for the lifetime of the dispatcher.
	fds, err := dupLinkFDs(files)
	if err != nil {
		return nil, err
	}
	log.Infof("Creating XDP link %q (%v) with %d channels", link.Name, link.LinkAddress, link.NumChannels)
	ep, err := xdp.New(&xdp.Options{
		FD:                fds[0],
		Address:           tcpip.LinkAddress(link.LinkAddress),
		TXChecksumOffload: link.TXChecksumOffload,
		RXChecksumOffload: link.RXChecksumOffload,
		InterfaceIndex:    link.InterfaceIndex,
		Bind:              link.Bind == sentryapi.BindSentry,
		GRO:               link.GVisorGRO,
	})
	if err != nil {
		closeLinkFDs(fds)
	}
	return ep, err
}

type networkSetup struct {
	network     *Network
	nicIDs      map[string]tcpip.NICID
	routes      []tcpip.Route
	captureFile *os.File
	capture     *sniffer.PCAP
	logPackets  bool
}

type externalNIC struct {
	name      string
	addresses []sentryapi.IPWithPrefix
	routes    []sentryapi.Route
	neighbors []sentryapi.Neighbor
	qdisc     config.QueueingDiscipline
	rate      uint64
	burst     uint32
}

func (s *networkSetup) addExternalNIC(ep stack.LinkEndpoint, link externalNIC) error {
	if s.captureFile != nil {
		if s.capture == nil {
			// The first external endpoint writes the file header. Later NICs
			// append records to the same stream.
			capture, err := openPacketCapture(s.captureFile)
			if err != nil {
				return err
			}
			s.capture = capture
		}
		ep = s.capture.Wrap(ep)
	} else if s.logPackets {
		ep = sniffer.New(ep)
	}

	var qDisc stack.QueueingDiscipline
	switch link.qdisc {
	case config.QDiscNone:
	case config.QDiscFIFO:
		log.Infof("Enabling FIFO QDisc on %q", link.name)
		qDisc = fifo.New(ep, gomaxprocs.Base(), 1000)
	case config.QDiscTBF:
		log.Infof("Enabling TBF QDisc on %q rate=%d burst=%d", link.name, link.rate, link.burst)
		var err error
		qDisc, err = tbf.New(ep, s.network.Stack.Clock(), link.rate, link.burst, 1000)
		if err != nil {
			return fmt.Errorf("creating TBF qdisc for %q: %w", link.name, err)
		}
	}
	nicID, err := s.addNIC(ep, link.name, link.addresses, link.routes, qDisc)
	if err != nil {
		return err
	}
	for _, neigh := range link.neighbors {
		proto, addr := ipToAddressAndProto(neigh.IP)
		s.network.Stack.AddStaticNeighbor(nicID, proto, addr, tcpip.LinkAddress(neigh.HardwareAddr))
	}
	return nil
}

func (s *networkSetup) addNIC(ep stack.LinkEndpoint, name string, addrs []sentryapi.IPWithPrefix, routes []sentryapi.Route, qDisc stack.QueueingDiscipline) (tcpip.NICID, error) {
	nicID := s.network.Stack.NextNICID()
	log.Infof("Enabling interface %q with id %d on addresses %+v", name, nicID, addrs)
	opts := stack.NICOptions{Name: name, QDisc: qDisc, DeliverLinkPackets: true}
	if err := s.network.createNICWithAddrs(nicID, ep, opts, addrs); err != nil {
		return 0, err
	}
	s.nicIDs[name] = nicID
	for _, r := range routes {
		route, err := toTcpipRoute(&r, nicID)
		if err != nil {
			return 0, err
		}
		s.routes = append(s.routes, route)
	}
	return nicID, nil
}

// createNICWithAddrs creates a NIC in the network stack and adds the given
// addresses.
func (n *Network) createNICWithAddrs(id tcpip.NICID, ep stack.LinkEndpoint, opts stack.NICOptions, addrs []sentryapi.IPWithPrefix) error {
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
