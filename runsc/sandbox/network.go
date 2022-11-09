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

package sandbox

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// setupNetwork configures the network stack to mimic the local network
// configuration. Docker uses network namespaces with vnets to configure the
// network for the container. The untrusted app expects to see the same network
// inside the sandbox. Routing and port mapping is handled directly by docker
// with most of network information not even available to the runtime.
//
// Netstack inside the sandbox speaks directly to the device using a raw socket.
// All IP addresses assigned to the NIC, are removed and passed on to netstack's
// device.
//
// If 'conf.Network' is NoNetwork, skips local configuration and creates a
// loopback interface only.
//
// Run the following container to test it:
//
//	docker run -di --runtime=runsc -p 8080:80 -v $PWD:/usr/local/apache2/htdocs/ httpd:2.4
func setupNetwork(conn *urpc.Client, pid int, conf *config.Config) error {
	log.Infof("Setting up network")

	switch conf.Network {
	case config.NetworkNone:
		log.Infof("Network is disabled, create loopback interface only")
		if err := createDefaultLoopbackInterface(conn); err != nil {
			return fmt.Errorf("creating default loopback interface: %v", err)
		}
	case config.NetworkSandbox:
		// Build the path to the net namespace of the sandbox process.
		// This is what we will copy.
		nsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns/net")
		if err := createInterfacesAndRoutesFromNS(conn, nsPath, conf); err != nil {
			return fmt.Errorf("creating interfaces from net namespace %q: %v", nsPath, err)
		}
	case config.NetworkHost:
		// Nothing to do here.
	default:
		return fmt.Errorf("invalid network type: %v", conf.Network)
	}
	return nil
}

func createDefaultLoopbackInterface(conn *urpc.Client) error {
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &boot.CreateLinksAndRoutesArgs{
		LoopbackLinks: []boot.LoopbackLink{boot.DefaultLoopbackLink},
	}, nil); err != nil {
		return fmt.Errorf("creating loopback link and routes: %v", err)
	}
	return nil
}

func joinNetNS(nsPath string) (func(), error) {
	runtime.LockOSThread()
	restoreNS, err := specutils.ApplyNS(specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: nsPath,
	})
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("joining net namespace %q: %v", nsPath, err)
	}
	return func() {
		restoreNS()
		runtime.UnlockOSThread()
	}, nil
}

// isRootNS determines whether we are running in the root net namespace.
// /proc/sys/net/core/rmem_default only exists in root network namespace.
func isRootNS() (bool, error) {
	err := unix.Access("/proc/sys/net/core/rmem_default", unix.F_OK)
	switch err {
	case nil:
		return true, nil
	case unix.ENOENT:
		return false, nil
	default:
		return false, fmt.Errorf("failed to access /proc/sys/net/core/rmem_default: %v", err)
	}
}

// createInterfacesAndRoutesFromNS scrapes the interface and routes from the
// net namespace with the given path, creates them in the sandbox, and removes
// them from the host.
func createInterfacesAndRoutesFromNS(conn *urpc.Client, nsPath string, conf *config.Config) error {
	// Join the network namespace that we will be copying.
	restore, err := joinNetNS(nsPath)
	if err != nil {
		return err
	}
	defer restore()

	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("querying interfaces: %w", err)
	}

	isRoot, err := isRootNS()
	if err != nil {
		return err
	}
	if isRoot {
		return fmt.Errorf("cannot run with network enabled in root network namespace")
	}

	// Collect addresses and routes from the interfaces.
	var args boot.CreateLinksAndRoutesArgs
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			log.Infof("Skipping down interface: %+v", iface)
			continue
		}

		allAddrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("fetching interface addresses for %q: %w", iface.Name, err)
		}

		// We build our own loopback device.
		if iface.Flags&net.FlagLoopback != 0 {
			link, err := loopbackLink(iface, allAddrs)
			if err != nil {
				return fmt.Errorf("getting loopback link for iface %q: %w", iface.Name, err)
			}
			args.LoopbackLinks = append(args.LoopbackLinks, link)
			continue
		}

		var ipAddrs []*net.IPNet
		for _, ifaddr := range allAddrs {
			ipNet, ok := ifaddr.(*net.IPNet)
			if !ok {
				return fmt.Errorf("address is not IPNet: %+v", ifaddr)
			}
			ipAddrs = append(ipAddrs, ipNet)
		}
		if len(ipAddrs) == 0 {
			log.Warningf("No usable IP addresses found for interface %q, skipping", iface.Name)
			continue
		}

		// Collect data from the ARP table.
		dump, err := netlink.NeighList(iface.Index, 0)
		if err != nil {
			return fmt.Errorf("fetching ARP table for %q: %w", iface.Name, err)
		}

		var neighbors []boot.Neighbor
		for _, n := range dump {
			// There are only two "good" states NUD_PERMANENT and NUD_REACHABLE,
			// but NUD_REACHABLE is fully dynamic and will be re-probed anyway.
			if n.State == netlink.NUD_PERMANENT {
				log.Debugf("Copying a static ARP entry: %+v %+v", n.IP, n.HardwareAddr)
				// No flags are copied because Stack.AddStaticNeighbor does not support flags right now.
				neighbors = append(neighbors, boot.Neighbor{IP: n.IP, HardwareAddr: n.HardwareAddr})
			}
		}

		// Scrape the routes before removing the address, since that
		// will remove the routes as well.
		routes, defv4, defv6, err := routesForIface(iface)
		if err != nil {
			return fmt.Errorf("getting routes for interface %q: %v", iface.Name, err)
		}
		if defv4 != nil {
			if !args.Defaultv4Gateway.Route.Empty() {
				return fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, defv4, args.Defaultv4Gateway)
			}
			args.Defaultv4Gateway.Route = *defv4
			args.Defaultv4Gateway.Name = iface.Name
		}

		if defv6 != nil {
			if !args.Defaultv6Gateway.Route.Empty() {
				return fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, defv6, args.Defaultv6Gateway)
			}
			args.Defaultv6Gateway.Route = *defv6
			args.Defaultv6Gateway.Name = iface.Name
		}

		// Get the link for the interface.
		ifaceLink, err := netlink.LinkByName(iface.Name)
		if err != nil {
			return fmt.Errorf("getting link for interface %q: %w", iface.Name, err)
		}
		linkAddress := ifaceLink.Attrs().HardwareAddr

		// Collect the addresses for the interface, enable forwarding,
		// and remove them from the host.
		var addresses []boot.IPWithPrefix
		for _, addr := range ipAddrs {
			prefix, _ := addr.Mask.Size()
			addresses = append(addresses, boot.IPWithPrefix{Address: addr.IP, PrefixLen: prefix})

			// Steal IP address from NIC.
			if err := removeAddress(ifaceLink, addr.String()); err != nil {
				// If we encounter an error while deleting the ip,
				// verify the ip is still present on the interface.
				if present, err := isAddressOnInterface(iface.Name, addr); err != nil {
					return fmt.Errorf("checking if address %v is on interface %q: %w", addr, iface.Name, err)
				} else if !present {
					continue
				}
				return fmt.Errorf("removing address %v from device %q: %w", addr, iface.Name, err)
			}
		}

		if conf.AFXDP {
			xdpSockFDs, err := createSocketXDP(iface)
			if err != nil {
				return fmt.Errorf("failed to create XDP socket: %v", err)
			}
			args.FilePayload.Files = append(args.FilePayload.Files, xdpSockFDs...)
			args.XDPLinks = append(args.XDPLinks, boot.XDPLink{
				Name:              iface.Name,
				InterfaceIndex:    iface.Index,
				Routes:            routes,
				TXChecksumOffload: conf.TXChecksumOffload,
				RXChecksumOffload: conf.RXChecksumOffload,
				NumChannels:       conf.NumNetworkChannels,
				QDisc:             conf.QDisc,
				Neighbors:         neighbors,
				LinkAddress:       linkAddress,
				Addresses:         addresses,
			})
		} else {
			link := boot.FDBasedLink{
				Name:              iface.Name,
				MTU:               iface.MTU,
				Routes:            routes,
				TXChecksumOffload: conf.TXChecksumOffload,
				RXChecksumOffload: conf.RXChecksumOffload,
				NumChannels:       conf.NumNetworkChannels,
				QDisc:             conf.QDisc,
				Neighbors:         neighbors,
				LinkAddress:       linkAddress,
				Addresses:         addresses,
			}

			log.Debugf("Setting up network channels")
			// Create the socket for the device.
			for i := 0; i < link.NumChannels; i++ {
				log.Debugf("Creating Channel %d", i)
				socketEntry, err := createSocket(iface, ifaceLink, conf.HostGSO)
				if err != nil {
					return fmt.Errorf("failed to createSocket for %s : %w", iface.Name, err)
				}
				if i == 0 {
					link.GSOMaxSize = socketEntry.gsoMaxSize
				} else {
					if link.GSOMaxSize != socketEntry.gsoMaxSize {
						return fmt.Errorf("inconsistent gsoMaxSize %d and %d when creating multiple channels for same interface: %s",
							link.GSOMaxSize, socketEntry.gsoMaxSize, iface.Name)
					}
				}
				args.FilePayload.Files = append(args.FilePayload.Files, socketEntry.deviceFile)
			}

			if link.GSOMaxSize == 0 && conf.GvisorGSO {
				// Host GSO is disabled. Let's enable gVisor GSO.
				link.GSOMaxSize = stack.GvisorGSOMaxSize
				link.GvisorGSOEnabled = true
			}
			link.GvisorGROTimeout = conf.GvisorGROTimeout

			args.FDBasedLinks = append(args.FDBasedLinks, link)
		}
	}

	// Pass PCAP log file if present.
	if conf.PCAP != "" {
		args.PCAP = true
		pcap, err := os.OpenFile(conf.PCAP, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return fmt.Errorf("failed to open PCAP file %s: %v", conf.PCAP, err)
		}
		args.FilePayload.Files = append(args.FilePayload.Files, pcap)
	}

	log.Debugf("Setting up network, config: %+v", args)
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &args, nil); err != nil {
		return fmt.Errorf("creating links and routes: %w", err)
	}
	return nil
}

// isAddressOnInterface checks if an address is on an interface
func isAddressOnInterface(ifaceName string, addr *net.IPNet) (bool, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("getting interface by name %q: %w", ifaceName, err)
	}
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("fetching interface addresses for %q: %w", iface.Name, err)
	}
	for _, ifaceAddr := range ifaceAddrs {
		ipNet, ok := ifaceAddr.(*net.IPNet)
		if !ok {
			log.Warningf("Can't cast address to *net.IPNet, skipping: %+v", ifaceAddr)
			continue
		}
		if ipNet.String() == addr.String() {
			return true, nil
		}
	}
	return false, nil
}

type socketEntry struct {
	deviceFile *os.File
	gsoMaxSize uint32
}

// createSocket creates an underlying AF_PACKET socket and configures it for
// use by the sentry and returns an *os.File that wraps the underlying socket
// fd.
func createSocket(iface net.Interface, ifaceLink netlink.Link, enableGSO bool) (*socketEntry, error) {
	// Create the socket.
	const protocol = 0x0300 // htons(ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("unable to create raw socket: %v", err)
	}
	deviceFile := os.NewFile(uintptr(fd), "raw-device-fd")
	// Bind to the appropriate device.
	ll := unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &ll); err != nil {
		return nil, fmt.Errorf("unable to bind to %q: %v", iface.Name, err)
	}

	gsoMaxSize := uint32(0)
	if enableGSO {
		gso, err := isGSOEnabled(fd, iface.Name)
		if err != nil {
			return nil, fmt.Errorf("getting GSO for interface %q: %v", iface.Name, err)
		}
		if gso {
			if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
				return nil, fmt.Errorf("unable to enable the PACKET_VNET_HDR option: %v", err)
			}
			gsoMaxSize = ifaceLink.Attrs().GSOMaxSize
		} else {
			log.Infof("GSO not available in host.")
		}
	}

	// Use SO_RCVBUFFORCE/SO_SNDBUFFORCE because on linux the receive/send buffer
	// for an AF_PACKET socket is capped by "net.core.rmem_max/wmem_max".
	// wmem_max/rmem_max default to a unusually low value of 208KB. This is too
	// low for gVisor to be able to receive packets at high throughputs without
	// incurring packet drops.
	const bufSize = 4 << 20 // 4MB.

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bufSize); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize)
		sz, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)

		if sz < bufSize {
			log.Warningf("Failed to increase rcv buffer to %d on SOCK_RAW on %s. Current buffer %d: %v", bufSize, iface.Name, sz, err)
		}
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bufSize); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize)
		sz, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if sz < bufSize {
			log.Warningf("Failed to increase snd buffer to %d on SOCK_RAW on %s. Current buffer %d: %v", bufSize, iface.Name, sz, err)
		}
	}

	return &socketEntry{deviceFile, gsoMaxSize}, nil
}

// program is the BPF program to attach to the socket.
//
//go:embed bpf/af_xdp_ebpf.o
var program []byte

func createSocketXDP(iface net.Interface) ([]*os.File, error) {
	// Create an XDP socket. The sentry will mmap memory for the various
	// rings and bind to the device.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to create AF_XDP socket: %v", err)
	}

	// We also need to, before dropping privileges, attach a program to the
	// device and insert our socket into its map.

	// Load into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
		SockMap *ebpf.Map     `ebpf:"sock_map"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load program: %v", err)
	}

	rawLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: objects.Program,
		Attach:  ebpf.AttachXDP,
		Target:  iface.Index,
		// By not setting the Flag field, the kernel will choose the
		// fastest mode. In order those are:
		// - Offloaded onto the NIC.
		// - Running directly in the driver.
		// - Generic mode, which works with any NIC/driver but lacks
		//   much of the XDP performance boost.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF program: %v", err)
	}

	// Insert our AF_XDP socket into the BPF map that dictates where
	// packets are redirected to.
	key := uint32(0)
	val := uint32(fd)
	if err := objects.SockMap.Update(&key, &val, 0 /* flags */); err != nil {
		return nil, fmt.Errorf("failed to insert socket into BPF map: %v", err)
	}

	// We need to keep the Program, SockMap, and link FDs open until they
	// can be passed to the sandbox process.
	progFD, err := unix.Dup(objects.Program.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF program: %v", err)
	}
	sockMapFD, err := unix.Dup(objects.SockMap.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF map: %v", err)
	}
	linkFD, err := unix.Dup(rawLink.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF link: %v", err)
	}

	return []*os.File{
		os.NewFile(uintptr(fd), "xdp-fd"),            // The socket.
		os.NewFile(uintptr(progFD), "program-fd"),    // The XDP program.
		os.NewFile(uintptr(sockMapFD), "sockmap-fd"), // The XDP map.
		os.NewFile(uintptr(linkFD), "link-fd"),       // The XDP link.
	}, nil
}

// loopbackLink returns the link with addresses and routes for a loopback
// interface.
func loopbackLink(iface net.Interface, addrs []net.Addr) (boot.LoopbackLink, error) {
	link := boot.LoopbackLink{
		Name: iface.Name,
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			return boot.LoopbackLink{}, fmt.Errorf("address is not IPNet: %+v", addr)
		}

		prefix, _ := ipNet.Mask.Size()
		link.Addresses = append(link.Addresses, boot.IPWithPrefix{
			Address:   ipNet.IP,
			PrefixLen: prefix,
		})

		dst := *ipNet
		dst.IP = dst.IP.Mask(dst.Mask)
		link.Routes = append(link.Routes, boot.Route{
			Destination: dst,
		})
	}
	return link, nil
}

// routesForIface iterates over all routes for the given interface and converts
// them to boot.Routes. It also returns the a default v4/v6 route if found.
func routesForIface(iface net.Interface) ([]boot.Route, *boot.Route, *boot.Route, error) {
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, nil, nil, err
	}
	rs, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting routes from %q: %v", iface.Name, err)
	}

	var defv4, defv6 *boot.Route
	var routes []boot.Route
	for _, r := range rs {
		// Is it a default route?
		if r.Dst == nil {
			if r.Gw == nil {
				return nil, nil, nil, fmt.Errorf("default route with no gateway %q: %+v", iface.Name, r)
			}
			// Create a catch all route to the gateway.
			switch len(r.Gw) {
			case header.IPv4AddressSize:
				if defv4 != nil {
					return nil, nil, nil, fmt.Errorf("more than one default route found %q, def: %+v, route: %+v", iface.Name, defv4, r)
				}
				defv4 = &boot.Route{
					Destination: net.IPNet{
						IP:   net.IPv4zero,
						Mask: net.IPMask(net.IPv4zero),
					},
					Gateway: r.Gw,
				}
			case header.IPv6AddressSize:
				if defv6 != nil {
					return nil, nil, nil, fmt.Errorf("more than one default route found %q, def: %+v, route: %+v", iface.Name, defv6, r)
				}

				defv6 = &boot.Route{
					Destination: net.IPNet{
						IP:   net.IPv6zero,
						Mask: net.IPMask(net.IPv6zero),
					},
					Gateway: r.Gw,
				}
			default:
				return nil, nil, nil, fmt.Errorf("unexpected address size for gateway: %+v for route: %+v", r.Gw, r)
			}
			continue
		}

		dst := *r.Dst
		dst.IP = dst.IP.Mask(dst.Mask)
		routes = append(routes, boot.Route{
			Destination: dst,
			Gateway:     r.Gw,
		})
	}
	return routes, defv4, defv6, nil
}

// removeAddress removes IP address from network device. It's equivalent to:
//
//	ip addr del <ipAndMask> dev <name>
func removeAddress(source netlink.Link, ipAndMask string) error {
	addr, err := netlink.ParseAddr(ipAndMask)
	if err != nil {
		return err
	}
	return netlink.AddrDel(source, addr)
}
