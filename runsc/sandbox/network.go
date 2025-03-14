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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
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

	if conf.Network == config.NetworkHost {
		// Nothing to do here.
		return nil
	}

	netConf, err := getNetworkConfig(conn, pid, conf)
	if err != nil {
		return fmt.Errorf("getNetworkConfig failed with error: %v", err)
	}

	if err := conn.Call(boot.NetworkSetupNetwork, netConf, nil); err != nil {
		return fmt.Errorf("SetupNetwork failed with error: %v", err)
	}
	return nil
}

func checkAndConfigureXDP(conn *urpc.Client, pid int, conf *config.Config) (bool, error) {
	nsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns/net")
	switch conf.XDP.Mode {
	case config.XDPModeOff:
	case config.XDPModeNS:
	case config.XDPModeRedirect:
		if err := createRedirectInterfacesAndRoutes(conn, conf); err != nil {
			return true, fmt.Errorf("failed to create XDP redirect interface: %w", err)
		}
		return true, nil
	case config.XDPModeTunnel:
		if err := createXDPTunnel(conn, nsPath, conf); err != nil {
			return true, fmt.Errorf("failed to create XDP tunnel: %w", err)
		}
		return true, nil
	default:
		return true, fmt.Errorf("unknown XDP mode: %v", conf.XDP.Mode)
	}
	return false, nil
}

func getNetworkConfig(conn *urpc.Client, pid int, conf *config.Config) (*boot.NetworkConfig, error) {
	switch conf.Network {
	case config.NetworkNone:
		return getLoopbackNetworkConfig(conf)
	case config.NetworkPlugin:
		return getPluginNetworkConfig(pid, conf)
	case config.NetworkSandbox:
		isXDP, err := checkAndConfigureXDP(conn, pid, conf)
		if err != nil {
			return nil, fmt.Errorf("setup XDP network failed with error: %v", err)
		}
		if isXDP {
			return nil, nil
		}
		return getSandboxNetworkConfig(pid, conf)
	case config.NetworkHost:
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid network type: %v", conf.Network)
	}
}

func getLoopbackNetworkConfig(conf *config.Config) (*boot.NetworkConfig, error) {
	link := boot.DefaultLoopbackLink
	link.GVisorGRO = conf.GVisorGRO
	args := &boot.CreateLinksAndRoutesArgs{
		LoopbackLinks: []boot.LoopbackLink{link},
		DisconnectOk:  conf.NetDisconnectOk,
	}
	netConf := &boot.NetworkConfig{
		Args:    args,
		Network: config.NetworkNone,
	}
	return netConf, nil
}

func getPluginNetworkConfig(pid int, conf *config.Config) (*boot.NetworkConfig, error) {
	pluginStack := plugin.GetPluginStack()
	if pluginStack == nil {
		return nil, fmt.Errorf("plugin stack is not registered")
	}

	initStr, fds, err := pluginStack.PreInit(&plugin.PreInitStackArgs{Pid: pid})
	if err != nil {
		return nil, fmt.Errorf("plugin stack PreInit failed: %v", err)
	}
	args := &boot.InitPluginStackArgs{
		InitStr: initStr,
	}
	for _, fd := range fds {
		args.FilePayload.Files = append(args.FilePayload.Files, os.NewFile(uintptr(fd), ""))
	}

	log.Debugf("Initializing plugin network stack, config: %+v", args)
	netConf := &boot.NetworkConfig{
		InitArgs: args,
		Network:  config.NetworkPlugin,
	}
	return netConf, nil
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

// isRootNetNS determines whether we are running in the root net namespace.
// /proc/sys/net/core/dev_weight only exists in root network namespace.
func isRootNetNS() (bool, error) {
	err := unix.Access("/proc/sys/net/core/dev_weight", unix.F_OK)
	switch err {
	case nil:
		return true, nil
	case unix.ENOENT:
		return false, nil
	default:
		return false, fmt.Errorf("failed to access /proc/sys/net/core/dev_weight: %v", err)
	}
}

func getSandboxNetworkConfig(pid int, conf *config.Config) (*boot.NetworkConfig, error) {
	nsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns/net")
	args, err := createInterfacesAndRoutesFromNS(nsPath, conf)
	if err != nil {
		return nil, err
	}
	netConf := &boot.NetworkConfig{
		Args:    args,
		Network: config.NetworkSandbox,
	}
	return netConf, nil
}

// createInterfacesAndRoutesFromNS scrapes the interface and routes from the
// net namespace with the given path, creates them in the sandbox, and removes
// them from the host.
func createInterfacesAndRoutesFromNS(nsPath string, conf *config.Config) (*boot.CreateLinksAndRoutesArgs, error) {
	// Join the network namespace that we will be copying.
	restore, err := joinNetNS(nsPath)
	if err != nil {
		return nil, err
	}
	defer restore()

	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("querying interfaces: %w", err)
	}

	isRoot, err := isRootNetNS()
	if err != nil {
		return nil, err
	}
	if isRoot {
		return nil, fmt.Errorf("cannot run with network enabled in root network namespace")
	}

	// Collect addresses and routes from the interfaces.
	args := &boot.CreateLinksAndRoutesArgs{
		DisconnectOk: conf.NetDisconnectOk,
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			log.Infof("Skipping down interface: %+v", iface)
			continue
		}

		allAddrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("fetching interface addresses for %q: %w", iface.Name, err)
		}

		// We build our own loopback device.
		if iface.Flags&net.FlagLoopback != 0 {
			link, err := loopbackLink(conf, iface, allAddrs)
			if err != nil {
				return nil, fmt.Errorf("getting loopback link for iface %q: %w", iface.Name, err)
			}
			args.LoopbackLinks = append(args.LoopbackLinks, link)
			continue
		}

		var ipAddrs []*net.IPNet
		for _, ifaddr := range allAddrs {
			ipNet, ok := ifaddr.(*net.IPNet)
			if !ok {
				return nil, fmt.Errorf("address is not IPNet: %+v", ifaddr)
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
			return nil, fmt.Errorf("fetching ARP table for %q: %w", iface.Name, err)
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
			return nil, fmt.Errorf("getting routes for interface %q: %v", iface.Name, err)
		}
		if defv4 != nil {
			if !args.Defaultv4Gateway.Route.Empty() {
				return nil, fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, defv4, args.Defaultv4Gateway)
			}
			args.Defaultv4Gateway.Route = *defv4
			args.Defaultv4Gateway.Name = iface.Name
		}

		if defv6 != nil {
			if !args.Defaultv6Gateway.Route.Empty() {
				return nil, fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, defv6, args.Defaultv6Gateway)
			}
			args.Defaultv6Gateway.Route = *defv6
			args.Defaultv6Gateway.Name = iface.Name
		}

		// Get the link for the interface.
		ifaceLink, err := netlink.LinkByName(iface.Name)
		if err != nil {
			return nil, fmt.Errorf("getting link for interface %q: %w", iface.Name, err)
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
					return nil, fmt.Errorf("checking if address %v is on interface %q: %w", addr, iface.Name, err)
				} else if !present {
					continue
				}
				return nil, fmt.Errorf("removing address %v from device %q: %w", addr, iface.Name, err)
			}
		}

		if conf.XDP.Mode == config.XDPModeNS {
			xdpSockFDs, err := createSocketXDP(iface)
			if err != nil {
				return nil, fmt.Errorf("failed to create XDP socket: %v", err)
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
				GVisorGRO:         conf.GVisorGRO,
			})
		} else {
			link := boot.FDBasedLink{
				Name:                 iface.Name,
				MTU:                  iface.MTU,
				Routes:               routes,
				TXChecksumOffload:    conf.TXChecksumOffload,
				RXChecksumOffload:    conf.RXChecksumOffload,
				NumChannels:          conf.NumNetworkChannels,
				ProcessorsPerChannel: conf.NetworkProcessorsPerChannel,
				QDisc:                conf.QDisc,
				Neighbors:            neighbors,
				LinkAddress:          linkAddress,
				Addresses:            addresses,
			}

			log.Debugf("Setting up network channels")
			// Create the socket for the device.
			for i := 0; i < link.NumChannels; i++ {
				log.Debugf("Creating Channel %d", i)
				socketEntry, err := createSocket(iface, ifaceLink, conf.HostGSO)
				if err != nil {
					return nil, fmt.Errorf("failed to createSocket for %s : %w", iface.Name, err)
				}
				if i == 0 {
					link.GSOMaxSize = socketEntry.gsoMaxSize
				} else {
					if link.GSOMaxSize != socketEntry.gsoMaxSize {
						return nil, fmt.Errorf("inconsistent gsoMaxSize %d and %d when creating multiple channels for same interface: %s",
							link.GSOMaxSize, socketEntry.gsoMaxSize, iface.Name)
					}
				}
				args.FilePayload.Files = append(args.FilePayload.Files, socketEntry.deviceFile)
			}

			if link.GSOMaxSize == 0 && conf.GVisorGSO {
				// Host GSO is disabled. Let's enable gVisor GSO.
				link.GSOMaxSize = stack.GVisorGSOMaxSize
				link.GVisorGSOEnabled = true
			}
			link.GVisorGRO = conf.GVisorGRO

			args.FDBasedLinks = append(args.FDBasedLinks, link)
		}
	}

	if err := pcapAndNAT(args, conf); err != nil {
		return nil, err
	}

	log.Debugf("Setting up network, config: %+v", args)
	return args, nil
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
	const protocol = 0x0300                                  // htons(ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0) // pass protocol 0 to avoid slow bind()
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

// loopbackLink returns the link with addresses and routes for a loopback
// interface.
func loopbackLink(conf *config.Config, iface net.Interface, addrs []net.Addr) (boot.LoopbackLink, error) {
	link := boot.LoopbackLink{
		Name:      iface.Name,
		GVisorGRO: conf.GVisorGRO,
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

func pcapAndNAT(args *boot.CreateLinksAndRoutesArgs, conf *config.Config) error {
	// Possibly enable packet logging.
	args.LogPackets = conf.LogPackets

	// Pass PCAP log file if present.
	if conf.PCAP != "" {
		args.PCAP = true
		pcap, err := os.OpenFile(conf.PCAP, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return fmt.Errorf("failed to open PCAP file %s: %v", conf.PCAP, err)
		}
		args.FilePayload.Files = append(args.FilePayload.Files, pcap)
	}

	// Pass the host's NAT table if requested.
	if conf.ReproduceNftables || conf.ReproduceNAT {
		var f *os.File
		var err error
		if conf.ReproduceNftables {
			log.Infof("reproing nftables")
			f, err = checkNftables()
		} else if conf.ReproduceNAT {
			log.Infof("reproing legacy tables")
			f, err = writeNATBlob()
		}
		if err != nil {
			return fmt.Errorf("failed to write NAT blob: %v", err)
		}
		if f != nil {
			args.NATBlob = true
			args.FilePayload.Files = append(args.FilePayload.Files, f)
		}
	}

	return nil
}

// The below is a work around to generate iptables-legacy rules on machines
// that use iptables-nftables. The logic goes something like this:
//
//             start
//               |
//               v               no
//     are legacy tables empty? -----> scrape rules -----> done <----+
//               |                                          ^        |
//               | yes                                      |        |
//               v                        yes               |        |
//     are nft tables empty? -------------------------------+        |
//               |                                                   |
//               | no                                                |
//               v                                                   |
//     pipe iptables-nft-save -t nat to iptables-legacy-restore      |
//     scrape rules                                                  |
//     delete iptables-legacy rules                                  |
//               |                                                   |
//               +---------------------------------------------------+
//
// If we fail at some point (e.g. to find a binary), we just try to scrape the
// legacy rules.

const emptyNatRules = `-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
`

// checkNftables can return a nil file and error if it finds only
// emptyNatRules.
func checkNftables() (*os.File, error) {
	// Use iptables (not iptables-save) to test table emptiness because it
	// gives predictable results: no counters and no comments.

	// Is the legacy table empty?
	if out, err := exec.Command("iptables-legacy", "-t", "nat", "-S").Output(); err != nil || string(out) != emptyNatRules {
		return writeNATBlob()
	}

	// Is the nftables table empty?
	if out, err := exec.Command("iptables-nft", "-t", "nat", "-S").Output(); err != nil || string(out) == emptyNatRules {
		return nil, nil
	}

	// Get the current (empty) legacy rules.
	currLegacy, err := exec.Command("iptables-legacy-save", "-t", "nat").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to save existing rules with error (%v) and output: %s", err, currLegacy)
	}

	// Restore empty legacy rules.
	defer func() {
		cmd := exec.Command("iptables-legacy-restore")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Warningf("failed to get stdin pipe: %v", err)
			return
		}

		go func() {
			defer stdin.Close()
			stdin.Write(currLegacy)
		}()

		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warningf("failed to restore iptables error (%v) with output: %s", err, out)
		}
	}()

	// Pipe the output of iptables-nft-save to iptables-legacy-restore.
	nftOut, err := exec.Command("iptables-nft-save", "-t", "nat").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run iptables-nft-save: %v", err)
	}

	cmd := exec.Command("iptables-legacy-restore")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	go func() {
		defer stdin.Close()
		stdin.Write(nftOut)
	}()

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to restore iptables error (%v) with output: %s", err, out)
	}

	return writeNATBlob()
}
