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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
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
//  docker run -di --runtime=runsc -p 8080:80 -v $PWD:/usr/local/apache2/htdocs/ httpd:2.4
func setupNetwork(conn *urpc.Client, pid int, spec *specs.Spec, conf *boot.Config) error {
	log.Infof("Setting up network")

	switch conf.Network {
	case boot.NetworkNone:
		log.Infof("Network is disabled, create loopback interface only")
		if err := createDefaultLoopbackInterface(conn); err != nil {
			return fmt.Errorf("creating default loopback interface: %v", err)
		}
	case boot.NetworkSandbox:
		// Build the path to the net namespace of the sandbox process.
		// This is what we will copy.
		nsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns/net")
		if err := createInterfacesAndRoutesFromNS(conn, nsPath, conf.GSO, conf.NumNetworkChannels); err != nil {
			return fmt.Errorf("creating interfaces from net namespace %q: %v", nsPath, err)
		}
	case boot.NetworkHost:
		// Nothing to do here.
	default:
		return fmt.Errorf("invalid network type: %d", conf.Network)
	}
	return nil
}

func createDefaultLoopbackInterface(conn *urpc.Client) error {
	link := boot.LoopbackLink{
		Name: "lo",
		Addresses: []net.IP{
			net.IP("\x7f\x00\x00\x01"),
			net.IPv6loopback,
		},
		Routes: []boot.Route{
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
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &boot.CreateLinksAndRoutesArgs{
		LoopbackLinks: []boot.LoopbackLink{link},
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
	err := syscall.Access("/proc/sys/net/core/rmem_default", syscall.F_OK)
	switch err {
	case nil:
		return true, nil
	case syscall.ENOENT:
		return false, nil
	default:
		return false, fmt.Errorf("failed to access /proc/sys/net/core/rmem_default: %v", err)
	}
}

// createInterfacesAndRoutesFromNS scrapes the interface and routes from the
// net namespace with the given path, creates them in the sandbox, and removes
// them from the host.
func createInterfacesAndRoutesFromNS(conn *urpc.Client, nsPath string, enableGSO bool, numNetworkChannels int) error {
	// Join the network namespace that we will be copying.
	restore, err := joinNetNS(nsPath)
	if err != nil {
		return err
	}
	defer restore()

	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("querying interfaces: %v", err)
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
			return fmt.Errorf("fetching interface addresses for %q: %v", iface.Name, err)
		}

		// We build our own loopback devices.
		if iface.Flags&net.FlagLoopback != 0 {
			links, err := loopbackLinks(iface, allAddrs)
			if err != nil {
				return fmt.Errorf("getting loopback routes and links for iface %q: %v", iface.Name, err)
			}
			args.LoopbackLinks = append(args.LoopbackLinks, links...)
			continue
		}

		// Keep only IPv4 addresses.
		var ip4addrs []*net.IPNet
		for _, ifaddr := range allAddrs {
			ipNet, ok := ifaddr.(*net.IPNet)
			if !ok {
				return fmt.Errorf("address is not IPNet: %+v", ifaddr)
			}
			if ipNet.IP.To4() == nil {
				log.Warningf("IPv6 is not supported, skipping: %v", ipNet)
				continue
			}
			ip4addrs = append(ip4addrs, ipNet)
		}
		if len(ip4addrs) == 0 {
			log.Warningf("No IPv4 address found for interface %q, skipping", iface.Name)
			continue
		}

		// Scrape the routes before removing the address, since that
		// will remove the routes as well.
		routes, def, err := routesForIface(iface)
		if err != nil {
			return fmt.Errorf("getting routes for interface %q: %v", iface.Name, err)
		}
		if def != nil {
			if !args.DefaultGateway.Route.Empty() {
				return fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, def, args.DefaultGateway)
			}
			args.DefaultGateway.Route = *def
			args.DefaultGateway.Name = iface.Name
		}

		link := boot.FDBasedLink{
			Name:        iface.Name,
			MTU:         iface.MTU,
			Routes:      routes,
			NumChannels: numNetworkChannels,
		}

		// Get the link for the interface.
		ifaceLink, err := netlink.LinkByName(iface.Name)
		if err != nil {
			return fmt.Errorf("getting link for interface %q: %v", iface.Name, err)
		}
		link.LinkAddress = ifaceLink.Attrs().HardwareAddr

		log.Debugf("Setting up network channels")
		// Create the socket for the device.
		for i := 0; i < link.NumChannels; i++ {
			log.Debugf("Creating Channel %d", i)
			socketEntry, err := createSocket(iface, ifaceLink, enableGSO)
			if err != nil {
				return fmt.Errorf("failed to createSocket for %s : %v", iface.Name, err)
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

		// Collect the addresses for the interface, enable forwarding,
		// and remove them from the host.
		for _, addr := range ip4addrs {
			link.Addresses = append(link.Addresses, addr.IP)

			// Steal IP address from NIC.
			if err := removeAddress(ifaceLink, addr.String()); err != nil {
				return fmt.Errorf("removing address %v from device %q: %v", iface.Name, addr, err)
			}
		}

		args.FDBasedLinks = append(args.FDBasedLinks, link)
	}

	log.Debugf("Setting up network, config: %+v", args)
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &args, nil); err != nil {
		return fmt.Errorf("creating links and routes: %v", err)
	}
	return nil
}

type socketEntry struct {
	deviceFile *os.File
	gsoMaxSize uint32
}

// createSocket creates an underlying AF_PACKET socket and configures it for use by
// the sentry and returns an *os.File that wraps the underlying socket fd.
func createSocket(iface net.Interface, ifaceLink netlink.Link, enableGSO bool) (*socketEntry, error) {
	// Create the socket.
	const protocol = 0x0300 // htons(ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("unable to create raw socket: %v", err)
	}
	deviceFile := os.NewFile(uintptr(fd), "raw-device-fd")
	// Bind to the appropriate device.
	ll := syscall.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  iface.Index,
		Hatype:   0, // No ARP type.
		Pkttype:  syscall.PACKET_OTHERHOST,
	}
	if err := syscall.Bind(fd, &ll); err != nil {
		return nil, fmt.Errorf("unable to bind to %q: %v", iface.Name, err)
	}

	gsoMaxSize := uint32(0)
	if enableGSO {
		gso, err := isGSOEnabled(fd, iface.Name)
		if err != nil {
			return nil, fmt.Errorf("getting GSO for interface %q: %v", iface.Name, err)
		}
		if gso {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
				return nil, fmt.Errorf("unable to enable the PACKET_VNET_HDR option: %v", err)
			}
			gsoMaxSize = ifaceLink.Attrs().GSOMaxSize
		} else {
			log.Infof("GSO not available in host.")
		}
	}

	// Use SO_RCVBUFFORCE because on linux the receive buffer for an
	// AF_PACKET socket is capped by "net.core.rmem_max". rmem_max
	// defaults to a unusually low value of 208KB. This is too low
	// for gVisor to be able to receive packets at high throughputs
	// without incurring packet drops.
	const rcvBufSize = 4 << 20 // 4MB.

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, rcvBufSize); err != nil {
		return nil, fmt.Errorf("failed to increase socket rcv buffer to %d: %v", rcvBufSize, err)
	}
	return &socketEntry{deviceFile, gsoMaxSize}, nil
}

// loopbackLinks collects the links for a loopback interface.
func loopbackLinks(iface net.Interface, addrs []net.Addr) ([]boot.LoopbackLink, error) {
	var links []boot.LoopbackLink
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("address is not IPNet: %+v", addr)
		}
		dst := *ipNet
		dst.IP = dst.IP.Mask(dst.Mask)
		links = append(links, boot.LoopbackLink{
			Name:      iface.Name,
			Addresses: []net.IP{ipNet.IP},
			Routes: []boot.Route{{
				Destination: dst,
			}},
		})
	}
	return links, nil
}

// routesForIface iterates over all routes for the given interface and converts
// them to boot.Routes.
func routesForIface(iface net.Interface) ([]boot.Route, *boot.Route, error) {
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, nil, err
	}
	rs, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, fmt.Errorf("getting routes from %q: %v", iface.Name, err)
	}

	var def *boot.Route
	var routes []boot.Route
	for _, r := range rs {
		// Is it a default route?
		if r.Dst == nil {
			if r.Gw == nil {
				return nil, nil, fmt.Errorf("default route with no gateway %q: %+v", iface.Name, r)
			}
			if r.Gw.To4() == nil {
				log.Warningf("IPv6 is not supported, skipping default route: %v", r)
				continue
			}
			if def != nil {
				return nil, nil, fmt.Errorf("more than one default route found %q, def: %+v, route: %+v", iface.Name, def, r)
			}
			// Create a catch all route to the gateway.
			def = &boot.Route{
				Destination: net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.IPMask(net.IPv4zero),
				},
				Gateway: r.Gw,
			}
			continue
		}
		if r.Dst.IP.To4() == nil {
			log.Warningf("IPv6 is not supported, skipping route: %v", r)
			continue
		}
		dst := *r.Dst
		dst.IP = dst.IP.Mask(dst.Mask)
		routes = append(routes, boot.Route{
			Destination: dst,
			Gateway:     r.Gw,
		})
	}
	return routes, def, nil
}

// removeAddress removes IP address from network device. It's equivalent to:
//   ip addr del <ipAndMask> dev <name>
func removeAddress(source netlink.Link, ipAndMask string) error {
	addr, err := netlink.ParseAddr(ipAndMask)
	if err != nil {
		return err
	}
	return netlink.AddrDel(source, addr)
}
