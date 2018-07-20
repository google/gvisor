// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
	"gvisor.googlesource.com/gvisor/runsc/boot"
)

const (
	// Annotations used to indicate whether the container corresponds to a
	// pod or a container within a pod.
	crioContainerTypeAnnotation       = "io.kubernetes.cri-o.ContainerType"
	containerdContainerTypeAnnotation = "io.kubernetes.cri.container-type"
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

	// HACK!
	//
	// When kubernetes starts a pod, it first creates a sandbox with an
	// application that just pauses forever.  Later, when a container is
	// added to the pod, kubernetes will create another sandbox with a
	// config that corresponds to the containerized application, and add it
	// to the same namespaces as the pause sandbox.
	//
	// Running a second sandbox currently breaks because the two sandboxes
	// have the same network namespace and configuration, and try to create
	// a tap device on the same host device which fails.
	//
	// Runsc will eventually need to detect that this container is meant to
	// be run in the same sandbox as the pausing application, and somehow
	// make that happen.
	//
	// For now the following HACK disables networking for the "pause"
	// sandbox, allowing the second sandbox to start up successfully.
	//
	// TODO: Remove this once multiple containers per sandbox
	// is properly supported.
	if spec.Annotations[crioContainerTypeAnnotation] == "sandbox" ||
		spec.Annotations[containerdContainerTypeAnnotation] == "sandbox" {
		log.Warningf("HACK: Disabling network")
		conf.Network = boot.NetworkNone
	}

	switch conf.Network {
	case boot.NetworkNone:
		log.Infof("Network is disabled, create loopback interface only")
		if err := createDefaultLoopbackInterface(conn); err != nil {
			return fmt.Errorf("error creating default loopback interface: %v", err)
		}
	case boot.NetworkSandbox:
		// Build the path to the net namespace of the sandbox process.
		// This is what we will copy.
		nsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns/net")
		if err := createInterfacesAndRoutesFromNS(conn, nsPath); err != nil {
			return fmt.Errorf("error creating interfaces from net namespace %q: %v", nsPath, err)
		}
	case boot.NetworkHost:
		// Nothing to do here.
	default:
		return fmt.Errorf("Invalid network type: %d", conf.Network)
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
				Destination: net.IP("\x7f\x00\x00\x00"),
				Mask:        net.IPMask("\xff\x00\x00\x00"),
			},
			{
				Destination: net.IPv6loopback,
				Mask:        net.IPMask(strings.Repeat("\xff", 16)),
			},
		},
	}
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &boot.CreateLinksAndRoutesArgs{
		LoopbackLinks: []boot.LoopbackLink{link},
	}, nil); err != nil {
		return fmt.Errorf("error creating loopback link and routes: %v", err)
	}
	return nil
}

func joinNetNS(nsPath string) (func(), error) {
	runtime.LockOSThread()
	restoreNS, err := applyNS(specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: nsPath,
	})
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("error joining net namespace %q: %v", nsPath, err)
	}
	return func() {
		restoreNS()
		runtime.UnlockOSThread()
	}, nil
}

// isRootNS determines whether we are running in the root net namespace.
//
// TODO: Find a better way to detect root network.
func isRootNS(ifaces []net.Interface) bool {
	for _, iface := range ifaces {
		if iface.Name == "docker0" {
			return true
		}
	}
	return false

}

// createInterfacesAndRoutesFromNS scrapes the interface and routes from the
// net namespace with the given path, creates them in the sandbox, and removes
// them from the host.
func createInterfacesAndRoutesFromNS(conn *urpc.Client, nsPath string) error {
	// Join the network namespace that we will be copying.
	restore, err := joinNetNS(nsPath)
	if err != nil {
		return err
	}
	defer restore()

	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("error querying interfaces: %v", err)
	}

	if isRootNS(ifaces) {
		return fmt.Errorf("cannot run in with network enabled in root network namespace")
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
			return fmt.Errorf("error fetching interface addresses for %q: %v", iface.Name, err)
		}

		// We build our own loopback devices.
		if iface.Flags&net.FlagLoopback != 0 {
			links, err := loopbackLinks(iface, allAddrs)
			if err != nil {
				return fmt.Errorf("error getting loopback routes and links for iface %q: %v", iface.Name, err)
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

		// Get the link for the interface.
		ifaceLink, err := netlink.LinkByName(iface.Name)
		if err != nil {
			return fmt.Errorf("error getting link for interface %q: %v", iface.Name, err)
		}

		// Create the socket.
		const protocol = 0x0300 // htons(ETH_P_ALL)
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, protocol)
		if err != nil {
			return fmt.Errorf("unable to create raw socket: %v", err)
		}
		deviceFile := os.NewFile(uintptr(fd), "raw-device-fd")

		// Bind to the appropriate device.
		ll := syscall.SockaddrLinklayer{
			Protocol: protocol,
			Ifindex:  ifaceLink.Attrs().Index,
			Hatype:   0, // No ARP type.
			Pkttype:  syscall.PACKET_OTHERHOST,
		}
		if err := syscall.Bind(fd, &ll); err != nil {
			return fmt.Errorf("unable to bind to %q: %v", iface.Name, err)
		}

		// Scrape the routes before removing the address, since that
		// will remove the routes as well.
		routes, def, err := routesForIface(iface)
		if err != nil {
			return fmt.Errorf("error getting routes for interface %q: %v", iface.Name, err)
		}
		if def != nil {
			if !args.DefaultGateway.Route.Empty() {
				return fmt.Errorf("more than one default route found, interface: %v, route: %v, default route: %+v", iface.Name, def, args.DefaultGateway)
			}
			args.DefaultGateway.Route = *def
			args.DefaultGateway.Name = iface.Name
		}

		link := boot.FDBasedLink{
			Name:   iface.Name,
			MTU:    iface.MTU,
			Routes: routes,
		}

		// Collect the addresses for the interface, enable forwarding,
		// and remove them from the host.
		for _, addr := range ip4addrs {
			link.Addresses = append(link.Addresses, addr.IP)

			// Steal IP address from NIC.
			if err := removeAddress(ifaceLink, addr.String()); err != nil {
				return fmt.Errorf("error removing address %v from device %q: %v", iface.Name, addr, err)
			}
		}

		args.FilePayload.Files = append(args.FilePayload.Files, deviceFile)
		args.FDBasedLinks = append(args.FDBasedLinks, link)
	}

	log.Debugf("Setting up network, config: %+v", args)
	if err := conn.Call(boot.NetworkCreateLinksAndRoutes, &args, nil); err != nil {
		return fmt.Errorf("error creating links and routes: %v", err)
	}
	return nil
}

// loopbackLinks collects the links for a loopback interface.
func loopbackLinks(iface net.Interface, addrs []net.Addr) ([]boot.LoopbackLink, error) {
	var links []boot.LoopbackLink
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("address is not IPNet: %+v", addr)
		}
		links = append(links, boot.LoopbackLink{
			Name:      iface.Name,
			Addresses: []net.IP{ipNet.IP},
			Routes: []boot.Route{{
				Destination: ipNet.IP.Mask(ipNet.Mask),
				Mask:        ipNet.Mask,
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
		return nil, nil, fmt.Errorf("error getting routes from %q: %v", iface.Name, err)
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
				Destination: net.IPv4zero,
				Mask:        net.IPMask(net.IPv4zero),
				Gateway:     r.Gw,
			}
			continue
		}
		if r.Dst.IP.To4() == nil {
			log.Warningf("IPv6 is not supported, skipping route: %v", r)
			continue
		}
		routes = append(routes, boot.Route{
			Destination: r.Dst.IP.Mask(r.Dst.Mask),
			Mask:        r.Dst.Mask,
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
