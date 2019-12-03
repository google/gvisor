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

// Binary tcp_proxy is a simple TCP proxy.
package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	port    = flag.Int("port", 0, "bind port (all addresses)")
	forward = flag.String("forward", "", "forwarding target")
	client  = flag.Bool("client", false, "use netstack for listen")
	server  = flag.Bool("server", false, "use netstack for dial")

	// Netstack-specific options.
	mtu                = flag.Int("mtu", 1280, "mtu for network stack")
	addr               = flag.String("addr", "", "address for tap-based netstack")
	mask               = flag.Int("mask", 8, "mask size for address")
	iface              = flag.String("iface", "", "network interface name to bind for netstack")
	sack               = flag.Bool("sack", false, "enable SACK support for netstack")
	cubic              = flag.Bool("cubic", false, "enable use of CUBIC congestion control for netstack")
	gso                = flag.Int("gso", 0, "GSO maximum size")
	swgso              = flag.Bool("swgso", false, "software-level GSO")
	clientTCPProbeFile = flag.String("client_tcp_probe_file", "", "if specified, installs a tcp probe to dump endpoint state to the specified file.")
	serverTCPProbeFile = flag.String("server_tcp_probe_file", "", "if specified, installs a tcp probe to dump endpoint state to the specified file.")
	cpuprofile         = flag.String("cpuprofile", "", "write cpu profile to the specified file.")
	memprofile         = flag.String("memprofile", "", "write memory profile to the specified file.")
)

type impl interface {
	dial(address string) (net.Conn, error)
	listen(port int) (net.Listener, error)
	printStats()
}

type netImpl struct{}

func (netImpl) dial(address string) (net.Conn, error) {
	return net.Dial("tcp", address)
}

func (netImpl) listen(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

func (netImpl) printStats() {
}

const (
	nicID      = 1       // Fixed.
	rcvBufSize = 1 << 20 // 1MB.
)

type netstackImpl struct {
	s    *stack.Stack
	addr tcpip.Address
	mode string
}

func setupNetwork(ifaceName string) (fd int, err error) {
	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return -1, fmt.Errorf("querying interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name != ifaceName {
			continue
		}
		// Create the socket.
		const protocol = 0x0300 // htons(ETH_P_ALL)
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, protocol)
		if err != nil {
			return -1, fmt.Errorf("unable to create raw socket: %v", err)
		}

		// Bind to the appropriate device.
		ll := syscall.SockaddrLinklayer{
			Protocol: protocol,
			Ifindex:  iface.Index,
			Pkttype:  syscall.PACKET_HOST,
		}
		if err := syscall.Bind(fd, &ll); err != nil {
			return -1, fmt.Errorf("unable to bind to %q: %v", iface.Name, err)
		}

		// RAW Sockets by default have a very small SO_RCVBUF of 256KB,
		// up it to at least 1MB to reduce packet drops.
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBufSize); err != nil {
			return -1, fmt.Errorf("setsockopt(..., SO_RCVBUF, %v,..) = %v", rcvBufSize, err)
		}

		if !*swgso && *gso != 0 {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
				return -1, fmt.Errorf("unable to enable the PACKET_VNET_HDR option: %v", err)
			}
		}
		return fd, nil
	}
	return -1, fmt.Errorf("failed to find interface: %v", ifaceName)
}

func newNetstackImpl(mode string) (impl, error) {
	fd, err := setupNetwork(*iface)
	if err != nil {
		return nil, err
	}

	// Parse details.
	parsedAddr := tcpip.Address(net.ParseIP(*addr).To4())
	parsedDest := tcpip.Address("")     // Filled in below.
	parsedMask := tcpip.AddressMask("") // Filled in below.
	switch *mask {
	case 8:
		parsedDest = tcpip.Address([]byte{parsedAddr[0], 0, 0, 0})
		parsedMask = tcpip.AddressMask([]byte{0xff, 0, 0, 0})
	case 16:
		parsedDest = tcpip.Address([]byte{parsedAddr[0], parsedAddr[1], 0, 0})
		parsedMask = tcpip.AddressMask([]byte{0xff, 0xff, 0, 0})
	case 24:
		parsedDest = tcpip.Address([]byte{parsedAddr[0], parsedAddr[1], parsedAddr[2], 0})
		parsedMask = tcpip.AddressMask([]byte{0xff, 0xff, 0xff, 0})
	default:
		// This is just laziness; we don't expect a different mask.
		return nil, fmt.Errorf("mask %d not supported", mask)
	}

	// Create a new network stack.
	netProtos := []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()}
	transProtos := []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()}
	s := stack.New(stack.Options{
		NetworkProtocols:   netProtos,
		TransportProtocols: transProtos,
	})

	// Generate a new mac for the eth device.
	mac := make(net.HardwareAddr, 6)
	rand.Read(mac) // Fill with random data.
	mac[0] &^= 0x1 // Clear multicast bit.
	mac[0] |= 0x2  // Set local assignment bit (IEEE802).
	ep, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            uint32(*mtu),
		EthernetHeader: true,
		Address:        tcpip.LinkAddress(mac),
		// Enable checksum generation as we need to generate valid
		// checksums for the veth device to deliver our packets to the
		// peer. But we do want to disable checksum verification as veth
		// devices do perform GRO and the linux host kernel may not
		// regenerate valid checksums after GRO.
		TXChecksumOffload:  false,
		RXChecksumOffload:  true,
		PacketDispatchMode: fdbased.RecvMMsg,
		GSOMaxSize:         uint32(*gso),
		SoftwareGSOEnabled: *swgso,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create FD endpoint: %v", err)
	}
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("error creating NIC %q: %v", *iface, err)
	}
	if err := s.AddAddress(nicID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		return nil, fmt.Errorf("error adding ARP address to %q: %v", *iface, err)
	}
	if err := s.AddAddress(nicID, ipv4.ProtocolNumber, parsedAddr); err != nil {
		return nil, fmt.Errorf("error adding IP address to %q: %v", *iface, err)
	}

	subnet, err := tcpip.NewSubnet(parsedDest, parsedMask)
	if err != nil {
		return nil, fmt.Errorf("tcpip.Subnet(%s, %s): %s", parsedDest, parsedMask, err)
	}
	// Add default route; we only support
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	// Set protocol options.
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(*sack)); err != nil {
		return nil, fmt.Errorf("SetTransportProtocolOption for SACKEnabled failed: %v", err)
	}

	// Set Congestion Control to cubic if requested.
	if *cubic {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, tcpip.CongestionControlOption("cubic")); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption for CongestionControlOption(cubic) failed: %v", err)
		}
	}

	return netstackImpl{
		s:    s,
		addr: parsedAddr,
		mode: mode,
	}, nil
}

func (n netstackImpl) dial(address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		// A host must be provided for the dial.
		return nil, fmt.Errorf("no host provided")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(net.ParseIP(host).To4()),
		Port: uint16(portNumber),
	}
	conn, err := gonet.DialTCP(n.s, addr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (n netstackImpl) listen(port int) (net.Listener, error) {
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Port: uint16(port),
	}
	listener, err := gonet.NewListener(n.s, addr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

var zeroFieldsRegexp = regexp.MustCompile(`\s*[a-zA-Z0-9]*:0`)

func (n netstackImpl) printStats() {
	// Don't show zero fields.
	stats := zeroFieldsRegexp.ReplaceAllString(fmt.Sprintf("%+v", n.s.Stats()), "")
	log.Printf("netstack %s Stats: %+v\n", n.mode, stats)
}

// installProbe installs a TCP Probe function that will dump endpoint
// state to the specified file. It also returns a close func() that
// can be used to close the probeFile.
func (n netstackImpl) installProbe(probeFileName string) (close func()) {
	// Install Probe to dump out end point state.
	probeFile, err := os.Create(probeFileName)
	if err != nil {
		log.Fatalf("failed to create tcp_probe file %s: %v", probeFileName, err)
	}
	probeEncoder := gob.NewEncoder(probeFile)
	// Install a TCP Probe.
	n.s.AddTCPProbe(func(state stack.TCPEndpointState) {
		probeEncoder.Encode(state)
	})
	return func() { probeFile.Close() }
}

func main() {
	flag.Parse()
	if *port == 0 {
		log.Fatalf("no port provided")
	}
	if *forward == "" {
		log.Fatalf("no forward provided")
	}
	// Seed the random number generator to ensure that we are given MAC addresses that don't
	// for the case of the client and server stack.
	rand.Seed(time.Now().UTC().UnixNano())

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Print("error closing CPU profile: ", err)
			}
		}()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	var (
		in  impl
		out impl
		err error
	)
	if *server {
		in, err = newNetstackImpl("server")
		if *serverTCPProbeFile != "" {
			defer in.(netstackImpl).installProbe(*serverTCPProbeFile)()
		}

	} else {
		in = netImpl{}
	}
	if err != nil {
		log.Fatalf("netstack error: %v", err)
	}
	if *client {
		out, err = newNetstackImpl("client")
		if *clientTCPProbeFile != "" {
			defer out.(netstackImpl).installProbe(*clientTCPProbeFile)()
		}
	} else {
		out = netImpl{}
	}
	if err != nil {
		log.Fatalf("netstack error: %v", err)
	}

	// Dial forward before binding.
	var next net.Conn
	for {
		next, err = out.dial(*forward)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
		log.Printf("connect failed retrying: %v", err)
	}

	// Bind once to the server socket.
	listener, err := in.listen(*port)
	if err != nil {
		// Should not happen, everything must be bound by this time
		// this proxy is started.
		log.Fatalf("unable to listen: %v", err)
	}
	log.Printf("client=%v, server=%v, ready.", *client, *server)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		<-sigs
		if *cpuprofile != "" {
			pprof.StopCPUProfile()
		}
		if *memprofile != "" {
			f, err := os.Create(*memprofile)
			if err != nil {
				log.Fatal("could not create memory profile: ", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Print("error closing memory profile: ", err)
				}
			}()
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatalf("Unable to write heap profile: %v", err)
			}
		}
		os.Exit(0)
	}()

	for {
		// Forward all connections.
		inConn, err := listener.Accept()
		if err != nil {
			// This should not happen; we are listening
			// successfully. Exhausted all available FDs?
			log.Fatalf("accept error: %v", err)
		}
		log.Printf("incoming connection established.")

		// Copy both ways.
		go io.Copy(inConn, next)
		go io.Copy(next, inConn)

		// Print stats every second.
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				<-t.C
				in.printStats()
				out.printStats()
			}
		}()

		for {
			// Dial again.
			next, err = out.dial(*forward)
			if err == nil {
				break
			}
		}
	}
}
