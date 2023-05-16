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
	"runtime/trace"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
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
	rack               = flag.Bool("rack", false, "enable RACK in TCP")
	moderateRecvBuf    = flag.Bool("moderate_recv_buf", false, "enable TCP Receive Buffer Auto-tuning")
	cubic              = flag.Bool("cubic", false, "enable use of CUBIC congestion control for netstack")
	gso                = flag.Int("gso", 0, "GSO maximum size")
	swgso              = flag.Bool("swgso", false, "gVisor-level GSO")
	gro                = flag.Duration("gro", 0, "gVisor-level GRO timeout")
	clientTCPProbeFile = flag.String("client_tcp_probe_file", "", "if specified, installs a tcp probe to dump endpoint state to the specified file.")
	serverTCPProbeFile = flag.String("server_tcp_probe_file", "", "if specified, installs a tcp probe to dump endpoint state to the specified file.")
	cpuprofile         = flag.String("cpuprofile", "", "write cpu profile to the specified file.")
	memprofile         = flag.String("memprofile", "", "write memory profile to the specified file.")
	blockprofile       = flag.String("blockprofile", "", "write a goroutine blocking profile to the specified file.")
	mutexprofile       = flag.String("mutexprofile", "", "write a mutex profile to the specified file.")
	traceprofile       = flag.String("traceprofile", "", "write a 5s trace of the benchmark to the specified file.")
	useIpv6            = flag.Bool("ipv6", false, "use ipv6 instead of ipv4.")
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
	nicID   = 1       // Fixed.
	bufSize = 4 << 20 // 4MB.
)

type netstackImpl struct {
	s    *stack.Stack
	addr tcpip.Address
	mode string
}

func setupNetwork(ifaceName string, numChannels int) (fds []int, err error) {
	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("querying interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name != ifaceName {
			continue
		}
		// Create the socket.
		const protocol = 0x0300 // htons(ETH_P_ALL)
		fds := make([]int, numChannels)
		for i := range fds {
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protocol)
			if err != nil {
				return nil, fmt.Errorf("unable to create raw socket: %v", err)
			}

			// Bind to the appropriate device.
			ll := unix.SockaddrLinklayer{
				Protocol: protocol,
				Ifindex:  iface.Index,
				Pkttype:  unix.PACKET_HOST,
			}
			if err := unix.Bind(fd, &ll); err != nil {
				return nil, fmt.Errorf("unable to bind to %q: %v", iface.Name, err)
			}

			// RAW Sockets by default have a very small SO_RCVBUF of 256KB,
			// up it to at least 4MB to reduce packet drops.
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize); err != nil {
				return nil, fmt.Errorf("setsockopt(..., SO_RCVBUF, %v,..) = %v", bufSize, err)
			}

			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize); err != nil {
				return nil, fmt.Errorf("setsockopt(..., SO_SNDBUF, %v,..) = %v", bufSize, err)
			}

			if !*swgso && *gso != 0 {
				if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
					return nil, fmt.Errorf("unable to enable the PACKET_VNET_HDR option: %v", err)
				}
			}
			fds[i] = fd
		}
		return fds, nil
	}
	return nil, fmt.Errorf("failed to find interface: %v", ifaceName)
}

func newNetstackImpl(mode string) (impl, error) {
	fds, err := setupNetwork(*iface, runtime.GOMAXPROCS(-1))
	if err != nil {
		return nil, err
	}

	// Parse details.
	var parsedAddr tcpip.Address
	if *useIpv6 {
		parsedAddr = tcpip.AddrFrom16Slice(net.ParseIP(*addr).To16())
	} else {
		parsedAddr = tcpip.AddrFrom4Slice(net.ParseIP(*addr).To4())
	}
	parsedBytes := parsedAddr.AsSlice()
	var parsedDest tcpip.Address      // Filled in below.
	var parsedMask tcpip.AddressMask  // Filled in below.
	var parsedDest6 tcpip.Address     // Filled in below.
	var parsedMask6 tcpip.AddressMask // Filled in below.
	switch *mask {
	case 8:
		parsedDest = tcpip.AddrFrom4([4]byte{parsedBytes[0], 0, 0, 0})
		parsedMask = tcpip.MaskFromBytes([]byte{0xff, 0, 0, 0})
		parsedDest6 = tcpip.AddrFrom16Slice(append([]byte{parsedBytes[0]}, make([]byte, 15)...))
		parsedMask6 = tcpip.MaskFromBytes(append([]byte{0xff}, make([]byte, 15)...))
	case 16:
		parsedDest = tcpip.AddrFrom4([4]byte{parsedBytes[0], parsedBytes[1], 0, 0})
		parsedMask = tcpip.MaskFromBytes([]byte{0xff, 0xff, 0, 0})
		parsedDest6 = tcpip.AddrFrom16Slice(append([]byte{parsedBytes[0], parsedBytes[1]}, make([]byte, 14)...))
		parsedMask6 = tcpip.MaskFromBytes(append([]byte{0xff, 0xff}, make([]byte, 14)...))
	case 24:
		parsedDest = tcpip.AddrFrom4([4]byte{parsedBytes[0], parsedBytes[1], parsedBytes[2], 0})
		parsedMask = tcpip.MaskFromBytes([]byte{0xff, 0xff, 0xff, 0})
		parsedDest6 = tcpip.AddrFrom16Slice(append([]byte{parsedBytes[0], parsedBytes[1], parsedBytes[2]}, make([]byte, 13)...))
		parsedMask6 = tcpip.MaskFromBytes(append([]byte{0xff, 0xff, 0xff}, make([]byte, 13)...))
	default:
		// This is just laziness; we don't expect a different mask.
		return nil, fmt.Errorf("mask %d not supported", mask)
	}

	// Create a new network stack.
	netProtos := []stack.NetworkProtocolFactory{ipv6.NewProtocol, ipv4.NewProtocol, arp.NewProtocol}
	transProtos := []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}
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
		FDs:            fds,
		MTU:            uint32(*mtu),
		EthernetHeader: true,
		Address:        tcpip.LinkAddress(mac),
		// Enable checksum generation as we need to generate valid
		// checksums for the veth device to deliver our packets to the
		// peer. But we do want to disable checksum verification as veth
		// devices do perform GRO and the linux host kernel may not
		// regenerate valid checksums after GRO.
		TXChecksumOffload: false,
		RXChecksumOffload: true,
		//PacketDispatchMode: fdbased.RecvMMsg,
		PacketDispatchMode: fdbased.PacketMMap,
		GSOMaxSize:         uint32(*gso),
		GvisorGSOEnabled:   *swgso,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create FD endpoint: %v", err)
	}

	qDisc := fifo.New(ep, runtime.GOMAXPROCS(0), 1000)
	opts := stack.NICOptions{QDisc: qDisc, GROTimeout: *gro}
	if err := s.CreateNICWithOptions(nicID, ep, opts); err != nil {
		return nil, fmt.Errorf("error creating NIC %q: %v", *iface, err)
	}
	proto := ipv4.ProtocolNumber
	if *useIpv6 {
		proto = ipv6.ProtocolNumber
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: parsedAddr.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("error adding IP address %+v to %q: %s", protocolAddr, *iface, err)
	}

	subnet4, err := tcpip.NewSubnet(parsedDest, parsedMask)
	if err != nil {
		return nil, fmt.Errorf("tcpip.Subnet(%s, %s): %s", parsedDest, parsedMask, err)
	}
	subnet6, err := tcpip.NewSubnet(parsedDest6, parsedMask6)
	if err != nil {
		return nil, fmt.Errorf("tcpip.Subnet(%s, %s): %s", parsedDest, parsedMask, err)
	}

	// Add default route; we only support
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet4,
			NIC:         nicID,
		},
		{
			Destination: subnet6,
			NIC:         nicID,
		},
	})

	// Set protocol options.
	{
		opt := tcpip.TCPSACKEnabled(*sack)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}

	if *rack {
		opt := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("enabling RACK failed: %v", err)
		}
	}

	// Enable Receive Buffer Auto-Tuning.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(*moderateRecvBuf)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}

	// Set Congestion Control to cubic if requested.
	if *cubic {
		opt := tcpip.CongestionControlOption("cubic")
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, err)
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
		Addr: tcpip.AddrFromSlice(net.ParseIP(host)),
		Port: uint16(portNumber),
	}
	proto := ipv4.ProtocolNumber
	if *useIpv6 {
		proto = ipv6.ProtocolNumber
	}
	conn, err := gonet.DialTCP(n.s, addr, proto)
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
	proto := ipv4.ProtocolNumber
	if *useIpv6 {
		proto = ipv6.ProtocolNumber
	}
	listener, err := gonet.ListenTCP(n.s, addr, proto)
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
	n.s.AddTCPProbe(func(state *stack.TCPEndpointState) {
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

	if *traceprofile != "" {
		f, err := os.Create(*traceprofile)
		if err != nil {
			log.Fatal("could not create trace profile: ", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Print("error closing trace profile: ", err)
			}
		}()
		go func() {
			// Delay tracing to give workload sometime to start.
			time.Sleep(2 * time.Second)
			if err := trace.Start(f); err != nil {
				log.Fatal("could not start Go trace:", err)
			}
			defer trace.Stop()
			<-time.After(5 * time.Second)
		}()
	}

	if *mutexprofile != "" {
		runtime.SetMutexProfileFraction(100)
	}

	if *blockprofile != "" {
		runtime.SetBlockProfileRate(1000)
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
	signal.Notify(sigs, unix.SIGTERM)
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
		if *blockprofile != "" {
			f, err := os.Create(*blockprofile)
			if err != nil {
				log.Fatal("could not create block profile: ", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Print("error closing block profile: ", err)
				}
			}()
			if err := pprof.Lookup("block").WriteTo(f, 0); err != nil {
				log.Fatalf("Unable to write block profile: %v", err)
			}
		}
		if *mutexprofile != "" {
			f, err := os.Create(*mutexprofile)
			if err != nil {
				log.Fatal("could not create mutex profile: ", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Print("error closing mutex profile: ", err)
				}
			}()
			if err := pprof.Lookup("mutex").WriteTo(f, 0); err != nil {
				log.Fatalf("Unable to write mutex profile: %v", err)
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
