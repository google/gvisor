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

//go:build linux
// +build linux

// This sample creates a stack with TCP and IPv4 protocols on top of a TUN
// device, and connects to a peer. Similar to "nc <address> <port>". While the
// sample is running, attempts to connect to its IPv4 address will result in
// a RST segment.
//
// As an example of how to run it, a TUN device can be created and enabled on
// a linux host as follows (this only needs to be done once per boot):
//
// [sudo] ip tuntap add user <username> mode tun <device-name>
// [sudo] ip link set <device-name> up
// [sudo] ip addr add <ipv4-address>/<mask-length> dev <device-name>
//
// A concrete example:
//
// $ sudo ip tuntap add user wedsonaf mode tun tun0
// $ sudo ip link set tun0 up
// $ sudo ip addr add 192.168.1.1/24 dev tun0
//
// Then one can run tun_tcp_connect as such:
//
// $ ./tun/tun_tcp_connect tun0 192.168.1.2 0 192.168.1.1 1234
//
// This will attempt to connect to the linux host's stack. One can run nc in
// listen mode to accept a connect from tun_tcp_connect and exchange data.
package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// writer reads from standard input and writes to the endpoint until standard
// input is closed. It signals that it's done by closing the provided channel.
func writer(ch chan struct{}, ep tcpip.Endpoint) {
	defer func() {
		ep.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()

	var b bytes.Buffer
	if err := func() error {
		for {
			if _, err := b.ReadFrom(os.Stdin); err != nil {
				return fmt.Errorf("b.ReadFrom failed: %w", err)
			}

			for b.Len() != 0 {
				if _, err := ep.Write(&b, tcpip.WriteOptions{Atomic: true}); err != nil {
					return fmt.Errorf("ep.Write failed: %s", err)
				}
			}
		}
	}(); err != nil {
		fmt.Println(err)
	}
}

func main() {
	if len(os.Args) != 6 {
		log.Fatal("Usage: ", os.Args[0], " <tun-device> <local-ipv4-address> <local-port> <remote-ipv4-address> <remote-port>")
	}

	tunName := os.Args[1]
	addrName := os.Args[2]
	portName := os.Args[3]
	remoteAddrName := os.Args[4]
	remotePortName := os.Args[5]

	rand.Seed(time.Now().UnixNano())

	addr := tcpip.Address(net.ParseIP(addrName).To4())
	remote := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(net.ParseIP(remoteAddrName).To4()),
	}

	var localPort uint16
	if v, err := strconv.Atoi(portName); err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	} else {
		localPort = uint16(v)
	}

	if v, err := strconv.Atoi(remotePortName); err != nil {
		log.Fatalf("Unable to convert port %v: %v", remotePortName, err)
	} else {
		remote.Port = uint16(v)
	}

	// Create the stack with ipv4 and tcp protocols, then add a tun-based
	// NIC and ipv4 address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		log.Fatal(err)
	}

	fd, err := tun.Open(tunName)
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.CreateNIC(1, sniffer.New(linkEP)); err != nil {
		log.Fatal(err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, addr); err != nil {
		log.Fatal(err)
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
	})

	// Create TCP endpoint.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if e != nil {
		log.Fatal(e)
	}

	// Bind if a port is specified.
	if localPort != 0 {
		if err := ep.Bind(tcpip.FullAddress{0, "", localPort}); err != nil {
			log.Fatal("Bind failed: ", err)
		}
	}

	// Issue connect request and wait for it to complete.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.WritableEvents)
	terr := ep.Connect(remote)
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		fmt.Println("Connect is pending...")
		<-notifyCh
		terr = ep.LastError()
	}
	wq.EventUnregister(&waitEntry)

	if terr != nil {
		log.Fatal("Unable to connect: ", terr)
	}

	fmt.Println("Connected")

	// Start the writer in its own goroutine.
	writerCompletedCh := make(chan struct{})
	go writer(writerCompletedCh, ep) // S/R-SAFE: sample code.

	// Read data and write to standard output until the peer closes the
	// connection from its side.
	wq.EventRegister(&waitEntry, waiter.ReadableEvents)
	for {
		_, err := ep.Read(os.Stdout, tcpip.ReadOptions{})
		if err != nil {
			if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
				break
			}

			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}

			log.Fatal("Read() failed:", err)
		}
	}
	wq.EventUnregister(&waitEntry)

	// The reader has completed. Now wait for the writer as well.
	<-writerCompletedCh

	ep.Close()
}
