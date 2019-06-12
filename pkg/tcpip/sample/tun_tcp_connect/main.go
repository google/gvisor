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
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/tun"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// writer reads from standard input and writes to the endpoint until standard
// input is closed. It signals that it's done by closing the provided channel.
func writer(ch chan struct{}, ep tcpip.Endpoint) {
	defer func() {
		ep.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()

	r := bufio.NewReader(os.Stdin)
	for {
		v := buffer.NewView(1024)
		n, err := r.Read(v)
		if err != nil {
			return
		}

		v.CapLength(n)
		for len(v) > 0 {
			n, _, err := ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
			if err != nil {
				fmt.Println("Write failed:", err)
				return
			}

			v.TrimFront(int(n))
		}
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
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName}, stack.Options{})

	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		log.Fatal(err)
	}

	fd, err := tun.Open(tunName)
	if err != nil {
		log.Fatal(err)
	}

	linkID, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.CreateNIC(1, sniffer.New(linkID)); err != nil {
		log.Fatal(err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, addr); err != nil {
		log.Fatal(err)
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: "\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
	})

	// Create TCP endpoint.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
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
	wq.EventRegister(&waitEntry, waiter.EventOut)
	terr := ep.Connect(remote)
	if terr == tcpip.ErrConnectStarted {
		fmt.Println("Connect is pending...")
		<-notifyCh
		terr = ep.GetSockOpt(tcpip.ErrorOption{})
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
	wq.EventRegister(&waitEntry, waiter.EventIn)
	for {
		v, _, err := ep.Read(nil)
		if err != nil {
			if err == tcpip.ErrClosedForReceive {
				break
			}

			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}

			log.Fatal("Read() failed:", err)
		}

		os.Stdout.Write(v)
	}
	wq.EventUnregister(&waitEntry)

	// The reader has completed. Now wait for the writer as well.
	<-writerCompletedCh

	ep.Close()
}
