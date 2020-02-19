// Copyright 2020 The gVisor Authors.
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

// Package testbench has utilities to send and receive packets and also command
// the DUT to run POSIX functions.
package testbench

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/imdario/mergo"
	"github.com/mohae/deepcopy"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var localIP = flag.String("local_ip", "", "local ip address for test packets")
var remoteIP = flag.String("remote_ip", "", "remote ip address for test packets")
var localMAC = flag.String("local_mac", "", "local mac address for test packets")
var remoteMAC = flag.String("remote_mac", "", "remote mac address for test packets")

// TCPIPv4 maintains state about a TCP/IPv4 connection.
type TCPIPv4 struct {
	outgoing     Layers
	incoming     Layers
	localSeqNum  uint32
	remoteSeqNum uint32
	sniffer      Sniffer
	injector     Injector
	portPickerFD int
	t            *testing.T
}

// pickPort bings a new socket and returns the socket FD and port. The caller
// must close the FD when done with the port but only if the FD is not -1. Even
// if there is an error.
func pickPort() (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return fd, 0, err
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[0:4], net.ParseIP(*localIP).To4())
	if err := unix.Bind(fd, &sa); err != nil {
		return fd, 0, err
	}
	newSockAddr, err := unix.Getsockname(fd)
	if err != nil {
		return fd, 0, err
	}
	newSockAddrInet4, ok := newSockAddr.(*unix.SockaddrInet4)
	if !ok {
		return fd, 0, fmt.Errorf("can't cast Getsockname result to SockaddrInet4")
	}
	return fd, uint16(newSockAddrInet4.Port), nil
}

// tcpLayerIndex is the position of the TCP layer in the TCPIPv4 connection. It
// is the third, after Ethernet and IPv4.
const tcpLayerIndex int = 2

// NewTCPIPv4 creates a new TCPIPv4 connection with reasonable defaults.
func NewTCPIPv4(t *testing.T, dut DUT, outgoingTCP, incomingTCP TCP) TCPIPv4 {
	lMAC, err := tcpip.ParseMACAddress(*localMAC)
	if err != nil {
		t.Fatalf("can't parse localMAC %q: %s", *localMAC, err)
	}

	rMAC, err := tcpip.ParseMACAddress(*remoteMAC)
	if err != nil {
		t.Fatalf("can't parse remoteMAC %q: %s", *remoteMAC, err)
	}

	// TODO(eyalsoha): Find a better way to select local ports.
	portPickerFD, localPort, err := pickPort()
	if err != nil {
		t.Fatalf("can't pick a port: %s", err)
	}
	lIP := tcpip.Address(net.ParseIP(*localIP).To4())
	rIP := tcpip.Address(net.ParseIP(*remoteIP).To4())

	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make new sniffer: %s", err)
	}

	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make new injector: %s", err)
	}

	newOutgoingTCP := &TCP{
		DataOffset: Uint8(header.TCPMinimumSize),
		WindowSize: Uint16(32768),
		SrcPort:    &localPort,
	}
	mergo.Merge(newOutgoingTCP, outgoingTCP, mergo.WithOverride)
	newIncomingTCP := &TCP{
		DstPort: &localPort,
	}
	mergo.Merge(newOutgoingTCP, outgoingTCP, mergo.WithOverride)
	tcpipv4 := TCPIPv4{
		outgoing: Layers{
			&Ether{SrcAddr: &lMAC, DstAddr: &rMAC},
			&IPv4{SrcAddr: &lIP, DstAddr: &rIP},
			newOutgoingTCP},
		incoming: Layers{
			&Ether{SrcAddr: &rMAC, DstAddr: &lMAC},
			&IPv4{SrcAddr: &rIP, DstAddr: &lIP},
			newIncomingTCP},
		sniffer:      sniffer,
		injector:     injector,
		portPickerFD: portPickerFD,
		t:            t,
		localSeqNum:  rand.Uint32(),
	}
	return tcpipv4
}

// Close the injector and sniffer associated with this connection.
func (conn *TCPIPv4) Close() {
	conn.sniffer.Close()
	conn.injector.Close()
	if err := unix.Close(conn.portPickerFD); err != nil {
		conn.t.Fatalf("can't close portPickerFD: %s", err)
	}
}

// Send a packet with reasonable defaults and override some fields by tcp.
func (conn *TCPIPv4) Send(tcp TCP) {
	if tcp.SeqNum == nil {
		tcp.SeqNum = &conn.localSeqNum
	}
	if tcp.AckNum == nil {
		tcp.AckNum = &conn.remoteSeqNum
	}
	layersToSend := deepcopy.Copy(conn.outgoing).(Layers)
	err := mergo.Merge(layersToSend[tcpLayerIndex], tcp, mergo.WithOverride)
	if err != nil {
		conn.t.Fatalf("can't merge outgoing TCP packet: %s", err)
	}
	outBytes, err := layersToSend.toBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing TCP packet: %s", err)
	}
	conn.injector.Send(outBytes)

	// Compute the next TCP sequence number.
	for i := tcpLayerIndex + 1; i < len(layersToSend); i++ {
		conn.localSeqNum += uint32(layersToSend[i].length())
	}
	if tcp.Flags != nil && *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		conn.localSeqNum++
	}
}

// Recv gets a packet from the sniffer within the timeout provided. If no packet
// arrives before the timeout, it returns nil.
func (conn *TCPIPv4) Recv(timeout time.Duration) *TCP {
	deadline := time.Now().Add(timeout)
	for {
		timeout = deadline.Sub(time.Now())
		if timeout <= 0 {
			break
		}
		b := conn.sniffer.Recv(timeout)
		if b == nil {
			break
		}
		layers, err := ParseEther(b)
		if err != nil {
			continue // Ignore packets that can't be parsed.
		}
		if !conn.incoming.match(layers) {
			continue // Ignore packets that don't match the expected incoming.
		}
		tcpHeader := (layers[tcpLayerIndex]).(*TCP)
		conn.remoteSeqNum = *tcpHeader.SeqNum
		if *tcpHeader.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
			conn.remoteSeqNum++
		}
		for i := tcpLayerIndex + 1; i < len(layers); i++ {
			conn.remoteSeqNum += uint32(layers[i].length())
		}
		return tcpHeader
	}
	return nil
}

// Expect a packet that matches the provided tcp within the timeout specified.
// If it doesn't arrive in time, the test fails.
func (conn *TCPIPv4) Expect(tcp TCP, timeout time.Duration) *TCP {
	deadline := time.Now().Add(timeout)
	for {
		timeout = deadline.Sub(time.Now())
		if timeout <= 0 {
			return nil
		}
		gotTCP := conn.Recv(timeout)
		if gotTCP == nil {
			return nil
		}
		if tcp.match(gotTCP) {
			return gotTCP
		}
	}
}

// Handshake performs a TCP 3-way handshake.
func (conn *TCPIPv4) Handshake() {
	// Send the SYN.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagSyn)})

	// Wait for the SYNACK.
	if gotOne := conn.Expect(TCP{Flags: Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second); gotOne == nil {
		conn.t.Fatalf("didn't get synack during handshake")
	}

	// Send an ACK.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagAck)})
}
