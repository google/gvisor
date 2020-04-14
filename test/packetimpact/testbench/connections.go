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
	"strings"
	"testing"
	"time"

	"github.com/mohae/deepcopy"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

var localIPv4 = flag.String("local_ipv4", "", "local IPv4 address for test packets")
var remoteIPv4 = flag.String("remote_ipv4", "", "remote IPv4 address for test packets")
var localMAC = flag.String("local_mac", "", "local mac address for test packets")
var remoteMAC = flag.String("remote_mac", "", "remote mac address for test packets")

// pickPort makes a new socket and returns the socket FD and port. The caller
// must close the FD when done with the port if there is no error.
func pickPort() (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, 0, err
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[0:4], net.ParseIP(*localIPv4).To4())
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	newSockAddr, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	newSockAddrInet4, ok := newSockAddr.(*unix.SockaddrInet4)
	if !ok {
		unix.Close(fd)
		return -1, 0, fmt.Errorf("can't cast Getsockname result to SockaddrInet4")
	}
	return fd, uint16(newSockAddrInet4.Port), nil
}

// TCPIPv4 maintains state about a TCP/IPv4 connection.
type TCPIPv4 struct {
	outgoing     Layers
	incoming     Layers
	LocalSeqNum  seqnum.Value
	RemoteSeqNum seqnum.Value
	SynAck       *TCP
	sniffer      Sniffer
	injector     Injector
	portPickerFD int
	t            *testing.T
}

// tcpLayerIndex is the position of the TCP layer in the TCPIPv4 connection. It
// is the third, after Ethernet and IPv4.
const tcpLayerIndex int = 2

// NewTCPIPv4 creates a new TCPIPv4 connection with reasonable defaults.
func NewTCPIPv4(t *testing.T, outgoingTCP, incomingTCP TCP) TCPIPv4 {
	lMAC, err := tcpip.ParseMACAddress(*localMAC)
	if err != nil {
		t.Fatalf("can't parse localMAC %q: %s", *localMAC, err)
	}

	rMAC, err := tcpip.ParseMACAddress(*remoteMAC)
	if err != nil {
		t.Fatalf("can't parse remoteMAC %q: %s", *remoteMAC, err)
	}

	portPickerFD, localPort, err := pickPort()
	if err != nil {
		t.Fatalf("can't pick a port: %s", err)
	}
	lIP := tcpip.Address(net.ParseIP(*localIPv4).To4())
	rIP := tcpip.Address(net.ParseIP(*remoteIPv4).To4())

	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make new sniffer: %s", err)
	}

	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make new injector: %s", err)
	}

	newOutgoingTCP := &TCP{
		SrcPort: &localPort,
	}
	if err := newOutgoingTCP.merge(outgoingTCP); err != nil {
		t.Fatalf("can't merge %+v into %+v: %s", outgoingTCP, newOutgoingTCP, err)
	}
	newIncomingTCP := &TCP{
		DstPort: &localPort,
	}
	if err := newIncomingTCP.merge(incomingTCP); err != nil {
		t.Fatalf("can't merge %+v into %+v: %s", incomingTCP, newIncomingTCP, err)
	}
	return TCPIPv4{
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
		LocalSeqNum:  seqnum.Value(rand.Uint32()),
	}
}

// Close the injector and sniffer associated with this connection.
func (conn *TCPIPv4) Close() {
	conn.sniffer.Close()
	conn.injector.Close()
	if err := unix.Close(conn.portPickerFD); err != nil {
		conn.t.Fatalf("can't close portPickerFD: %s", err)
	}
	conn.portPickerFD = -1
}

// CreateFrame builds a frame for the connection with tcp overriding defaults
// and additionalLayers added after the TCP header.
func (conn *TCPIPv4) CreateFrame(tcp TCP, additionalLayers ...Layer) Layers {
	if tcp.SeqNum == nil {
		tcp.SeqNum = Uint32(uint32(conn.LocalSeqNum))
	}
	if tcp.AckNum == nil {
		tcp.AckNum = Uint32(uint32(conn.RemoteSeqNum))
	}
	layersToSend := deepcopy.Copy(conn.outgoing).(Layers)
	if err := layersToSend[tcpLayerIndex].(*TCP).merge(tcp); err != nil {
		conn.t.Fatalf("can't merge %+v into %+v: %s", tcp, layersToSend[tcpLayerIndex], err)
	}
	layersToSend = append(layersToSend, additionalLayers...)
	return layersToSend
}

// SendFrame sends a frame with reasonable defaults.
func (conn *TCPIPv4) SendFrame(frame Layers) {
	outBytes, err := frame.toBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing TCP packet: %s", err)
	}
	conn.injector.Send(outBytes)

	// Compute the next TCP sequence number.
	for i := tcpLayerIndex + 1; i < len(frame); i++ {
		conn.LocalSeqNum.UpdateForward(seqnum.Size(frame[i].length()))
	}
	tcp := frame[tcpLayerIndex].(*TCP)
	if tcp.Flags != nil && *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		conn.LocalSeqNum.UpdateForward(1)
	}
}

// Send a packet with reasonable defaults and override some fields by tcp.
func (conn *TCPIPv4) Send(tcp TCP, additionalLayers ...Layer) {
	conn.SendFrame(conn.CreateFrame(tcp, additionalLayers...))
}

// Recv gets a packet from the sniffer within the timeout provided.
// If no packet arrives before the timeout, it returns nil.
func (conn *TCPIPv4) Recv(timeout time.Duration) *TCP {
	layers := conn.RecvFrame(timeout)
	if tcpLayerIndex < len(layers) {
		return layers[tcpLayerIndex].(*TCP)
	}
	return nil
}

// RecvFrame gets a frame (of type Layers) within the timeout provided.
// If no frame arrives before the timeout, it returns nil.
func (conn *TCPIPv4) RecvFrame(timeout time.Duration) Layers {
	deadline := time.Now().Add(timeout)
	for {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			break
		}
		b := conn.sniffer.Recv(timeout)
		if b == nil {
			break
		}
		layers := Parse(ParseEther, b)
		if !conn.incoming.match(layers) {
			continue // Ignore packets that don't match the expected incoming.
		}
		tcpHeader := (layers[tcpLayerIndex]).(*TCP)
		conn.RemoteSeqNum = seqnum.Value(*tcpHeader.SeqNum)
		if *tcpHeader.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
			conn.RemoteSeqNum.UpdateForward(1)
		}
		for i := tcpLayerIndex + 1; i < len(layers); i++ {
			conn.RemoteSeqNum.UpdateForward(seqnum.Size(layers[i].length()))
		}
		return layers
	}
	return nil
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *TCPIPv4) Drain() {
	conn.sniffer.Drain()
}

// Expect a packet that matches the provided tcp within the timeout specified.
// If it doesn't arrive in time, it returns nil.
func (conn *TCPIPv4) Expect(tcp TCP, timeout time.Duration) (*TCP, error) {
	// We cannot implement this directly using ExpectFrame as we cannot specify
	// the Payload part.
	deadline := time.Now().Add(timeout)
	var allTCP []string
	for {
		var gotTCP *TCP
		if timeout = time.Until(deadline); timeout > 0 {
			gotTCP = conn.Recv(timeout)
		}
		if gotTCP == nil {
			return nil, fmt.Errorf("got %d packets:\n%s", len(allTCP), strings.Join(allTCP, "\n"))
		}
		if tcp.match(gotTCP) {
			return gotTCP, nil
		}
		allTCP = append(allTCP, gotTCP.String())
	}
}

// ExpectFrame expects a frame that matches the specified layers within the
// timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *TCPIPv4) ExpectFrame(layers Layers, timeout time.Duration) Layers {
	deadline := time.Now().Add(timeout)
	for {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil
		}
		gotLayers := conn.RecvFrame(timeout)
		if layers.match(gotLayers) {
			return gotLayers
		}
	}
}

// ExpectData is a convenient method that expects a TCP packet along with
// the payload to arrive within the timeout specified. If it doesn't arrive
// in time, it causes a fatal test failure.
func (conn *TCPIPv4) ExpectData(tcp TCP, data []byte, timeout time.Duration) {
	expected := []Layer{&Ether{}, &IPv4{}, &tcp}
	if len(data) > 0 {
		expected = append(expected, &Payload{Bytes: data})
	}
	if conn.ExpectFrame(expected, timeout) == nil {
		conn.t.Fatalf("expected to get a TCP frame %s with payload %x", &tcp, data)
	}
}

// Handshake performs a TCP 3-way handshake.
func (conn *TCPIPv4) Handshake() {
	// Send the SYN.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagSyn)})

	// Wait for the SYN-ACK.
	synAck, err := conn.Expect(TCP{Flags: Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if synAck == nil {
		conn.t.Fatalf("didn't get synack during handshake: %s", err)
	}
	conn.SynAck = synAck

	// Send an ACK.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagAck)})
}

// UDPIPv4 maintains state about a UDP/IPv4 connection.
type UDPIPv4 struct {
	outgoing     Layers
	incoming     Layers
	sniffer      Sniffer
	injector     Injector
	portPickerFD int
	t            *testing.T
}

// udpLayerIndex is the position of the UDP layer in the UDPIPv4 connection. It
// is the third, after Ethernet and IPv4.
const udpLayerIndex int = 2

// NewUDPIPv4 creates a new UDPIPv4 connection with reasonable defaults.
func NewUDPIPv4(t *testing.T, outgoingUDP, incomingUDP UDP) UDPIPv4 {
	lMAC, err := tcpip.ParseMACAddress(*localMAC)
	if err != nil {
		t.Fatalf("can't parse localMAC %q: %s", *localMAC, err)
	}

	rMAC, err := tcpip.ParseMACAddress(*remoteMAC)
	if err != nil {
		t.Fatalf("can't parse remoteMAC %q: %s", *remoteMAC, err)
	}

	portPickerFD, localPort, err := pickPort()
	if err != nil {
		t.Fatalf("can't pick a port: %s", err)
	}
	lIP := tcpip.Address(net.ParseIP(*localIPv4).To4())
	rIP := tcpip.Address(net.ParseIP(*remoteIPv4).To4())

	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make new sniffer: %s", err)
	}

	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make new injector: %s", err)
	}

	newOutgoingUDP := &UDP{
		SrcPort: &localPort,
	}
	if err := newOutgoingUDP.merge(outgoingUDP); err != nil {
		t.Fatalf("can't merge %+v into %+v: %s", outgoingUDP, newOutgoingUDP, err)
	}
	newIncomingUDP := &UDP{
		DstPort: &localPort,
	}
	if err := newIncomingUDP.merge(incomingUDP); err != nil {
		t.Fatalf("can't merge %+v into %+v: %s", incomingUDP, newIncomingUDP, err)
	}
	return UDPIPv4{
		outgoing: Layers{
			&Ether{SrcAddr: &lMAC, DstAddr: &rMAC},
			&IPv4{SrcAddr: &lIP, DstAddr: &rIP},
			newOutgoingUDP},
		incoming: Layers{
			&Ether{SrcAddr: &rMAC, DstAddr: &lMAC},
			&IPv4{SrcAddr: &rIP, DstAddr: &lIP},
			newIncomingUDP},
		sniffer:      sniffer,
		injector:     injector,
		portPickerFD: portPickerFD,
		t:            t,
	}
}

// Close the injector and sniffer associated with this connection.
func (conn *UDPIPv4) Close() {
	conn.sniffer.Close()
	conn.injector.Close()
	if err := unix.Close(conn.portPickerFD); err != nil {
		conn.t.Fatalf("can't close portPickerFD: %s", err)
	}
	conn.portPickerFD = -1
}

// CreateFrame builds a frame for the connection with the provided udp
// overriding defaults and the additionalLayers added after the UDP header.
func (conn *UDPIPv4) CreateFrame(udp UDP, additionalLayers ...Layer) Layers {
	layersToSend := deepcopy.Copy(conn.outgoing).(Layers)
	if err := layersToSend[udpLayerIndex].(*UDP).merge(udp); err != nil {
		conn.t.Fatalf("can't merge %+v into %+v: %s", udp, layersToSend[udpLayerIndex], err)
	}
	layersToSend = append(layersToSend, additionalLayers...)
	return layersToSend
}

// SendFrame sends a frame with reasonable defaults.
func (conn *UDPIPv4) SendFrame(frame Layers) {
	outBytes, err := frame.toBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing UDP packet: %s", err)
	}
	conn.injector.Send(outBytes)
}

// Send a packet with reasonable defaults and override some fields by udp.
func (conn *UDPIPv4) Send(udp UDP, additionalLayers ...Layer) {
	conn.SendFrame(conn.CreateFrame(udp, additionalLayers...))
}

// Recv gets a packet from the sniffer within the timeout provided. If no packet
// arrives before the timeout, it returns nil.
func (conn *UDPIPv4) Recv(timeout time.Duration) *UDP {
	deadline := time.Now().Add(timeout)
	for {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			break
		}
		b := conn.sniffer.Recv(timeout)
		if b == nil {
			break
		}
		layers := Parse(ParseEther, b)
		if !conn.incoming.match(layers) {
			continue // Ignore packets that don't match the expected incoming.
		}
		return (layers[udpLayerIndex]).(*UDP)
	}
	return nil
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *UDPIPv4) Drain() {
	conn.sniffer.Drain()
}

// Expect a packet that matches the provided udp within the timeout specified.
// If it doesn't arrive in time, the test fails.
func (conn *UDPIPv4) Expect(udp UDP, timeout time.Duration) (*UDP, error) {
	deadline := time.Now().Add(timeout)
	var allUDP []string
	for {
		var gotUDP *UDP
		if timeout = time.Until(deadline); timeout > 0 {
			gotUDP = conn.Recv(timeout)
		}
		if gotUDP == nil {
			return nil, fmt.Errorf("got %d packets:\n%s", len(allUDP), strings.Join(allUDP, "\n"))
		}
		if udp.match(gotUDP) {
			return gotUDP, nil
		}
		allUDP = append(allUDP, gotUDP.String())
	}
}
