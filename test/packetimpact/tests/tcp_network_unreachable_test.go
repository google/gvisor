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

package tcp_synsent_reset_test

import (
	"context"
	"flag"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

// TestTCPSynSentUnreachable verifies that TCP connections fail immediately when
// an ICMP destination unreachable message is sent in response to the inital
// SYN.
func TestTCPSynSentUnreachable(t *testing.T) {
	// Create the DUT and connection.
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, net.ParseIP(testbench.RemoteIPv4))
	port := uint16(9001)
	conn := testbench.NewTCPIPv4(t, testbench.TCP{SrcPort: &port, DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort, DstPort: &port})
	defer conn.Close(t)

	// Bring the DUT to SYN-SENT state with a non-blocking connect.
	ctx, cancel := context.WithTimeout(context.Background(), testbench.RPCTimeout)
	defer cancel()
	sa := unix.SockaddrInet4{Port: int(port)}
	copy(sa.Addr[:], net.IP(net.ParseIP(testbench.LocalIPv4)).To4())
	if _, err := dut.ConnectWithErrno(ctx, t, clientFD, &sa); err != syscall.Errno(unix.EINPROGRESS) {
		t.Errorf("expected connect to fail with EINPROGRESS, but got %v", err)
	}

	// Get the SYN.
	tcpLayers, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.Uint8(header.TCPFlagSyn)}, nil, time.Second)
	if err != nil {
		t.Fatalf("expected SYN: %s", err)
	}

	// Send a host unreachable message.
	rawConn := (*testbench.Connection)(&conn)
	layers := rawConn.CreateFrame(t, nil)
	layers = layers[:len(layers)-1]
	const ipLayer = 1
	const tcpLayer = ipLayer + 1
	ip, ok := tcpLayers[ipLayer].(*testbench.IPv4)
	if !ok {
		t.Fatalf("expected %s to be IPv4", tcpLayers[ipLayer])
	}
	tcp, ok := tcpLayers[tcpLayer].(*testbench.TCP)
	if !ok {
		t.Fatalf("expected %s to be TCP", tcpLayers[tcpLayer])
	}
	var icmpv4 testbench.ICMPv4 = testbench.ICMPv4{
		Type: testbench.ICMPv4Type(header.ICMPv4DstUnreachable),
		Code: testbench.ICMPv4Code(header.ICMPv4HostUnreachable)}
	layers = append(layers, &icmpv4, ip, tcp)
	rawConn.SendFrameStateless(t, layers)

	if _, err = dut.ConnectWithErrno(ctx, t, clientFD, &sa); err != syscall.Errno(unix.EHOSTUNREACH) {
		t.Errorf("expected connect to fail with EHOSTUNREACH, but got %v", err)
	}
}

// TestTCPSynSentUnreachable6 verifies that TCP connections fail immediately when
// an ICMP destination unreachable message is sent in response to the inital
// SYN.
func TestTCPSynSentUnreachable6(t *testing.T) {
	// Create the DUT and connection.
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, net.ParseIP(testbench.RemoteIPv6))
	conn := testbench.NewTCPIPv6(t, testbench.TCP{DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort})
	defer conn.Close(t)

	// Bring the DUT to SYN-SENT state with a non-blocking connect.
	ctx, cancel := context.WithTimeout(context.Background(), testbench.RPCTimeout)
	defer cancel()
	sa := unix.SockaddrInet6{
		Port:   int(conn.SrcPort()),
		ZoneId: uint32(testbench.RemoteInterfaceID),
	}
	copy(sa.Addr[:], net.IP(net.ParseIP(testbench.LocalIPv6)).To16())
	if _, err := dut.ConnectWithErrno(ctx, t, clientFD, &sa); err != syscall.Errno(unix.EINPROGRESS) {
		t.Errorf("expected connect to fail with EINPROGRESS, but got %v", err)
	}

	// Get the SYN.
	tcpLayers, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.Uint8(header.TCPFlagSyn)}, nil, time.Second)
	if err != nil {
		t.Fatalf("expected SYN: %s", err)
	}

	// Send a host unreachable message.
	rawConn := (*testbench.Connection)(&conn)
	layers := rawConn.CreateFrame(t, nil)
	layers = layers[:len(layers)-1]
	const ipLayer = 1
	const tcpLayer = ipLayer + 1
	ip, ok := tcpLayers[ipLayer].(*testbench.IPv6)
	if !ok {
		t.Fatalf("expected %s to be IPv6", tcpLayers[ipLayer])
	}
	tcp, ok := tcpLayers[tcpLayer].(*testbench.TCP)
	if !ok {
		t.Fatalf("expected %s to be TCP", tcpLayers[tcpLayer])
	}
	var icmpv6 testbench.ICMPv6 = testbench.ICMPv6{
		Type: testbench.ICMPv6Type(header.ICMPv6DstUnreachable),
		Code: testbench.ICMPv6Code(header.ICMPv6NetworkUnreachable),
		// Per RFC 4443 3.1, the payload contains 4 zeroed bytes.
		Payload: []byte{0, 0, 0, 0},
	}
	layers = append(layers, &icmpv6, ip, tcp)
	rawConn.SendFrameStateless(t, layers)

	if _, err = dut.ConnectWithErrno(ctx, t, clientFD, &sa); err != syscall.Errno(unix.ENETUNREACH) {
		t.Errorf("expected connect to fail with ENETUNREACH, but got %v", err)
	}
}
