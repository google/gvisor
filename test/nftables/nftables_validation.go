// Copyright 2025 The gVisor Authors.
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

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/test/netutils"
)

// Add test cases here.
var validationTests = []TestCase{
	&JumpAndDropAll{},
	&tcpDNAT{},
	&tcpSNAT{},
	&mapTest{},
	&fibTest{},
	&ctTest{},
	&tcpMasq{},
	&deletionTest{},
}

func init() {
	for _, test := range validationTests {
		RegisterTestCase(test)
	}
}

// JumpAndDropAll is a test case that verifies that a jump to a chain with a drop rule works.
type JumpAndDropAll struct{ containerCase }

var _ TestCase = (*JumpAndDropAll)(nil)

// Name returns the name of the test case.
func (*JumpAndDropAll) Name() string {
	return "JumpAndDropAll"
}

// ContainerAction are the commands that are ran in the container.
func (*JumpAndDropAll) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	tableName := "TABLE"
	cmds := [][]string{
		// Create a table: JUMP_TABLE.
		{"add", "table", "inet", tableName},
		// Create DROPS_ALL_CHAIN with drop rule.
		{"add", "chain", "inet", tableName, "DROPS_ALL_CHAIN", "{ drop; }"},
		// Create FORWARDS_TO_DROP_CHAIN with jump to DROPS_ALL_CHAIN rule.
		{"add", "chain", "inet", tableName, "FORWARDS_TO_DROP_CHAIN", "{ jump DROPS_ALL_CHAIN; }"},
		// Create BASE_CHAIN with accept all policy.
		{"add", "chain", "inet", tableName, "BASE_CHAIN", "{ type filter hook input priority 0; policy accept; }"},
		// Add rule to BASE_CHAIN to jump to FORWARDS_TO_DROP_CHAIN
		// if dport(0x0961) & 0x0fff == 0x961.
		{"add", "rule", "inet", tableName, "BASE_CHAIN", "udp", "dport", "&", "0x0fff", "==", "0x0961", "jump", "FORWARDS_TO_DROP_CHAIN"},
	}
	// Run all the commands.
	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Listen for all packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction are the commands that are ran on the test runner.
func (*JumpAndDropAll) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// Timeout implements TestCase.Timeout.
func (*JumpAndDropAll) Timeout() time.Duration {
	return 30 * time.Second
}

// tcpDNAT verifies DNAT on TCP packets.
type tcpDNAT struct{ containerCase }

var _ TestCase = (*tcpDNAT)(nil)

// Name returns the name of the test case.
func (*tcpDNAT) Name() string {
	return "tcpDNAT"
}

// ContainerAction are the commands that are ran in the container.
// Creates a table with a DNAT rule at serverAddr:serverPort.
// Verify that the server is reachable at the dnatAddr:dnatPort.
func (*tcpDNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		// Skip for IPv6 since the requested rules are for IPv4 only.
		log.Warningf("DNAT is not supported for IPv6 yet.")
		return nil
	}
	testMsg := "Hello World!"
	serverAddr := "127.0.0.1"
	serverPort := "9000"
	dnatAddr := "100.100.100.100"
	dnatPort := "8080"
	cmds := [][]string{
		// Create NAT table.
		{"add", "table", "inet", "nat"},
		// Create output chain in NAT table.
		{"add", "chain", "inet", "nat", "output", "{ type nat hook output priority 100; }"},
		// Add rule to change destination from dnatAddr:dnatPort to serverAddr:serverPort.
		{"add", "rule", "inet", "nat", "output", "ip", "daddr", dnatAddr, "tcp", "dport", dnatPort, "dnat", "to", fmt.Sprintf("%s:%s", serverAddr, serverPort)},
	}
	// Run all the commands.
	for _, cmd := range cmds {
		// Program the nftables rules.
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Start listening on serverAddr:serverPort.
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%s", serverAddr, serverPort))
	if err != nil {
		return fmt.Errorf("net.Listen failed: %v", err)
	}
	defer l.Close()

	errCh := make(chan error, 1)
	// Start the server.
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		msg := string(buf[:n])
		// Check that the message is the same as the one sent.
		if msg != testMsg {
			errCh <- fmt.Errorf("unexpected message: %q", msg)
			return
		}
		errCh <- nil
	}()

	// Dial to the server at dnatAddr:dnatPort.
	// Expected to reach serverAddr:serverPort.
	var conn net.Conn
	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%s", dnatAddr, dnatPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("net.Dial failed: %v", err)
	}
	defer conn.Close()

	// Send testMsg to the server.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		return fmt.Errorf("conn.Write failed: %v", err)
	}

	// Wait for error or timeout.
	select {
	case err := <-errCh:
		return err
	case <-time.After(1 * time.Minute):
		return fmt.Errorf("timeout waiting for the client connection")
	}
}

// LocalAction are the commands that are ran on the test runner.
func (*tcpDNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// Timeout implements TestCase.Timeout.
func (*tcpDNAT) Timeout() time.Duration {
	// TODO: b/486197011 - Reduce the timeout.
	return 1 * time.Minute
}

// tcpSNAT verifies SNAT on TCP packets.
type tcpSNAT struct{ containerCase }

var _ TestCase = (*tcpSNAT)(nil)

func (*tcpSNAT) Name() string {
	return "tcpSNAT"
}

// ContainerAction are the commands that are ran in the container.
// Creates a table with a SNAT rule for TCP packets to port 9000.
// Verify that any client connection to port 9000
// has the source address: snatAddr.
func (*tcpSNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("SNAT is not supported for IPv6 yet.")
		return nil
	}
	// Expected SNAT address of client connection to server.
	snatAddr := "127.0.0.99"
	cmds := [][]string{
		// Create NAT table.
		{"add", "table", "inet", "nat"},
		// Create input chain in NAT table.
		{"add", "chain", "inet", "nat", "input", "{ type nat hook input priority 100; }"},
		// Add rule to change source address to snatAddr for TCP packets to port 9000.
		{"add", "rule", "inet", "nat", "input", "tcp", "dport", "9000", "counter", "snat", "ip", "to", snatAddr},
	}
	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// start the server inside gvisor.
	l, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		return fmt.Errorf("net.Listen failed: %v", err)
	}
	defer l.Close()

	errCh := make(chan error, 1)
	go func() {
		log.Infof("Waiting for client connection")
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			errCh <- fmt.Errorf("failed to parse the client addr, err: %v", err)
			return
		}
		if remoteAddr != snatAddr {
			errCh <- fmt.Errorf("unexpected client addr: %s, expected addr: %s", remoteAddr, snatAddr)
			return
		}
		errCh <- nil
	}()

	// Wait for error or timeout.
	select {
	case err := <-errCh:
		return err
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for the client connection")
	}
}

// LocalAction are the commands that are ran on the test runner.
// Connects to the server inside the container at port 9000.
func (*tcpSNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		return nil
	}

	// Connect to the server inside the container at port 9000.
	var conn net.Conn
	var err error
	dialAddr := net.JoinHostPort(ip.String(), "9000")
	// Retry while the server in the container isn't up.
	for i := 0; i < 10; i++ {
		conn, err = net.DialTimeout("tcp", dialAddr, 5*time.Second)
		if err == nil {
			break
		}
		log.Warningf("net.Dial failed: %v, waiting for the server in container to start...", err)
		// Sleep to give the server in the container some time to start.
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("net.Dial failed: %v", err)
	}
	defer conn.Close()
	return nil
}

// Timeout implements TestCase.Timeout.
func (*tcpSNAT) Timeout() time.Duration {
	return 30 * time.Second
}

// udpDNAT verifies DNAT on UDP packets.
type udpDNAT struct{ containerCase }

var _ TestCase = (*udpDNAT)(nil)

// Name returns the name of the test case.
func (*udpDNAT) Name() string {
	return "udpDNAT"
}

// ContainerAction are the commands that are ran in the container.
// Creates a table with a DNAT rule at serverAddr:serverPort.
// Verify that the server is reachable at the dnatAddr:dnatPort.
func (*udpDNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		// Skip for IPv6 since the requested rules are for IPv4 only.
		log.Warningf("DNAT is not supported for IPv6 yet.")
		return nil
	}
	testMsg := "Hello World!"
	serverAddr := "127.0.0.1"
	serverPort := "9000"
	dnatAddr := "100.100.100.100"
	dnatPort := "8080"
	cmds := [][]string{
		// Create NAT table.
		{"add", "table", "inet", "nat"},
		// Create output chain in NAT table.
		{"add", "chain", "inet", "nat", "output", "{ type nat hook output priority 100; }"},
		// Add rule to change destination from dnatAddr:dnatPort to serverAddr:serverPort/udp.
		{"add", "rule", "inet", "nat", "output", "ip", "daddr", dnatAddr, "udp", "dport", dnatPort, "dnat", "to", fmt.Sprintf("%s:%s", serverAddr, serverPort)},
	}
	// Run all the commands.
	for _, cmd := range cmds {
		// Program the nftables rules.
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Start listening on serverAddr:serverPort for UDP.
	l, err := net.ListenPacket("udp", fmt.Sprintf("%s:%s", serverAddr, serverPort))
	if err != nil {
		return fmt.Errorf("net.ListenPacket failed: %v", err)
	}
	defer l.Close()

	errCh := make(chan error, 1)
	// Start the server.
	go func() {
		buf := make([]byte, 1024)
		l.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := l.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		msg := string(buf[:n])
		// Check that the message is the same as the one sent.
		if msg != testMsg {
			errCh <- fmt.Errorf("unexpected message: %q", msg)
			return
		}
		errCh <- nil
	}()

	// Dial to the server at dnatAddr:dnatPort.
	// Expected to reach serverAddr:serverPort.
	var conn net.Conn
	conn, err = net.DialTimeout("udp", fmt.Sprintf("%s:%s", dnatAddr, dnatPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("net.Dial failed: %v", err)
	}
	defer conn.Close()

	// Send testMsg to the server.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		return fmt.Errorf("conn.Write failed: %v", err)
	}

	// Wait for error or timeout.
	select {
	case err := <-errCh:
		return err
	case <-time.After(1 * time.Minute):
		return fmt.Errorf("timeout waiting for the client connection")
	}
}

// LocalAction are the commands that are ran on the test runner.
func (*udpDNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// Timeout implements TestCase.Timeout.
func (*udpDNAT) Timeout() time.Duration {
	// TODO: b/486197011 - Reduce the timeout.
	return 1 * time.Minute
}

// udpSNAT verifies SNAT on UDP packets.
type udpSNAT struct{ containerCase }

var _ TestCase = (*udpSNAT)(nil)

func (*udpSNAT) Name() string {
	return "udpSNAT"
}

// ContainerAction are the commands that are ran in the container.
// Creates a table with a SNAT rule for UDP packets to port 9000.
// Verify that any client connection to port 9000
// has the source address: snatAddr.
func (*udpSNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("SNAT is not supported for IPv6 yet.")
		return nil
	}
	// Expected SNAT address of client connection to server.
	snatAddr := "127.0.0.99"
	cmds := [][]string{
		// Create NAT table.
		{"add", "table", "inet", "nat"},
		// Create input chain in NAT table.
		{"add", "chain", "inet", "nat", "input", "{ type nat hook input priority 100; }"},
		// Add rule to change source address to snatAddr for UDP packets to port 9000.
		{"add", "rule", "inet", "nat", "input", "udp", "dport", "9000", "counter", "snat", "ip", "to", snatAddr},
	}
	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// start the UDP server inside gvisor.
	l, err := net.ListenPacket("udp", "0.0.0.0:9000")
	if err != nil {
		return fmt.Errorf("net.ListenPacket failed: %v", err)
	}
	defer l.Close()

	errCh := make(chan error, 1)
	go func() {
		log.Infof("Waiting for client connection")
		buf := make([]byte, 1024)
		l.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, remoteAddrNet, err := l.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		remoteAddr, _, err := net.SplitHostPort(remoteAddrNet.String())
		if err != nil {
			errCh <- fmt.Errorf("failed to parse the client addr, err: %v", err)
			return
		}
		if remoteAddr != snatAddr {
			errCh <- fmt.Errorf("unexpected client addr: %s, expected addr: %s", remoteAddr, snatAddr)
			return
		}
		errCh <- nil
	}()

	// Wait for error or timeout.
	select {
	case err := <-errCh:
		return err
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for the client connection")
	}
}

// LocalAction are the commands that are ran on the test runner.
// Connects to the server inside the container at port 9000.
func (*udpSNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		return nil
	}

	dialAddr := net.JoinHostPort(ip.String(), "9000")
	conn, err := net.Dial("udp", dialAddr)
	if err != nil {
		return fmt.Errorf("net.Dial failed: %v", err)
	}
	defer conn.Close()

	// Send UDP packets repeatedly to handle the connectionless startup race.
	for i := 0; i < 20; i++ {
		if ctx.Err() != nil {
			break
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			log.Warningf("conn.Write failed: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

// Timeout implements TestCase.Timeout.
func (*udpSNAT) Timeout() time.Duration {
	return 30 * time.Second
}

// mapTest tests installs Nftables rules such that:
//  1. Incoming packets to port 9000 match a verdict map and jump to a sub-chain.
//  2. In the sub-chain, the source IP should match a map and
//     be translated to a new source IP.
//  3. The packet is then forwarded to the destination port 9000.
type mapTest struct{ containerCase }

var _ TestCase = (*mapTest)(nil)

func (*mapTest) Name() string {
	return "mapTest"
}

// ContainerAction implements TestCase.ContainerAction.
func (t *mapTest) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("mapTest is not supported for IPv6 yet.")
		return nil
	}

	snatAddr := "127.0.0.99"

	//
	if err := func() error {
		// Start a listener on port 8999
		// This verifies that:
		//   a) the ContainerAction and the LocalAction can connect to each other.
		//   b) sync with LocalAction that the nft-rules are programmed.
		l1, err := net.Listen("tcp", "0.0.0.0:8999")
		if err != nil {
			return fmt.Errorf("initial net.Listen failed: %v", err)
		}
		defer l1.Close()

		// 2. Program the rules targeting port 9000 while the client waits on 8999.
		cmds := [][]string{
			// Create NAT table.
			{"add", "table", "inet", "nat"},
			// Create input chain.
			{"add", "chain", "inet", "nat", "input", "{ type nat hook input priority 100; }"},
			// Create target sub-chain (non-base chain).
			{"add", "chain", "inet", "nat", "snat_chain"},
			// Create maps.
			{"add", "map", "inet", "nat", "client_vmap", "{ type ipv4_addr : verdict; }"},
			{"add", "map", "inet", "nat", "client_snat_map", "{ type ipv4_addr : ipv4_addr; }"},
			// Add element to verdict map to jump to sub-chain.
			{"add", "element", "inet", "nat", "client_vmap", fmt.Sprintf("{ %s : jump snat_chain }", ip.String())},
			// Add element to normal map mapping client IP -> snatAddr.
			{"add", "element", "inet", "nat", "client_snat_map", fmt.Sprintf("{ %s : %s }", ip.String(), snatAddr)},
			// Add rule on base input chain to use vmap.
			{"add", "rule", "inet", "nat", "input", "tcp", "dport", "9000", "ip", "saddr", "vmap", "@client_vmap"},
			// Add rule inside snat_chain to apply SNAT map translation on matching packet.
			{"add", "rule", "inet", "nat", "snat_chain", "snat", "ip", "to", "ip", "saddr", "map", "@client_snat_map"},
		}

		for _, cmd := range cmds {
			if err := nftCmd(cmd); err != nil {
				return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
			}
		}

		// Dump & list client_vmap and client_snat_map to verify map dump and setup.
		out, err := nftCmdOut([]string{"list", "map", "inet", "nat", "client_vmap"})
		if err != nil {
			return fmt.Errorf("failed to list client_vmap: %v", err)
		}
		if !strings.Contains(out, ip.String()) || !strings.Contains(out, "jump snat_chain") {
			return fmt.Errorf("unexpected verdict map dump output: %s", out)
		}

		out, err = nftCmdOut([]string{"list", "map", "inet", "nat", "client_snat_map"})
		if err != nil {
			return fmt.Errorf("failed to list client_snat_map: %v", err)
		}
		if !strings.Contains(out, ip.String()) || !strings.Contains(out, snatAddr) {
			return fmt.Errorf("unexpected normal map dump output: %s", out)
		}

		// 3. Accept connection on 8999 to sync with the LocalAction.
		errCh1 := make(chan error, 1)
		go func() {
			conn, err := l1.Accept()
			if err != nil {
				errCh1 <- err
				return
			}
			conn.Close()
			errCh1 <- nil
		}()

		select {
		case err := <-errCh1:
			if err != nil {
				return err
			}
		case <-time.After(10 * time.Second):
			return fmt.Errorf("timeout waiting for initial client TCP connection on port 8999")
		}
		return nil
	}(); err != nil {
		return err
	}

	// 4. Verify both maps behave correctly by listening on TCP port 9000.
	// Packet must jump to snat_chain and get source IP translated to snatAddr.
	l2, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		return fmt.Errorf("second net.Listen failed: %v", err)
	}

	errCh2 := make(chan error, 1)
	go func() {
		defer l2.Close()
		conn, err := l2.Accept()
		if err != nil {
			errCh2 <- err
			return
		}
		defer conn.Close()

		remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			errCh2 <- fmt.Errorf("failed to parse client address, err: %v", err)
			return
		}
		if remoteAddr != snatAddr {
			errCh2 <- fmt.Errorf("unexpected client address after SNAT: %s, expected: %s", remoteAddr, snatAddr)
			return
		}
		errCh2 <- nil
	}()

	select {
	case err := <-errCh2:
		if err != nil {
			return err
		}
	case <-time.After(15 * time.Second):
		l2.Close()
		return fmt.Errorf("timeout waiting for client TCP connection post-SNAT on port 9000")
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (t *mapTest) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		return nil
	}

	dialAddr1 := net.JoinHostPort(ip.String(), "8999")
	dialAddr2 := net.JoinHostPort(ip.String(), "9000")

	// Sync by waiting for the container to be ready to accept connections on port 8999.
	var conn1 net.Conn
	var err error
	for i := 0; i < 10; i++ {
		conn1, err = net.Dial("tcp", dialAddr1)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("first net.Dial failed: %v", err)
	}
	conn1.Close()

	// Send a TCP packet to port 9000 to verify SNAT is working.
	var conn2 net.Conn
	for i := 0; i < 10; i++ {
		conn2, err = net.Dial("tcp", dialAddr2)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("second net.Dial failed: %v", err)
	}
	conn2.Close()

	return nil
}

// Timeout implements TestCase.Timeout.
func (*mapTest) Timeout() time.Duration {
	return 30 * time.Second
}

// fibTest tests installs Nftables rules such that:
//  1. Incoming packets to port 9005 match a FIB lookup.
//  2. If matched, the packet is accepted. Otherwise dropped.
type fibTest struct{ containerCase }

var _ TestCase = (*fibTest)(nil)

func (*fibTest) Name() string {
	return "fibTest"
}

// ContainerAction implements TestCase.ContainerAction.
func (t *fibTest) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("fibTest is not supported for IPv6 yet.")
		return nil
	}

	// Find the interface dynamically.
	targetIface, ok := netutils.GetNonLoopbackInterface()
	if !ok {
		return fmt.Errorf("no non-loopback interface found")
	}
	log.Infof("FIB test using interface: %s (Index: %d)", targetIface.Name, targetIface.Index)

	// install_rules
	{
		cmds := [][]string{
			{"add", "table", "inet", "filter"},
			// Policy set to drop by default; if FIB fails, packet should be dropped.
			{"add", "chain", "inet", "filter", "input", "{ type filter hook input priority 0; policy drop; }"},
			// Accept connections to 8995 to bypass drop policy for the test setup sync, also validate iifname.
			{"add", "rule", "inet", "filter", "input", "tcp", "dport", "8995", "meta", "iifname", targetIface.Name, "accept"},
			// Output Chain to validate oifname.
			{"add", "chain", "inet", "filter", "output", "{ type filter hook output priority 0; policy drop; }"},
			{"add", "rule", "inet", "filter", "output", "meta", "oifname", "lo", "accept"},
			{"add", "rule", "inet", "filter", "output", "tcp", "sport", "8995", "meta", "oifname", targetIface.Name, "accept"},
			// Try to trigger all the FIB paths and validate iifname.
			{"add", "rule", "inet", "filter", "input", "udp", "dport", "9005",
				"meta", "iifname", targetIface.Name,
				"fib", "saddr", ".", "iif", "oif", fmt.Sprintf("%d", targetIface.Index),
				"fib", "saddr", ".", "iif", "oifname", targetIface.Name,
				"fib", "saddr", ".", "iif", "oif", "exists",
				"fib", "saddr", ".", "iif", "oifname", "exists",
				"fib", "saddr", "type", "unicast",
				"fib", "daddr", "type", "local",
				"accept"},
		}

		for _, cmd := range cmds {
			if err := nftCmd(cmd); err != nil {
				return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
			}
		}
		log.Infof("fibTest: NFT rules installed successfully")
	}

	// Verify that the UDP packets from outside the container can reach port 9005.
	// This verifies that the FIB rules are evaluated correctly.
	udpListener, err := net.ListenPacket("udp", "0.0.0.0:9005")
	if err != nil {
		return fmt.Errorf("UDP net.ListenPacket failed on 9005: %v", err)
	}
	defer udpListener.Close()
	log.Infof("fibTest: Listening for UDP on port 9005")

	udpErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			udpListener.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, _, err := udpListener.ReadFrom(buf)
			if err != nil {
				udpErrCh <- fmt.Errorf("failed receiving remote UDP packet: %v", err)
				return
			}
			if string(buf[:n]) == "remote_test" {
				break
			}
		}
		udpErrCh <- nil
	}()

	// Sync setup with LocalAction.
	{
		syncListener, err := net.Listen("tcp", "0.0.0.0:8995")
		if err != nil {
			return fmt.Errorf("net.Listen failed on 8995: %v", err)
		}
		log.Infof("fibTest: Listening for sync connection on port 8995")

		syncErrCh := make(chan error, 1)
		go func() {
			defer syncListener.Close()
			conn, err := syncListener.Accept()
			if err != nil {
				syncErrCh <- err
				return
			}
			defer conn.Close()
			syncErrCh <- nil
		}()

		select {
		case err := <-syncErrCh:
			if err != nil {
				return err
			}
			log.Infof("fibTest: Sync with LocalAction successful")
		case <-time.After(15 * time.Second):
			syncListener.Close()
			return fmt.Errorf("timeout waiting for client TCP connection on 8995")
		}
	}

	// Wait for remote UDP
	select {
	case err := <-udpErrCh:
		if err != nil {
			return err
		}
		log.Infof("fibTest: Received remote UDP packet 'remote_test'")
	case <-time.After(15 * time.Second):
		return fmt.Errorf("timeout waiting for remote client UDP connection on 9005")
	}

	// verify UDP negative logic (Local Loopback)
	// Packets sent to itself (127.0.0.1) should fail the FIB interface check
	// and be dropped by the default policy.
	log.Infof("fibTest: Starting negative test (Local Loopback to 127.0.0.1:9005)")
	conn, err := net.Dial("udp", "127.0.0.1:9005")
	if err != nil {
		return fmt.Errorf("local UDP dial failed: %v", err)
	}

	if _, err := conn.Write([]byte("local_test")); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write local UDP packet: %v", err)
	}
	conn.Close()

	// Read loop to verify local_test doesn't arrive.
	buf := make([]byte, 1024)
	udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))
	for {
		n, _, err := udpListener.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Infof("fibTest: Success! Local UDP packet was dropped (Timed out waiting for packet)")
				break
			}
			return fmt.Errorf("unexpected error waiting for local UDP: %v", err)
		}
		if string(buf[:n]) == "local_test" {
			return fmt.Errorf("local UDP transmission to 9005 succeeded when it should have been dropped")
		}
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (t *fibTest) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		return nil
	}

	// 1. Sync with ContainerAction by connecting to port 8995.
	log.Infof("fibTest (LocalAction): Attempting to sync with container on port 8995")
	{
		addr := net.JoinHostPort(ip.String(), "8995")
		var err error
		var conn net.Conn
		for i := 0; i < 10; i++ {
			conn, err = net.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				break
			}
			time.Sleep(1 * time.Second)
		}
		if err != nil {
			return fmt.Errorf("sync dial failed: %v", err)
		}
		log.Infof("fibTest (LocalAction): Sync successful")
	}

	// 2. Validate that remote UDP packets reach Container..
	log.Infof("fibTest (LocalAction): Sending remote UDP packets to container")
	{
		conn, err := net.Dial("udp", net.JoinHostPort(ip.String(), "9005"))
		if err != nil {
			return fmt.Errorf("udp dial failed: %v", err)
		}
		defer conn.Close()

		// Send multiple times to ensure delivery over UDP
		for i := 0; i < 10; i++ {
			conn.Write([]byte("remote_test"))
			time.Sleep(1 * time.Second)
		}
		log.Infof("fibTest (LocalAction): Finished sending remote UDP packets")
	}

	return nil
}

// Timeout implements TestCase.Timeout.
func (*fibTest) Timeout() time.Duration {
	// TODO: b/486197011 - Reduce the timeout.
	return 90 * time.Second
}

// ctTest verifies conntrack functionality.
type ctTest struct{ containerCase }

var _ TestCase = (*ctTest)(nil)

func (*ctTest) Name() string {
	return "ctTest"
}

// ContainerAction implements TestCase.ContainerAction.
func (t *ctTest) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("ctTest is not supported for IPv6 yet.")
		return nil
	}

	// install_rules
	{
		cmds := [][]string{
			{"add", "table", "inet", "filter"},
			// Policy set to drop by default; if conntrack fails, packet should be dropped.
			{"add", "chain", "inet", "filter", "input",
				"{ type filter hook input priority 0; policy drop; }"},
			// Accept connections to 8995 to bypass drop policy for the test setup sync
			{"add", "rule", "inet", "filter", "input", "tcp", "dport", "8995", "accept"},
			// Rule 1: Allow initial packet of a new connection.
			{"add", "rule", "inet", "filter", "input", "tcp", "dport", "29008",
				"ct", "state", "new",
				"ct", "original", "protocol", "tcp",
				"ct", "original", "proto-src", "29007",
				"ct", "direction", "original",
				"accept"},
			// Rule 2: Allow all subsequent packets for connections that have already
			// been established or are related to them.
			{"add", "rule", "inet", "filter", "input", "ct", "state", "established,related", "accept"},
			// Output Chain
			{"add", "chain", "inet", "filter", "output", "{ type filter hook output priority 0; policy drop; }"},
			// Accept LocalAction sync replies.
			{"add", "rule", "inet", "filter", "output", "tcp", "sport", "8995", "accept"},
			// Rule 3: Verify Reply packets on Output chain.
			{"add", "rule", "inet", "filter", "output", "tcp", "sport", "29008",
				"ct", "direction", "reply",
				"ct", "reply", "proto-src", "29008",
				"ct", "reply", "proto-dst", "29007",
				"accept"},
		}

		for _, cmd := range cmds {
			if err := nftCmd(cmd); err != nil {
				return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
			}
		}
		log.Infof("ctTest: NFT rules installed successfully")
	}

	// Start listening on 29008.
	l, err := net.Listen("tcp", "0.0.0.0:29008")
	if err != nil {
		return fmt.Errorf("net.Listen failed on 29008: %v", err)
	}
	defer l.Close()
	log.Infof("ctTest: Listening for TCP on port 29008")

	errCh := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if string(buf[:n]) == "remote_test" {
			errCh <- nil
		} else {
			errCh <- fmt.Errorf("unexpected message: %s", string(buf[:n]))
		}
	}()

	// Sync setup with LocalAction.
	{
		syncListener, err := net.Listen("tcp", "0.0.0.0:8995")
		if err != nil {
			return fmt.Errorf("net.Listen failed on 8995: %v", err)
		}
		log.Infof("ctTest: Listening for sync connection on port 8995")

		syncErrCh := make(chan error, 1)
		go func() {
			defer syncListener.Close()
			conn, err := syncListener.Accept()
			if err != nil {
				syncErrCh <- err
				return
			}
			defer conn.Close()
			syncErrCh <- nil
		}()

		select {
		case err := <-syncErrCh:
			if err != nil {
				return err
			}
			log.Infof("ctTest: Sync with LocalAction successful")
		case <-time.After(15 * time.Second):
			syncListener.Close()
			return fmt.Errorf("timeout waiting for client TCP connection on 8995")
		}
	}

	// Wait for remote TCP
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		log.Infof("ctTest: Received remote TCP packet 'remote_test'")
	case <-time.After(15 * time.Second):
		return fmt.Errorf("timeout waiting for remote client TCP connection on 29008")
	}

	return nil
}

// dialTCPWithReuseAddr dials a TCP connection with the SO_REUSEADDR and SO_LINGER option set.
func dialTCPWithReuseAddr(ctx context.Context, localAddr, remoteAddr net.Addr) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
			return err
		},
	}
	conn, err := d.DialContext(ctx, "tcp", remoteAddr.String())
	if err != nil {
		return nil, err
	}
	conn.(*net.TCPConn).SetLinger(0)
	return conn, nil
}

// LocalAction implements TestCase.LocalAction.
func (t *ctTest) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		// ctTest is not supported for IPv6 yet.
		return nil
	}

	// 1. Sync with ContainerAction setup.
	{
		log.Infof("ctTest (LocalAction): Waiting for sync...")
		var conn net.Conn
		var err error
		for i := 0; i < 10; i++ {
			conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "8995"), 2*time.Second)
			if err == nil {
				conn.Close()
				break
			}
			time.Sleep(1 * time.Second)
		}
		if err != nil {
			return fmt.Errorf("sync dial failed: %v", err)
		}
		log.Infof("ctTest (LocalAction): Sync successful")
	}

	// 2. Connect using source port 29007 (allowed port).
	log.Infof("ctTest (LocalAction): Sending positive TCP packets to container (port 29007 -> 29008)")
	{
		localAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:29007")
		if err != nil {
			return fmt.Errorf("resolve local TCP addr failed: %v", err)
		}
		remoteAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip.String(), "29008"))
		if err != nil {
			return fmt.Errorf("resolve remote TCP addr failed: %v", err)
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dialCancel()
		conn, err := dialTCPWithReuseAddr(dialCtx, localAddr, remoteAddr)
		if err != nil {
			return fmt.Errorf("positive TCP dial failed: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("remote_test")); err != nil {
			return fmt.Errorf("failed to write positive TCP payload: %v", err)
		}
		log.Infof("ctTest (LocalAction): Finished sending positive TCP packets")
	}

	// 3. Negative Test: Connecting using ephemeral port should be dropped.
	log.Infof("ctTest (LocalAction): Sending negative TCP packets to container (ephemeral port -> 29008)")
	{
		// Expect this to timeout or fail to connect because it won't match proto-src 29007.
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "29008"), 5*time.Second)
		if err == nil {
			conn.Close()
			return fmt.Errorf("TCP connection succeeded when it should have been dropped")
		}
		log.Infof("ctTest (LocalAction): Connection failed as expected: %v", err)
	}

	return nil
}

// Timeout implements TestCase.Timeout.
func (*ctTest) Timeout() time.Duration {
	// TODO: b/486197011 - Reduce the timeout.
	return 60 * time.Second
}

// tcpMasq verifies Masquerade on TCP packets.
type tcpMasq struct{ containerCase }

var _ TestCase = (*tcpMasq)(nil)

func (t *tcpMasq) setupClientNamespace() (func(), error) {
	if err := runCmd("ip", "netns", "add", "client_ns"); err != nil {
		return nil, err
	}
	cleanup := func() {
		runCmd("ip", "netns", "del", "client_ns")
	}

	cmds := [][]string{
		{"ip", "link", "add", "veth-router", "type", "veth", "peer", "name", "veth-client"},
		{"ip", "link", "set", "veth-client", "netns", "client_ns"},
		{"ip", "addr", "add", "192.168.1.1/24", "dev", "veth-router"},
		{"ip", "link", "set", "veth-router", "up"},
		{"ip", "-n", "client_ns", "addr", "add", "192.168.1.2/24", "dev", "veth-client"},
		{"ip", "-n", "client_ns", "link", "set", "veth-client", "up"},
		{"ip", "-n", "client_ns", "link", "set", "lo", "up"},
		{"ip", "-n", "client_ns", "route", "replace", "default", "via", "192.168.1.1", "dev", "veth-client"},
	}

	for _, cmd := range cmds {
		if err := runCmd(cmd[0], cmd[1:]...); err != nil {
			cleanup()
			return nil, err
		}
	}

	return cleanup, nil
}

// acceptSync listens on the specified port with a timeout,
// and calls the handle function on the connection.
func acceptSync(ip net.IP, port string, timeout time.Duration, handle func(net.Conn) error) error {
	l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return err
	}
	defer l.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		if handle != nil {
			errCh <- handle(conn)
		} else {
			errCh <- nil
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for sync connection on %s", port)
	}
}

// dialSync attempts to connect to the specified IP and port,
// and calls the handle function on the connection.
func dialSync(ip net.IP, port string, retries int, handle func(net.Conn) error) error {
	dialAddr := net.JoinHostPort(ip.String(), port)
	var lastErr error
	for i := 0; i < retries; i++ {
		conn, err := net.DialTimeout("tcp", dialAddr, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if handle != nil {
				return handle(conn)
			}
			return nil
		}
		lastErr = err
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("failed to connect to %s after %d attempts: %v", dialAddr, retries, lastErr)
}

func (*tcpMasq) Name() string {
	return "tcpMasq"
}

// ContainerAction implements TestCase.ContainerAction.
// Setup a client namespace and NAT masq TCP rules.
// Enable IP forwarding.
// Generate traffic from namespace to trigger NAT masq.
func (t *tcpMasq) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		log.Warningf("Masq is not supported for IPv6 yet.")
		return nil
	}

	targetIface, ok := netutils.GetNonLoopbackInterface()
	if !ok {
		return fmt.Errorf("no non-loopback interface found")
	}

	// Setup namespace and veth pair.
	// When a packet is sent from the namespace, NAT masq should replace the
	// source IP address (namespace IP) to the container's IP.

	cleanup, err := t.setupClientNamespace()
	if err != nil {
		return err
	}
	defer cleanup()

	// Enable IP forwarding.
	if err := runCmd("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"); err != nil {
		return err
	}

	// Sync setup with LocalAction and get the target port.
	// This is to avoid port in use issues.
	var remotePort int

	if err := acceptSync(net.ParseIP("0.0.0.0"), "8995", 15*time.Second, func(conn net.Conn) error {
		if _, err := fmt.Fscanf(conn, "%d", &remotePort); err != nil {
			return fmt.Errorf("failed to read target port: %v", err)
		}
		return nil
	}); err != nil {
		return err
	}
	log.Infof("tcpMasq: Sync with LocalAction successful, got remote port: %d", remotePort)

	// Install NFTable rules.
	{
		cmds := [][]string{
			{"add", "table", "inet", "nat"},
			// Postrouting hook is required for masquerade.
			{"add", "chain", "inet", "nat", "postrouting", "{ type nat hook postrouting priority 100; }"},
			// Masq outgoing TCP traffic to remotePort on the target interface to custom port range.
			{"add", "rule", "inet", "nat", "postrouting", "meta", "oifname", targetIface.Name, "tcp",
				"dport", fmt.Sprintf("%d", remotePort), "counter", "masquerade", "to", ":10000-10005"},
		}

		for _, cmd := range cmds {
			if err := nftCmd(cmd); err != nil {
				return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
			}
		}
		log.Infof("tcpMasq: NFT rules installed successfully")
	}

	// Generate traffic from namespace to trigger masquerade.
	{
		dialAddr := ip.String()
		log.Infof("tcpMasq: Generating traffic from namespace to %s:%d", dialAddr, remotePort)

		// Wait a bit for forwarding to settle.
		time.Sleep(1 * time.Second)

		// Send TCP packet through nc inside client_ns.
		// Ignore safetext/shsprintf linter suggestion.
		bashCmd := fmt.Sprintf("echo remote_test | nc -v -w 5 %s %d", dialAddr, remotePort)
		var lastErr error
		for i := 0; i < 5; i++ {
			lastErr = runCmd("ip", "netns", "exec", "client_ns", "bash", "-c", bashCmd)
			if lastErr == nil {
				break
			}
			log.Warningf("tcpMasq: Attempt %d to send traffic failed: %v", i+1, lastErr)
			time.Sleep(1 * time.Second)
		}

		if lastErr != nil {
			return fmt.Errorf("failed to generate traffic from namespace after retries: %v", lastErr)
		}
		log.Infof("tcpMasq: Traffic generated successfully")
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// Setup a TCP server to listen on dynamic port (to avoid port reuse issues).
// Share the port with ContainerAction and verify the masq IP.
func (*tcpMasq) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if ipv6 {
		return nil
	}

	// Listen on dynamic port to accept connections from container.
	log.Infof("tcpMasq (LocalAction): Listening on dynamic port")
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("net.Listen failed: %v", err)
	}
	defer l.Close()
	pickedPort := l.Addr().(*net.TCPAddr).Port
	log.Infof("tcpMasq (LocalAction): Picked port %d", pickedPort)

	// Sync with ContainerAction setup and share the picked port.
	{
		log.Infof("tcpMasq (LocalAction): Waiting for container sync on port 8995...")
		if err := dialSync(ip, "8995", 10, func(conn net.Conn) error {
			_, err := fmt.Fprintf(conn, "%d\n", pickedPort)
			return err
		}); err != nil {
			return fmt.Errorf("sync dial failed: %v", err)
		}
		log.Infof("tcpMasq (LocalAction): Sync successful")
	}

	// Verify that the connection is established and
	// 1. the remote address is the container's main IP
	// 2. the remote port is in the masq range
	{
		errCh := make(chan error, 1)
		go func() {
			conn, err := l.Accept()
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			log.Infof("tcpMasq (LocalAction): Accepted connection from %s", conn.RemoteAddr())

			// Assert that the remote port is in the masq range.
			remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
			if remoteAddr.Port < 10000 || remoteAddr.Port > 10005 {
				errCh <- fmt.Errorf("unexpected remote port: %d, expected range 10000-10005", remoteAddr.Port)
				return
			}

			// Assert that the remote IP is the container's IP and not the namespace IP.
			if remoteAddr.IP.String() != ip.String() {
				errCh <- fmt.Errorf("unexpected remote IP: %s, expected %s", remoteAddr.IP.String(), ip.String())
				return
			}
			errCh <- nil
		}()

		// Wait for connection or timeout.
		select {
		case err := <-errCh:
			if err != nil {
				return err
			}
			log.Infof("tcpMasq (LocalAction): Successfully handled connection")
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timeout waiting for the client connection")
		}
	}

	return nil
}

// Timeout implements TestCase.Timeout.
func (*tcpMasq) Timeout() time.Duration {
	return 30 * time.Second
}

// deletionTest verifies flushing chains and tables.
type deletionTest struct{ containerCase }

func (*deletionTest) Name() string {
	return "deletionTest"
}

// ContainerAction implements TestCase.ContainerAction.
// Sets up drop rules in multiple chains and tables.
// Verifies that Flush Chain, Flush Table, Flush Ruleset
// and Delete Set Element clear the rules/set correctly and restore flow.
func (*deletionTest) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	tableName := "FLUSH_TEST_TABLE"
	chainName1 := "CHAIN1"
	chainName2 := "CHAIN2"
	port1 := 2402
	port2 := 2403
	port3 := 2404

	family := "ip"
	if ipv6 {
		family = "ip6"
	}

	verifyDrop := func(p int) error {
		timedCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := netutils.ListenTCP(timedCtx, p, ipv6); err == nil {
			return fmt.Errorf("packets should have been dropped on port %d, but got a packet", p)
		} else if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("error reading port %d: %v", p, err)
		}
		return nil
	}

	verifyAccept := func(p int) error {
		timedCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := netutils.ListenTCP(timedCtx, p, ipv6); err != nil {
			return fmt.Errorf("packets should have been accepted on port %d: %v", p, err)
		}
		return nil
	}

	cmds := [][]string{
		// Create a table in the inet family.
		{"add", "table", "inet", tableName},
		// Create chain 1 with accept policy.
		{"add", "chain", "inet", tableName, chainName1, "{ type filter hook input priority 0; policy accept; }"},
		// Create chain 2 with accept policy.
		{"add", "chain", "inet", tableName, chainName2, "{ type filter hook input priority 1; policy accept; }"},
		// Add rule to chain 1 to drop packets on port 1.
		{"add", "rule", "inet", tableName, chainName1, "tcp", "dport", fmt.Sprintf("%d", port1), "drop"},
		// Add rule to chain 2 to drop packets on port 2.
		{"add", "rule", "inet", tableName, chainName2, "tcp", "dport", fmt.Sprintf("%d", port2), "drop"},
	}

	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Verify both drop.
	if err := verifyDrop(port1); err != nil {
		return fmt.Errorf("port1 before flush: %v", err)
	}
	if err := verifyDrop(port2); err != nil {
		return fmt.Errorf("port2 before flush: %v", err)
	}

	// 1. Flush Chain
	if err := nftCmd([]string{"flush", "chain", "inet", tableName, chainName1}); err != nil {
		return fmt.Errorf("failed to flush chain: %v", err)
	}

	// Verify port1 accepts, port2 still drops.
	if err := verifyAccept(port1); err != nil {
		return fmt.Errorf("port1 after chain flush: %v", err)
	}
	if err := verifyDrop(port2); err != nil {
		return fmt.Errorf("port2 after chain flush: %v", err)
	}

	// 2. Flush Table
	// Add drop rule back to chain1 to make sure table flush cleans it too.
	if err := nftCmd([]string{"add", "rule", "inet", tableName, chainName1, "tcp", "dport", fmt.Sprintf("%d", port1), "drop"}); err != nil {
		return fmt.Errorf("failed to add rule back: %v", err)
	}
	if err := verifyDrop(port1); err != nil {
		return fmt.Errorf("port1 after adding back: %v", err)
	}

	if err := nftCmd([]string{"flush", "table", "inet", tableName}); err != nil {
		return fmt.Errorf("failed to flush table: %v", err)
	}

	// Verify both accept.
	if err := verifyAccept(port1); err != nil {
		return fmt.Errorf("port1 after table flush: %v", err)
	}
	if err := verifyAccept(port2); err != nil {
		return fmt.Errorf("port2 after table flush: %v", err)
	}

	// 3. Flush Ruleset
	// Clear everything to ensure a clean slate and avoid dependency on prior step behavior.
	if err := nftCmd([]string{"flush", "ruleset"}); err != nil {
		return fmt.Errorf("failed to flush ruleset before ruleset test setup: %v", err)
	}

	cmds = [][]string{
		// Create a table in the inet family.
		{"add", "table", "inet", tableName},
		// Create chain 1 with accept policy in the inet table.
		{"add", "chain", "inet", tableName, chainName1, "{ type filter hook input priority 0; policy accept; }"},
		// Create a map for ports and later delete elements from it.
		{"add", "map", "inet", tableName, "drop_ports", "{ type inet_service : verdict; }"},
		{"add", "element", "inet", tableName, "drop_ports", fmt.Sprintf("{ %d : drop, %d : drop }", port1, port2)},
		// Add rule to chain 1 to drop packets on ports in the map.
		{"add", "rule", "inet", tableName, chainName1, "tcp", "dport", "vmap", "@drop_ports"},
		// Create a table in the specified family (ip or ip6).
		{"add", "table", family, "FLUSH_RULESET_IP"},
		// Create an input chain in the new table.
		{"add", "chain", family, "FLUSH_RULESET_IP", "input", "{ type filter hook input priority 0; policy accept; }"},
		// Add rule to the input chain to drop packets on port 3.
		{"add", "rule", family, "FLUSH_RULESET_IP", "input", "tcp", "dport", fmt.Sprintf("%d", port3), "drop"},
	}

	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Verify port1, port2, and port3 drop.
	if err := verifyDrop(port1); err != nil {
		return fmt.Errorf("port1 before ruleset flush: %v", err)
	}
	if err := verifyDrop(port2); err != nil {
		return fmt.Errorf("port2 before ruleset flush: %v", err)
	}
	if err := verifyDrop(port3); err != nil {
		return fmt.Errorf("port3 before ruleset flush: %v", err)
	}

	// Delete port1 from set to test DeleteSetElements.
	if err := nftCmd([]string{"delete", "element", "inet", tableName, "drop_ports", fmt.Sprintf("{ %d }", port1)}); err != nil {
		return fmt.Errorf("failed to delete set element: %v", err)
	}

	// Verify port1 accepts, port2 and port3 still drop.
	if err := verifyAccept(port1); err != nil {
		return fmt.Errorf("port1 after set element deletion: %v", err)
	}
	if err := verifyDrop(port2); err != nil {
		return fmt.Errorf("port2 after set element deletion: %v", err)
	}
	if err := verifyDrop(port3); err != nil {
		return fmt.Errorf("port3 after set element deletion: %v", err)
	}

	if err := nftCmd([]string{"flush", "ruleset"}); err != nil {
		return fmt.Errorf("failed to flush ruleset: %v", err)
	}

	// Verify all accept.
	if err := verifyAccept(port1); err != nil {
		return fmt.Errorf("port1 after ruleset flush: %v", err)
	}
	if err := verifyAccept(port2); err != nil {
		return fmt.Errorf("port2 after ruleset flush: %v", err)
	}
	if err := verifyAccept(port3); err != nil {
		return fmt.Errorf("port3 after ruleset flush: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// Continuously sends TCP packets to all target ports (2402, 2403, 2404)
// to generate traffic for the container to filter and verify.
func (*deletionTest) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ports := []int{2402, 2403, 2404}
	errCh := make(chan error, len(ports))
	for _, port := range ports {
		go func(p int) {
			contAddr := net.TCPAddr{
				IP:   ip,
				Port: p,
			}
			for {
				select {
				case <-ctx.Done():
					errCh <- nil
					return
				default:
					// Dial with short timeout to generate frequent SYNs.
					d := net.Dialer{Timeout: 500 * time.Millisecond}
					conn, err := d.DialContext(ctx, netutils.TCPNetwork(ipv6), contAddr.String())
					if err == nil {
						conn.Close()
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		}(port)
	}

	for i := 0; i < len(ports); i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

func (*deletionTest) Timeout() time.Duration {
	return 60 * time.Second
}
