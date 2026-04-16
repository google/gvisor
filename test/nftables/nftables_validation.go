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
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/test/netutils"
)

// Add test cases here.
var validationTests = []TestCase{
	&JumpAndDropAll{},
	&tcpDNAT{},
	&tcpSNAT{},
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
		// Add rule to BASE_CHAIN to jump to FORWARDS_TO_DROP_CHAIN.
		{"add", "rule", "inet", tableName, "BASE_CHAIN", "jump", "FORWARDS_TO_DROP_CHAIN"},
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

// Timeout returns the timeout for the test case.
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

func (*tcpDNAT) Timeout() time.Duration {
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

// Timeout returns the timeout for the test case.
func (*tcpSNAT) Timeout() time.Duration {
	return 30 * time.Second
}
