// Copyright 2026 The gVisor Authors.
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

// Package natfwd reproduces the node->ClusterIP->pod return-path payload drop.
//
// The "node" stack has two NICs (eth0, cni0) and forwarding enabled. A client
// socket on the node is bound to eth0's address and connects to a backend that
// is reachable via cni0; POSTROUTING MASQUERADE rewrites the source to cni0's
// address on the way out. The backend's reply returns to cni0's address; the
// PREROUTING conntrack SNAT-reversal rewrites the destination back to eth0's
// address, but the packet arrived on cni0 -- a different NIC than eth0 -- so it
// takes the forward-then-local re-delivery path
// (ipv4.forwardUnicastPacket -> findEndpointWithAddress -> handleValidatedPacket)
// back to the node's own client socket on eth0.
//
// The TCP handshake completes (control segments survive that path), but the
// backend's payload-bearing DATA reply is dropped before reaching the client.
// Plain cross-NIC delivery (TestForwarding) and plain DNAT-forward
// (TestNATCrossNICForwardPayload... in prior iterations) both deliver payload
// fine, so this isolates the MASQUERADE-reversal-cross-NIC case.
package natfwd

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	eth0ID       = 1
	cni0ID       = 2
	backendNICID = 1
	cni0Name     = "cni0"
	serverPort   = 8080
)

var (
	nodeEth0Addr = testutil.MustParse4("192.168.1.2") // node's "eth0"
	nodeCni0Addr = testutil.MustParse4("10.44.0.1")   // node's "cni0" (masquerade src)
	backendAddr  = testutil.MustParse4("10.44.0.2")   // backend "pod"
)

func addAddr(t *testing.T, s *stack.Stack, nic tcpip.NICID, addr tcpip.Address) {
	t.Helper()
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}
	if err := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %v): %s", nic, addr, err)
	}
}

// installMasquerade programs POSTROUTING to MASQUERADE traffic leaving cni0.
func installMasquerade(t *testing.T, s *stack.Stack) {
	t.Helper()
	table := stack.Table{
		Rules: []stack.Rule{
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Prerouting idx 0
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Input idx 1
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Forward idx 2
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Output idx 3
			// Postrouting idx 4: MASQUERADE out cni0
			{
				Filter: stack.IPHeaderFilter{Protocol: header.TCPProtocolNumber, CheckProtocol: true, OutputInterface: cni0Name},
				Target: &stack.MasqueradeTarget{NetworkProtocol: ipv4.ProtocolNumber},
			},
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // idx 5
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     2,
			stack.Output:      3,
			stack.Postrouting: 4,
		},
	}
	s.IPTables().ForceReplaceTable(stack.NATID, table, false /* ipv6 */)
}

func TestNATMasqueradeReplyCrossNICPayload(t *testing.T) {
	cni0Ep, backendEp := pipe.New("" /* linkAddr1 */, "" /* linkAddr2 */, 1500)
	eth0Ep, _ := pipe.New("", "", 1500) // eth0 link end is unused (client is local; reply returns via cni0)

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	node := stack.New(opts)
	backend := stack.New(opts)

	if err := node.CreateNIC(eth0ID, eth0Ep); err != nil {
		t.Fatalf("node.CreateNIC(eth0): %s", err)
	}
	if err := node.CreateNICWithOptions(cni0ID, cni0Ep, stack.NICOptions{Name: cni0Name}); err != nil {
		t.Fatalf("node.CreateNICWithOptions(cni0): %s", err)
	}
	addAddr(t, node, eth0ID, nodeEth0Addr)
	addAddr(t, node, cni0ID, nodeCni0Addr)

	if err := backend.CreateNIC(backendNICID, backendEp); err != nil {
		t.Fatalf("backend.CreateNIC: %s", err)
	}
	addAddr(t, backend, backendNICID, backendAddr)

	node.SetRouteTable([]tcpip.Route{
		{Destination: backendAddr.WithPrefix().Subnet(), NIC: cni0ID},
		{Destination: nodeEth0Addr.WithPrefix().Subnet(), NIC: eth0ID},
	})
	backend.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: backendNICID},
	})

	if err := node.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwarding: %s", err)
	}
	installMasquerade(t, node)

	// Backend server echoes a reply payload.
	ln, err := gonet.ListenTCP(backend, tcpip.FullAddress{Addr: backendAddr, Port: serverPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP(backend): %s", err)
	}
	defer ln.Close()

	reply := []byte("BACKEND-REPLY-PAYLOAD")
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil { // read the client's request first
			srvErr <- err
			return
		}
		if _, err := conn.Write(reply); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	// Node client: bound to eth0, connects to backend via cni0 (masqueraded).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialTCPWithBind(ctx, node,
		tcpip.FullAddress{Addr: nodeEth0Addr}, /* localAddr = eth0 */
		tcpip.FullAddress{Addr: backendAddr, Port: serverPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("node DialTCPWithBind (eth0->backend via cni0): %s (handshake failed)", err)
	}
	defer conn.Close()

	t.Logf("node client LocalAddr=%v (want eth0=%v); backend reachable only via cni0, so a reply to eth0 must cross NICs", conn.LocalAddr(), nodeEth0Addr)

	if _, err := conn.Write([]byte("REQ")); err != nil {
		t.Fatalf("node conn.Write: %s", err)
	}

	// The reply (backend->node, un-SNAT'd cross-NIC to the node's eth0 socket).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("node did not receive the reply payload: %s -- dropped on MASQUERADE-reversal cross-NIC forward-then-local re-delivery", err)
	}
	if got := buf[:n]; !bytes.Equal(got, reply) {
		t.Errorf("node received %q, want %q", got, reply)
	}
	if e := <-srvErr; e != nil {
		t.Fatalf("backend side: %s", e)
	}
}

// TestNATMasqueradeReplyThroughBridge is the same node-as-client MASQUERADE
// scenario, but cni0 is an actual gVisor BRIDGE NIC with an enslaved veth port
// to the pod (the real SUT topology). The reply from the pod traverses the
// bridge module's dataplane on its way back to the node's eth0 socket. If this
// drops the payload while the plain-NIC TestNATMasqueradeReplyCrossNICPayload
// delivers it, the bug is isolated to the bridge module.
func TestNATMasqueradeReplyThroughBridge(t *testing.T) {
	const (
		bEth0ID   = 1
		bCni0ID   = 2 // the bridge NIC (named cni0Name so MASQUERADE matches)
		bVethNode = 3
		podVethID = 1
		bServPort = 8080
	)
	var (
		bEth0Addr = testutil.MustParse4("192.168.1.2")
		bCni0Addr = testutil.MustParse4("10.44.0.1")
		bPodAddr  = testutil.MustParse4("10.44.0.2")
	)

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	node := stack.New(opts)
	pod := stack.New(opts)

	// eth0: plain L3 NIC (its link is unused; the reply is re-delivered locally).
	eth0Ep := channel.New(4, 1500, "\x02\x00\x00\x00\x00\x01")
	if err := node.CreateNIC(bEth0ID, eth0Ep); err != nil {
		t.Fatalf("node.CreateNIC(eth0): %s", err)
	}
	addAddr(t, node, bEth0ID, bEth0Addr)

	// cni0: bridge NIC (holds 10.44.0.1) with an enslaved veth port to the pod.
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress("\x02\x00\x00\x00\x0a\x01")
	veth2.SetLinkAddress("\x02\x00\x00\x00\x0a\x02")
	br := stack.NewBridgeEndpoint(1500)
	br.SetLinkAddress("\x02\x00\x00\x00\x0b\x01")
	if err := node.CreateNICWithOptions(bCni0ID, br, stack.NICOptions{Name: cni0Name}); err != nil {
		t.Fatalf("node.CreateNICWithOptions(cni0 bridge): %s", err)
	}
	if err := node.CreateNIC(bVethNode, ethernet.New(veth1)); err != nil {
		t.Fatalf("node.CreateNIC(veth-node): %s", err)
	}
	if err := node.SetNICCoordinator(bVethNode, bCni0ID); err != nil {
		t.Fatalf("node.SetNICCoordinator(veth-node -> cni0): %s", err)
	}
	addAddr(t, node, bCni0ID, bCni0Addr)

	if err := pod.CreateNIC(podVethID, ethernet.New(veth2)); err != nil {
		t.Fatalf("pod.CreateNIC(veth-pod): %s", err)
	}
	addAddr(t, pod, podVethID, bPodAddr)

	node.SetRouteTable([]tcpip.Route{
		{Destination: bPodAddr.WithPrefix().Subnet(), NIC: bCni0ID},
		{Destination: bEth0Addr.WithPrefix().Subnet(), NIC: bEth0ID},
	})
	pod.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: podVethID},
	})

	if err := node.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwarding: %s", err)
	}
	installMasquerade(t, node) // POSTROUTING MASQUERADE out cni0Name

	ln, err := gonet.ListenTCP(pod, tcpip.FullAddress{Addr: bPodAddr, Port: bServPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP(pod): %s", err)
	}
	defer ln.Close()

	reply := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 64*1024) // 256 KiB, many segments
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil {
			srvErr <- err
			return
		}
		if _, err := conn.Write(reply); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := gonet.DialTCPWithBind(ctx, node,
		tcpip.FullAddress{Addr: bEth0Addr},
		tcpip.FullAddress{Addr: bPodAddr, Port: bServPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("node DialTCPWithBind (eth0->pod via cni0 bridge): %s (handshake failed through bridge)", err)
	}
	defer conn.Close()
	t.Logf("node client LocalAddr=%v (want eth0=%v); pod reply returns through the cni0 BRIDGE and must cross to eth0", conn.LocalAddr(), bEth0Addr)

	if _, err := conn.Write([]byte("REQ")); err != nil {
		t.Fatalf("node conn.Write: %s", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("node read of pod reply failed after %d/%d bytes: %s -- payload dropped on the bridge-module return path (MASQUERADE-reversal cross-NIC re-delivery through cni0 bridge)", len(got), len(reply), err)
	}
	if len(got) != len(reply) {
		t.Fatalf("node received %d bytes, want %d -- data segment(s) dropped on the bridge return path", len(got), len(reply))
	}
	if !bytes.Equal(got, reply) {
		t.Errorf("node received corrupted payload through the bridge")
	}
	if e := <-srvErr; e != nil {
		t.Fatalf("pod side: %s", e)
	}
}

// TestNATClusterIPNodeToPod tests a node client dialing a ClusterIP address
// where OUTPUT DNAT rewrites the destination to a pod on the bridge, and
// POSTROUTING MASQUERADE rewrites the source to the bridge address.
func TestNATClusterIPNodeToPod(t *testing.T) {
	const (
		cEth0ID   = 1
		cCni0ID   = 2
		cVethNode = 3
		cPodNICID = 1
		cPort     = 8080
	)
	var (
		cEth0Addr      = testutil.MustParse4("192.168.1.2")
		cCni0Addr      = testutil.MustParse4("10.44.0.1")
		cPodAddr       = testutil.MustParse4("10.44.0.2")
		cClusterIPAddr = testutil.MustParse4("10.99.0.10")
	)

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	node := stack.New(opts)
	pod := stack.New(opts)

	eth0Ep := channel.New(4, 1500, "\x02\x00\x00\x00\x00\x01")
	if err := node.CreateNIC(cEth0ID, eth0Ep); err != nil {
		t.Fatalf("node.CreateNIC(eth0): %s", err)
	}
	addAddr(t, node, cEth0ID, cEth0Addr)

	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress("\x02\x00\x00\x00\x0a\x01")
	veth2.SetLinkAddress("\x02\x00\x00\x00\x0a\x02")
	br := stack.NewBridgeEndpoint(1500)
	br.SetLinkAddress("\x02\x00\x00\x00\x0b\x01")
	if err := node.CreateNICWithOptions(cCni0ID, br, stack.NICOptions{Name: cni0Name}); err != nil {
		t.Fatalf("node.CreateNICWithOptions(cni0): %s", err)
	}
	if err := node.CreateNIC(cVethNode, ethernet.New(veth1)); err != nil {
		t.Fatalf("node.CreateNIC(veth-node): %s", err)
	}
	if err := node.SetNICCoordinator(cVethNode, cCni0ID); err != nil {
		t.Fatalf("node.SetNICCoordinator: %s", err)
	}
	addAddr(t, node, cCni0ID, cCni0Addr)

	if err := pod.CreateNIC(cPodNICID, ethernet.New(veth2)); err != nil {
		t.Fatalf("pod.CreateNIC: %s", err)
	}
	addAddr(t, pod, cPodNICID, cPodAddr)

	// Node routes: pod subnet goes to cni0, everything else (including ClusterIP) defaults to eth0.
	node.SetRouteTable([]tcpip.Route{
		{Destination: cPodAddr.WithPrefix().Subnet(), NIC: cCni0ID},
		{Destination: header.IPv4EmptySubnet, NIC: cEth0ID},
	})
	pod.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: cPodNICID},
	})

	if err := node.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwarding: %s", err)
	}

	// Install OUTPUT DNAT (ClusterIP -> pod) + POSTROUTING MASQUERADE
	table := stack.Table{
		Rules: []stack.Rule{
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Prerouting 0
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Input 1
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Forward 2
			// Output 3: DNAT ClusterIP -> pod
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      header.TCPProtocolNumber,
					CheckProtocol: true,
					Dst:           cClusterIPAddr,
					DstMask:       testutil.MustParse4("255.255.255.255"),
				},
				Target: &stack.DNATTarget{
					NetworkProtocol: ipv4.ProtocolNumber,
					Addr:            cPodAddr,
					Port:            cPort,
					ChangeAddress:   true,
					ChangePort:      true,
				},
			},
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Output 4
			// Postrouting 5: MASQUERADE out cni0
			{
				Filter: stack.IPHeaderFilter{
					Protocol:        header.TCPProtocolNumber,
					CheckProtocol:   true,
					OutputInterface: cni0Name,
				},
				Target: &stack.MasqueradeTarget{NetworkProtocol: ipv4.ProtocolNumber},
			},
			{Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}, // Postrouting 6
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     2,
			stack.Output:      3,
			stack.Postrouting: 5,
		},
	}
	node.IPTables().ForceReplaceTable(stack.NATID, table, false)

	// Start server on pod
	ln, err := gonet.ListenTCP(pod, tcpip.FullAddress{Addr: cPodAddr, Port: cPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP: %s", err)
	}
	defer ln.Close()

	reply := []byte("CLUSTERIP-POD-REPLY-OK")
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil {
			srvErr <- err
			return
		}
		if _, err := conn.Write(reply); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	// Node dials the ClusterIP. OUTPUT DNAT rewrites the destination to the pod
	// and the post-DNAT reroute must select cni0 (not the eth0 default route) so
	// POSTROUTING MASQUERADE fires and the pod's reply can return.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, node, tcpip.FullAddress{Addr: cClusterIPAddr, Port: cPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("node DialContextTCP to ClusterIP %v: %s -- SYN likely egressed eth0 instead of cni0 after the DNAT reroute", cClusterIPAddr, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("REQ")); err != nil {
		t.Fatalf("node conn.Write: %s", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("node read of pod reply failed after %d byte(s): %s -- payload dropped on the ClusterIP DNAT+MASQUERADE return path", len(got), err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("node received %q, want %q", got, reply)
	}
	if e := <-srvErr; e != nil {
		t.Fatalf("pod side: %s", e)
	}

	// The rerouted SYN must leave via cni0; the eth0 uplink must stay idle.
	if n := eth0Ep.Drain(); n != 0 {
		t.Errorf("eth0 saw %d packet(s); DNATed traffic must egress cni0, not the eth0 default route", n)
	}
}
