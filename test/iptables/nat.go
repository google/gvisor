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

package iptables

import (
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	redirectPort = 42
)

func init() {
	RegisterTestCase(NATPreRedirectUDPPort{})
	RegisterTestCase(NATPreRedirectTCPPort{})
	RegisterTestCase(NATPreRedirectTCPOutgoing{})
	RegisterTestCase(NATOutRedirectTCPIncoming{})
	RegisterTestCase(NATOutRedirectUDPPort{})
	RegisterTestCase(NATOutRedirectTCPPort{})
	RegisterTestCase(NATDropUDP{})
	RegisterTestCase(NATAcceptAll{})
	RegisterTestCase(NATPreRedirectIP{})
	RegisterTestCase(NATPreDontRedirectIP{})
	RegisterTestCase(NATPreRedirectInvert{})
	RegisterTestCase(NATOutRedirectIP{})
	RegisterTestCase(NATOutDontRedirectIP{})
	RegisterTestCase(NATOutRedirectInvert{})
	RegisterTestCase(NATRedirectRequiresProtocol{})
	RegisterTestCase(NATLoopbackSkipsPrerouting{})
}

// NATPreRedirectUDPPort tests that packets are redirected to different port.
type NATPreRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectUDPPort) Name() string {
	return "NATPreRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectUDPPort) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(redirectPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", redirectPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectUDPPort) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATPreRedirectTCPPort tests that connections are redirected on specified ports.
type NATPreRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPPort) Name() string {
	return "NATPreRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPPort) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	// Listen for TCP packets on redirect port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPPort) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, dropPort, sendloopDuration)
}

// NATPreRedirectTCPOutgoing verifies that outgoing TCP connections aren't
// affected by PREROUTING connection tracking.
type NATPreRedirectTCPOutgoing struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPOutgoing) Name() string {
	return "NATPreRedirectTCPOutgoing"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPOutgoing) ContainerAction(ip net.IP, ipv6 bool) error {
	// Redirect all incoming TCP traffic to a closed port.
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPOutgoing) LocalAction(ip net.IP, ipv6 bool) error {
	return listenTCP(acceptPort, sendloopDuration)
}

// NATOutRedirectTCPIncoming verifies that incoming TCP connections aren't
// affected by OUTPUT connection tracking.
type NATOutRedirectTCPIncoming struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPIncoming) Name() string {
	return "NATOutRedirectTCPIncoming"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPIncoming) ContainerAction(ip net.IP, ipv6 bool) error {
	// Redirect all outgoing TCP traffic to a closed port.
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectTCPIncoming) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// NATOutRedirectUDPPort tests that packets are redirected to different port.
type NATOutRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectUDPPort) Name() string {
	return "NATOutRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectUDPPort) ContainerAction(ip net.IP, ipv6 bool) error {
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)), "-A", "OUTPUT", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectUDPPort) LocalAction(ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATDropUDP tests that packets are not received in ports other than redirect
// port.
type NATDropUDP struct{}

// Name implements TestCase.Name.
func (NATDropUDP) Name() string {
	return "NATDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATDropUDP) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been redirected to port %d", acceptPort, redirectPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATDropUDP) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATAcceptAll tests that all UDP packets are accepted.
type NATAcceptAll struct{}

// Name implements TestCase.Name.
func (NATAcceptAll) Name() string {
	return "NATAcceptAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATAcceptAll) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "ACCEPT"); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATAcceptAll) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATOutRedirectIP uses iptables to select packets based on destination IP and
// redirects them.
type NATOutRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutRedirectIP) Name() string {
	return "NATOutRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectIP) ContainerAction(ip net.IP, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)),
		"-A", "OUTPUT",
		"-d", nowhereIP(ipv6),
		"-p", "udp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectIP) LocalAction(ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATOutDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATOutDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutDontRedirectIP) Name() string {
	return "NATOutDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutDontRedirectIP) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "OUTPUT", "-d", localIP(ipv6), "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutDontRedirectIP) LocalAction(ip net.IP, ipv6 bool) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// NATOutRedirectInvert tests that iptables can match with "! -d".
type NATOutRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATOutRedirectInvert) Name() string {
	return "NATOutRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectInvert) ContainerAction(ip net.IP, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := "192.0.2.2"
	if ipv6 {
		dest = "2001:db8::2"
	}
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)),
		"-A", "OUTPUT",
		"!", "-d", dest,
		"-p", "udp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectInvert) LocalAction(ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATPreRedirectIP tests that we can use iptables to select packets based on
// destination IP and redirect them.
type NATPreRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreRedirectIP) Name() string {
	return "NATPreRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectIP) ContainerAction(ip net.IP, ipv6 bool) error {
	addrs, err := localAddrs(ipv6)
	if err != nil {
		return err
	}

	var rules [][]string
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "PREROUTING", "-p", "udp", "-d", addr, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)})
	}
	if err := natTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectIP) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, dropPort, sendloopDuration)
}

// NATPreDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATPreDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreDontRedirectIP) Name() string {
	return "NATPreDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreDontRedirectIP) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreDontRedirectIP) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATPreRedirectInvert tests that iptables can match with "! -d".
type NATPreRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATPreRedirectInvert) Name() string {
	return "NATPreRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectInvert) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "!", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectInvert) LocalAction(ip net.IP, ipv6 bool) error {
	return spawnUDPLoop(ip, dropPort, sendloopDuration)
}

// NATRedirectRequiresProtocol tests that use of the --to-ports flag requires a
// protocol to be specified with -p.
type NATRedirectRequiresProtocol struct{}

// Name implements TestCase.Name.
func (NATRedirectRequiresProtocol) Name() string {
	return "NATRedirectRequiresProtocol"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectRequiresProtocol) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err == nil {
		return errors.New("expected an error using REDIRECT --to-ports without a protocol")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectRequiresProtocol) LocalAction(ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATOutRedirectTCPPort tests that connections are redirected on specified ports.
type NATOutRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPPort) Name() string {
	return "NATOutRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPPort) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	timeout := 20 * time.Second
	localAddr := net.TCPAddr{
		IP:   net.ParseIP(localIP(ipv6)),
		Port: acceptPort,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Accept connections on port.
	lConn.SetDeadline(time.Now().Add(timeout))
	err = connectTCP(ip, dropPort, timeout)
	if err != nil {
		return err
	}

	conn, err := lConn.AcceptTCP()
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectTCPPort) LocalAction(ip net.IP, ipv6 bool) error {
	return nil
}

// NATLoopbackSkipsPrerouting tests that packets sent via loopback aren't
// affected by PREROUTING rules.
type NATLoopbackSkipsPrerouting struct{}

// Name implements TestCase.Name.
func (NATLoopbackSkipsPrerouting) Name() string {
	return "NATLoopbackSkipsPrerouting"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATLoopbackSkipsPrerouting) ContainerAction(ip net.IP, ipv6 bool) error {
	// Redirect anything sent to localhost to an unused port.
	dest := []byte{127, 0, 0, 1}
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection via localhost. If the PREROUTING rule did apply to
	// loopback traffic, the connection would fail.
	sendCh := make(chan error)
	go func() {
		sendCh <- connectTCP(dest, acceptPort, sendloopDuration)
	}()

	if err := listenTCP(acceptPort, sendloopDuration); err != nil {
		return err
	}
	return <-sendCh
}

// LocalAction implements TestCase.LocalAction.
func (NATLoopbackSkipsPrerouting) LocalAction(ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// loopbackTests runs an iptables rule and ensures that packets sent to
// dest:dropPort are received by localhost:acceptPort.
func loopbackTest(ipv6 bool, dest net.IP, args ...string) error {
	if err := natTable(ipv6, args...); err != nil {
		return err
	}
	sendCh := make(chan error)
	listenCh := make(chan error)
	go func() {
		sendCh <- sendUDPLoop(dest, dropPort, sendloopDuration)
	}()
	go func() {
		listenCh <- listenUDP(acceptPort, sendloopDuration)
	}()
	select {
	case err := <-listenCh:
		if err != nil {
			return err
		}
	case <-time.After(sendloopDuration):
		return errors.New("timed out")
	}
	// sendCh will always take the full sendloop time.
	return <-sendCh
}
