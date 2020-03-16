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
	RegisterTestCase(NATRedirectUDPPort{})
	RegisterTestCase(NATRedirectTCPPort{})
	RegisterTestCase(NATDropUDP{})
	RegisterTestCase(NATAcceptAll{})
	RegisterTestCase(NATPreRedirectIP{})
	RegisterTestCase(NATPreDontRedirectIP{})
	RegisterTestCase(NATPreRedirectInvert{})
	RegisterTestCase(NATOutRedirectIP{})
	RegisterTestCase(NATOutDontRedirectIP{})
	RegisterTestCase(NATOutRedirectInvert{})
	RegisterTestCase(NATRedirectRequiresProtocol{})
}

// NATRedirectUDPPort tests that packets are redirected to different port.
type NATRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATRedirectUDPPort) Name() string {
	return "NATRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectUDPPort) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(redirectPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", redirectPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATRedirectTCPPort tests that connections are redirected on specified ports.
type NATRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATRedirectTCPPort) Name() string {
	return "NATRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectTCPPort) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	// Listen for TCP packets on redirect port.
	return listenTCP(redirectPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectTCPPort) LocalAction(ip net.IP) error {
	return connectTCP(ip, dropPort, sendloopDuration)
}

// NATDropUDP tests that packets are not received in ports other than redirect
// port.
type NATDropUDP struct{}

// Name implements TestCase.Name.
func (NATDropUDP) Name() string {
	return "NATDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATDropUDP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been redirected to port %d", acceptPort, redirectPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATDropUDP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATAcceptAll tests that all UDP packets are accepted.
type NATAcceptAll struct{}

// Name implements TestCase.Name.
func (NATAcceptAll) Name() string {
	return "NATAcceptAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATAcceptAll) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "ACCEPT"); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATAcceptAll) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATOutRedirectIP uses iptables to select packets based on destination IP and
// redirects them.
type NATOutRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutRedirectIP) Name() string {
	return "NATOutRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectIP) ContainerAction(ip net.IP) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := net.IP([]byte{200, 0, 0, 2})
	return loopbackTest(dest, "-A", "OUTPUT", "-d", dest.String(), "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectIP) LocalAction(ip net.IP) error {
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
func (NATOutDontRedirectIP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "OUTPUT", "-d", localIP, "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutDontRedirectIP) LocalAction(ip net.IP) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// NATOutRedirectInvert tests that iptables can match with "! -d".
type NATOutRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATOutRedirectInvert) Name() string {
	return "NATOutRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectInvert) ContainerAction(ip net.IP) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := []byte{200, 0, 0, 3}
	destStr := "200.0.0.2"
	return loopbackTest(dest, "-A", "OUTPUT", "!", "-d", destStr, "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectInvert) LocalAction(ip net.IP) error {
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
func (NATPreRedirectIP) ContainerAction(ip net.IP) error {
	addrs, err := localAddrs()
	if err != nil {
		return err
	}

	var rules [][]string
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "PREROUTING", "-p", "udp", "-d", addr, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)})
	}
	if err := natTableRules(rules); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectIP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// NATPreDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATPreDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreDontRedirectIP) Name() string {
	return "NATPreDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreDontRedirectIP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreDontRedirectIP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATPreRedirectInvert tests that iptables can match with "! -d".
type NATPreRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATPreRedirectInvert) Name() string {
	return "NATPreRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectInvert) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "!", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectInvert) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// NATRedirectRequiresProtocol tests that use of the --to-ports flag requires a
// protocol to be specified with -p.
type NATRedirectRequiresProtocol struct{}

// Name implements TestCase.Name.
func (NATRedirectRequiresProtocol) Name() string {
	return "NATRedirectRequiresProtocol"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectRequiresProtocol) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err == nil {
		return errors.New("expected an error using REDIRECT --to-ports without a protocol")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectRequiresProtocol) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// loopbackTests runs an iptables rule and ensures that packets sent to
// dest:dropPort are received by localhost:acceptPort.
func loopbackTest(dest net.IP, args ...string) error {
	if err := natTable(args...); err != nil {
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
