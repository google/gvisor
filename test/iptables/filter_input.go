// Copyright 2019 The gVisor Authors.
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
	dropPort         = 2401
	acceptPort       = 2402
	sendloopDuration = 2 * time.Second
	network          = "udp4"
)

func init() {
	RegisterTestCase(FilterInputDropAll{})
	RegisterTestCase(FilterInputDropDifferentUDPPort{})
	RegisterTestCase(FilterInputDropOnlyUDP{})
	RegisterTestCase(FilterInputDropTCPDestPort{})
	RegisterTestCase(FilterInputDropTCPSrcPort{})
	RegisterTestCase(FilterInputDropUDPPort{})
	RegisterTestCase(FilterInputDropUDP{})
}

// FilterInputDropUDP tests that we can drop UDP traffic.
type FilterInputDropUDP struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDP) Name() string {
	return "FilterInputDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDP) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// FilterInputDropOnlyUDP tests that "-p udp -j DROP" only affects UDP traffic.
type FilterInputDropOnlyUDP struct{}

// Name implements TestCase.Name.
func (FilterInputDropOnlyUDP) Name() string {
	return "FilterInputDropOnlyUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropOnlyUDP) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for a TCP connection, which should be allowed.
	if err := listenTCP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("failed to establish a connection %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropOnlyUDP) LocalAction(ip net.IP) error {
	// Try to establish a TCP connection with the container, which should
	// succeed.
	return connectTCP(ip, acceptPort, dropPort, sendloopDuration)
}

// FilterInputDropUDPPort tests that we can drop UDP traffic by port.
type FilterInputDropUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDPPort) Name() string {
	return "FilterInputDropUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDPPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// FilterInputDropDifferentUDPPort tests that dropping traffic for a single UDP port
// doesn't drop packets on other ports.
type FilterInputDropDifferentUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropDifferentUDPPort) Name() string {
	return "FilterInputDropDifferentUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropDifferentUDPPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on another port.
	if err := listenUDP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropDifferentUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// FilterInputDropTCPDestPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPDestPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropTCPDestPort) Name() string {
	return "FilterInputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPDestPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	if err := listenTCP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPDestPort) LocalAction(ip net.IP) error {
	if err := connectTCP(ip, dropPort, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterInputDropTCPSrcPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPSrcPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropTCPSrcPort) Name() string {
	return "FilterInputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPSrcPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "tcp", "-m", "tcp", "--sport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPSrcPort) LocalAction(ip net.IP) error {
	if err := connectTCP(ip, acceptPort, dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be acceptedi, but got accepted", dropPort)
	}

	return nil
}

// FilterInputDropAll tests that we can drop all traffic to the INPUT chain.
type FilterInputDropAll struct{}

// Name implements TestCase.Name.
func (FilterInputDropAll) Name() string {
	return "FilterInputDropAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropAll) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for all packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropAll) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// FilterInputMultiUDPRules verifies that multiple UDP rules are applied
// correctly. This has the added benefit of testing whether we're serializing
// rules correctly -- if we do it incorrectly, the iptables tool will
// misunderstand and save the wrong tables.
type FilterInputMultiUDPRules struct{}

// Name implements TestCase.Name.
func (FilterInputMultiUDPRules) Name() string {
	return "FilterInputMultiUDPRules"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputMultiUDPRules) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-j", "ACCEPT"); err != nil {
		return err
	}
	return filterTable("-L")
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputMultiUDPRules) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// FilterInputRequireProtocolUDP checks that "-m udp" requires "-p udp" to be
// specified.
type FilterInputRequireProtocolUDP struct{}

// Name implements TestCase.Name.
func (FilterInputRequireProtocolUDP) Name() string {
	return "FilterInputRequireProtocolUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputRequireProtocolUDP) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err == nil {
		return errors.New("expected iptables to fail with out \"-p udp\", but succeeded")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputRequireProtocolUDP) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}
