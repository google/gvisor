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
	"fmt"
	"net"
)

func init() {
	RegisterTestCase(FilterOutputDropTCPDestPort{})
	RegisterTestCase(FilterOutputDropTCPSrcPort{})
	RegisterTestCase(FilterOutputDestination{})
	RegisterTestCase(FilterOutputInvertDestination{})
}

// FilterOutputDropTCPDestPort tests that connections are not accepted on
// specified source ports.
type FilterOutputDropTCPDestPort struct{}

// Name implements TestCase.Name.
func (FilterOutputDropTCPDestPort) Name() string {
	return "FilterOutputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropTCPDestPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropTCPDestPort) LocalAction(ip net.IP) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterOutputDropTCPSrcPort tests that connections are not accepted on
// specified source ports.
type FilterOutputDropTCPSrcPort struct{}

// Name implements TestCase.Name.
func (FilterOutputDropTCPSrcPort) Name() string {
	return "FilterOutputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropTCPSrcPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--sport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	if err := listenTCP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropTCPSrcPort) LocalAction(ip net.IP) error {
	if err := connectTCP(ip, dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterOutputDestination tests that we can selectively allow packets to
// certain destinations.
type FilterOutputDestination struct{}

// Name implements TestCase.Name.
func (FilterOutputDestination) Name() string {
	return "FilterOutputDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDestination) ContainerAction(ip net.IP) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT"},
		{"-P", "OUTPUT", "DROP"},
	}
	if err := filterTableRules(rules); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDestination) LocalAction(ip net.IP) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// FilterOutputInvertDestination tests that we can selectively allow packets
// not headed for a particular destination.
type FilterOutputInvertDestination struct{}

// Name implements TestCase.Name.
func (FilterOutputInvertDestination) Name() string {
	return "FilterOutputInvertDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInvertDestination) ContainerAction(ip net.IP) error {
	rules := [][]string{
		{"-A", "OUTPUT", "!", "-d", localIP, "-j", "ACCEPT"},
		{"-P", "OUTPUT", "DROP"},
	}
	if err := filterTableRules(rules); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInvertDestination) LocalAction(ip net.IP) error {
	return listenUDP(acceptPort, sendloopDuration)
}
