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

const (
	redirectPort = 42
)

func init() {
	RegisterTestCase(NATRedirectUDPPort{})
	RegisterTestCase(NATDropUDP{})
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

// NATDropUDP tests that packets are not received in ports other than redirect port.
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
