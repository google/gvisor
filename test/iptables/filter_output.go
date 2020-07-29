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
	RegisterTestCase(FilterOutputAcceptTCPOwner{})
	RegisterTestCase(FilterOutputDropTCPOwner{})
	RegisterTestCase(FilterOutputAcceptUDPOwner{})
	RegisterTestCase(FilterOutputDropUDPOwner{})
	RegisterTestCase(FilterOutputOwnerFail{})
	RegisterTestCase(FilterOutputAcceptGIDOwner{})
	RegisterTestCase(FilterOutputDropGIDOwner{})
	RegisterTestCase(FilterOutputInvertGIDOwner{})
	RegisterTestCase(FilterOutputInvertUIDOwner{})
	RegisterTestCase(FilterOutputInvertUIDAndGIDOwner{})
	RegisterTestCase(FilterOutputInterfaceAccept{})
	RegisterTestCase(FilterOutputInterfaceDrop{})
	RegisterTestCase(FilterOutputInterface{})
	RegisterTestCase(FilterOutputInterfaceBeginsWith{})
	RegisterTestCase(FilterOutputInterfaceInvertDrop{})
	RegisterTestCase(FilterOutputInterfaceInvertAccept{})
}

// FilterOutputDropTCPDestPort tests that connections are not accepted on
// specified source ports.
type FilterOutputDropTCPDestPort struct{}

// Name implements TestCase.Name.
func (FilterOutputDropTCPDestPort) Name() string {
	return "FilterOutputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropTCPDestPort) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "1024:65535", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropTCPDestPort) LocalAction(ip net.IP, ipv6 bool) error {
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
func (FilterOutputDropTCPSrcPort) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--sport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	if err := listenTCP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropTCPSrcPort) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterOutputAcceptTCPOwner tests that TCP connections from uid owner are accepted.
type FilterOutputAcceptTCPOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputAcceptTCPOwner) Name() string {
	return "FilterOutputAcceptTCPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputAcceptTCPOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputAcceptTCPOwner) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// FilterOutputDropTCPOwner tests that TCP connections from uid owner are dropped.
type FilterOutputDropTCPOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputDropTCPOwner) Name() string {
	return "FilterOutputDropTCPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropTCPOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should be dropped, but got accepted", acceptPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropTCPOwner) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should be dropped, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputAcceptUDPOwner tests that UDP packets from uid owner are accepted.
type FilterOutputAcceptUDPOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputAcceptUDPOwner) Name() string {
	return "FilterOutputAcceptUDPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputAcceptUDPOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "--uid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Send UDP packets on acceptPort.
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputAcceptUDPOwner) LocalAction(ip net.IP, ipv6 bool) error {
	// Listen for UDP packets on acceptPort.
	return listenUDP(acceptPort, sendloopDuration)
}

// FilterOutputDropUDPOwner tests that UDP packets from uid owner are dropped.
type FilterOutputDropUDPOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputDropUDPOwner) Name() string {
	return "FilterOutputDropUDPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropUDPOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "--uid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Send UDP packets on dropPort.
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropUDPOwner) LocalAction(ip net.IP, ipv6 bool) error {
	// Listen for UDP packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets should not be received")
	}

	return nil
}

// FilterOutputOwnerFail tests that without uid/gid option, owner rule
// will fail.
type FilterOutputOwnerFail struct{}

// Name implements TestCase.Name.
func (FilterOutputOwnerFail) Name() string {
	return "FilterOutputOwnerFail"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputOwnerFail) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "-j", "ACCEPT"); err == nil {
		return fmt.Errorf("Invalid argument")
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputOwnerFail) LocalAction(ip net.IP, ipv6 bool) error {
	// no-op.
	return nil
}

// FilterOutputAcceptGIDOwner tests that TCP connections from gid owner are accepted.
type FilterOutputAcceptGIDOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputAcceptGIDOwner) Name() string {
	return "FilterOutputAcceptGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputAcceptGIDOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--gid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputAcceptGIDOwner) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// FilterOutputDropGIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputDropGIDOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputDropGIDOwner) Name() string {
	return "FilterOutputDropGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputDropGIDOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--gid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDropGIDOwner) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInvertGIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputInvertGIDOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputInvertGIDOwner) Name() string {
	return "FilterOutputInvertGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInvertGIDOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--gid-owner", "root", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInvertGIDOwner) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInvertUIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputInvertUIDOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputInvertUIDOwner) Name() string {
	return "FilterOutputInvertUIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInvertUIDOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "root", "-j", "DROP"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInvertUIDOwner) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// FilterOutputInvertUIDAndGIDOwner tests that TCP connections from uid and gid
// owner are dropped.
type FilterOutputInvertUIDAndGIDOwner struct{}

// Name implements TestCase.Name.
func (FilterOutputInvertUIDAndGIDOwner) Name() string {
	return "FilterOutputInvertUIDAndGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInvertUIDAndGIDOwner) ContainerAction(ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "root", "!", "--gid-owner", "root", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInvertUIDAndGIDOwner) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
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
func (FilterOutputDestination) ContainerAction(ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT"},
		{"-P", "OUTPUT", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputDestination) LocalAction(ip net.IP, ipv6 bool) error {
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
func (FilterOutputInvertDestination) ContainerAction(ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "!", "-d", localIP(ipv6), "-j", "ACCEPT"},
		{"-P", "OUTPUT", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInvertDestination) LocalAction(ip net.IP, ipv6 bool) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// FilterOutputInterfaceAccept tests that packets are sent via interface
// matching the iptables rule.
type FilterOutputInterfaceAccept struct{}

// Name implements TestCase.Name.
func (FilterOutputInterfaceAccept) Name() string {
	return "FilterOutputInterfaceAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterfaceAccept) ContainerAction(ip net.IP, ipv6 bool) error {
	ifname, ok := getInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", ifname, "-j", "ACCEPT"); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterfaceAccept) LocalAction(ip net.IP, ipv6 bool) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// FilterOutputInterfaceDrop tests that packets are not sent via interface
// matching the iptables rule.
type FilterOutputInterfaceDrop struct{}

// Name implements TestCase.Name.
func (FilterOutputInterfaceDrop) Name() string {
	return "FilterOutputInterfaceDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterfaceDrop) ContainerAction(ip net.IP, ipv6 bool) error {
	ifname, ok := getInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", ifname, "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterfaceDrop) LocalAction(ip net.IP, ipv6 bool) error {
	if err := listenUDP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets should not be received on port %v, but are received", acceptPort)
	}

	return nil
}

// FilterOutputInterface tests that packets are sent via interface which is
// not matching the interface name in the iptables rule.
type FilterOutputInterface struct{}

// Name implements TestCase.Name.
func (FilterOutputInterface) Name() string {
	return "FilterOutputInterface"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterface) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", "lo", "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterface) LocalAction(ip net.IP, ipv6 bool) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// FilterOutputInterfaceBeginsWith tests that packets are not sent via an
// interface which begins with the given interface name.
type FilterOutputInterfaceBeginsWith struct{}

// Name implements TestCase.Name.
func (FilterOutputInterfaceBeginsWith) Name() string {
	return "FilterOutputInterfaceBeginsWith"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterfaceBeginsWith) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", "e+", "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterfaceBeginsWith) LocalAction(ip net.IP, ipv6 bool) error {
	if err := listenUDP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets should not be received on port %v, but are received", acceptPort)
	}

	return nil
}

// FilterOutputInterfaceInvertDrop tests that we selectively do not send
// packets via interface not matching the interface name.
type FilterOutputInterfaceInvertDrop struct{}

// Name implements TestCase.Name.
func (FilterOutputInterfaceInvertDrop) Name() string {
	return "FilterOutputInterfaceInvertDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterfaceInvertDrop) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	if err := listenTCP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterfaceInvertDrop) LocalAction(ip net.IP, ipv6 bool) error {
	if err := connectTCP(ip, acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInterfaceInvertAccept tests that we can selectively send packets
// not matching the specific outgoing interface.
type FilterOutputInterfaceInvertAccept struct{}

// Name implements TestCase.Name.
func (FilterOutputInterfaceInvertAccept) Name() string {
	return "FilterOutputInterfaceInvertAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterOutputInterfaceInvertAccept) ContainerAction(ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (FilterOutputInterfaceInvertAccept) LocalAction(ip net.IP, ipv6 bool) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}
