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
	"context"
	"errors"
	"fmt"
	"net"
)

func init() {
	RegisterTestCase(&FilterOutputDropTCPDestPort{})
	RegisterTestCase(&FilterOutputDropTCPSrcPort{})
	RegisterTestCase(&FilterOutputDestination{})
	RegisterTestCase(&FilterOutputInvertDestination{})
	RegisterTestCase(&FilterOutputAcceptTCPOwner{})
	RegisterTestCase(&FilterOutputDropTCPOwner{})
	RegisterTestCase(&FilterOutputAcceptUDPOwner{})
	RegisterTestCase(&FilterOutputDropUDPOwner{})
	RegisterTestCase(&FilterOutputOwnerFail{})
	RegisterTestCase(&FilterOutputAcceptGIDOwner{})
	RegisterTestCase(&FilterOutputDropGIDOwner{})
	RegisterTestCase(&FilterOutputInvertGIDOwner{})
	RegisterTestCase(&FilterOutputInvertUIDOwner{})
	RegisterTestCase(&FilterOutputInvertUIDAndGIDOwner{})
	RegisterTestCase(&FilterOutputInterfaceAccept{})
	RegisterTestCase(&FilterOutputInterfaceDrop{})
	RegisterTestCase(&FilterOutputInterface{})
	RegisterTestCase(&FilterOutputInterfaceBeginsWith{})
	RegisterTestCase(&FilterOutputInterfaceInvertDrop{})
	RegisterTestCase(&FilterOutputInterfaceInvertAccept{})
	RegisterTestCase(&FilterOutputInvertSportAccept{})
	RegisterTestCase(&FilterOutputInvertSportDrop{})
	RegisterTestCase(&FilterOutputAcceptInvertSrcPorts{})
	RegisterTestCase(&FilterOutputDropSrcPorts{})
	RegisterTestCase(&FilterOutputAcceptInvertPorts{})
}

// multiportPortCountLimit is the maximum number of
// ports that can be specified for a multiport match.
const multiportPortCountLimit = 15

// FilterOutputDropTCPDestPort tests that connections are not accepted on
// specified source ports.
type FilterOutputDropTCPDestPort struct{ baseCase }

var _ TestCase = (*FilterOutputDropTCPDestPort)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropTCPDestPort) Name() string {
	return "FilterOutputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDropTCPDestPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "1024:65535", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDropTCPDestPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterOutputDropTCPSrcPort tests that connections are not accepted on
// specified source ports.
type FilterOutputDropTCPSrcPort struct{ baseCase }

var _ TestCase = (*FilterOutputDropTCPSrcPort)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropTCPSrcPort) Name() string {
	return "FilterOutputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDropTCPSrcPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--sport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDropTCPSrcPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", dropPort)
	}

	return nil
}

// FilterOutputAcceptTCPOwner tests that TCP connections from uid owner are accepted.
type FilterOutputAcceptTCPOwner struct{ baseCase }

var _ TestCase = (*FilterOutputAcceptTCPOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputAcceptTCPOwner) Name() string {
	return "FilterOutputAcceptTCPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputAcceptTCPOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputAcceptTCPOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterOutputDropTCPOwner tests that TCP connections from uid owner are dropped.
type FilterOutputDropTCPOwner struct{ baseCase }

var _ TestCase = (*FilterOutputDropTCPOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropTCPOwner) Name() string {
	return "FilterOutputDropTCPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDropTCPOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should be dropped, but got accepted", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDropTCPOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should be dropped, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputAcceptUDPOwner tests that UDP packets from uid owner are accepted.
type FilterOutputAcceptUDPOwner struct{ localCase }

var _ TestCase = (*FilterOutputAcceptUDPOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputAcceptUDPOwner) Name() string {
	return "FilterOutputAcceptUDPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputAcceptUDPOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "--uid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Send UDP packets on acceptPort.
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputAcceptUDPOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Listen for UDP packets on acceptPort.
	return listenUDP(ctx, acceptPort, ipv6)
}

// FilterOutputDropUDPOwner tests that UDP packets from uid owner are dropped.
type FilterOutputDropUDPOwner struct{ localCase }

var _ TestCase = (*FilterOutputDropUDPOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropUDPOwner) Name() string {
	return "FilterOutputDropUDPOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDropUDPOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "--uid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Send UDP packets on dropPort.
	return sendUDPLoop(ctx, ip, dropPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDropUDPOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets should not be received")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// FilterOutputOwnerFail tests that without uid/gid option, owner rule
// will fail.
type FilterOutputOwnerFail struct{ baseCase }

var _ TestCase = (*FilterOutputOwnerFail)(nil)

// Name implements TestCase.Name.
func (*FilterOutputOwnerFail) Name() string {
	return "FilterOutputOwnerFail"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputOwnerFail) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "owner", "-j", "ACCEPT"); err == nil {
		return fmt.Errorf("invalid argument")
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputOwnerFail) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// no-op.
	return nil
}

// FilterOutputAcceptGIDOwner tests that TCP connections from gid owner are accepted.
type FilterOutputAcceptGIDOwner struct{ baseCase }

var _ TestCase = (*FilterOutputAcceptGIDOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputAcceptGIDOwner) Name() string {
	return "FilterOutputAcceptGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputAcceptGIDOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--gid-owner", "root", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputAcceptGIDOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterOutputDropGIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputDropGIDOwner struct{ baseCase }

var _ TestCase = (*FilterOutputDropGIDOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropGIDOwner) Name() string {
	return "FilterOutputDropGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDropGIDOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--gid-owner", "root", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDropGIDOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInvertGIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputInvertGIDOwner struct{ baseCase }

var _ TestCase = (*FilterOutputInvertGIDOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertGIDOwner) Name() string {
	return "FilterOutputInvertGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertGIDOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--gid-owner", "root", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertGIDOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInvertUIDOwner tests that TCP connections from gid owner are dropped.
type FilterOutputInvertUIDOwner struct{ baseCase }

var _ TestCase = (*FilterOutputInvertUIDOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertUIDOwner) Name() string {
	return "FilterOutputInvertUIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertUIDOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "root", "-j", "DROP"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertUIDOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterOutputInvertUIDAndGIDOwner tests that TCP connections from uid and gid
// owner are dropped.
type FilterOutputInvertUIDAndGIDOwner struct{ baseCase }

var _ TestCase = (*FilterOutputInvertUIDAndGIDOwner)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertUIDAndGIDOwner) Name() string {
	return "FilterOutputInvertUIDAndGIDOwner"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertUIDAndGIDOwner) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "root", "!", "--gid-owner", "root", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertUIDAndGIDOwner) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputDestination tests that we can selectively allow packets to
// certain destinations.
type FilterOutputDestination struct{ localCase }

var _ TestCase = (*FilterOutputDestination)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDestination) Name() string {
	return "FilterOutputDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	var rules [][]string
	if ipv6 {
		rules = [][]string{
			{"-A", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT"},
			// Allow solicited node multicast addresses so we can send neighbor
			// solicitations.
			{"-A", "OUTPUT", "-d", "ff02::1:ff00:0/104", "-j", "ACCEPT"},
			{"-P", "OUTPUT", "DROP"},
		}
	} else {
		rules = [][]string{
			{"-A", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT"},
			{"-P", "OUTPUT", "DROP"},
		}
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenUDP(ctx, acceptPort, ipv6)
}

// FilterOutputInvertDestination tests that we can selectively allow packets
// not headed for a particular destination.
type FilterOutputInvertDestination struct{ localCase }

var _ TestCase = (*FilterOutputInvertDestination)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertDestination) Name() string {
	return "FilterOutputInvertDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "OUTPUT", "!", "-d", localIP(ipv6), "-j", "ACCEPT"},
		{"-P", "OUTPUT", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenUDP(ctx, acceptPort, ipv6)
}

// FilterOutputInterfaceAccept tests that packets are sent via interface
// matching the iptables rule.
type FilterOutputInterfaceAccept struct{ localCase }

var _ TestCase = (*FilterOutputInterfaceAccept)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterfaceAccept) Name() string {
	return "FilterOutputInterfaceAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterfaceAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ifname, ok := getInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", ifname, "-j", "ACCEPT"); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterfaceAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenUDP(ctx, acceptPort, ipv6)
}

// FilterOutputInterfaceDrop tests that packets are not sent via interface
// matching the iptables rule.
type FilterOutputInterfaceDrop struct{ localCase }

var _ TestCase = (*FilterOutputInterfaceDrop)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterfaceDrop) Name() string {
	return "FilterOutputInterfaceDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterfaceDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ifname, ok := getInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", ifname, "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterfaceDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("packets should not be received on port %v, but are received", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// FilterOutputInterface tests that packets are sent via interface which is
// not matching the interface name in the iptables rule.
type FilterOutputInterface struct{ localCase }

var _ TestCase = (*FilterOutputInterface)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterface) Name() string {
	return "FilterOutputInterface"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterface) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", "lo", "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterface) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenUDP(ctx, acceptPort, ipv6)
}

// FilterOutputInterfaceBeginsWith tests that packets are not sent via an
// interface which begins with the given interface name.
type FilterOutputInterfaceBeginsWith struct{ localCase }

var _ TestCase = (*FilterOutputInterfaceBeginsWith)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterfaceBeginsWith) Name() string {
	return "FilterOutputInterfaceBeginsWith"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterfaceBeginsWith) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-o", "e+", "-j", "DROP"); err != nil {
		return err
	}

	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterfaceBeginsWith) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("packets should not be received on port %v, but are received", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// FilterOutputInterfaceInvertDrop tests that we selectively do not send
// packets via interface not matching the interface name.
type FilterOutputInterfaceInvertDrop struct{ baseCase }

var _ TestCase = (*FilterOutputInterfaceInvertDrop)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterfaceInvertDrop) Name() string {
	return "FilterOutputInterfaceInvertDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterfaceInvertDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", acceptPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterfaceInvertDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but got accepted", acceptPort)
	}

	return nil
}

// FilterOutputInterfaceInvertAccept tests that we can selectively send packets
// not matching the specific outgoing interface.
type FilterOutputInterfaceInvertAccept struct{ baseCase }

var _ TestCase = (*FilterOutputInterfaceInvertAccept)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInterfaceInvertAccept) Name() string {
	return "FilterOutputInterfaceInvertAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInterfaceInvertAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInterfaceInvertAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterOutputInvertSportAccept tests that we can send packets on a negated
// --sport match
type FilterOutputInvertSportAccept struct{ baseCase }

var _ TestCase = (*FilterOutputInvertSportAccept)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertSportAccept) Name() string {
	return "FilterOutputInvertSportAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertSportAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "--sport", fmt.Sprintf("%d", dropPort), "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertSportAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterOutputInvertSportDrop tests that we can send packets on a negated
// --dport match
type FilterOutputInvertSportDrop struct{ baseCase }

var _ TestCase = (*FilterOutputInvertSportDrop)(nil)

// Name implements TestCase.Name.
func (*FilterOutputInvertSportDrop) Name() string {
	return "FilterOutputInvertSportDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterOutputInvertSportDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "!", "--sport", fmt.Sprintf("%d", acceptPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection was established when it shouldnt have been")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterOutputInvertSportDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on %d port was accepted when it should have been dropped", dropPort)
	}

	return nil
}

// FilterOutputAcceptInvertSrcPorts tests that all UDP outbound connections
// are allowed except those going to specific source ports. The rule uses
// a negated multiport match to ACCEPT traffic for any destination port not
// listed.
//
// Rule(s):
//
//	-A OUTPUT -p udp -m multiport ! --sports 53,15008,32000 -j ACCEPT
type FilterOutputAcceptInvertSrcPorts struct {
	containerCase
}

var _ TestCase = (*FilterOutputAcceptInvertSrcPorts)(nil)

// Name implements TestCase.Name.
func (*FilterOutputAcceptInvertSrcPorts) Name() string {
	return "FilterOutputAcceptInvertSrcPorts"
}

// ContainerAction implements TestCase.ContainerAction.
// It installs the single ACCEPT rule with negation and then
// attempts to connect to a local UDP server listening on a
// blocked port.
func (*FilterOutputAcceptInvertSrcPorts) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add the multiport rule that accepts all but the blocked ports.
	err := filterTable(
		ipv6,
		"-A", "OUTPUT", "-p", "udp", "-m", "multiport",
		"!", "--sports", "53,15008", "-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	testPort := 53
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()

	// No response will be sent.
	if err = listenUDP(timedCtx, testPort, ipv6); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("expected timeout error, vut got: %w", err)
		}
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// It attempts to connect to the container on the specified port.
// Since the container cannot send back responses, the connection
// attempt will fail or time out.
func (*FilterOutputAcceptInvertSrcPorts) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	testPort := 53
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()

	// This should time out.
	if err := sendUDPLoop(timedCtx, ip, testPort, ipv6); err == nil {
		return fmt.Errorf("expected connect failure on port: %d", testPort)
	}

	return nil
}

// FilterOutputDropSrcPorts tests that any TCP packet leaving the
// container from a source port in set is dropped, preventing the
// container from making outbound responses on these ports.
//
// Rule(s):
//
//	-A OUTPUT -p tcp -m multiport --sports 22,53,80:443 -j DROP
type FilterOutputDropSrcPorts struct {
	containerCase
}

var _ TestCase = (*FilterOutputDropSrcPorts)(nil)

// Name implements TestCase.Name.
func (*FilterOutputDropSrcPorts) Name() string {
	return "FilterOutputDropSrcPorts"
}

// ContainerAction implements TestCase.ContainerAction.
// It installs the DROP rule for outbound packets with the specified
// source ports. The container then listens on those ports, expecting
// connection attempts from the local side. Because responses from
// these ports are dropped, no handshake completes.
func (*FilterOutputDropSrcPorts) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add the DROP rule for outbound packets from the specified source ports.
	err := filterTable(
		ipv6,
		"-A", "OUTPUT", "-p", "tcp", "-m", "multiport",
		"--sports", "22,53,80:443", "-j", "DROP",
	)
	if err != nil {
		return err
	}

	// Listen on a set of ports within the blocked range.
	ports := []int{22, 53, 80, 443}
	errCh := make(chan error, len(ports))

	for _, p := range ports {
		go func(port int) {
			// Attempt to accept connections. Even if an inbound
			// connection is created, it won't receive are reply.
			timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
			defer cancel()

			if err := listenTCP(timedCtx, port, ipv6); err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					errCh <- fmt.Errorf(
						"unexpected error on port %d: %w",
						port, err,
					)
					return
				}
			}
			// Timing out or no successful connection is expected.
			errCh <- nil
		}(p)
	}

	// Wait for all listeners to report.
	for i := 0; i < len(ports); i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// It attempts to connect to the container on each of the blocked
// source ports. Since the container cannot send back responses,
// the connection attempts will fail or time out.
func (*FilterOutputDropSrcPorts) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ports := []int{22, 53, 80, 443}
	errCh := make(chan error, len(ports))

	for _, p := range ports {
		go func(port int) {
			// Attempt to connect, but it will time out.
			timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
			defer cancel()

			if err := connectTCP(timedCtx, ip, port, ipv6); err == nil {
				errCh <- fmt.Errorf(
					"expected timout error on port %d, but got: %w",
					port, err,
				)
				return
			}
			errCh <- nil
		}(p)
	}

	// Wait for all client to report.
	for i := 0; i < len(ports); i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	return nil
}

// FilterOutputAcceptInvertPorts tests a negation of either ports
// matching on OUTPUT. The rule accepts all UDP packets if either
// their source and destination ports fall into the matched set.
//
// Rule(s):
//
//	-A OUTPUT -p tcp -m multiport ! --ports 22,53:80,443 -j ACCEPT
type FilterOutputAcceptInvertPorts struct {
	containerCase
}

var _ TestCase = (*FilterOutputAcceptInvertPorts)(nil)

// Name implements TestCase.Name.
func (*FilterOutputAcceptInvertPorts) Name() string {
	return "FilterOutputAcceptInvertPorts"
}

// ContainerAction implements TestCase.ContainerAction.
// It installs the single ACCEPT rule with negation. The container then
// listens on those ports, expecting connection attempts from the local
// side, which will all succeed.
func (*FilterOutputAcceptInvertPorts) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	err := filterTable(
		ipv6,
		"-A", "OUTPUT", "-p", "tcp", "-m", "multiport",
		"!", "--ports", "53:80,22,443", "-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	// Even though some of the ports belong to the inverted set, the
	// combination of the source and destination port will not match.
	// Since the listener ports "low" ports, the chances of this failing
	// is low.
	testPorts := []int{22, 27017}
	errCh := make(chan error, len(testPorts))

	for _, p := range testPorts {
		go func(port int) {
			timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
			defer cancel()

			if err := listenTCP(timedCtx, port, ipv6); err != nil {
				errCh <- fmt.Errorf(
					"unexpected error on allowed port: %s, got: %w",
					port, err,
				)
				return
			}

			errCh <- nil
		}(p)
	}

	// Wait for listeners.
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// It attempts to connect to the container on each ports
// being listened on. Since this is an either port match,
// both connections should succeed.
func (*FilterOutputAcceptInvertPorts) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	testPorts := []int{22, 27017}
	errCh := make(chan error, len(testPorts))

	// All connections should succeed.
	for _, p := range testPorts {
		go func(port int) {
			timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
			defer cancel()
			if err := connectTCP(timedCtx, ip, port, ipv6); err != nil {
				errCh <- fmt.Errorf(
					"failed to connect on port %d: %w",
					port, err,
				)
				return
			}

			errCh <- nil
		}(p)
	}

	// Wait for clients.
	for i := 0; i < len(testPorts); i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	return nil
}
