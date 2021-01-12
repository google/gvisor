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
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	dropPort         = 2401
	acceptPort       = 2402
	sendloopDuration = 2 * time.Second
	chainName        = "foochain"
)

func init() {
	RegisterTestCase(FilterInputDropAll{})
	RegisterTestCase(FilterInputDropDifferentUDPPort{})
	RegisterTestCase(FilterInputDropOnlyUDP{})
	RegisterTestCase(FilterInputDropTCPDestPort{})
	RegisterTestCase(FilterInputDropTCPSrcPort{})
	RegisterTestCase(FilterInputDropUDPPort{})
	RegisterTestCase(FilterInputDropUDP{})
	RegisterTestCase(FilterInputCreateUserChain{})
	RegisterTestCase(FilterInputDefaultPolicyAccept{})
	RegisterTestCase(FilterInputDefaultPolicyDrop{})
	RegisterTestCase(FilterInputReturnUnderflow{})
	RegisterTestCase(FilterInputSerializeJump{})
	RegisterTestCase(FilterInputJumpBasic{})
	RegisterTestCase(FilterInputJumpReturn{})
	RegisterTestCase(FilterInputJumpReturnDrop{})
	RegisterTestCase(FilterInputJumpBuiltin{})
	RegisterTestCase(FilterInputJumpTwice{})
	RegisterTestCase(FilterInputDestination{})
	RegisterTestCase(FilterInputInvertDestination{})
	RegisterTestCase(FilterInputSource{})
	RegisterTestCase(FilterInputInvertSource{})
}

// FilterInputDropUDP tests that we can drop UDP traffic.
type FilterInputDropUDP struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDropUDP) Name() string {
	return "FilterInputDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort)
}

// FilterInputDropOnlyUDP tests that "-p udp -j DROP" only affects UDP traffic.
type FilterInputDropOnlyUDP struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputDropOnlyUDP) Name() string {
	return "FilterInputDropOnlyUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropOnlyUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for a TCP connection, which should be allowed.
	if err := listenTCP(ctx, acceptPort); err != nil {
		return fmt.Errorf("failed to establish a connection %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropOnlyUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Try to establish a TCP connection with the container, which should
	// succeed.
	return connectTCP(ctx, ip, acceptPort)
}

// FilterInputDropUDPPort tests that we can drop UDP traffic by port.
type FilterInputDropUDPPort struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDropUDPPort) Name() string {
	return "FilterInputDropUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort)
}

// FilterInputDropDifferentUDPPort tests that dropping traffic for a single UDP port
// doesn't drop packets on other ports.
type FilterInputDropDifferentUDPPort struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDropDifferentUDPPort) Name() string {
	return "FilterInputDropDifferentUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropDifferentUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on another port.
	if err := listenUDP(ctx, acceptPort); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropDifferentUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputDropTCPDestPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPDestPort struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputDropTCPDestPort) Name() string {
	return "FilterInputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPDestPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPDestPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Ensure we cannot connect to the container.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, dropPort); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect on port %d", dropPort)
	}
	return nil
}

// FilterInputDropTCPSrcPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPSrcPort struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputDropTCPSrcPort) Name() string {
	return "FilterInputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPSrcPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop anything from an ephemeral port.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--sport", "1024:65535", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenTCP(timedCtx, acceptPort); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but was", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPSrcPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Ensure we cannot connect to the container.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := connectTCP(timedCtx, ip, dropPort); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect on port %d", acceptPort)
	}
	return nil
}

// FilterInputDropAll tests that we can drop all traffic to the INPUT chain.
type FilterInputDropAll struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDropAll) Name() string {
	return "FilterInputDropAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropAll) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for all packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropAll) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort)
}

// FilterInputMultiUDPRules verifies that multiple UDP rules are applied
// correctly. This has the added benefit of testing whether we're serializing
// rules correctly -- if we do it incorrectly, the iptables tool will
// misunderstand and save the wrong tables.
type FilterInputMultiUDPRules struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputMultiUDPRules) Name() string {
	return "FilterInputMultiUDPRules"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputMultiUDPRules) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"},
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-j", "ACCEPT"},
		{"-L"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputMultiUDPRules) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputRequireProtocolUDP checks that "-m udp" requires "-p udp" to be
// specified.
type FilterInputRequireProtocolUDP struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputRequireProtocolUDP) Name() string {
	return "FilterInputRequireProtocolUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputRequireProtocolUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err == nil {
		return errors.New("expected iptables to fail with out \"-p udp\", but succeeded")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputRequireProtocolUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputCreateUserChain tests chain creation.
type FilterInputCreateUserChain struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputCreateUserChain) Name() string {
	return "FilterInputCreateUserChain"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputCreateUserChain) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		// Create a chain.
		{"-N", chainName},
		// Add a simple rule to the chain.
		{"-A", chainName, "-j", "DROP"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputCreateUserChain) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputDefaultPolicyAccept tests the default ACCEPT policy.
type FilterInputDefaultPolicyAccept struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDefaultPolicyAccept) Name() string {
	return "FilterInputDefaultPolicyAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDefaultPolicyAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Set the default policy to accept, then receive a packet.
	if err := filterTable(ipv6, "-P", "INPUT", "ACCEPT"); err != nil {
		return err
	}
	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDefaultPolicyAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputDefaultPolicyDrop tests the default DROP policy.
type FilterInputDefaultPolicyDrop struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDefaultPolicyDrop) Name() string {
	return "FilterInputDefaultPolicyDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDefaultPolicyDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-P", "INPUT", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDefaultPolicyDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputReturnUnderflow tests that -j RETURN in a built-in chain causes
// the underflow rule (i.e. default policy) to be executed.
type FilterInputReturnUnderflow struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputReturnUnderflow) Name() string {
	return "FilterInputReturnUnderflow"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputReturnUnderflow) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add a RETURN rule followed by an unconditional accept, and set the
	// default policy to DROP.
	rules := [][]string{
		{"-A", "INPUT", "-j", "RETURN"},
		{"-A", "INPUT", "-j", "DROP"},
		{"-P", "INPUT", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// We should receive packets, as the RETURN rule will trigger the default
	// ACCEPT policy.
	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputReturnUnderflow) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputSerializeJump verifies that we can serialize jumps.
type FilterInputSerializeJump struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputSerializeJump) Name() string {
	return "FilterInputSerializeJump"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputSerializeJump) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Write a JUMP rule, the serialize it with `-L`.
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-L"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputSerializeJump) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputJumpBasic jumps to a chain and executes a rule there.
type FilterInputJumpBasic struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputJumpBasic) Name() string {
	return "FilterInputJumpBasic"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpBasic) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on acceptPort.
	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpBasic) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputJumpReturn jumps, returns, and executes a rule.
type FilterInputJumpReturn struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputJumpReturn) Name() string {
	return "FilterInputJumpReturn"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpReturn) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-P", "INPUT", "ACCEPT"},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "RETURN"},
		{"-A", chainName, "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on acceptPort.
	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpReturn) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputJumpReturnDrop jumps to a chain, returns, and DROPs packets.
type FilterInputJumpReturnDrop struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputJumpReturnDrop) Name() string {
	return "FilterInputJumpReturnDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpReturnDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", "INPUT", "-j", "DROP"},
		{"-A", chainName, "-j", "RETURN"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, dropPort); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpReturnDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort)
}

// FilterInputJumpBuiltin verifies that jumping to a top-levl chain is illegal.
type FilterInputJumpBuiltin struct{ baseCase }

// Name implements TestCase.Name.
func (FilterInputJumpBuiltin) Name() string {
	return "FilterInputJumpBuiltin"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpBuiltin) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-j", "OUTPUT"); err == nil {
		return fmt.Errorf("iptables should be unable to jump to a built-in chain")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpBuiltin) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputJumpTwice jumps twice, then returns twice and executes a rule.
type FilterInputJumpTwice struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputJumpTwice) Name() string {
	return "FilterInputJumpTwice"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpTwice) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	const chainName2 = chainName + "2"
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-N", chainName2},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", chainName2},
		{"-A", "INPUT", "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	// UDP packets should jump and return twice, eventually hitting the
	// ACCEPT rule.
	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpTwice) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputDestination verifies that we can filter packets via `-d
// <ipaddr>`.
type FilterInputDestination struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputDestination) Name() string {
	return "FilterInputDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	addrs, err := localAddrs(ipv6)
	if err != nil {
		return err
	}

	// Make INPUT's default action DROP, then ACCEPT all packets bound for
	// this machine.
	rules := [][]string{{"-P", "INPUT", "DROP"}}
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "INPUT", "-d", addr, "-j", "ACCEPT"})
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputInvertDestination verifies that we can filter packets via `! -d
// <ipaddr>`.
type FilterInputInvertDestination struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputInvertDestination) Name() string {
	return "FilterInputInvertDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputInvertDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-d", localIP(ipv6), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputInvertDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputSource verifies that we can filter packets via `-s
// <ipaddr>`.
type FilterInputSource struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputSource) Name() string {
	return "FilterInputSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputSource) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets from this
	// machine.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "-s", fmt.Sprintf("%v", ip), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputSource) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}

// FilterInputInvertSource verifies that we can filter packets via `! -s
// <ipaddr>`.
type FilterInputInvertSource struct{ containerCase }

// Name implements TestCase.Name.
func (FilterInputInvertSource) Name() string {
	return "FilterInputInvertSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputInvertSource) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-s", localIP(ipv6), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return listenUDP(ctx, acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputInvertSource) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort)
}
