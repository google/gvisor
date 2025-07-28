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

	"gvisor.dev/gvisor/test/netutils"
)

// IptFilterInputDropUDP tests that we can drop UDP traffic.
type IptFilterInputDropUDP struct{ containerCase }

var _ TestCase = (*IptFilterInputDropUDP)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropUDP) Name() string {
	return "IptFilterInputDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// IptFilterInputDropOnlyUDP tests that "-p udp -j DROP" only affects UDP traffic.
type IptFilterInputDropOnlyUDP struct{ baseCase }

var _ TestCase = (*IptFilterInputDropOnlyUDP)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropOnlyUDP) Name() string {
	return "IptFilterInputDropOnlyUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropOnlyUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for a TCP connection, which should be allowed.
	if err := netutils.ListenTCP(ctx, acceptPort, ipv6); err != nil {
		return fmt.Errorf("failed to establish a connection %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropOnlyUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Try to establish a TCP connection with the container, which should
	// succeed.
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputDropUDPPort tests that we can drop UDP traffic by port.
type IptFilterInputDropUDPPort struct{ containerCase }

var _ TestCase = (*IptFilterInputDropUDPPort)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropUDPPort) Name() string {
	return "IptFilterInputDropUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// IptFilterInputDropDifferentUDPPort tests that dropping traffic for a single UDP port
// doesn't drop packets on other ports.
type IptFilterInputDropDifferentUDPPort struct{ containerCase }

var _ TestCase = (*IptFilterInputDropDifferentUDPPort)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropDifferentUDPPort) Name() string {
	return "IptFilterInputDropDifferentUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropDifferentUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on another port.
	if err := netutils.ListenUDP(ctx, acceptPort, ipv6); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropDifferentUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputDropTCPDestPort tests that connections are not accepted on specified source ports.
type IptFilterInputDropTCPDestPort struct{ baseCase }

var _ TestCase = (*IptFilterInputDropTCPDestPort)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropTCPDestPort) Name() string {
	return "IptFilterInputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropTCPDestPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on drop port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should not be accepted, but got accepted", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropTCPDestPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Ensure we cannot connect to the container.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ConnectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect on port %d", dropPort)
	}
	return nil
}

// IptFilterInputDropTCPSrcPort tests that connections are not accepted on specified source ports.
type IptFilterInputDropTCPSrcPort struct{ baseCase }

var _ TestCase = (*IptFilterInputDropTCPSrcPort)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropTCPSrcPort) Name() string {
	return "IptFilterInputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropTCPSrcPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop anything from an ephemeral port.
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--sport", "1024:65535", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("connection destined to port %d should not be accepted, but was", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropTCPSrcPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Ensure we cannot connect to the container.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ConnectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect on port %d", acceptPort)
	}
	return nil
}

// IptFilterInputDropAll tests that we can drop all traffic to the INPUT chain.
type IptFilterInputDropAll struct{ containerCase }

var _ TestCase = (*IptFilterInputDropAll)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropAll) Name() string {
	return "IptFilterInputDropAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDropAll) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for all packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
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

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDropAll) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// FilterInputMultiUDPRules verifies that multiple UDP rules are applied
// correctly. This has the added benefit of testing whether we're serializing
// rules correctly -- if we do it incorrectly, the iptables tool will
// misunderstand and save the wrong tables.
type FilterInputMultiUDPRules struct{ baseCase }

var _ TestCase = (*FilterInputMultiUDPRules)(nil)

// Name implements TestCase.Name.
func (*FilterInputMultiUDPRules) Name() string {
	return "IptFilterInputMultiUDPRules"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterInputMultiUDPRules) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"},
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-j", "ACCEPT"},
		{"-L"},
	}
	return ipFilterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (*FilterInputMultiUDPRules) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// FilterInputRequireProtocolUDP checks that "-m udp" requires "-p udp" to be
// specified.
type FilterInputRequireProtocolUDP struct{ baseCase }

var _ TestCase = (*FilterInputRequireProtocolUDP)(nil)

// Name implements TestCase.Name.
func (*FilterInputRequireProtocolUDP) Name() string {
	return "IptFilterInputRequireProtocolUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*FilterInputRequireProtocolUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err == nil {
		return errors.New("expected iptables to fail with out \"-p udp\", but succeeded")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*FilterInputRequireProtocolUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// IptFilterInputCreateUserChain tests chain creation.
type IptFilterInputCreateUserChain struct{ baseCase }

var _ TestCase = (*IptFilterInputCreateUserChain)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputCreateUserChain) Name() string {
	return "IptFilterInputCreateUserChain"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputCreateUserChain) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		// Create a chain.
		{"-N", chainName},
		// Add a simple rule to the chain.
		{"-A", chainName, "-j", "DROP"},
	}
	return ipFilterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputCreateUserChain) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// IptFilterInputDefaultPolicyAccept tests the default ACCEPT policy.
type IptFilterInputDefaultPolicyAccept struct{ containerCase }

var _ TestCase = (*IptFilterInputDefaultPolicyAccept)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDefaultPolicyAccept) Name() string {
	return "IptFilterInputDefaultPolicyAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDefaultPolicyAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Set the default policy to accept, then receive a packet.
	if err := ipFilterTable(ipv6, "-P", "INPUT", "ACCEPT"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDefaultPolicyAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputDefaultPolicyDrop tests the default DROP policy.
type IptFilterInputDefaultPolicyDrop struct{ containerCase }

var _ TestCase = (*IptFilterInputDefaultPolicyDrop)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDefaultPolicyDrop) Name() string {
	return "IptFilterInputDefaultPolicyDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDefaultPolicyDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-P", "INPUT", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDefaultPolicyDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputReturnUnderflow tests that -j RETURN in a built-in chain causes
// the underflow rule (i.e. default policy) to be executed.
type IptFilterInputReturnUnderflow struct{ containerCase }

var _ TestCase = (*IptFilterInputReturnUnderflow)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputReturnUnderflow) Name() string {
	return "IptFilterInputReturnUnderflow"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputReturnUnderflow) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add a RETURN rule followed by an unconditional accept, and set the
	// default policy to DROP.
	rules := [][]string{
		{"-A", "INPUT", "-j", "RETURN"},
		{"-A", "INPUT", "-j", "DROP"},
		{"-P", "INPUT", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	// We should receive packets, as the RETURN rule will trigger the default
	// ACCEPT policy.
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputReturnUnderflow) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputSerializeJump verifies that we can serialize jumps.
type IptFilterInputSerializeJump struct{ baseCase }

var _ TestCase = (*IptFilterInputSerializeJump)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputSerializeJump) Name() string {
	return "IptFilterInputSerializeJump"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputSerializeJump) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Write a JUMP rule, the serialize it with `-L`.
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-L"},
	}
	return ipFilterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputSerializeJump) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// IptFilterInputJumpBasic jumps to a chain and executes a rule there.
type IptFilterInputJumpBasic struct{ containerCase }

var _ TestCase = (*IptFilterInputJumpBasic)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputJumpBasic) Name() string {
	return "IptFilterInputJumpBasic"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputJumpBasic) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on acceptPort.
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputJumpBasic) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputJumpReturn jumps, returns, and executes a rule.
type IptFilterInputJumpReturn struct{ containerCase }

var _ TestCase = (*IptFilterInputJumpReturn)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputJumpReturn) Name() string {
	return "IptFilterInputJumpReturn"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputJumpReturn) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-P", "INPUT", "ACCEPT"},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "RETURN"},
		{"-A", chainName, "-j", "DROP"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on acceptPort.
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputJumpReturn) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputJumpReturnDrop jumps to a chain, returns, and DROPs packets.
type IptFilterInputJumpReturnDrop struct{ containerCase }

var _ TestCase = (*IptFilterInputJumpReturnDrop)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputJumpReturnDrop) Name() string {
	return "IptFilterInputJumpReturnDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputJumpReturnDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", "INPUT", "-j", "DROP"},
		{"-A", chainName, "-j", "RETURN"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputJumpReturnDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// IptFilterInputJumpBuiltin verifies that jumping to a top-levl chain is illegal.
type IptFilterInputJumpBuiltin struct{ baseCase }

var _ TestCase = (*IptFilterInputJumpBuiltin)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputJumpBuiltin) Name() string {
	return "IptFilterInputJumpBuiltin"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputJumpBuiltin) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-j", "OUTPUT"); err == nil {
		return fmt.Errorf("iptables should be unable to jump to a built-in chain")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputJumpBuiltin) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// IptFilterInputJumpTwice jumps twice, then returns twice and executes a rule.
type IptFilterInputJumpTwice struct{ containerCase }

var _ TestCase = (*IptFilterInputJumpTwice)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputJumpTwice) Name() string {
	return "IptFilterInputJumpTwice"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputJumpTwice) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	const chainName2 = chainName + "2"
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-N", chainName2},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", chainName2},
		{"-A", "INPUT", "-j", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	// UDP packets should jump and return twice, eventually hitting the
	// ACCEPT rule.
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputJumpTwice) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputDestination verifies that we can filter packets via `-d
// <ipaddr>`.
type IptFilterInputDestination struct{ containerCase }

var _ TestCase = (*IptFilterInputDestination)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDestination) Name() string {
	return "IptFilterInputDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	addrs, err := netutils.LocalAddrs(ipv6)
	if err != nil {
		return err
	}

	// Make INPUT's default action DROP, then ACCEPT all packets bound for
	// this machine.
	rules := [][]string{{"-P", "INPUT", "DROP"}}
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "INPUT", "-d", addr, "-j", "ACCEPT"})
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInvertDestination verifies that we can filter packets via `! -d
// <ipaddr>`.
type IptFilterInputInvertDestination struct{ containerCase }

var _ TestCase = (*IptFilterInputInvertDestination)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInvertDestination) Name() string {
	return "IptFilterInputInvertDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInvertDestination) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-d", netutils.LocalIP(ipv6), "-j", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInvertDestination) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputSource verifies that we can filter packets via `-s
// <ipaddr>`.
type IptFilterInputSource struct{ containerCase }

var _ TestCase = (*IptFilterInputSource)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputSource) Name() string {
	return "IptFilterInputSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputSource) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets from this
	// machine.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "-s", fmt.Sprintf("%v", ip), "-j", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputSource) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInvertSource verifies that we can filter packets via `! -s
// <ipaddr>`.
type IptFilterInputInvertSource struct{ containerCase }

var _ TestCase = (*IptFilterInputInvertSource)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInvertSource) Name() string {
	return "IptFilterInputInvertSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInvertSource) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-s", netutils.LocalIP(ipv6), "-j", "ACCEPT"},
	}
	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInvertSource) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInterfaceAccept tests that packets are accepted from interface
// matching the iptables rule.
type IptFilterInputInterfaceAccept struct{ localCase }

var _ TestCase = (*IptFilterInputInterfaceAccept)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterfaceAccept) Name() string {
	return "IptFilterInputInterfaceAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterfaceAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ifname, ok := netutils.GetInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-i", ifname, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := netutils.ListenUDP(ctx, acceptPort, ipv6); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %w", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterfaceAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInterfaceDrop tests that packets are dropped from interface
// matching the iptables rule.
type IptFilterInputInterfaceDrop struct{ localCase }

var _ TestCase = (*IptFilterInputInterfaceDrop)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterfaceDrop) Name() string {
	return "IptFilterInputInterfaceDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterfaceDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	ifname, ok := netutils.GetInterfaceName()
	if !ok {
		return fmt.Errorf("no interface is present, except loopback")
	}
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-i", ifname, "-j", "DROP"); err != nil {
		return err
	}
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, acceptPort, ipv6); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("error reading: %w", err)
	}
	return fmt.Errorf("packets should have been dropped, but got a packet")
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterfaceDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInterface tests that packets are not dropped from interface which
// is not matching the interface name in the iptables rule.
type IptFilterInputInterface struct{ localCase }

var _ TestCase = (*IptFilterInputInterface)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterface) Name() string {
	return "IptFilterInputInterface"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterface) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-i", "lo", "-j", "DROP"); err != nil {
		return err
	}
	if err := netutils.ListenUDP(ctx, acceptPort, ipv6); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %w", acceptPort, err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterface) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInterfaceBeginsWith tests that packets are dropped from an
// interface which begins with the given interface name.
type IptFilterInputInterfaceBeginsWith struct{ localCase }

var _ TestCase = (*IptFilterInputInterfaceBeginsWith)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterfaceBeginsWith) Name() string {
	return "IptFilterInputInterfaceBeginsWith"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterfaceBeginsWith) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "udp", "-i", "e+", "-j", "DROP"); err != nil {
		return err
	}
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, acceptPort, ipv6); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("error reading: %w", err)
	}
	return fmt.Errorf("packets should have been dropped, but got a packet")
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterfaceBeginsWith) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInterfaceInvertDrop tests that we selectively drop packets from
// interface not matching the interface name.
type IptFilterInputInterfaceInvertDrop struct{ baseCase }

var _ TestCase = (*IptFilterInputInterfaceInvertDrop)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterfaceInvertDrop) Name() string {
	return "IptFilterInputInterfaceInvertDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterfaceInvertDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "!", "-i", "lo", "-j", "DROP"); err != nil {
		return err
	}
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, acceptPort, ipv6); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("error reading: %w", err)
	}
	return fmt.Errorf("connection on port %d should not be accepted, but was accepted", acceptPort)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterfaceInvertDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ConnectTCP(timedCtx, ip, acceptPort, ipv6); err != nil {
		var operr *net.OpError
		if errors.As(err, &operr) && operr.Timeout() {
			return nil
		}
		return fmt.Errorf("error connecting: %w", err)
	}
	return fmt.Errorf("connection destined to port %d should not be accepted, but was accepted", acceptPort)
}

// IptFilterInputInterfaceInvertAccept tests that we can selectively accept packets
// not matching the specific incoming interface.
type IptFilterInputInterfaceInvertAccept struct{ baseCase }

var _ TestCase = (*IptFilterInputInterfaceInvertAccept)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInterfaceInvertAccept) Name() string {
	return "IptFilterInputInterfaceInvertAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInterfaceInvertAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "!", "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	return netutils.ListenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInterfaceInvertAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInvertDportAccept tests that we can send packets on a negated
// --dport match
type IptFilterInputInvertDportAccept struct{ baseCase }

var _ TestCase = (*IptFilterInputInvertDportAccept)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInvertDportAccept) Name() string {
	return "IptFilterInputInvertDportAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInvertDportAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "!", "--dport", fmt.Sprintf("%d", dropPort), "-j", "ACCEPT"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	return netutils.ListenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInvertDportAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}

// IptFilterInputInvertDportDrop tests that we can send packets on a negated
// --dport match
type IptFilterInputInvertDportDrop struct{ baseCase }

var _ TestCase = (*IptFilterInputInvertDportDrop)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputInvertDportDrop) Name() string {
	return "IptFilterInputInvertDportDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*IptFilterInputInvertDportDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := ipFilterTable(ipv6, "-A", "INPUT", "-p", "tcp", "!", "--dport", fmt.Sprintf("%d", acceptPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for TCP packets on accept port.
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection was established when it shouldn't have been")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*IptFilterInputInvertDportDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ConnectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on %d port was accepted when it should have been dropped", dropPort)
	}

	return nil
}

// IptFilterInputDropAllSrcPorts tests that all TCP packets, regardless
// of source port, are dropped. The rule covers all the source ports
// so that no incoming TCP packet on INPUT is accepted.
//
// Rule(s):
//
//	-A INPUT -p tcp -m multiport --sports 0,1,2:32000,32001:65535 -j DROP
type IptFilterInputDropAllSrcPorts struct {
	containerCase
}

var _ TestCase = (*IptFilterInputDropAllSrcPorts)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropAllSrcPorts) Name() string {
	return "IptFilterInputDropAllSrcPorts"
}

// ContainerAction implements TestCase.ContainerAction.
// The container will then attempt to receive a UDP packet,
// which should never arrive due to the DROP rule.
func (*IptFilterInputDropAllSrcPorts) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add the multiport rule that drops all TCP packets from any source port.
	err := ipFilterTable(
		ipv6,
		"-A", "INPUT", "-p", "tcp", "-m", "multiport",
		"--sports", "0,1,2:32000,32001:65535", "-j", "DROP",
	)
	if err != nil {
		return err
	}

	testPort := 42
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()

	// netutils.ListenTCP attempts to receive a TCP packet. Since all
	// TCP packets are dropped, it should time out and return
	// an error (DeadlineExceeded).
	err = netutils.ListenTCP(timedCtx, testPort, ipv6)
	if err == nil {
		return fmt.Errorf("unexpected receive on port: %d", testPort)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("expected timeout error, vut got: %w", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// It tries to connect to the container's test port, but the
// DROP rule ensures the packet never arrives at the port.
func (*IptFilterInputDropAllSrcPorts) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	testPort := 42
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()

	if err := netutils.ConnectTCP(timedCtx, ip, testPort, ipv6); err == nil {
		return fmt.Errorf(
			"expected connect failure on port: %d",
			testPort,
		)
	}

	return nil
}

// IptFilterInputDropAllExceptOneDstPort tests that only packets destined
// to a specific port are accepted, while connections to any other port
// are dropped. The rule uses a negated multiport destination port
// specification to allow only one port.
//
// Rule(s):
//
//	-P INPUT DROP
//	-A INPUT -p tcp -m multiport ! --dports 0:442,444:32000,32001:65535 -j ACCEPT
type IptFilterInputDropAllExceptOneDstPort struct {
	containerCase
}

var _ TestCase = (*IptFilterInputDropAllExceptOneDstPort)(nil)

// Name implements TestCase.Name.
func (*IptFilterInputDropAllExceptOneDstPort) Name() string {
	return "IptFilterInputDropAllExceptOneDstPort"
}

// ContainerAction implements TestCase.ContainerAction.
// It installs a catch-all DROP policy for the input chain and a single
// ACCEPT rule for packets destined to the allowed port. The container
// listens on allowed and blocked ports; only the former should receive
// a connection.
func (*IptFilterInputDropAllExceptOneDstPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Add the multiport rule that allows inbound on 443 only.
	rules := [][]string{
		{"-A", "INPUT", "-p", "tcp", "-m", "multiport",
			"!", "--dports", "0:442,444:32000,32001:65535", "-j", "ACCEPT"},
		{"-P", "INPUT", "DROP"},
	}

	if err := ipFilterTableRules(ipv6, rules); err != nil {
		return err
	}

	allowedPort := 443
	blockedPort := 80
	errCh := make(chan error, 2)

	// Listen on port allowed port.
	go func() {
		timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
		defer cancel()

		if err := netutils.ListenTCP(timedCtx, allowedPort, ipv6); err != nil {
			errCh <- fmt.Errorf(
				"unexpected error on allowed port: %d, got: %w",
				allowedPort, err,
			)
			return
		}
		errCh <- nil
	}()

	// Listen on blocked port.
	go func() {
		timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
		defer cancel()

		err := netutils.ListenTCP(timedCtx, blockedPort, ipv6)
		if err == nil {
			// Should not receive any traffic.
			errCh <- fmt.Errorf("unexpected receive on port: %d", blockedPort)
			return
		}

		if !errors.Is(err, context.DeadlineExceeded) {
			errCh <- fmt.Errorf(
				"expected timeout error on port: %d, but got: %w",
				blockedPort, err,
			)
			return
		}

		errCh <- nil
	}()

	// Wait for both listeners.
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
// It connects to both the allowed port and the
// blocked port, only the former should succeed.
func (*IptFilterInputDropAllExceptOneDstPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	allowedPort := 443
	blockedPort := 80

	// Connect to allowed port.
	allowTimedCtx, allowCancel := context.WithTimeout(ctx, NegativeTimeout)
	defer allowCancel()
	if err := netutils.ConnectTCP(allowTimedCtx, ip, allowedPort, ipv6); err != nil {
		return fmt.Errorf("failed to connect on port %d: %w", allowedPort, err)
	}

	// Connect to blocked port.
	blockTimedCtx, blockCancel := context.WithTimeout(ctx, NegativeTimeout)
	defer blockCancel()
	if err := netutils.ConnectTCP(blockTimedCtx, ip, blockedPort, ipv6); err == nil {
		return fmt.Errorf("expected connect error on port: %d", blockedPort)
	}

	return nil
}
