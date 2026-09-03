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

package iptables

import (
	"context"
	"errors"
	"fmt"
	"net"

	"gvisor.dev/gvisor/test/netutils"
)

func init() {
	RegisterTestCase(&ManglePreroutingRuleContinue{})
	RegisterTestCase(&MangleMarkPropagateToFilter{})
	RegisterTestCase(&MangleInputDrop{})
}

func mangleTable(ipv6 bool, args ...string) error {
	return run(append([]string{"-t", "mangle"}, args...), ipv6)
}

// ManglePreroutingRuleContinue tests that the MARK target executes non-terminating
// (RuleContinue) semantics in the mangle table.
type ManglePreroutingRuleContinue struct{ containerCase }

var _ TestCase = (*ManglePreroutingRuleContinue)(nil)

func (*ManglePreroutingRuleContinue) Name() string {
	return "ManglePreroutingRuleContinue"
}

func (*ManglePreroutingRuleContinue) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Rule 1: Set mark 0x42
	if err := mangleTable(ipv6, "-A", "PREROUTING", "-p", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "MARK", "--set-mark", "0x42"); err != nil {
		return err
	}
	// Rule 2: If mark 0x42, DROP. If RuleContinue works, this rule runs and drops the packet.
	if err := mangleTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-m", "mark", "--mark", "0x42", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

func (*ManglePreroutingRuleContinue) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}

// MangleMarkPropagateToFilter tests that a mark applied in mangle PREROUTING persists
// and is matched by filter INPUT.
type MangleMarkPropagateToFilter struct{ containerCase }

var _ TestCase = (*MangleMarkPropagateToFilter)(nil)

func (*MangleMarkPropagateToFilter) Name() string {
	return "MangleMarkPropagateToFilter"
}

func (*MangleMarkPropagateToFilter) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Mark in mangle PREROUTING
	if err := mangleTable(ipv6, "-A", "PREROUTING", "-p", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "MARK", "--set-mark", "0x10"); err != nil {
		return err
	}
	// Drop in filter INPUT on mark match
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "mark", "--mark", "0x10", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

func (*MangleMarkPropagateToFilter) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}

// MangleInputDrop tests dropping packets in mangle table INPUT chain.
type MangleInputDrop struct{ containerCase }

var _ TestCase = (*MangleInputDrop)(nil)

func (*MangleInputDrop) Name() string {
	return "MangleInputDrop"
}

func (*MangleInputDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := mangleTable(ipv6, "-A", "INPUT", "-p", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped in mangle INPUT, but got packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

func (*MangleInputDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}
