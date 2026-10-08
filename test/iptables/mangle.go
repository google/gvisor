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
	RegisterTestCase(&MangleInputDrop{})
	RegisterTestCase(&ManglePreroutingMarkContinue{})
	RegisterTestCase(&MangleOutputMark{})
	RegisterTestCase(&ManglePostroutingDrop{})
}

func mangleTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "mangle", args)
}

// MangleInputDrop tests dropping packets in mangle table INPUT chain.
type MangleInputDrop struct{ containerCase }

var _ TestCase = (*MangleInputDrop)(nil)

// Name implements TestCase.Name.
func (*MangleInputDrop) Name() string {
	return "MangleInputDrop"
}

// ContainerAction implements TestCase.ContainerAction.
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

// LocalAction implements TestCase.LocalAction.
func (*MangleInputDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// ManglePreroutingMarkContinue tests that a packet continues through the chain
// after MARK and carries the mark into filter INPUT.
type ManglePreroutingMarkContinue struct{ containerCase }

var _ TestCase = (*ManglePreroutingMarkContinue)(nil)

// Name implements TestCase.Name.
func (*ManglePreroutingMarkContinue) Name() string {
	return "ManglePreroutingMarkContinue"
}

// ContainerAction implements TestCase.ContainerAction.
func (*ManglePreroutingMarkContinue) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := mangleTable(ipv6, "-A", "PREROUTING", "-p", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-j", "MARK", "--set-mark", "0x42"); err != nil {
		return err
	}
	// Only packets carrying the mark reach the listener.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-m", "mark", "!", "--mark", "0x42", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*ManglePreroutingMarkContinue) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// MangleOutputMark tests that MARK in mangle OUTPUT sets a mark that filter
// OUTPUT sees.
type MangleOutputMark struct{ localCase }

var _ TestCase = (*MangleOutputMark)(nil)

// Name implements TestCase.Name.
func (*MangleOutputMark) Name() string {
	return "MangleOutputMark"
}

// ContainerAction implements TestCase.ContainerAction.
func (*MangleOutputMark) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := mangleTable(ipv6, "-A", "OUTPUT", "-p", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-j", "MARK", "--set-mark", "0x20"); err != nil {
		return err
	}
	// Only packets carrying the mark leave the container.
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-m", "mark", "!", "--mark", "0x20", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*MangleOutputMark) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

// ManglePostroutingDrop tests dropping packets in the mangle POSTROUTING chain.
type ManglePostroutingDrop struct{ localCase }

var _ TestCase = (*ManglePostroutingDrop)(nil)

// Name implements TestCase.Name.
func (*ManglePostroutingDrop) Name() string {
	return "ManglePostroutingDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (*ManglePostroutingDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := mangleTable(ipv6, "-A", "POSTROUTING", "-p", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*ManglePostroutingDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped in mangle POSTROUTING, but got a packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}
