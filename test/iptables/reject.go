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
	"time"

	"gvisor.dev/gvisor/test/netutils"
)

func init() {
	RegisterTestCase(&FilterInputRejectDefault{})
	RegisterTestCase(&FilterInputRejectDefaultUnmatched{})
	RegisterTestCase(&FilterInputRejectTCPReset{})
	RegisterTestCase(&FilterInputRejectTCPResetUnmatched{})
}

// FilterInputRejectDefault tests default reject (ICMP port unreachable).
type FilterInputRejectDefault struct{ baseCase }

var _ TestCase = (*FilterInputRejectDefault)(nil)

// Name implements TestCase.Name.
func (*FilterInputRejectDefault) Name() string {
	return "FilterInputRejectDefault"
}

// ContainerAction implements TestCase.ContainerAction.
// Verifies that a TCP server listening on dropPort receives no connections.
func (*FilterInputRejectDefault) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REJECT"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d kept accepted, but should have been rejected", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
// Verifies that the connection fails immediately due to active rejection
// (receiving connection refused) rather than dropping silently (timing out).
func (*FilterInputRejectDefault) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", dropPort))
	conn, err := d.DialContext(ctx, netutils.TCPNetwork(ipv6), addr)
	if err == nil {
		conn.Close()
		return fmt.Errorf("expected connection to %s to fail", addr)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("connection timed out (dropped) instead of being rejected: %w", err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("connection timed out instead of being rejected: %w", err)
	}
	return nil
}

// FilterInputRejectDefaultUnmatched tests that a packet which shouldn't be rejected
// is allowed through.
type FilterInputRejectDefaultUnmatched struct{ baseCase }

var _ TestCase = (*FilterInputRejectDefaultUnmatched)(nil)

// Name implements TestCase.Name.
func (*FilterInputRejectDefaultUnmatched) Name() string {
	return "FilterInputRejectDefaultUnmatched"
}

// ContainerAction implements TestCase.ContainerAction.
// Installs the REJECT rule on dropPort, but starts a listener on acceptPort.
// Expects that the acceptPort traffic passes through.
func (*FilterInputRejectDefaultUnmatched) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REJECT"); err != nil {
		return err
	}

	return netutils.ListenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
// Verifies that dialing the container on acceptPort is allowed.
func (*FilterInputRejectDefaultUnmatched) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterInputRejectTCPReset tests reject with TCP RST.
type FilterInputRejectTCPReset struct{ baseCase }

var _ TestCase = (*FilterInputRejectTCPReset)(nil)

// Name implements TestCase.Name.
func (*FilterInputRejectTCPReset) Name() string {
	return "FilterInputRejectTCPReset"
}

// ContainerAction implements TestCase.ContainerAction.
// Installs an iptables rule to REJECT incoming TCP packets on dropPort with tcp-reset.
// Verifies that a TCP server listening on dropPort receives no connections.
func (*FilterInputRejectTCPReset) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d kept accepted, but should have been rejected with tcp-reset", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
// Dials the container on dropPort and verifies that the connection
// is actively aborted with a TCP Reset (RST) packet rather than dropping (timing out).
func (*FilterInputRejectTCPReset) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", dropPort))
	conn, err := d.DialContext(ctx, netutils.TCPNetwork(ipv6), addr)
	if err == nil {
		conn.Close()
		return fmt.Errorf("expected connection to %s to fail", addr)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("connection timed out (dropped) instead of being rejected with tcp-reset: %w", err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("connection timed out instead of being rejected with tcp-reset: %w", err)
	}
	return nil
}

// FilterInputRejectTCPResetUnmatched tests that a packet which shouldn't be rejected
// by a TCP Reset rule is allowed through.
type FilterInputRejectTCPResetUnmatched struct{ baseCase }

var _ TestCase = (*FilterInputRejectTCPResetUnmatched)(nil)

// Name implements TestCase.Name.
func (*FilterInputRejectTCPResetUnmatched) Name() string {
	return "FilterInputRejectTCPResetUnmatched"
}

// ContainerAction implements TestCase.ContainerAction.
// Installs the TCP Reset rule on dropPort, but listens on acceptPort to
// verify unmatched traffic flows normally.
func (*FilterInputRejectTCPResetUnmatched) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
		return err
	}

	return netutils.ListenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
// Verifies that connecting to acceptPort succeeds.
func (*FilterInputRejectTCPResetUnmatched) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}
