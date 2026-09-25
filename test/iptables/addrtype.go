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
	RegisterTestCase(&FilterInputAddrTypeLocalDrop{})
	RegisterTestCase(&FilterInputAddrTypeUnicastNotBroadcast{})
	RegisterTestCase(&FilterInputAddrTypeUnicastNotMulticast{})
	RegisterTestCase(&FilterInputAddrTypeInvertBroadcastDrop{})
	RegisterTestCase(&FilterInputAddrTypeFIBReject{})
	RegisterTestCase(&FilterInputAddrTypeLocalAccept{})
	RegisterTestCase(&FilterInputAddrTypeIPv6BroadcastReject{})
}

// FilterInputAddrTypeLocalDrop tests that --dst-type LOCAL matches packets to an
// address assigned to the container.
type FilterInputAddrTypeLocalDrop struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeLocalDrop)(nil)

func (*FilterInputAddrTypeLocalDrop) Name() string {
	return "FilterInputAddrTypeLocalDrop"
}

func (*FilterInputAddrTypeLocalDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "LOCAL", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
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

func (*FilterInputAddrTypeLocalDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// FilterInputAddrTypeUnicastNotBroadcast tests that --dst-type BROADCAST does not
// match unicast packets.
type FilterInputAddrTypeUnicastNotBroadcast struct{ localCase }

var _ TestCase = (*FilterInputAddrTypeUnicastNotBroadcast)(nil)

func (*FilterInputAddrTypeUnicastNotBroadcast) Name() string {
	return "FilterInputAddrTypeUnicastNotBroadcast"
}

func (*FilterInputAddrTypeUnicastNotBroadcast) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop broadcast packets, but unicast should pass through to acceptPort.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputAddrTypeUnicastNotBroadcast) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// FilterInputAddrTypeUnicastNotMulticast tests that --dst-type MULTICAST does not
// match unicast packets.
type FilterInputAddrTypeUnicastNotMulticast struct{ localCase }

var _ TestCase = (*FilterInputAddrTypeUnicastNotMulticast)(nil)

func (*FilterInputAddrTypeUnicastNotMulticast) Name() string {
	return "FilterInputAddrTypeUnicastNotMulticast"
}

func (*FilterInputAddrTypeUnicastNotMulticast) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop multicast packets, but unicast should pass through.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "MULTICAST", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputAddrTypeUnicastNotMulticast) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// FilterInputAddrTypeInvertBroadcastDrop tests inverted match ! --dst-type BROADCAST.
type FilterInputAddrTypeInvertBroadcastDrop struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeInvertBroadcastDrop)(nil)

func (*FilterInputAddrTypeInvertBroadcastDrop) Name() string {
	return "FilterInputAddrTypeInvertBroadcastDrop"
}

func (*FilterInputAddrTypeInvertBroadcastDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop anything that is NOT broadcast (i.e. unicast) destined for dropPort.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "!", "--dst-type", "BROADCAST", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
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

func (*FilterInputAddrTypeInvertBroadcastDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}

// FilterInputAddrTypeFIBReject tests that BLACKHOLE is rejected at rule load.
// Linux rejects it for IPv6; for IPv4 the FIB route types are not implemented.
type FilterInputAddrTypeFIBReject struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeFIBReject)(nil)

func (*FilterInputAddrTypeFIBReject) Name() string {
	return "FilterInputAddrTypeFIBReject"
}

func (*FilterInputAddrTypeFIBReject) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "BLACKHOLE", "-j", "DROP"); err == nil {
		return fmt.Errorf("expected error installing addrtype rule with unsupported BLACKHOLE type, but succeeded")
	}
	return nil
}

func (*FilterInputAddrTypeFIBReject) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// FilterInputAddrTypeLocalAccept tests that packets to an address assigned to
// the container are classified as LOCAL: only packets that are not LOCAL are
// dropped, so the listener must receive.
type FilterInputAddrTypeLocalAccept struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeLocalAccept)(nil)

func (*FilterInputAddrTypeLocalAccept) Name() string {
	return "FilterInputAddrTypeLocalAccept"
}

func (*FilterInputAddrTypeLocalAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "--destination-port", fmt.Sprintf("%d", acceptPort), "-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputAddrTypeLocalAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// FilterInputAddrTypeIPv6BroadcastReject tests that --dst-type BROADCAST is
// rejected for IPv6, as in Linux addrtype_mt_checkentry_v1.
type FilterInputAddrTypeIPv6BroadcastReject struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeIPv6BroadcastReject)(nil)

func (*FilterInputAddrTypeIPv6BroadcastReject) Name() string {
	return "FilterInputAddrTypeIPv6BroadcastReject"
}

func (*FilterInputAddrTypeIPv6BroadcastReject) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "DROP")
	if ipv6 && err == nil {
		return fmt.Errorf("expected error installing addrtype BROADCAST rule for IPv6, but succeeded")
	}
	if !ipv6 && err != nil {
		return fmt.Errorf("installing addrtype BROADCAST rule for IPv4: %w", err)
	}
	return nil
}

func (*FilterInputAddrTypeIPv6BroadcastReject) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}
