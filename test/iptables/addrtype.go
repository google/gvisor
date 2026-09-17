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
	RegisterTestCase(&FilterInputAddrTypeUnicastDrop{})
	RegisterTestCase(&FilterInputAddrTypeBroadcastDrop{})
	RegisterTestCase(&FilterInputAddrTypeMulticastDrop{})
	RegisterTestCase(&FilterInputAddrTypeInvertBroadcastDrop{})
	RegisterTestCase(&FilterInputAddrTypeFIBReject{})
}

// FilterInputAddrTypeUnicastDrop tests dropping packets matching --dst-type UNICAST.
type FilterInputAddrTypeUnicastDrop struct{ containerCase }

var _ TestCase = (*FilterInputAddrTypeUnicastDrop)(nil)

func (*FilterInputAddrTypeUnicastDrop) Name() string {
	return "FilterInputAddrTypeUnicastDrop"
}

func (*FilterInputAddrTypeUnicastDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "UNICAST", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
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

func (*FilterInputAddrTypeUnicastDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}

// FilterInputAddrTypeBroadcastDrop tests matching with --dst-type BROADCAST.
type FilterInputAddrTypeBroadcastDrop struct{ localCase }

var _ TestCase = (*FilterInputAddrTypeBroadcastDrop)(nil)

func (*FilterInputAddrTypeBroadcastDrop) Name() string {
	return "FilterInputAddrTypeBroadcastDrop"
}

func (*FilterInputAddrTypeBroadcastDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop broadcast packets, but unicast should pass through to acceptPort.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputAddrTypeBroadcastDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, sendloopDuration)
}

// FilterInputAddrTypeMulticastDrop tests matching with --dst-type MULTICAST.
type FilterInputAddrTypeMulticastDrop struct{ localCase }

var _ TestCase = (*FilterInputAddrTypeMulticastDrop)(nil)

func (*FilterInputAddrTypeMulticastDrop) Name() string {
	return "FilterInputAddrTypeMulticastDrop"
}

func (*FilterInputAddrTypeMulticastDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop multicast packets, but unicast should pass through.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "addrtype", "--dst-type", "MULTICAST", "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputAddrTypeMulticastDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, sendloopDuration)
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
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}

// FilterInputAddrTypeFIBReject tests that unsupported FIB routing address types
// (such as BLACKHOLE, UNREACHABLE, PROHIBIT) are explicitly rejected during rule load.
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
