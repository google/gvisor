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
	RegisterTestCase(&FilterInputConntrackNewDrop{})
	RegisterTestCase(&FilterInputConntrackEstablishedAccept{})
	RegisterTestCase(&FilterInputConntrackInvertNewDrop{})
	RegisterTestCase(&FilterInputConntrackUDPNewDrop{})
	RegisterTestCase(&FilterInputConntrackUDPEstablishedAccept{})
	RegisterTestCase(&FilterInputConntrackICMPEcho{})
}

// FilterInputConntrackNewDrop tests dropping new TCP connections based on ctstate NEW.
type FilterInputConntrackNewDrop struct{ containerCase }

var _ TestCase = (*FilterInputConntrackNewDrop)(nil)

func (*FilterInputConntrackNewDrop) Name() string {
	return "FilterInputConntrackNewDrop"
}

func (*FilterInputConntrackNewDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenTCP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("connection on port %d should have been dropped, but succeeded", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error listening: %v", err)
	}

	return nil
}

func (*FilterInputConntrackNewDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ConnectTCP(timedCtx, ip, dropPort, ipv6); err == nil {
		return fmt.Errorf("expected connect error on port %d", dropPort)
	}
	return nil
}

// FilterInputConntrackEstablishedAccept tests allowing established traffic while dropping new traffic.
type FilterInputConntrackEstablishedAccept struct{ localCase }

var _ TestCase = (*FilterInputConntrackEstablishedAccept)(nil)

func (*FilterInputConntrackEstablishedAccept) Name() string {
	return "FilterInputConntrackEstablishedAccept"
}

func (*FilterInputConntrackEstablishedAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Accept established connections, drop everything else.
	if err := filterTable(ipv6, "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}
	return netutils.ListenTCP(ctx, acceptPort, ipv6)
}

func (*FilterInputConntrackEstablishedAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.ConnectTCP(ctx, ip, acceptPort, ipv6)
}

// FilterInputConntrackInvertNewDrop tests inverted matching: ! --ctstate NEW.
type FilterInputConntrackInvertNewDrop struct{ containerCase }

var _ TestCase = (*FilterInputConntrackInvertNewDrop)(nil)

func (*FilterInputConntrackInvertNewDrop) Name() string {
	return "FilterInputConntrackInvertNewDrop"
}

func (*FilterInputConntrackInvertNewDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Drop anything that is NOT new, accept new.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "conntrack", "!", "--ctstate", "NEW", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}
	return nil
}

func (*FilterInputConntrackInvertNewDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// FilterInputConntrackUDPNewDrop tests dropping new UDP flows via --ctstate NEW.
type FilterInputConntrackUDPNewDrop struct{ containerCase }

var _ TestCase = (*FilterInputConntrackUDPNewDrop)(nil)

func (*FilterInputConntrackUDPNewDrop) Name() string {
	return "FilterInputConntrackUDPNewDrop"
}

func (*FilterInputConntrackUDPNewDrop) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "conntrack", "--ctstate", "NEW", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("UDP packets on port %d should have been dropped, but got packet", dropPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error listening: %v", err)
	}

	return nil
}

func (*FilterInputConntrackUDPNewDrop) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, sendloopDuration)
}

// FilterInputConntrackUDPEstablishedAccept tests matching UDP traffic under --ctstate ESTABLISHED.
type FilterInputConntrackUDPEstablishedAccept struct{ localCase }

var _ TestCase = (*FilterInputConntrackUDPEstablishedAccept)(nil)

func (*FilterInputConntrackUDPEstablishedAccept) Name() string {
	return "FilterInputConntrackUDPEstablishedAccept"
}

func (*FilterInputConntrackUDPEstablishedAccept) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}
	return netutils.ListenUDP(ctx, acceptPort, ipv6)
}

func (*FilterInputConntrackUDPEstablishedAccept) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, acceptPort, sendloopDuration)
}

// FilterInputConntrackICMPEcho tests matching ICMP echo packets under --ctstate NEW.
type FilterInputConntrackICMPEcho struct{ localCase }

var _ TestCase = (*FilterInputConntrackICMPEcho)(nil)

func (*FilterInputConntrackICMPEcho) Name() string {
	return "FilterInputConntrackICMPEcho"
}

func (*FilterInputConntrackICMPEcho) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	proto := "icmp"
	if ipv6 {
		proto = "icmpv6"
	}
	if err := filterTable(ipv6, "-A", "INPUT", "-p", proto, "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

func (*FilterInputConntrackICMPEcho) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}
