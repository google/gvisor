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
	"syscall"
	"time"

	"gvisor.dev/gvisor/test/netutils"
)

func init() {
	RegisterTestCase(&FilterInputConntrackNewDrop{})
	RegisterTestCase(&FilterInputConntrackEstablishedAccept{})
	RegisterTestCase(&FilterInputConntrackInvertNewDrop{})
	RegisterTestCase(&FilterInputConntrackUDPNewDrop{})
	RegisterTestCase(&FilterInputConntrackUDPEstablishedAccept{})
	RegisterTestCase(&FilterInputConntrackICMPEcho{})
	RegisterTestCase(&FilterInputConntrackRelated{})
	RegisterTestCase(&FilterOutputConntrackDNAT{})
	RegisterTestCase(&FilterOutputConntrackNoDNAT{})
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
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
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
	return netutils.SendUDPLoop(ctx, ip, acceptPort, ipv6)
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

// FilterInputConntrackRelated tests that an ICMP error for a tracked flow
// matches --ctstate RELATED.
type FilterInputConntrackRelated struct{ containerCase }

var _ TestCase = (*FilterInputConntrackRelated)(nil)

func (*FilterInputConntrackRelated) Name() string {
	return "FilterInputConntrackRelated"
}

func (*FilterInputConntrackRelated) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	proto := "icmp"
	if ipv6 {
		proto = "icmpv6"
	}
	// Only RELATED ICMP from the peer gets through, so the port unreachable
	// for the UDP flow below must match RELATED to reach the socket.
	if err := filterTable(ipv6, "-A", "INPUT", "-s", ip.String(), "-m", "conntrack", "--ctstate", "RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := filterTable(ipv6, "-A", "INPUT", "-s", ip.String(), "-p", proto, "-j", "DROP"); err != nil {
		return err
	}

	// Nothing listens on dropPort on the peer, which answers with an ICMP port
	// unreachable. A connected UDP socket reports it as ECONNREFUSED.
	conn, err := net.DialUDP(netutils.UDPNetwork(ipv6), nil, &net.UDPAddr{IP: ip, Port: dropPort})
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, 1)
	for {
		if _, err := conn.Write([]byte{0}); errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}
		if _, err := conn.Read(buf); errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no ICMP port unreachable received for port %d: %w", dropPort, ctx.Err())
		default:
		}
	}
}

func (*FilterInputConntrackRelated) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// FilterOutputConntrackDNAT tests that a DNATed flow matches --ctstate DNAT.
type FilterOutputConntrackDNAT struct{ containerCase }

var _ TestCase = (*FilterOutputConntrackDNAT)(nil)

func (*FilterOutputConntrackDNAT) Name() string {
	return "FilterOutputConntrackDNAT"
}

func (*FilterOutputConntrackDNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "conntrack", "!", "--ctstate", "DNAT", "-j", "DROP"); err != nil {
		return err
	}
	dst := netutils.NowhereIP(ipv6)
	target := fmt.Sprintf("127.0.0.1:%d", acceptPort)
	if ipv6 {
		target = fmt.Sprintf("[::1]:%d", acceptPort)
	}
	return loopbackTest(ctx, ipv6, net.ParseIP(dst),
		"-A", "OUTPUT",
		"-d", dst,
		"-p", "udp", "-m", "udp",
		"-j", "DNAT", "--to-destination", target)
}

func (*FilterOutputConntrackDNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// FilterOutputConntrackNoDNAT tests that a flow the nat table does not
// translate does not match --ctstate DNAT.
type FilterOutputConntrackNoDNAT struct{ containerCase }

var _ TestCase = (*FilterOutputConntrackNoDNAT)(nil)

func (*FilterOutputConntrackNoDNAT) Name() string {
	return "FilterOutputConntrackNoDNAT"
}

func (*FilterOutputConntrackNoDNAT) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-m", "conntrack", "--ctstate", "DNAT", "-j", "DROP"); err != nil {
		return err
	}
	dst := "127.0.0.1"
	if ipv6 {
		dst = "::1"
	}
	sendCh := make(chan error, 1)
	listenCh := make(chan error, 1)
	go func() {
		sendCh <- netutils.SendUDPLoop(ctx, net.ParseIP(dst), acceptPort, ipv6)
	}()
	go func() {
		listenCh <- netutils.ListenUDP(ctx, acceptPort, ipv6)
	}()
	select {
	case err := <-listenCh:
		return err
	case err := <-sendCh:
		return err
	}
}

func (*FilterOutputConntrackNoDNAT) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}
