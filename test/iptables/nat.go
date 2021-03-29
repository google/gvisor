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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/hostarch"
)

const redirectPort = 42

func init() {
	RegisterTestCase(&NATPreRedirectUDPPort{})
	RegisterTestCase(&NATPreRedirectTCPPort{})
	RegisterTestCase(&NATPreRedirectTCPOutgoing{})
	RegisterTestCase(&NATOutRedirectTCPIncoming{})
	RegisterTestCase(&NATOutRedirectUDPPort{})
	RegisterTestCase(&NATOutRedirectTCPPort{})
	RegisterTestCase(&NATDropUDP{})
	RegisterTestCase(&NATAcceptAll{})
	RegisterTestCase(&NATPreRedirectIP{})
	RegisterTestCase(&NATPreDontRedirectIP{})
	RegisterTestCase(&NATPreRedirectInvert{})
	RegisterTestCase(&NATOutRedirectIP{})
	RegisterTestCase(&NATOutDontRedirectIP{})
	RegisterTestCase(&NATOutRedirectInvert{})
	RegisterTestCase(&NATRedirectRequiresProtocol{})
	RegisterTestCase(&NATLoopbackSkipsPrerouting{})
	RegisterTestCase(&NATPreOriginalDst{})
	RegisterTestCase(&NATOutOriginalDst{})
	RegisterTestCase(&NATPreRECVORIGDSTADDR{})
	RegisterTestCase(&NATOutRECVORIGDSTADDR{})
}

// NATPreRedirectUDPPort tests that packets are redirected to different port.
type NATPreRedirectUDPPort struct{ containerCase }

var _ TestCase = (*NATPreRedirectUDPPort)(nil)

// Name implements TestCase.Name.
func (*NATPreRedirectUDPPort) Name() string {
	return "NATPreRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRedirectUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(ctx, redirectPort, ipv6); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", redirectPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRedirectUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// NATPreRedirectTCPPort tests that connections are redirected on specified ports.
type NATPreRedirectTCPPort struct{ baseCase }

var _ TestCase = (*NATPreRedirectTCPPort)(nil)

// Name implements TestCase.Name.
func (*NATPreRedirectTCPPort) Name() string {
	return "NATPreRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRedirectTCPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	// Listen for TCP packets on redirect port.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRedirectTCPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, dropPort, ipv6)
}

// NATPreRedirectTCPOutgoing verifies that outgoing TCP connections aren't
// affected by PREROUTING connection tracking.
type NATPreRedirectTCPOutgoing struct{ baseCase }

var _ TestCase = (*NATPreRedirectTCPOutgoing)(nil)

// Name implements TestCase.Name.
func (*NATPreRedirectTCPOutgoing) Name() string {
	return "NATPreRedirectTCPOutgoing"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRedirectTCPOutgoing) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect all incoming TCP traffic to a closed port.
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRedirectTCPOutgoing) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenTCP(ctx, acceptPort, ipv6)
}

// NATOutRedirectTCPIncoming verifies that incoming TCP connections aren't
// affected by OUTPUT connection tracking.
type NATOutRedirectTCPIncoming struct{ baseCase }

var _ TestCase = (*NATOutRedirectTCPIncoming)(nil)

// Name implements TestCase.Name.
func (*NATOutRedirectTCPIncoming) Name() string {
	return "NATOutRedirectTCPIncoming"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRedirectTCPIncoming) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect all outgoing TCP traffic to a closed port.
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return listenTCP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRedirectTCPIncoming) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, acceptPort, ipv6)
}

// NATOutRedirectUDPPort tests that packets are redirected to different port.
type NATOutRedirectUDPPort struct{ containerCase }

var _ TestCase = (*NATOutRedirectUDPPort)(nil)

// Name implements TestCase.Name.
func (*NATOutRedirectUDPPort) Name() string {
	return "NATOutRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRedirectUDPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return loopbackTest(ctx, ipv6, net.ParseIP(nowhereIP(ipv6)), "-A", "OUTPUT", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRedirectUDPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATDropUDP tests that packets are not received in ports other than redirect
// port.
type NATDropUDP struct{ containerCase }

var _ TestCase = (*NATDropUDP)(nil)

// Name implements TestCase.Name.
func (*NATDropUDP) Name() string {
	return "NATDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATDropUDP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	timedCtx, cancel := context.WithTimeout(ctx, NegativeTimeout)
	defer cancel()
	if err := listenUDP(timedCtx, acceptPort, ipv6); err == nil {
		return fmt.Errorf("packets on port %d should have been redirected to port %d", acceptPort, redirectPort)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATDropUDP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// NATAcceptAll tests that all UDP packets are accepted.
type NATAcceptAll struct{ containerCase }

var _ TestCase = (*NATAcceptAll)(nil)

// Name implements TestCase.Name.
func (*NATAcceptAll) Name() string {
	return "NATAcceptAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATAcceptAll) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "ACCEPT"); err != nil {
		return err
	}

	if err := listenUDP(ctx, acceptPort, ipv6); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATAcceptAll) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// NATOutRedirectIP uses iptables to select packets based on destination IP and
// redirects them.
type NATOutRedirectIP struct{ baseCase }

var _ TestCase = (*NATOutRedirectIP)(nil)

// Name implements TestCase.Name.
func (*NATOutRedirectIP) Name() string {
	return "NATOutRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRedirectIP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	return loopbackTest(ctx, ipv6, net.ParseIP(nowhereIP(ipv6)),
		"-A", "OUTPUT",
		"-d", nowhereIP(ipv6),
		"-p", "udp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRedirectIP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATOutDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATOutDontRedirectIP struct{ localCase }

var _ TestCase = (*NATOutDontRedirectIP)(nil)

// Name implements TestCase.Name.
func (*NATOutDontRedirectIP) Name() string {
	return "NATOutDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutDontRedirectIP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "OUTPUT", "-d", localIP(ipv6), "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutDontRedirectIP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return listenUDP(ctx, acceptPort, ipv6)
}

// NATOutRedirectInvert tests that iptables can match with "! -d".
type NATOutRedirectInvert struct{ baseCase }

var _ TestCase = (*NATOutRedirectInvert)(nil)

// Name implements TestCase.Name.
func (*NATOutRedirectInvert) Name() string {
	return "NATOutRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRedirectInvert) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := "192.0.2.2"
	if ipv6 {
		dest = "2001:db8::2"
	}
	return loopbackTest(ctx, ipv6, net.ParseIP(nowhereIP(ipv6)),
		"-A", "OUTPUT",
		"!", "-d", dest,
		"-p", "udp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRedirectInvert) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATPreRedirectIP tests that we can use iptables to select packets based on
// destination IP and redirect them.
type NATPreRedirectIP struct{ containerCase }

var _ TestCase = (*NATPreRedirectIP)(nil)

// Name implements TestCase.Name.
func (*NATPreRedirectIP) Name() string {
	return "NATPreRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRedirectIP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	addrs, err := localAddrs(ipv6)
	if err != nil {
		return err
	}

	var rules [][]string
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "PREROUTING", "-p", "udp", "-d", addr, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)})
	}
	if err := natTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRedirectIP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort, ipv6)
}

// NATPreDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATPreDontRedirectIP struct{ containerCase }

var _ TestCase = (*NATPreDontRedirectIP)(nil)

// Name implements TestCase.Name.
func (*NATPreDontRedirectIP) Name() string {
	return "NATPreDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreDontRedirectIP) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return listenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreDontRedirectIP) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// NATPreRedirectInvert tests that iptables can match with "! -d".
type NATPreRedirectInvert struct{ containerCase }

var _ TestCase = (*NATPreRedirectInvert)(nil)

// Name implements TestCase.Name.
func (*NATPreRedirectInvert) Name() string {
	return "NATPreRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRedirectInvert) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "!", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}
	return listenUDP(ctx, acceptPort, ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRedirectInvert) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, dropPort, ipv6)
}

// NATRedirectRequiresProtocol tests that use of the --to-ports flag requires a
// protocol to be specified with -p.
type NATRedirectRequiresProtocol struct{ baseCase }

var _ TestCase = (*NATRedirectRequiresProtocol)(nil)

// Name implements TestCase.Name.
func (*NATRedirectRequiresProtocol) Name() string {
	return "NATRedirectRequiresProtocol"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATRedirectRequiresProtocol) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err == nil {
		return errors.New("expected an error using REDIRECT --to-ports without a protocol")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATRedirectRequiresProtocol) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATOutRedirectTCPPort tests that connections are redirected on specified ports.
type NATOutRedirectTCPPort struct{ baseCase }

var _ TestCase = (*NATOutRedirectTCPPort)(nil)

// Name implements TestCase.Name.
func (*NATOutRedirectTCPPort) Name() string {
	return "NATOutRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRedirectTCPPort) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	localAddr := net.TCPAddr{
		IP:   net.ParseIP(localIP(ipv6)),
		Port: acceptPort,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Accept connections on port.
	if err := connectTCP(ctx, ip, dropPort, ipv6); err != nil {
		return err
	}

	conn, err := lConn.AcceptTCP()
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRedirectTCPPort) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return nil
}

// NATLoopbackSkipsPrerouting tests that packets sent via loopback aren't
// affected by PREROUTING rules.
type NATLoopbackSkipsPrerouting struct{ baseCase }

var _ TestCase = (*NATLoopbackSkipsPrerouting)(nil)

// Name implements TestCase.Name.
func (*NATLoopbackSkipsPrerouting) Name() string {
	return "NATLoopbackSkipsPrerouting"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATLoopbackSkipsPrerouting) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect anything sent to localhost to an unused port.
	dest := []byte{127, 0, 0, 1}
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection via localhost. If the PREROUTING rule did apply to
	// loopback traffic, the connection would fail.
	sendCh := make(chan error)
	go func() {
		sendCh <- connectTCP(ctx, dest, acceptPort, ipv6)
	}()

	if err := listenTCP(ctx, acceptPort, ipv6); err != nil {
		return err
	}
	return <-sendCh
}

// LocalAction implements TestCase.LocalAction.
func (*NATLoopbackSkipsPrerouting) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

// NATPreOriginalDst tests that SO_ORIGINAL_DST returns the pre-NAT destination
// of PREROUTING NATted packets.
type NATPreOriginalDst struct{ baseCase }

var _ TestCase = (*NATPreOriginalDst)(nil)

// Name implements TestCase.Name.
func (*NATPreOriginalDst) Name() string {
	return "NATPreOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreOriginalDst) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect incoming TCP connections to acceptPort.
	if err := natTable(ipv6, "-A", "PREROUTING",
		"-p", "tcp",
		"--destination-port", fmt.Sprintf("%d", dropPort),
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	addrs, err := getInterfaceAddrs(ipv6)
	if err != nil {
		return err
	}
	return listenForRedirectedConn(ctx, ipv6, addrs)
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreOriginalDst) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return connectTCP(ctx, ip, dropPort, ipv6)
}

// NATOutOriginalDst tests that SO_ORIGINAL_DST returns the pre-NAT destination
// of OUTBOUND NATted packets.
type NATOutOriginalDst struct{ baseCase }

var _ TestCase = (*NATOutOriginalDst)(nil)

// Name implements TestCase.Name.
func (*NATOutOriginalDst) Name() string {
	return "NATOutOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutOriginalDst) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// Redirect incoming TCP connections to acceptPort.
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	connCh := make(chan error)
	go func() {
		connCh <- connectTCP(ctx, ip, dropPort, ipv6)
	}()

	if err := listenForRedirectedConn(ctx, ipv6, []net.IP{ip}); err != nil {
		return err
	}
	return <-connCh
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutOriginalDst) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

func listenForRedirectedConn(ctx context.Context, ipv6 bool, originalDsts []net.IP) error {
	// The net package doesn't give guaranteed access to the connection's
	// underlying FD, and thus we cannot call getsockopt. We have to use
	// traditional syscalls.

	// Create the listening socket, bind, listen, and accept.
	family := unix.AF_INET
	if ipv6 {
		family = unix.AF_INET6
	}
	sockfd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sockfd)

	var bindAddr unix.Sockaddr
	if ipv6 {
		bindAddr = &unix.SockaddrInet6{
			Port: acceptPort,
			Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // in6addr_any
		}
	} else {
		bindAddr = &unix.SockaddrInet4{
			Port: acceptPort,
			Addr: [4]byte{0, 0, 0, 0}, // INADDR_ANY
		}
	}
	if err := unix.Bind(sockfd, bindAddr); err != nil {
		return err
	}

	if err := unix.Listen(sockfd, 1); err != nil {
		return err
	}

	// Block on accept() in another goroutine.
	connCh := make(chan int)
	errCh := make(chan error)
	go func() {
		for {
			connFD, _, err := unix.Accept(sockfd)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				errCh <- err
				return
			}
			connCh <- connFD
			return
		}
	}()

	// Wait for accept() to return or for the context to finish.
	var connFD int
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case connFD = <-connCh:
	}
	defer unix.Close(connFD)

	// Verify that, despite listening on acceptPort, SO_ORIGINAL_DST
	// indicates the packet was sent to originalDst:dropPort.
	if ipv6 {
		got, err := originalDestination6(connFD)
		if err != nil {
			return err
		}
		return addrMatches6(got, originalDsts, dropPort)
	}

	got, err := originalDestination4(connFD)
	if err != nil {
		return err
	}
	return addrMatches4(got, originalDsts, dropPort)
}

// loopbackTests runs an iptables rule and ensures that packets sent to
// dest:dropPort are received by localhost:acceptPort.
func loopbackTest(ctx context.Context, ipv6 bool, dest net.IP, args ...string) error {
	if err := natTable(ipv6, args...); err != nil {
		return err
	}
	sendCh := make(chan error, 1)
	listenCh := make(chan error, 1)
	go func() {
		sendCh <- sendUDPLoop(ctx, dest, dropPort, ipv6)
	}()
	go func() {
		listenCh <- listenUDP(ctx, acceptPort, ipv6)
	}()
	select {
	case err := <-listenCh:
		return err
	case err := <-sendCh:
		return err
	}
}

// NATPreRECVORIGDSTADDR tests that IP{V6}_RECVORIGDSTADDR gets the post-NAT
// address on the PREROUTING chain.
type NATPreRECVORIGDSTADDR struct{ containerCase }

var _ TestCase = (*NATPreRECVORIGDSTADDR)(nil)

// Name implements TestCase.Name.
func (*NATPreRECVORIGDSTADDR) Name() string {
	return "NATPreRECVORIGDSTADDR"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATPreRECVORIGDSTADDR) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := recvWithRECVORIGDSTADDR(ctx, ipv6, nil, redirectPort); err != nil {
		return err
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (*NATPreRECVORIGDSTADDR) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return sendUDPLoop(ctx, ip, acceptPort, ipv6)
}

// NATOutRECVORIGDSTADDR tests that IP{V6}_RECVORIGDSTADDR gets the post-NAT
// address on the OUTPUT chain.
type NATOutRECVORIGDSTADDR struct{ containerCase }

var _ TestCase = (*NATOutRECVORIGDSTADDR)(nil)

// Name implements TestCase.Name.
func (*NATOutRECVORIGDSTADDR) Name() string {
	return "NATOutRECVORIGDSTADDR"
}

// ContainerAction implements TestCase.ContainerAction.
func (*NATOutRECVORIGDSTADDR) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	sendCh := make(chan error)
	go func() {
		// Packets will be sent to a non-container IP and redirected
		// back to the container.
		sendCh <- sendUDPLoop(ctx, ip, acceptPort, ipv6)
	}()

	expectedIP := &net.IP{127, 0, 0, 1}
	if ipv6 {
		expectedIP = &net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	}
	if err := recvWithRECVORIGDSTADDR(ctx, ipv6, expectedIP, redirectPort); err != nil {
		return err
	}

	select {
	case err := <-sendCh:
		return err
	default:
		return nil
	}
}

// LocalAction implements TestCase.LocalAction.
func (*NATOutRECVORIGDSTADDR) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	// No-op.
	return nil
}

func recvWithRECVORIGDSTADDR(ctx context.Context, ipv6 bool, expectedDst *net.IP, port uint16) error {
	// The net package doesn't give guaranteed access to a connection's
	// underlying FD, and thus we cannot call getsockopt. We have to use
	// traditional syscalls for IP_RECVORIGDSTADDR.

	// Create the listening socket.
	var (
		family                 = unix.AF_INET
		level                  = unix.SOL_IP
		option                 = unix.IP_RECVORIGDSTADDR
		bindAddr unix.Sockaddr = &unix.SockaddrInet4{
			Port: int(port),
			Addr: [4]byte{0, 0, 0, 0}, // INADDR_ANY
		}
	)
	if ipv6 {
		family = unix.AF_INET6
		level = unix.SOL_IPV6
		option = 74 // IPV6_RECVORIGDSTADDR, which is missing from the syscall package.
		bindAddr = &unix.SockaddrInet6{
			Port: int(port),
			Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // in6addr_any
		}
	}
	sockfd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed Socket(%d, %d, 0): %w", family, unix.SOCK_DGRAM, err)
	}
	defer unix.Close(sockfd)

	if err := unix.Bind(sockfd, bindAddr); err != nil {
		return fmt.Errorf("failed Bind(%d, %+v): %v", sockfd, bindAddr, err)
	}

	// Enable IP_RECVORIGDSTADDR.
	if err := unix.SetsockoptInt(sockfd, level, option, 1); err != nil {
		return fmt.Errorf("failed SetsockoptByte(%d, %d, %d, 1): %v", sockfd, level, option, err)
	}

	addrCh := make(chan interface{})
	errCh := make(chan error)
	go func() {
		var addr interface{}
		var err error
		if ipv6 {
			addr, err = recvOrigDstAddr6(sockfd)
		} else {
			addr, err = recvOrigDstAddr4(sockfd)
		}
		if err != nil {
			errCh <- err
		} else {
			addrCh <- addr
		}
	}()

	// Wait to receive a packet.
	var addr interface{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case addr = <-addrCh:
	}

	// Get a list of local IPs to verify that the packet now appears to have
	// been sent to us.
	var localAddrs []net.IP
	if expectedDst != nil {
		localAddrs = []net.IP{*expectedDst}
	} else {
		localAddrs, err = getInterfaceAddrs(ipv6)
		if err != nil {
			return fmt.Errorf("failed to get local interfaces: %w", err)
		}
	}

	// Verify that the address has the post-NAT port and address.
	if ipv6 {
		return addrMatches6(addr.(unix.RawSockaddrInet6), localAddrs, redirectPort)
	}
	return addrMatches4(addr.(unix.RawSockaddrInet4), localAddrs, redirectPort)
}

func recvOrigDstAddr4(sockfd int) (unix.RawSockaddrInet4, error) {
	buf, err := recvOrigDstAddr(sockfd, unix.SOL_IP, unix.SizeofSockaddrInet4)
	if err != nil {
		return unix.RawSockaddrInet4{}, err
	}
	var addr unix.RawSockaddrInet4
	binary.Unmarshal(buf, hostarch.ByteOrder, &addr)
	return addr, nil
}

func recvOrigDstAddr6(sockfd int) (unix.RawSockaddrInet6, error) {
	buf, err := recvOrigDstAddr(sockfd, unix.SOL_IP, unix.SizeofSockaddrInet6)
	if err != nil {
		return unix.RawSockaddrInet6{}, err
	}
	var addr unix.RawSockaddrInet6
	binary.Unmarshal(buf, hostarch.ByteOrder, &addr)
	return addr, nil
}

func recvOrigDstAddr(sockfd int, level uintptr, addrSize int) ([]byte, error) {
	buf := make([]byte, 64)
	oob := make([]byte, unix.CmsgSpace(addrSize))
	for {
		_, oobn, _, _, err := unix.Recvmsg(
			sockfd,
			buf, // Message buffer.
			oob, // Out-of-band buffer.
			0)   // Flags.
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed when calling Recvmsg: %w", err)
		}
		oob = oob[:oobn]

		// Parse out the control message.
		msgs, err := unix.ParseSocketControlMessage(oob)
		if err != nil {
			return nil, fmt.Errorf("failed to parse control message: %w", err)
		}
		return msgs[0].Data, nil
	}
}

func addrMatches4(got unix.RawSockaddrInet4, wantAddrs []net.IP, port uint16) error {
	for _, wantAddr := range wantAddrs {
		want := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(port),
		}
		copy(want.Addr[:], wantAddr.To4())
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("got %+v, but wanted one of %+v (note: port numbers are in network byte order)", got, wantAddrs)
}

func addrMatches6(got unix.RawSockaddrInet6, wantAddrs []net.IP, port uint16) error {
	for _, wantAddr := range wantAddrs {
		want := unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Port:   htons(port),
		}
		copy(want.Addr[:], wantAddr.To16())
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("got %+v, but wanted one of %+v (note: port numbers are in network byte order)", got, wantAddrs)
}
