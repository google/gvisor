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
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	redirectPort    = 42
	SO_ORIGINAL_DST = 80
	// originalDstErrno is returned by SO_ORIGINAL_DST when packet's aren't
	// NATed.
	originalDstErrno = syscall.ENOENT
)

func init() {
	RegisterTestCase(NATPreRedirectUDPPort{})
	RegisterTestCase(NATPreRedirectTCPPort{})
	RegisterTestCase(NATPreRedirectTCPOutgoing{})
	RegisterTestCase(NATOutRedirectTCPIncoming{})
	RegisterTestCase(NATOutRedirectUDPPort{})
	RegisterTestCase(NATOutRedirectTCPPort{})
	RegisterTestCase(NATDropUDP{})
	RegisterTestCase(NATAcceptAll{})
	RegisterTestCase(NATPreRedirectIP{})
	RegisterTestCase(NATPreDontRedirectIP{})
	RegisterTestCase(NATPreRedirectInvert{})
	RegisterTestCase(NATOutRedirectIP{})
	RegisterTestCase(NATOutDontRedirectIP{})
	RegisterTestCase(NATOutRedirectInvert{})
	RegisterTestCase(NATRedirectRequiresProtocol{})
	RegisterTestCase(NATLoopbackSkipsPrerouting{})
	RegisterTestCase(NATPreOriginalDst{})
	RegisterTestCase(NATOutOriginalDst{})
	// RegisterTestCase(NATPreOriginalDstUnchanged{})
}

// NATPreRedirectUDPPort tests that packets are redirected to different port.
type NATPreRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectUDPPort) Name() string {
	return "NATPreRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectUDPPort) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(redirectPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", redirectPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATPreRedirectTCPPort tests that connections are redirected on specified ports.
type NATPreRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPPort) Name() string {
	return "NATPreRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPPort) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	// Listen for TCP packets on redirect port.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPPort) LocalAction(ip net.IP) error {
	return connectTCP(ip, dropPort, sendloopDuration)
}

// NATPreRedirectTCPOutgoing verifies that outgoing TCP connections aren't
// affected by PREROUTING connection tracking.
type NATPreRedirectTCPOutgoing struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPOutgoing) Name() string {
	return "NATPreRedirectTCPOutgoing"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPOutgoing) ContainerAction(ip net.IP) error {
	// Redirect all incoming TCP traffic to a closed port.
	if err := natTable("-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPOutgoing) LocalAction(ip net.IP) error {
	return listenTCP(acceptPort, sendloopDuration)
}

// NATOutRedirectTCPIncoming verifies that incoming TCP connections aren't
// affected by OUTPUT connection tracking.
type NATOutRedirectTCPIncoming struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPIncoming) Name() string {
	return "NATOutRedirectTCPIncoming"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPIncoming) ContainerAction(ip net.IP) error {
	// Redirect all incoming TCP traffic to a closed port.
	if err := natTable("-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return listenTCP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectTCPIncoming) LocalAction(ip net.IP) error {
	return connectTCP(ip, acceptPort, sendloopDuration)
}

// NATOutRedirectUDPPort tests that packets are redirected to different port.
type NATOutRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectUDPPort) Name() string {
	return "NATOutRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectUDPPort) ContainerAction(ip net.IP) error {
	dest := []byte{200, 0, 0, 1}
	return loopbackTest(dest, "-A", "OUTPUT", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectUDPPort) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// NATDropUDP tests that packets are not received in ports other than redirect
// port.
type NATDropUDP struct{}

// Name implements TestCase.Name.
func (NATDropUDP) Name() string {
	return "NATDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATDropUDP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been redirected to port %d", acceptPort, redirectPort)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATDropUDP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATAcceptAll tests that all UDP packets are accepted.
type NATAcceptAll struct{}

// Name implements TestCase.Name.
func (NATAcceptAll) Name() string {
	return "NATAcceptAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATAcceptAll) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-j", "ACCEPT"); err != nil {
		return err
	}

	if err := listenUDP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATAcceptAll) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATOutRedirectIP uses iptables to select packets based on destination IP and
// redirects them.
type NATOutRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutRedirectIP) Name() string {
	return "NATOutRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectIP) ContainerAction(ip net.IP) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := net.IP([]byte{200, 0, 0, 2})
	return loopbackTest(dest, "-A", "OUTPUT", "-d", dest.String(), "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectIP) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// NATOutDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATOutDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutDontRedirectIP) Name() string {
	return "NATOutDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutDontRedirectIP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "OUTPUT", "-d", localIP, "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutDontRedirectIP) LocalAction(ip net.IP) error {
	return listenUDP(acceptPort, sendloopDuration)
}

// NATOutRedirectInvert tests that iptables can match with "! -d".
type NATOutRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATOutRedirectInvert) Name() string {
	return "NATOutRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectInvert) ContainerAction(ip net.IP) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := []byte{200, 0, 0, 3}
	destStr := "200.0.0.2"
	return loopbackTest(dest, "-A", "OUTPUT", "!", "-d", destStr, "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectInvert) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// NATPreRedirectIP tests that we can use iptables to select packets based on
// destination IP and redirect them.
type NATPreRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreRedirectIP) Name() string {
	return "NATPreRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectIP) ContainerAction(ip net.IP) error {
	addrs, err := localAddrs(false)
	if err != nil {
		return err
	}

	var rules [][]string
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "PREROUTING", "-p", "udp", "-d", addr, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)})
	}
	if err := natTableRules(rules); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectIP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// NATPreDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATPreDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreDontRedirectIP) Name() string {
	return "NATPreDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreDontRedirectIP) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreDontRedirectIP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// NATPreRedirectInvert tests that iptables can match with "! -d".
type NATPreRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATPreRedirectInvert) Name() string {
	return "NATPreRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectInvert) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-p", "udp", "!", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}
	return listenUDP(acceptPort, sendloopDuration)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectInvert) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// NATRedirectRequiresProtocol tests that use of the --to-ports flag requires a
// protocol to be specified with -p.
type NATRedirectRequiresProtocol struct{}

// Name implements TestCase.Name.
func (NATRedirectRequiresProtocol) Name() string {
	return "NATRedirectRequiresProtocol"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectRequiresProtocol) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "PREROUTING", "-d", localIP, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err == nil {
		return errors.New("expected an error using REDIRECT --to-ports without a protocol")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectRequiresProtocol) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// NATOutRedirectTCPPort tests that connections are redirected on specified ports.
type NATOutRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPPort) Name() string {
	return "NATOutRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPPort) ContainerAction(ip net.IP) error {
	if err := natTable("-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", dropPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err != nil {
		return err
	}

	timeout := 20 * time.Second
	dest := []byte{127, 0, 0, 1}
	localAddr := net.TCPAddr{
		IP:   dest,
		Port: acceptPort,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Accept connections on port.
	lConn.SetDeadline(time.Now().Add(timeout))
	err = connectTCP(ip, dropPort, timeout)
	if err != nil {
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
func (NATOutRedirectTCPPort) LocalAction(ip net.IP) error {
	return nil
}

// NATLoopbackSkipsPrerouting tests that packets sent via loopback aren't
// affected by PREROUTING rules.
type NATLoopbackSkipsPrerouting struct{}

// Name implements TestCase.Name.
func (NATLoopbackSkipsPrerouting) Name() string {
	return "NATLoopbackSkipsPrerouting"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATLoopbackSkipsPrerouting) ContainerAction(ip net.IP) error {
	// Redirect anything sent to localhost to an unused port.
	dest := []byte{127, 0, 0, 1}
	if err := natTable("-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection via localhost. If the PREROUTING rule did apply to
	// loopback traffic, the connection would fail.
	sendCh := make(chan error)
	go func() {
		sendCh <- connectTCP(dest, acceptPort, sendloopDuration)
	}()

	if err := listenTCP(acceptPort, sendloopDuration); err != nil {
		return err
	}
	return <-sendCh
}

// LocalAction implements TestCase.LocalAction.
func (NATLoopbackSkipsPrerouting) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// tests that SO_ORIGINAL_DST returns the pre-NAT destination of PREROUTING
// NATted packets.
type NATPreOriginalDst struct{}

// Name implements TestCase.Name.
func (NATPreOriginalDst) Name() string {
	return "NATPreOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreOriginalDst) ContainerAction(ip net.IP) error {
	// Redirect incoming TCP connections to acceptPort.
	if err := natTable("-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort)); err != nil {
		return fmt.Errorf("1")
		return err
	}

	addr, err := getInterfaceAddr()
	if err != nil {
		return err
	}
	log.Printf("addr is %v", addr)
	return listenForRedirectedConn(addr)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreOriginalDst) LocalAction(ip net.IP) error {
	return connectTCP(ip, dropPort, sendloopDuration)
}

// tests that SO_ORIGINAL_DST returns the pre-NAT destination of OUTBOUND NATted
// packets.
type NATOutOriginalDst struct{}

// Name implements TestCase.Name.
func (NATOutOriginalDst) Name() string {
	return "NATOutOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutOriginalDst) ContainerAction(ip net.IP) error {
	// Redirect incoming TCP connections to acceptPort.
	if err := natTable("-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", acceptPort)); err != nil {
		return fmt.Errorf("1")
		return err
	}

	connCh := make(chan error)
	go func() {
		connCh <- connectTCP(ip, dropPort, sendloopDuration)
	}()

	if err := listenForRedirectedConn(ip.To4()); err != nil {
		return err
	}
	return <-connCh
}

// LocalAction implements TestCase.LocalAction.
func (NATOutOriginalDst) LocalAction(ip net.IP) error {
	// No-op.
	return nil
}

// // Tests that SO_ORIGINAL_DST fails on PREROUTING connections not affected by
// // NAT.
// type NATPreOriginalDstUnchanged struct{}

// // Name implements TestCase.Name.
// func (NATPreOriginalDstUnchanged) Name() string {
// 	return "NATPreOriginalDstUnchanged"
// }

// // ContainerAction implements TestCase.ContainerAction.
// func (NATPreOriginalDstUnchanged) ContainerAction(ip net.IP) error {
// 	addr, err := getInterfaceAddr()
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("addr is %v", addr)
// 	// TODO: Check error type.
// 	err = listenForRedirectedConn(addr)
// 	if err == nil {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but no error occurred", originalDstErrno)
// 	}
// 	if err, ok := err.(originalDstError); !ok {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but got error: %v", err)
// 	} else if err.errno != originalDstErrno {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but got errno: %d", originalDstErrno, err.errno)
// 	} else {
// 		log.Printf("err.errno: %d", err.errno)
// 	}
// 	return nil
// }

// // LocalAction implements TestCase.LocalAction.
// func (NATPreOriginalDstUnchanged) LocalAction(ip net.IP) error {
// 	return connectTCP(ip, acceptPort, sendloopDuration)
// }

// // Tests that SO_ORIGINAL_DST fails on OUTPUT connections not affected by
// // NAT.
// type NATOutOriginalDstUnchanged struct{}

// // Name implements TestCase.Name.
// func (NATOutOriginalDstUnchanged) Name() string {
// 	return "NATOutOriginalDstUnchanged"
// }

// // ContainerAction implements TestCase.ContainerAction.
// func (NATOutOriginalDstUnchanged) ContainerAction(ip net.IP) error {
// 	connCh := make(chan error)
// 	go func() {
// 		connCh <- connectTCP(ip, dropPort, sendloopDuration)
// 	}()

// 	err := listenForRedirectedConn(ip.To4())
// 	if err == nil {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but no error occurred", syscall.EBADF)
// 	}
// 	if err, ok := err.(originalDstError); !ok {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but got error: %v", err)
// 	} else if err.errno != syscall.EFAULT {
// 		return fmt.Errorf("expected SO_ORIGINAL_DST to fail with errno %d, but got errno: %d", err.errno)
// 	}
// 	panic("yo")
// 	return <-connCh
// }

// // LocalAction implements TestCase.LocalAction.
// func (NATOutOriginalDstUnchanged) LocalAction(ip net.IP) error {
// 	// No-op.
// 	return nil
// }

type originalDstError struct {
	errno syscall.Errno
}

func (e originalDstError) Error() string {
	return fmt.Sprintf("errno (%d) when calling getsockopt(SOL_IP, SO_ORIGINAL_DST): %v", int(e.errno), e.errno.Error())
}

func listenForRedirectedConn(originalDst net.IP) error {
	// The net package doesn't give guarantee access to the connection's
	// underlying FD, and thus we cannot call getsockopt. We have to use
	// traditional syscalls for SO_ORIGINAL_DST.

	// Create the listening socket, bind, listen, and accept.
	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(sockfd)

	bindAddr := syscall.SockaddrInet4{
		Port: acceptPort,
		Addr: [4]byte{0, 0, 0, 0}, // INADDR_ANY
	}
	if err := syscall.Bind(sockfd, &bindAddr); err != nil {
		return err
	}

	if err := syscall.Listen(sockfd, 1); err != nil {
		return err
	}

	connfd, remoteAddr, err := syscall.Accept(sockfd)
	if err != nil {
		return err
	}
	defer syscall.Close(connfd)
	log.Printf("Incoming connection from %+v", remoteAddr)

	// Verify that, despite listening on acceptPort, SO_ORIGINAL_DST
	// indicates the packet was sent to originalDst:dropPort.
	var got syscall.RawSockaddrInet4
	var addrLen uint32 = syscall.SizeofSockaddrInet4
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(connfd),
		syscall.SOL_IP,
		SO_ORIGINAL_DST,
		uintptr(unsafe.Pointer(&got)),
		uintptr(unsafe.Pointer(&addrLen)),
		0)
	if errno != 0 {
		return originalDstError{errno}
	}
	want := syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Port:   htons(dropPort),
	}
	copy(want.Addr[:], originalDst.To4())
	if got != want {
		return fmt.Errorf("SO_ORIGINAL_DST returned %+v, but wanted %+v (note: port numbers are in network byte order)", got, want)
	}
	return nil
}

// loopbackTests runs an iptables rule and ensures that packets sent to
// dest:dropPort are received by localhost:acceptPort.
func loopbackTest(dest net.IP, args ...string) error {
	if err := natTable(args...); err != nil {
		return err
	}
	sendCh := make(chan error)
	listenCh := make(chan error)
	go func() {
		sendCh <- sendUDPLoop(dest, dropPort, sendloopDuration)
	}()
	go func() {
		listenCh <- listenUDP(acceptPort, sendloopDuration)
	}()
	select {
	case err := <-listenCh:
		if err != nil {
			return err
		}
	case <-time.After(sendloopDuration):
		return errors.New("timed out")
	}
	// sendCh will always take the full sendloop time.
	return <-sendCh
}
