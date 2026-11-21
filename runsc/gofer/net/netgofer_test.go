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

package net

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	egressfilter "gvisor.dev/gvisor/runsc/gofer/net/egressfilter"
)

var (
	testServerAddr4 = tcpip.AddrFrom4([4]byte{198, 51, 100, 1})
	testClientAddr4 = tcpip.AddrFrom4([4]byte{198, 51, 100, 2})
	testServerAddr6 = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	testClientAddr6 = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
)

type halfClosePipeConn struct {
	net.Conn
	r          *io.PipeReader
	w          *io.PipeWriter
	mu         sync.Mutex
	closed     bool
	writeClose bool
	readErr    error
}

func newHalfClosePipePair() (*halfClosePipeConn, *halfClosePipeConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &halfClosePipeConn{r: r1, w: w2}, &halfClosePipeConn{r: r2, w: w1}
}

func (c *halfClosePipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	err := c.readErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (c *halfClosePipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *halfClosePipeConn) CloseWrite() error {
	c.mu.Lock()
	c.writeClose = true
	c.mu.Unlock()
	return c.w.Close()
}

func (c *halfClosePipeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	_ = c.r.Close()
	_ = c.w.Close()
	return nil
}

type nonCloseWriterConn struct {
	net.Conn
	closed bool
}

func (c *nonCloseWriterConn) Close() error {
	c.closed = true
	return nil
}

func TestSpliceAndCloseWrite(t *testing.T) {
	t.Run("half_close_and_bidirectional_copy", func(t *testing.T) {
		clientSide, proxyClient := newHalfClosePipePair()
		proxyServer, serverSide := newHalfClosePipePair()

		done := make(chan struct{})
		go func() {
			splice(proxyClient, proxyServer)
			close(done)
		}()

		clientMsg := []byte("hello from sandbox client")
		serverMsg := []byte("response from host server after client EOF")
		go func() {
			_, _ = clientSide.Write(clientMsg)
			_ = clientSide.CloseWrite()
		}()

		if got, err := io.ReadAll(serverSide); err != nil || !bytes.Equal(got, clientMsg) {
			t.Fatalf("serverSide read = %q, %v; want %q", got, err, clientMsg)
		}
		if _, err := serverSide.Write(serverMsg); err != nil {
			t.Fatalf("serverSide.Write() failed: %v", err)
		}
		_ = serverSide.CloseWrite()

		if got, err := io.ReadAll(clientSide); err != nil || !bytes.Equal(got, serverMsg) {
			t.Fatalf("clientSide read = %q, %v; want %q", got, err, serverMsg)
		}
		<-done
	})

	t.Run("aborts_on_transport_error", func(t *testing.T) {
		_, proxyClient := newHalfClosePipePair()
		proxyServer, _ := newHalfClosePipePair()
		proxyClient.readErr = errors.New("simulated transport error")

		splice(proxyClient, proxyServer)
		if !proxyClient.closed || !proxyServer.closed {
			t.Errorf("proxyClient.closed=%v, proxyServer.closed=%v; want both true", proxyClient.closed, proxyServer.closed)
		}
	})

	t.Run("close_write_fallback", func(t *testing.T) {
		c := &nonCloseWriterConn{}
		closeWrite(c)
		if !c.closed {
			t.Errorf("closeWrite() did not fall back to Close()")
		}
	})
}

// dialLoopback rewrites the destination IP to loopback while preserving the
// dynamically intercepted port and using the same net.Dialer configuration as
// production netgofer. This allows tests to run in isolated network namespaces
// where only loopback (127.0.0.1 / ::1) is routable without CAP_NET_ADMIN.
func dialLoopback(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	loopbackHost := "127.0.0.1"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		loopbackHost = "::1"
	}
	dialer := net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: keepAlivePeriod,
	}
	if strings.HasPrefix(network, "udp") {
		dialer.Control = disableUDPBroadcastControl
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(loopbackHost, port))
}

func startEchoServer(t *testing.T, wantReq, wantResp []byte) (targetAddr tcpip.FullAddress, serverErr <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		gotReq, err := io.ReadAll(conn)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(gotReq, wantReq) {
			errCh <- fmt.Errorf("server received %q, want %q", gotReq, wantReq)
			return
		}
		_, err = conn.Write(wantResp)
		errCh <- err
	}()

	return tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(ln.Addr().(*net.TCPAddr).Port),
	}, errCh
}

func startUDPEchoServer(t *testing.T, wantReq, wantResp []byte) (targetAddr tcpip.FullAddress, serverErr <-chan error) {
	t.Helper()
	return startUDPEchoServerOn(t, "udp", "127.0.0.1:0", testServerAddr4, wantReq, wantResp)
}

func startUDPEchoServerOn(t *testing.T, network, listenAddr string, targetIP tcpip.Address, wantReq, wantResp []byte) (targetAddr tcpip.FullAddress, serverErr <-chan error) {
	t.Helper()
	pc, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket(%q, %q) failed: %v", network, listenAddr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		nr, peer, err := pc.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf[:nr], wantReq) {
			errCh <- fmt.Errorf("UDP server received %q, want %q", buf[:nr], wantReq)
			return
		}
		_, err = pc.WriteTo(wantResp, peer)
		errCh <- err
	}()

	return tcpip.FullAddress{
		NIC:  1,
		Addr: targetIP,
		Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
	}, errCh
}

func newTestClientStack(t *testing.T, clientFD int) *stack.Stack {
	t.Helper()
	return newTestClientStackWithOptions(t, clientFD, false)
}

func newTestClientStackWithOptions(t *testing.T, clientFD int, allowExternalLoopback bool) *stack.Stack {
	t.Helper()
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: allowExternalLoopback,
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				AllowExternalLoopbackTraffic: allowExternalLoopback,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:                []int{clientFD},
		MTU:                DefaultMTU,
		EthernetHeader:     false,
		PacketDispatchMode: fdbased.RecvMMsg,
		RXChecksumOffload:  true,
	})
	if err != nil {
		t.Fatalf("fdbased.New() failed: %v", err)
	}
	if err := st.CreateNIC(1, linkEP); err != nil {
		t.Fatalf("CreateNIC(1) failed: %v", err)
	}
	for _, pa := range []tcpip.ProtocolAddress{
		{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: testClientAddr4, PrefixLen: 24},
		},
		{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: testClientAddr6, PrefixLen: 64},
		},
	} {
		if err := st.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%v) failed: %v", pa, err)
		}
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	return st
}

func startInProcessProxy(t *testing.T, n *Netgofer) *stack.Stack {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Socketpair() failed: %v", err)
	}
	proxyFD, clientFD := fds[0], fds[1]

	n.udsFD = proxyFD
	n.mtu = DefaultMTU
	n.applyCaps = false
	n.disableSeccomp = true
	n.ready = make(chan struct{})

	proxyExit := make(chan subcommands.ExitStatus, 1)
	go func() {
		proxyExit <- n.runProxyMode(&config.Config{RXChecksumOffload: true})
	}()

	select {
	case <-n.ready:
	case status := <-proxyExit:
		_ = unix.Close(clientFD)
		t.Fatalf("runProxyMode() exited early with status %v", status)
	case <-time.After(5 * time.Second):
		_ = unix.Close(clientFD)
		t.Fatal("timed out waiting for runProxyMode() to become ready")
	}

	clientStack := newTestClientStackWithOptions(t, clientFD, n.allowLoopback)
	t.Cleanup(func() {
		clientStack.Destroy()
		_ = unix.Close(clientFD)
		select {
		case status := <-proxyExit:
			if status != subcommands.ExitSuccess {
				t.Errorf("runProxyMode() = %v, want %v", status, subcommands.ExitSuccess)
			}
		case <-time.After(5 * time.Second):
			t.Error("runProxyMode() did not exit after UDS peer closed")
		}
	})
	return clientStack
}

func verifyEchoRoundTrip(t *testing.T, clientStack *stack.Stack, targetAddr tcpip.FullAddress, wantReq, wantResp []byte, serverErr <-chan error) {
	t.Helper()
	dialCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	clientConn, err := gonet.DialContextTCP(dialCtx, clientStack, targetAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialContextTCP(%+v) failed: %v", targetAddr, err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(wantReq); err != nil {
		t.Fatalf("clientConn.Write() failed: %v", err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("clientConn.CloseWrite() failed: %v", err)
	}
	gotResp, err := io.ReadAll(clientConn)
	if err != nil || !bytes.Equal(gotResp, wantResp) {
		t.Fatalf("client received %q, %v; want %q", gotResp, err, wantResp)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func verifyUDPEchoRoundTrip(t *testing.T, clientStack *stack.Stack, targetAddr tcpip.FullAddress, wantReq, wantResp []byte, serverErr <-chan error) {
	t.Helper()
	verifyUDPEchoRoundTripProto(t, clientStack, targetAddr, ipv4.ProtocolNumber, wantReq, wantResp, serverErr)
}

func verifyUDPEchoRoundTripProto(t *testing.T, clientStack *stack.Stack, targetAddr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber, wantReq, wantResp []byte, serverErr <-chan error) {
	t.Helper()
	clientConn, err := gonet.DialUDP(clientStack, nil, &targetAddr, netProto)
	if err != nil {
		t.Fatalf("gonet.DialUDP(%+v) failed: %v", targetAddr, err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("clientConn.SetDeadline() failed: %v", err)
	}
	if _, err := clientConn.Write(wantReq); err != nil {
		t.Fatalf("clientConn.Write() failed: %v", err)
	}
	buf := make([]byte, 2048)
	nr, err := clientConn.Read(buf)
	if err != nil || !bytes.Equal(buf[:nr], wantResp) {
		t.Fatalf("UDP client received %q, %v; want %q", buf[:nr], err, wantResp)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("UDP server error: %v", err)
	}
}

func TestRunProxyModeEndToEnd(t *testing.T) {
	wantReq := []byte("ping from sandbox over UDS proxy")
	wantResp := []byte("pong from host TCP server")
	targetAddr, serverErr := startEchoServer(t, wantReq, wantResp)

	wantUDPReq := []byte("udp dns query from sandbox")
	wantUDPResp := []byte("udp dns response from host")
	udpTargetAddr, udpServerErr := startUDPEchoServer(t, wantUDPReq, wantUDPResp)

	// Also start a server that keeps accepted connections open and idle until
	// test cleanup to verify runProxyMode shuts down without hanging on active
	// outbound connections.
	idleLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = idleLn.Close() })
	idleDone := make(chan struct{})
	var idleConn *gonet.TCPConn
	t.Cleanup(func() {
		close(idleDone)
		if idleConn != nil {
			_ = idleConn.Close()
		}
	})
	go func() {
		conn, err := idleLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-idleDone
	}()

	clientStack := startInProcessProxy(t, &Netgofer{dialContext: dialLoopback})
	verifyEchoRoundTrip(t, clientStack, targetAddr, wantReq, wantResp, serverErr)
	verifyUDPEchoRoundTrip(t, clientStack, udpTargetAddr, wantUDPReq, wantUDPResp, udpServerErr)

	idleAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(idleLn.Addr().(*net.TCPAddr).Port),
	}
	idleConn, err = gonet.DialTCP(clientStack, idleAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCP(idleAddr) failed: %v", err)
	}
}

func TestRunProxyModeAllowLoopback(t *testing.T) {
	loopbackDNSAddr := tcpip.AddrFrom4([4]byte{127, 0, 0, 11})

	t.Run("disallowed_by_default", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() failed: %v", err)
		}
		defer ln.Close()
		port := uint16(ln.Addr().(*net.TCPAddr).Port)

		udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.ListenPacket() failed: %v", err)
		}
		defer udpPC.Close()
		udpPort := uint16(udpPC.LocalAddr().(*net.UDPAddr).Port)
		udpReceived := make(chan struct{}, 1)
		go func() {
			buf := make([]byte, 64)
			if _, _, err := udpPC.ReadFrom(buf); err == nil {
				udpReceived <- struct{}{}
			}
		}()

		clientStack := startInProcessProxy(t, &Netgofer{
			allowLoopback: false,
			dialContext:   dialLoopback,
		})
		// Enable external loopback on the client stack so it will transmit the
		// packet over the UDS link; netgofer must still reject it.
		opt := tcpip.AllowExternalLoopbackTrafficOption(true)
		if err := clientStack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
			t.Fatalf("SetNetworkProtocolOption() failed: %v", err)
		}

		dialCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if conn, err := gonet.DialContextTCP(dialCtx, clientStack, tcpip.FullAddress{
			NIC:  1,
			Addr: loopbackDNSAddr,
			Port: port,
		}, ipv4.ProtocolNumber); err == nil {
			_ = conn.Close()
			t.Fatal("DialContextTCP(127.0.0.11) succeeded with allowLoopback=false, want rejection")
		}

		udpConn, err := gonet.DialUDP(clientStack, nil, &tcpip.FullAddress{
			NIC:  1,
			Addr: loopbackDNSAddr,
			Port: udpPort,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("gonet.DialUDP() failed: %v", err)
		}
		defer udpConn.Close()
		if _, err := udpConn.Write([]byte("blocked udp loopback")); err != nil {
			t.Fatalf("udpConn.Write() failed: %v", err)
		}
		select {
		case <-udpReceived:
			t.Fatal("UDP server received loopback datagram with allowLoopback=false, want rejection")
		case <-time.After(150 * time.Millisecond):
		}
	})

	t.Run("allowed_when_enabled", func(t *testing.T) {
		wantTCPReq := []byte("tcp dns query to 127.0.0.11")
		wantTCPResp := []byte("tcp dns response from 127.0.0.11")
		tcpTarget, tcpErr := startEchoServer(t, wantTCPReq, wantTCPResp)
		tcpTarget.Addr = loopbackDNSAddr

		wantUDPReq := []byte("udp dns query to 127.0.0.11")
		wantUDPResp := []byte("udp dns response from 127.0.0.11")
		udpTarget, udpErr := startUDPEchoServer(t, wantUDPReq, wantUDPResp)
		udpTarget.Addr = loopbackDNSAddr

		clientStack := startInProcessProxy(t, &Netgofer{
			allowLoopback:  true,
			udpIdleTimeout: 100 * time.Millisecond,
			dialContext:    dialLoopback,
		})

		verifyEchoRoundTrip(t, clientStack, tcpTarget, wantTCPReq, wantTCPResp, tcpErr)
		verifyUDPEchoRoundTrip(t, clientStack, udpTarget, wantUDPReq, wantUDPResp, udpErr)
	})
}

func TestRunProxyModeWithSeccomp(t *testing.T) {
	if os.Getenv("NETGOFER_SECCOMP_CHILD") == "1" {
		log.SetLevel(log.Info)
		waitForStartupGoroutines()
		n := &Netgofer{
			udsFD:          3,
			mtu:            DefaultMTU,
			applyCaps:      false,
			disableSeccomp: false,
			dialContext:    dialLoopback,
		}
		os.Exit(int(n.runProxyMode(&config.Config{RXChecksumOffload: true})))
	}

	wantReq := []byte("ping from seccomp-hardened netgofer")
	wantResp := []byte("pong from host TCP server")
	targetAddr4, serverErr := startEchoServer(t, wantReq, wantResp)

	wantUDPReq := []byte("udp ping from seccomp-hardened netgofer")
	wantUDPResp := []byte("udp pong from host UDP server")
	udpTargetAddr4, udpServerErr := startUDPEchoServer(t, wantUDPReq, wantUDPResp)

	wantUDPReq6 := []byte("ipv6 udp ping from seccomp-hardened netgofer")
	wantUDPResp6 := []byte("ipv6 udp pong from host UDP server")
	udpTargetAddr6, udpServerErr6 := startUDPEchoServerOn(t, "udp6", "[::1]:0", testServerAddr6, wantUDPReq6, wantUDPResp6)

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Socketpair() failed: %v", err)
	}
	proxyFD, clientFD := fds[0], fds[1]
	closeClientFD := sync.OnceFunc(func() { _ = unix.Close(clientFD) })
	t.Cleanup(closeClientFD)

	proxyFile := os.NewFile(uintptr(proxyFD), "uds")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunProxyModeWithSeccomp$")
	cmd.Env = append(os.Environ(),
		"NETGOFER_SECCOMP_CHILD=1",
		"GOTRACEBACK=system",
	)
	cmd.ExtraFiles = []*os.File{proxyFile}

	pr, pw, err := os.Pipe()
	if err != nil {
		_ = proxyFile.Close()
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	defer pr.Close()
	var (
		outputMu   sync.Mutex
		childOut   bytes.Buffer
		childReady = make(chan bool, 1)
		readerDone = make(chan struct{})
	)
	getChildOutput := func() string {
		outputMu.Lock()
		defer outputMu.Unlock()
		return childOut.String()
	}
	go func() {
		defer close(readerDone)
		scanner := bufio.NewScanner(pr)
		readySent := false
		for scanner.Scan() {
			line := scanner.Text()
			outputMu.Lock()
			childOut.WriteString(line)
			childOut.WriteByte('\n')
			outputMu.Unlock()
			if !readySent && strings.Contains(line, "TCP and UDP forwarders registered") {
				readySent = true
				childReady <- true
			}
		}
		if !readySent {
			close(childReady)
		}
	}()

	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		_ = proxyFile.Close()
		_ = pw.Close()
		t.Fatalf("cmd.Start() failed: %v", err)
	}
	_ = proxyFile.Close()
	_ = pw.Close()

	cmdWaited := false
	t.Cleanup(func() {
		if !cmdWaited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	select {
	case ok := <-childReady:
		if !ok {
			<-readerDone
			waitErr := cmd.Wait()
			cmdWaited = true
			t.Fatalf("child netgofer exited before becoming ready (%v); output:\n%s", waitErr, getChildOutput())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for child netgofer ready log; output:\n%s", getChildOutput())
	}

	clientStack := newTestClientStack(t, clientFD)
	destroyClientStack := sync.OnceFunc(clientStack.Destroy)
	t.Cleanup(destroyClientStack)

	// Exercise outbound IPv6 TCP socket creation + setsockopt under seccomp.
	dialCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	targetAddr6 := tcpip.FullAddress{NIC: 1, Addr: testServerAddr6, Port: 12345}
	if conn6, err := gonet.DialContextTCP(dialCtx, clientStack, targetAddr6, ipv6.ProtocolNumber); err == nil {
		_ = conn6.Close()
	}

	verifyEchoRoundTrip(t, clientStack, targetAddr4, wantReq, wantResp, serverErr)
	verifyUDPEchoRoundTrip(t, clientStack, udpTargetAddr4, wantUDPReq, wantUDPResp, udpServerErr)
	verifyUDPEchoRoundTripProto(t, clientStack, udpTargetAddr6, ipv6.ProtocolNumber, wantUDPReq6, wantUDPResp6, udpServerErr6)

	destroyClientStack()
	closeClientFD()
	cmdWaited = true
	if err := cmd.Wait(); err != nil {
		<-readerDone
		t.Fatalf("seccomp child process failed: %v\noutput:\n%s", err, getChildOutput())
	}
}

func TestProxyLimitsConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	clientStack := startInProcessProxy(t, &Netgofer{
		maxActiveConns: 2,
		dialContext:    dialLoopback,
	})

	// Active connection limit (maxActiveConns=2): 3rd concurrent connection is rejected until 1st closes.
	targetAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(ln.Addr().(*net.TCPAddr).Port),
	}
	conn1, err := gonet.DialTCP(clientStack, targetAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("first DialTCP failed: %v", err)
	}
	defer conn1.Close()

	conn2, err := gonet.DialTCP(clientStack, targetAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("second DialTCP failed: %v", err)
	}
	defer conn2.Close()

	if conn3, err := gonet.DialTCP(clientStack, targetAddr, ipv4.ProtocolNumber); err == nil {
		_ = conn3.Close()
		t.Fatalf("third DialTCP succeeded while maxActiveConns=2 was full")
	}

	_ = conn1.Close()
	for i := 0; i < 50; i++ {
		if conn4, err := gonet.DialTCP(clientStack, targetAddr, ipv4.ProtocolNumber); err == nil {
			_ = conn4.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("DialTCP after closing conn1 failed to acquire released activeConns slot")
}

func TestProxyRejectsDisallowedDestinations(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	udpPC4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(udp4) failed: %v", err)
	}
	defer udpPC4.Close()

	udpPC6, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(udp6) failed: %v", err)
	}
	defer udpPC6.Close()

	udpReceived := make(chan string, 1)
	watchUDP := func(name string, pc net.PacketConn) {
		go func() {
			buf := make([]byte, 256)
			if _, _, err := pc.ReadFrom(buf); err == nil {
				select {
				case udpReceived <- name:
				default:
				}
			}
		}()
	}
	watchUDP("udp4", udpPC4)
	watchUDP("udp6", udpPC6)

	wantAllowedUDPReq := []byte("allowed udp ping")
	wantAllowedUDPResp := []byte("allowed udp pong")
	allowedUDPAddr, allowedUDPErr := startUDPEchoServer(t, wantAllowedUDPReq, wantAllowedUDPResp)
	allowedAddrStr := net.JoinHostPort(allowedUDPAddr.Addr.String(), fmt.Sprintf("%d", allowedUDPAddr.Port))

	localInterfaceAddr := tcpip.AddrFrom4([4]byte{198, 51, 100, 99})
	ef, err := egressfilter.New(egressfilter.Options{
		LocalAddrs: []net.IP{net.IPv4(198, 51, 100, 99)},
	})
	if err != nil {
		t.Fatalf("egressfilter.New: %v", err)
	}
	var (
		dialedMu sync.Mutex
		dialed   []string
	)
	recordingDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != allowedAddrStr {
			dialedMu.Lock()
			dialed = append(dialed, addr)
			dialedMu.Unlock()
		}
		return dialLoopback(ctx, network, addr)
	}
	clientStack := startInProcessProxy(t, &Netgofer{
		egressFilter: ef,
		dialContext:  recordingDial,
	})
	tcpPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	udpPort4 := uint16(udpPC4.LocalAddr().(*net.UDPAddr).Port)
	udpPort6 := uint16(udpPC6.LocalAddr().(*net.UDPAddr).Port)
	cases := []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		addr     tcpip.Address
		udpPort  uint16
	}{
		{
			name:     "ipv4_current_network_subnet",
			netProto: ipv4.ProtocolNumber,
			addr:     tcpip.AddrFrom4([4]byte{0, 0, 0, 1}),
			udpPort:  udpPort4,
		},
		{
			name:     "ipv4_link_local_unicast",
			netProto: ipv4.ProtocolNumber,
			addr:     tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
			udpPort:  udpPort4,
		},
		{
			name:     "ipv4_local_interface_ip",
			netProto: ipv4.ProtocolNumber,
			addr:     localInterfaceAddr,
			udpPort:  udpPort4,
		},
		{
			name:     "ipv6_link_local_unicast",
			netProto: ipv6.ProtocolNumber,
			addr:     tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			udpPort:  udpPort6,
		},
	}
	for _, tc := range cases {
		t.Run("tcp/"+tc.name, func(t *testing.T) {
			dialCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, err := gonet.DialContextTCP(dialCtx, clientStack, tcpip.FullAddress{
				NIC:  1,
				Addr: tc.addr,
				Port: tcpPort,
			}, tc.netProto)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialContextTCP(%s) succeeded, want rejection", tc.addr)
			}
			var opErr *net.OpError
			if !errors.As(err, &opErr) || opErr.Err.Error() != (&tcpip.ErrConnectionRefused{}).String() {
				t.Fatalf("DialContextTCP(%s) = %v, want connection refused by netgofer", tc.addr, err)
			}
		})
		t.Run("udp/"+tc.name, func(t *testing.T) {
			conn, err := gonet.DialUDP(clientStack, nil, &tcpip.FullAddress{
				NIC:  1,
				Addr: tc.addr,
				Port: tc.udpPort,
			}, tc.netProto)
			if err != nil {
				t.Fatalf("gonet.DialUDP(%s) failed: %v", tc.addr, err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("disallowed udp payload")); err != nil {
				t.Fatalf("conn.Write(%s) failed: %v", tc.addr, err)
			}
		})
	}

	// Because netgofer's UDP forwarder runs inline in the ordered UDS packet
	// dispatcher, completing a subsequent allowed UDP round trip ensures all
	// preceding disallowed UDP datagrams were processed.
	verifyUDPEchoRoundTrip(t, clientStack, allowedUDPAddr, wantAllowedUDPReq, wantAllowedUDPResp, allowedUDPErr)

	dialedMu.Lock()
	defer dialedMu.Unlock()
	if len(dialed) != 0 {
		t.Errorf("netgofer dialed %q, want no outbound dials for disallowed destinations", dialed)
	}

	select {
	case <-accepted:
		t.Fatal("host loopback listener accepted a connection from a disallowed destination")
	default:
	}

	select {
	case proto := <-udpReceived:
		t.Fatalf("host %s loopback listener received a UDP datagram to a disallowed destination", proto)
	default:
	}
}

func TestProxyLimitsUDPConnections(t *testing.T) {
	udpPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() failed: %v", err)
	}
	defer udpPC.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			nr, peer, err := udpPC.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udpPC.WriteTo(buf[:nr], peer); err != nil {
				return
			}
		}
	}()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	udpDialed := make(chan struct{}, 10)
	countingDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(network, "udp") {
			udpDialed <- struct{}{}
		}
		return dialLoopback(ctx, network, addr)
	}

	clientStack := startInProcessProxy(t, &Netgofer{
		maxActiveConns: 2,
		dialContext:    countingDial,
	})

	udpTarget := tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(udpPC.LocalAddr().(*net.UDPAddr).Port),
	}
	dialAndEcho := func(payload string) *gonet.UDPConn {
		t.Helper()
		conn, err := gonet.DialUDP(clientStack, nil, &udpTarget, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("gonet.DialUDP() failed: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline() failed: %v", err)
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("Write(%q) failed: %v", payload, err)
		}
		buf := make([]byte, 256)
		nr, err := conn.Read(buf)
		if err != nil || string(buf[:nr]) != payload {
			t.Fatalf("Read() = %q, %v; want %q", buf[:nr], err, payload)
		}
		return conn
	}

	_ = dialAndEcho("udp-flow-1")
	_ = dialAndEcho("udp-flow-2")
	for i := 0; i < 2; i++ {
		select {
		case <-udpDialed:
		default:
			t.Fatalf("expected 2 UDP outbound dials, got %d", i)
		}
	}

	// With maxActiveConns=2 occupied by the 2 active UDP flows, a 3rd UDP flow
	// should not be dialed.
	conn3, err := gonet.DialUDP(clientStack, nil, &udpTarget, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("third gonet.DialUDP() failed: %v", err)
	}
	defer conn3.Close()
	if _, err := conn3.Write([]byte("udp-flow-3")); err != nil {
		t.Fatalf("third conn.Write() failed: %v", err)
	}

	// Shared activeConns limit also rejects a subsequent TCP dial; completing the
	// TCP dial attempt acts as a dispatcher fence after conn3's UDP packet.
	tcpTarget := tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(tcpLn.Addr().(*net.TCPAddr).Port),
	}
	if tcpConn, err := gonet.DialTCP(clientStack, tcpTarget, ipv4.ProtocolNumber); err == nil {
		_ = tcpConn.Close()
		t.Fatalf("DialTCP succeeded while 2 UDP flows occupied maxActiveConns=2")
	}

	select {
	case <-udpDialed:
		t.Fatal("third UDP flow was dialed while maxActiveConns=2 was full")
	default:
	}

	if err := conn3.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	buf := make([]byte, 256)
	if nr, err := conn3.Read(buf); err == nil {
		t.Fatalf("third UDP flow unexpectedly received %q while maxActiveConns=2 was full", buf[:nr])
	}
}

type closeNotifyingConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *closeNotifyingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestProxyUDPIdleTimeout(t *testing.T) {
	udpPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() failed: %v", err)
	}
	defer udpPC.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			nr, peer, err := udpPC.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udpPC.WriteTo(buf[:nr], peer); err != nil {
				return
			}
		}
	}()

	closedChs := make(chan chan struct{}, 8)
	trackingDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialLoopback(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(network, "udp") {
			ch := make(chan struct{})
			closedChs <- ch
			return &closeNotifyingConn{Conn: conn, closed: ch}, nil
		}
		return conn, nil
	}

	clientStack := startInProcessProxy(t, &Netgofer{
		maxActiveConns: 1,
		udpIdleTimeout: 150 * time.Millisecond,
		dialContext:    trackingDial,
	})

	udpTarget := tcpip.FullAddress{
		NIC:  1,
		Addr: testServerAddr4,
		Port: uint16(udpPC.LocalAddr().(*net.UDPAddr).Port),
	}

	conn1, err := gonet.DialUDP(clientStack, nil, &udpTarget, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("first gonet.DialUDP() failed: %v", err)
	}
	defer conn1.Close()
	if err := conn1.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("conn1.SetDeadline() failed: %v", err)
	}
	if _, err := conn1.Write([]byte("idle-timeout-1")); err != nil {
		t.Fatalf("conn1.Write() failed: %v", err)
	}
	buf := make([]byte, 256)
	nr, err := conn1.Read(buf)
	if err != nil || string(buf[:nr]) != "idle-timeout-1" {
		t.Fatalf("conn1.Read() = %q, %v; want %q", buf[:nr], err, "idle-timeout-1")
	}

	var closed1 chan struct{}
	select {
	case closed1 = <-closedChs:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first UDP outbound dial")
	}

	// Leave conn1 open on the client; the proxy must close hostConn and release
	// the maxActiveConns=1 slot after udpIdleTimeout.
	select {
	case <-closed1:
	case <-time.After(5 * time.Second):
		t.Fatal("host UDP connection did not close after udpIdleTimeout")
	}

	conn2, err := gonet.DialUDP(clientStack, nil, &udpTarget, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("second gonet.DialUDP() failed: %v", err)
	}
	defer conn2.Close()
	for i := 0; i < 40; i++ {
		_ = conn2.SetDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := conn2.Write([]byte("idle-timeout-2")); err != nil {
			t.Fatalf("conn2.Write() failed: %v", err)
		}
		nr, err := conn2.Read(buf)
		if err == nil && string(buf[:nr]) == "idle-timeout-2" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("second UDP flow failed to acquire activeConns slot after udpIdleTimeout")
}

func getSocketBroadcastOption(t *testing.T, conn net.Conn) int {
	t.Helper()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", conn)
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() failed: %v", err)
	}
	var (
		val     int
		sockErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		val, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST)
	}); err != nil {
		t.Fatalf("rawConn.Control() failed: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("GetsockoptInt(SO_BROADCAST) failed: %v", sockErr)
	}
	return val
}

func TestOutboundUDPDialerDisablesBroadcast(t *testing.T) {
	for _, tc := range []struct {
		name       string
		network    string
		listenAddr string
	}{
		{name: "udp4", network: "udp4", listenAddr: "127.0.0.1:0"},
		{name: "udp6", network: "udp6", listenAddr: "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket(tc.network, tc.listenAddr)
			if err != nil {
				t.Fatalf("net.ListenPacket(%q, %q) failed: %v", tc.network, tc.listenAddr, err)
			}
			defer pc.Close()

			defaultConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(t.Context(), tc.network, pc.LocalAddr().String())
			if err != nil {
				t.Fatalf("default dialer failed: %v", err)
			}
			defer defaultConn.Close()
			if got := getSocketBroadcastOption(t, defaultConn); got == 0 {
				t.Fatalf("baseline Go UDP dialer SO_BROADCAST = %d, want non-zero", got)
			}

			dialer := newOutboundUDPDialer()
			conn, err := dialer.DialContext(t.Context(), tc.network, pc.LocalAddr().String())
			if err != nil {
				t.Fatalf("newOutboundUDPDialer().DialContext() failed: %v", err)
			}
			defer conn.Close()
			if got := getSocketBroadcastOption(t, conn); got != 0 {
				t.Errorf("SO_BROADCAST = %d, want 0", got)
			}
		})
	}
}

func TestNetgoferEarlyValidationClosesUDSFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[1])

	cmd := &Netgofer{}
	fs := flag.NewFlagSet("netgofer", flag.ContinueOnError)
	cmd.SetFlags(fs)
	if err := fs.Parse([]string{fmt.Sprintf("--uds-fd=%d", fds[0])}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Missing required positional argument (sandbox ID) -> ExitUsageError.
	if status := cmd.Execute(context.Background(), fs); status != subcommands.ExitUsageError {
		t.Errorf("Execute() with missing arg = %v, want ExitUsageError", status)
	}

	// Verify fds[0] was closed.
	var stat unix.Stat_t
	if err := unix.Fstat(fds[0], &stat); err != unix.EBADF {
		t.Errorf("Fstat on fds[0] = %v, want EBADF (fd should be closed)", err)
		_ = unix.Close(fds[0])
	}
}
