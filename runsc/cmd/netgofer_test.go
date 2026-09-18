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

package cmd

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
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	egressfilter "gvisor.dev/gvisor/runsc/netgofer/egressfilter"
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

func newTestClientStack(t *testing.T, clientFD int) *stack.Stack {
	t.Helper()
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
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

	clientStack := newTestClientStack(t, clientFD)
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

func TestRunProxyModeEndToEnd(t *testing.T) {
	wantReq := []byte("ping from sandbox over UDS proxy")
	wantResp := []byte("pong from host TCP server")
	targetAddr, serverErr := startEchoServer(t, wantReq, wantResp)

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

func TestRunProxyModeWithSeccomp(t *testing.T) {
	if os.Getenv("NETGOFER_SECCOMP_CHILD") == "1" {
		log.SetLevel(log.Info)
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
			if !readySent && strings.Contains(line, "TCP forwarder registered") {
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
			t.Fatalf("child netgofer exited before becoming ready; output:\n%s", getChildOutput())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for child netgofer ready log; output:\n%s", getChildOutput())
	}

	clientStack := newTestClientStack(t, clientFD)
	destroyClientStack := sync.OnceFunc(clientStack.Destroy)
	t.Cleanup(destroyClientStack)

	// Exercise outbound IPv6 socket creation + setsockopt under seccomp.
	dialCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	targetAddr6 := tcpip.FullAddress{NIC: 1, Addr: testServerAddr6, Port: 12345}
	if conn6, err := gonet.DialContextTCP(dialCtx, clientStack, targetAddr6, ipv6.ProtocolNumber); err == nil {
		_ = conn6.Close()
	}

	verifyEchoRoundTrip(t, clientStack, targetAddr4, wantReq, wantResp, serverErr)

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

	localInterfaceAddr := tcpip.AddrFrom4([4]byte{198, 51, 100, 99})
	ef, err := egressfilter.New(egressfilter.Options{
		LocalAddrs: []net.IP{net.IPv4(198, 51, 100, 99)},
	})
	if err != nil {
		t.Fatalf("egressfilter.New: %v", err)
	}
	clientStack := startInProcessProxy(t, &Netgofer{
		egressFilter: ef,
		dialContext:  dialLoopback,
	})
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	for _, tc := range []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		addr     tcpip.Address
	}{
		{
			name:     "ipv4_unspecified",
			netProto: ipv4.ProtocolNumber,
			addr:     header.IPv4Any,
		},
		{
			name:     "ipv4_current_network_subnet",
			netProto: ipv4.ProtocolNumber,
			addr:     tcpip.AddrFrom4([4]byte{0, 0, 0, 1}),
		},
		{
			name:     "ipv4_broadcast",
			netProto: ipv4.ProtocolNumber,
			addr:     header.IPv4Broadcast,
		},
		{
			name:     "ipv4_link_local_unicast",
			netProto: ipv4.ProtocolNumber,
			addr:     tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
		},
		{
			name:     "ipv4_local_interface_ip",
			netProto: ipv4.ProtocolNumber,
			addr:     localInterfaceAddr,
		},
		{
			name:     "ipv6_unspecified",
			netProto: ipv6.ProtocolNumber,
			addr:     header.IPv6Any,
		},
		{
			name:     "ipv6_link_local_unicast",
			netProto: ipv6.ProtocolNumber,
			addr:     tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, err := gonet.DialContextTCP(dialCtx, clientStack, tcpip.FullAddress{
				NIC:  1,
				Addr: tc.addr,
				Port: port,
			}, tc.netProto)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialContextTCP(%s) succeeded, want rejection", tc.addr)
			}
		})
	}

	select {
	case <-accepted:
		t.Fatal("host loopback listener accepted a connection from a disallowed destination")
	default:
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
