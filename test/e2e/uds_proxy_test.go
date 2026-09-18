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

// This file tests --network-uds-path. A userspace netstack acts as the
// external network proxy on the other side of the unix domain socket, and
// a container talks to it in both directions.
package integration

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}

const (
	// externalUDSRuntimeSuffix names the runtime installed by the
	// $(RUNTIME)-net-uds target in the Makefile.
	externalUDSRuntimeSuffix = "-net-uds"

	// externalUDSSocketPath must match the --network-uds-path value baked into
	// that runtime. It is a fixed path rather than a temporary one because the
	// runtime is installed once, before any test runs, and cannot learn a path
	// chosen later by the test.
	externalUDSSocketPath = "/tmp/gvisor-net-uds/proxy.sock"

	externalUDSProxyNIC   = tcpip.NICID(1)
	externalUDSTargetIP   = "198.51.100.1"
	externalUDSTargetPort = 8080

	// externalUDSWait bounds every step that waits on the container or on the
	// proxy stack.
	externalUDSWait = time.Minute
)

type externalUDSProxyEnv struct {
	container   *dockerutil.Container
	proxyStack  *stack.Stack
	containerIP net.IP
	targetAddr  tcpip.Address
}

// setupExternalUDSProxyEnv creates an external SOCK_SEQPACKET unix domain
// socket backed by a userspace TCP/IP stack (proxyStack) and starts a Docker
// container under the runtime configured with --network-uds-path pointing to
// that socket.
func setupExternalUDSProxyEnv(ctx context.Context, t *testing.T) *externalUDSProxyEnv {
	t.Helper()
	if testutil.IsRunningWithHostNet() {
		t.Skip("External UDS proxy (--network-uds-path) is only supported with sandbox networking.")
	}
	d := dockerutil.MakeContainerWithRuntime(ctx, t, externalUDSRuntimeSuffix)

	sockDir := filepath.Dir(externalUDSSocketPath)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q) failed: %v", sockDir, err)
	}
	if err := os.Chmod(sockDir, 0755); err != nil {
		t.Fatalf("os.Chmod(%q) failed: %v", sockDir, err)
	}
	// The path is fixed, so a socket left behind by a previous run (or by a
	// crashed test) would make net.Listen fail with EADDRINUSE.
	if err := os.Remove(externalUDSSocketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("os.Remove(%q) failed: %v", externalUDSSocketPath, err)
	}
	udsLn, err := net.Listen("unixpacket", externalUDSSocketPath)
	if err != nil {
		t.Fatalf(`net.Listen("unixpacket", %q) failed: %v`, externalUDSSocketPath, err)
	}

	proxyStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	var (
		linkEP stack.LinkEndpoint
		dupFD  = -1
	)

	udsAttached := make(chan error, 1)
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		_ = udsLn.Close()
		<-acceptDone
		proxyStack.Destroy()
		if linkEP != nil {
			linkEP.Wait()
		}
		if dupFD >= 0 {
			_ = unix.Close(dupFD)
		}
	})

	go func() {
		defer close(acceptDone)
		conn, err := udsLn.Accept()
		if err != nil {
			udsAttached <- fmt.Errorf("udsLn.Accept() failed: %w", err)
			return
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			udsAttached <- fmt.Errorf("accepted connection is %T, want *net.UnixConn", conn)
			return
		}
		f, err := unixConn.File()
		if err != nil {
			udsAttached <- fmt.Errorf("unixConn.File() failed: %w", err)
			return
		}
		defer f.Close()

		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			udsAttached <- fmt.Errorf("unix.Dup() failed: %w", err)
			return
		}
		ep, err := fdbased.New(&fdbased.Options{
			FDs: []int{fd},
			MTU: 1500,
		})
		if err != nil {
			_ = unix.Close(fd)
			udsAttached <- fmt.Errorf("fdbased.New() failed: %w", err)
			return
		}
		dupFD = fd
		linkEP = ep
		if err := proxyStack.CreateNIC(externalUDSProxyNIC, linkEP); err != nil {
			udsAttached <- fmt.Errorf("proxyStack.CreateNIC() failed: %v", err)
			return
		}
		if err := proxyStack.SetPromiscuousMode(externalUDSProxyNIC, true); err != nil {
			udsAttached <- fmt.Errorf("proxyStack.SetPromiscuousMode() failed: %v", err)
			return
		}
		if err := proxyStack.SetSpoofing(externalUDSProxyNIC, true); err != nil {
			udsAttached <- fmt.Errorf("proxyStack.SetSpoofing() failed: %v", err)
			return
		}
		proxyStack.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         externalUDSProxyNIC,
			},
		})
		udsAttached <- nil
	}()

	t.Cleanup(func() { d.CleanUp(ctx) })

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run under the %s runtime failed: %v", externalUDSRuntimeSuffix, err)
	}

	select {
	case err := <-udsAttached:
		if err != nil {
			t.Fatalf("attaching external UDS proxy failed: %v", err)
		}
	case <-time.After(externalUDSWait):
		t.Fatalf("timed out waiting for runsc to connect to %q", externalUDSSocketPath)
	}

	containerIP, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("d.FindIP() failed: %v", err)
	}

	return &externalUDSProxyEnv{
		container:   d,
		proxyStack:  proxyStack,
		containerIP: containerIP,
		targetAddr:  tcpip.AddrFrom4([4]byte{198, 51, 100, 1}),
	}
}

// waitForContainerListener blocks until a TCP socket inside the container is
// listening on port, or until the deadline expires, or until abort receives a
// value (which means the process that was supposed to listen has already
// exited).
func waitForContainerListener(ctx context.Context, t *testing.T, d *dockerutil.Container, port int, abort <-chan error) {
	t.Helper()
	// BusyBox nc -l binds a dual-stack AF_INET6 socket ([::]:port), which
	// appears in /proc/net/tcp6 rather than /proc/net/tcp.
	hexPort := fmt.Sprintf(":%04X ", port)
	grepCmd := fmt.Sprintf("grep -i %q /proc/net/tcp /proc/net/tcp6", hexPort)
	for deadline := time.Now().Add(externalUDSWait); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		select {
		case err := <-abort:
			t.Fatalf("the process that should listen on port %d exited first: %v", port, err)
		default:
		}
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", grepCmd); err == nil {
			return
		}
	}
	sockets, err := d.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", "cat /proc/net/tcp /proc/net/tcp6")
	if err != nil {
		sockets = fmt.Sprintf("<unavailable: %v>", err)
	}
	procs, err := d.Exec(ctx, dockerutil.ExecOpts{}, "ps")
	if err != nil {
		procs = fmt.Sprintf("<unavailable: %v>", err)
	}
	t.Fatalf("timed out waiting for a listener on port %d (looked for %q).\nSockets:\n%s\nProcesses:\n%s", port, hexPort, sockets, procs)
}

// TestExternalUDSProxyOutbound tests an outbound TCP connection initiated from
// inside a container configured with --network-uds-path to an external UDS
// proxy peer, verifying bidirectional data transfer and preservation of the
// container's scraped source IP and remote destination IP:port.
func TestExternalUDSProxyOutbound(t *testing.T) {
	ctx := context.Background()
	env := setupExternalUDSProxyEnv(ctx, t)

	const (
		wantReq  = "outbound ping over external uds\n"
		wantResp = "outbound pong over external uds\n"
	)

	tcpLn, err := gonet.ListenTCP(env.proxyStack, tcpip.FullAddress{
		NIC:  externalUDSProxyNIC,
		Addr: env.targetAddr,
		Port: externalUDSTargetPort,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP() failed: %v", err)
	}
	defer tcpLn.Close()

	type proxyResult struct {
		remoteAddr *net.TCPAddr
		localAddr  *net.TCPAddr
		payload    string
		err        error
	}
	proxyDone := make(chan proxyResult, 1)
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			proxyDone <- proxyResult{err: fmt.Errorf("tcpLn.Accept() failed: %w", err)}
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			proxyDone <- proxyResult{err: fmt.Errorf("reading from container TCP connection failed: %w", err)}
			return
		}
		if _, err := conn.Write([]byte(wantResp)); err != nil {
			proxyDone <- proxyResult{err: fmt.Errorf("writing to container TCP connection failed: %w", err)}
			return
		}
		rAddr, _ := conn.RemoteAddr().(*net.TCPAddr)
		lAddr, _ := conn.LocalAddr().(*net.TCPAddr)
		proxyDone <- proxyResult{
			remoteAddr: rAddr,
			localAddr:  lAddr,
			payload:    line,
		}
	}()

	got, err := env.container.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c",
		fmt.Sprintf("printf %q | nc -w 10 %s %d", wantReq, externalUDSTargetIP, externalUDSTargetPort))
	if err != nil {
		t.Fatalf("nc inside container failed: %v (output: %q)", err, got)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(wantResp) {
		t.Errorf("container received %q, want %q", got, wantResp)
	}

	select {
	case res := <-proxyDone:
		if res.err != nil {
			t.Fatalf("external UDS proxy TCP handler failed: %v", res.err)
		}
		if res.payload != wantReq {
			t.Errorf("external UDS proxy received %q, want %q", res.payload, wantReq)
		}
		if res.remoteAddr == nil || !res.remoteAddr.IP.Equal(env.containerIP) {
			t.Errorf("external UDS proxy saw source IP %v, want container IP %v", res.remoteAddr, env.containerIP)
		}
		if res.localAddr == nil || !res.localAddr.IP.Equal(net.ParseIP(externalUDSTargetIP)) || res.localAddr.Port != externalUDSTargetPort {
			t.Errorf("external UDS proxy saw destination %v, want %s:%d", res.localAddr, externalUDSTargetIP, externalUDSTargetPort)
		}
	case <-time.After(externalUDSWait):
		t.Fatal("timed out waiting for external UDS proxy to handle TCP connection")
	}
}

// TestExternalUDSProxyInbound tests an inbound TCP connection initiated from
// the external UDS proxy peer into a server listening inside the container on
// its scraped IP address, verifying bidirectional data transfer in the reverse
// direction.
func TestExternalUDSProxyInbound(t *testing.T) {
	ctx := context.Background()
	env := setupExternalUDSProxyEnv(ctx, t)

	const (
		listenPort = 8081
		wantReq    = "inbound ping over external uds\n"
		wantResp   = "inbound pong over external uds\n"
	)

	serverDone := make(chan error, 1)
	go func() {
		cmd := fmt.Sprintf(
			"mkfifo /tmp/uds_fifo && (head -n 1 < /tmp/uds_fifo > /tmp/uds_req.txt && printf %q) | nc -l -p %d > /tmp/uds_fifo",
			wantResp, listenPort,
		)
		if out, err := env.container.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd); err != nil {
			serverDone <- fmt.Errorf("container TCP server failed: %w (output: %q)", err, out)
			return
		}
		serverDone <- nil
	}()

	waitForContainerListener(ctx, t, env.container, listenPort, serverDone)

	containerIPv4 := env.containerIP.To4()
	if containerIPv4 == nil {
		t.Fatalf("container IP %v is not an IPv4 address", env.containerIP)
	}
	var containerAddrBytes [4]byte
	copy(containerAddrBytes[:], containerIPv4)

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := gonet.DialTCPWithBind(
		dialCtx,
		env.proxyStack,
		tcpip.FullAddress{NIC: externalUDSProxyNIC, Addr: env.targetAddr},
		tcpip.FullAddress{NIC: externalUDSProxyNIC, Addr: tcpip.AddrFrom4(containerAddrBytes), Port: listenPort},
		ipv4.ProtocolNumber,
	)
	if err != nil {
		t.Fatalf("gonet.DialTCPWithBind() to container %v:%d failed: %v", env.containerIP, listenPort, err)
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte(wantReq)); err != nil {
		_ = conn.Close()
		t.Fatalf("writing request from external UDS proxy to container failed: %v", err)
	}
	gotResp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("reading response from container over external UDS failed: %v", err)
	}
	if gotResp != wantResp {
		t.Errorf("external UDS proxy received %q from container, want %q", gotResp, wantResp)
	}
	// Close the client side of the TCP connection so BusyBox nc inside the
	// container sees EOF on the socket and exits.
	_ = conn.Close()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("container server failed: %v", err)
		}
	case <-time.After(externalUDSWait):
		t.Fatal("timed out waiting for container TCP server to exit")
	}

	gotReq, err := env.container.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/tmp/uds_req.txt")
	if err != nil {
		t.Fatalf("reading /tmp/uds_req.txt inside container failed: %v", err)
	}
	if strings.TrimSpace(gotReq) != strings.TrimSpace(wantReq) {
		t.Errorf("container TCP server received %q, want %q", gotReq, wantReq)
	}
}
