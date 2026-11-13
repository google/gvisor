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

// This file tests UDS network proxying (--network-proxy-path and --netgofer).
package integration

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

	// netgoferProxyRuntimeSuffix names the runtime installed by the
	// $(RUNTIME)-netgofer-proxy target in the Makefile (--netgofer=proxy).
	netgoferProxyRuntimeSuffix = "-netgofer-proxy"

	// netgoferProxyLoopbackRuntimeSuffix names the runtime installed by the
	// $(RUNTIME)-netgofer-proxy-loopback target in the Makefile (--netgofer=proxy-loopback).
	netgoferProxyLoopbackRuntimeSuffix = "-netgofer-proxy-loopback"

	// externalUDSSocketPath must match the --network-proxy-path value baked into
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
	targetAddr  netip.Addr
}

// setupExternalUDSProxyEnv creates an external SOCK_SEQPACKET unix domain
// socket backed by a userspace TCP/IP stack (proxyStack) and starts a Docker
// container under the runtime configured with --network-proxy-path pointing to
// that socket.
func setupExternalUDSProxyEnv(ctx context.Context, t *testing.T) *externalUDSProxyEnv {
	t.Helper()
	if testutil.IsRunningWithHostNet() {
		t.Skip("External UDS proxy (--network-proxy-path) is only supported with sandbox networking.")
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
		targetAddr:  netip.AddrFrom4([4]byte{198, 51, 100, 1}),
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
// inside a container configured with --network-proxy-path to an external UDS
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
		tcpip.FullAddress{NIC: externalUDSProxyNIC, Addr: netip.AddrFrom4(containerAddrBytes), Port: listenPort},
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

// TestNetgoferProxyOutbound tests that a container running under the
// --netgofer=proxy runtime can establish an outbound TCP connection to a server
// running in another container.
func TestNetgoferProxyOutbound(t *testing.T) {
	if !testutil.ShouldRun(t.Name()) {
		t.Skipf("Skipping test %q for shard %d of %d", t.Name(), testutil.Partition(), testutil.TotalPartitions())
	}
	if testutil.IsRunningWithHostNet() {
		t.Skip("Netgofer proxy (--netgofer) is only supported with sandbox networking.")
	}

	ctx := context.Background()
	server := dockerutil.MakeContainer(ctx, t)
	t.Cleanup(func() { server.CleanUp(ctx) })

	client := dockerutil.MakeContainerWithRuntime(ctx, t, netgoferProxyRuntimeSuffix)
	t.Cleanup(func() { client.CleanUp(ctx) })

	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run server failed: %v", err)
	}

	if err := client.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run client under %s failed: %v", netgoferProxyRuntimeSuffix, err)
	}

	const (
		port     = 8080
		wantReq  = "netgofer-ping\n"
		wantResp = "netgofer-pong\n"
	)

	serverDone := make(chan error, 1)
	go func() {
		cmd := fmt.Sprintf(
			"mkfifo /tmp/uds_fifo && (head -n 1 < /tmp/uds_fifo > /tmp/uds_req.txt && printf %q) | nc -l -p %d > /tmp/uds_fifo",
			wantResp, port,
		)
		if out, err := server.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd); err != nil {
			serverDone <- fmt.Errorf("server container failed: %w (output: %q)", err, out)
			return
		}
		serverDone <- nil
	}()

	waitForContainerListener(ctx, t, server, port, serverDone)

	serverIP, err := server.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("server.FindIP() failed: %v", err)
	}

	got, err := client.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c",
		fmt.Sprintf("printf %q | nc -w 10 %s %d", wantReq, serverIP, port))
	if err != nil {
		t.Fatalf("nc inside client container failed: %v (output: %q)", err, got)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(wantResp) {
		t.Errorf("client received %q, want %q", got, wantResp)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server container failed: %v", err)
		}
	case <-time.After(externalUDSWait):
		t.Fatal("timed out waiting for server container to exit")
	}

	gotReq, err := server.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/tmp/uds_req.txt")
	if err != nil {
		t.Fatalf("reading /tmp/uds_req.txt inside server container failed: %v", err)
	}
	if strings.TrimSpace(gotReq) != strings.TrimSpace(wantReq) {
		t.Errorf("server container received %q, want %q", gotReq, wantReq)
	}
}

func runCompose(ctx context.Context, composeFile, projectName string, args ...string) (string, error) {
	cmdArgs := append([]string{"compose", "-f", composeFile, "-p", projectName}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	return string(out), err
}

func waitForComposeServiceListener(ctx context.Context, t *testing.T, composeFile, projectName, service, proto string, port int) {
	t.Helper()
	hexPort := fmt.Sprintf(":%04X ", port)
	procNetPath := "/proc/net/" + proto
	for deadline := time.Now().Add(externalUDSWait); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err := runCompose(ctx, composeFile, projectName, "exec", "-T", service, "grep", "-i", hexPort, procNetPath); err == nil {
			return
		}
	}
	sockets, _ := runCompose(ctx, composeFile, projectName, "exec", "-T", service, "cat", procNetPath)
	procs, _ := runCompose(ctx, composeFile, projectName, "exec", "-T", service, "ps")
	t.Fatalf("timed out waiting for %s listener on port %d in service %q.\nSockets:\n%s\nProcesses:\n%s", proto, port, service, sockets, procs)
}

// TestNetgoferProxyDockerCompose tests containers running under --netgofer=proxy-loopback
// and --netgofer=proxy in a Docker Compose project. It verifies that with
// --netgofer=proxy-loopback:
//   - Docker Compose's embedded DNS server at 127.0.0.11:53 is reachable over
//     netgofer to resolve peer service names.
//   - Outbound TCP and UDP connections to peer services by Compose service name
//     succeed over netgofer.
//   - Sandbox-local loopback (127.0.0.1) remains isolated inside the container.
//
// It also contrasts this with --netgofer=proxy, where 127.0.0.0/8 remains
// sandbox-local (blocking 127.0.0.11 DNS) while direct IP TCP and UDP traffic
// to peer containers still succeeds over netgofer.
func TestNetgoferProxyDockerCompose(t *testing.T) {
	if !testutil.ShouldRun(t.Name()) {
		t.Skipf("Skipping test %q for shard %d of %d", t.Name(), testutil.Partition(), testutil.TotalPartitions())
	}
	if testutil.IsRunningWithHostNet() {
		t.Skip("Netgofer proxy (--netgofer) is only supported with sandbox networking.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if out, err := exec.CommandContext(ctx, "docker", "compose", "version").CombinedOutput(); err != nil {
		t.Fatalf("docker compose is required for this test: %v (output: %q)", err, out)
	}

	const (
		tcpPort = 8080
		udpPort = 8081
	)
	alpineImage := testutil.ImageByName("basic/alpine")
	baseRuntime := dockerutil.Runtime()
	proxyLoopbackRuntime := baseRuntime + netgoferProxyLoopbackRuntimeSuffix
	proxyRuntime := baseRuntime + netgoferProxyRuntimeSuffix

	composeDir := t.TempDir()
	composeFile := filepath.Join(composeDir, "docker-compose.yml")
	projectName := strings.ToLower(testutil.RandomID("netgofer-compose"))
	projectName = strings.ReplaceAll(projectName, "/", "-")
	projectName = strings.ReplaceAll(projectName, "+", "p")

	composeYAML := fmt.Sprintf(`services:
  echo-server:
    image: %q
    runtime: %q
    environment:
      - RUNSC_TEST_NAME=%s
    command:
      - sh
      - -c
      - "nc -lk -s 0.0.0.0 -p %d -e /bin/cat & (while true; do nc -u -l -s 0.0.0.0 -p %d -e /usr/bin/head -n 1; done) & wait"
  client-loopback:
    image: %q
    runtime: %q
    environment:
      - RUNSC_TEST_NAME=%s
    depends_on:
      - echo-server
    command:
      - sleep
      - infinity
  client-noloopback:
    image: %q
    runtime: %q
    environment:
      - RUNSC_TEST_NAME=%s
    depends_on:
      - echo-server
    command:
      - sleep
      - infinity
`,
		alpineImage, baseRuntime, t.Name(), tcpPort, udpPort,
		alpineImage, proxyLoopbackRuntime, t.Name(),
		alpineImage, proxyRuntime, t.Name(),
	)
	if err := os.WriteFile(composeFile, []byte(composeYAML), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", composeFile, err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if out, err := runCompose(cleanupCtx, composeFile, projectName, "down", "-v", "--remove-orphans", "--timeout", "5"); err != nil {
			t.Logf("docker compose down failed: %v (output: %s)", err, out)
		}
	})

	if out, err := runCompose(ctx, composeFile, projectName, "up", "-d"); err != nil {
		t.Fatalf("docker compose up failed: %v\nOutput:\n%s", err, out)
	}

	waitForComposeServiceListener(ctx, t, composeFile, projectName, "echo-server", "tcp", tcpPort)
	waitForComposeServiceListener(ctx, t, composeFile, projectName, "echo-server", "udp", udpPort)

	// Verify /etc/resolv.conf in the compose container points to Docker's
	// embedded DNS server at 127.0.0.11.
	resolvConf, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "cat", "/etc/resolv.conf")
	if err != nil {
		t.Fatalf("reading /etc/resolv.conf in client-loopback failed: %v (output: %q)", err, resolvConf)
	}
	if !strings.Contains(resolvConf, "127.0.0.11") {
		t.Fatalf("client-loopback /etc/resolv.conf = %q, want nameserver 127.0.0.11", resolvConf)
	}

	// Verify that --netgofer=proxy-loopback narrows lo to 127.0.0.1/32 so 127.0.0.11
	// routes to netgofer while 127.0.0.1 stays sandbox-local.
	loAddrLoopback, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "ip", "addr", "show", "dev", "lo")
	if err != nil {
		t.Fatalf("ip addr show dev lo in client-loopback failed: %v (output: %q)", err, loAddrLoopback)
	}
	if !strings.Contains(loAddrLoopback, "127.0.0.1/32") {
		t.Errorf("client-loopback lo addr = %q, want 127.0.0.1/32", loAddrLoopback)
	}

	// Verify sandbox-local loopback (127.0.0.1) still works inside client-loopback.
	// Wait for nc to listen on port 9090 (0x2382 in /proc/net/tcp) before connecting.
	const wantLocalLoopback = "sandbox-loopback-ok"
	localOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "sh", "-c",
		`nc -l -s 127.0.0.1 -p 9090 -e /bin/cat & for _ in $(seq 1 100); do grep -qi ':2382 ' /proc/net/tcp && break; sleep 0.05; done; printf '%s\n' "$1" | nc -w 5 127.0.0.1 9090`,
		"sh", wantLocalLoopback)
	if err != nil {
		t.Fatalf("sandbox-local 127.0.0.1 loopback in client-loopback failed: %v (output: %q)", err, localOut)
	}
	if strings.TrimSpace(localOut) != wantLocalLoopback {
		t.Errorf("sandbox-local loopback output = %q, want %q", strings.TrimSpace(localOut), wantLocalLoopback)
	}

	// Resolve the "echo-server" service via Docker Compose's embedded DNS (127.0.0.11:53).
	// Note: BusyBox nslookup ignores Docker's `options ndots:0` in /etc/resolv.conf,
	// so pass a trailing dot to query the unqualified Compose service name directly.
	if out, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "nslookup", "echo-server."); err != nil {
		t.Fatalf("nslookup echo-server. in client-loopback failed: %v (output: %q)", err, out)
	}
	getentOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "getent", "hosts", "echo-server")
	if err != nil {
		t.Fatalf("getent hosts echo-server in client-loopback failed: %v (output: %q)", err, getentOut)
	}
	fields := strings.Fields(getentOut)
	if len(fields) == 0 || net.ParseIP(fields[0]) == nil {
		t.Fatalf("getent hosts echo-server returned unexpected output %q", getentOut)
	}
	serverIP := fields[0]

	// Verify outbound TCP communication by Compose service name ("echo-server").
	const wantComposeTCP = "compose-tcp-ping"
	tcpOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "sh", "-c",
		`printf '%s\n' "$1" | nc -w 10 echo-server "$2"`,
		"sh", wantComposeTCP, fmt.Sprint(tcpPort))
	if err != nil {
		t.Fatalf("TCP nc to echo-server:%d in client-loopback failed: %v (output: %q)", tcpPort, err, tcpOut)
	}
	if strings.TrimSpace(tcpOut) != wantComposeTCP {
		t.Errorf("client-loopback TCP response = %q, want %q", strings.TrimSpace(tcpOut), wantComposeTCP)
	}

	// Verify outbound UDP communication by Compose service name ("echo-server").
	const wantComposeUDP = "compose-udp-ping"
	udpOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-loopback", "sh", "-c",
		`printf '%s\n' "$1" | nc -u -w 5 echo-server "$2"`,
		"sh", wantComposeUDP, fmt.Sprint(udpPort))
	if err != nil {
		t.Fatalf("UDP nc to echo-server:%d in client-loopback failed: %v (output: %q)", udpPort, err, udpOut)
	}
	if strings.TrimSpace(udpOut) != wantComposeUDP {
		t.Errorf("client-loopback UDP response = %q, want %q", strings.TrimSpace(udpOut), wantComposeUDP)
	}

	// Contrast with client-noloopback (--netgofer=proxy): lo keeps 127.0.0.1/8 so
	// 127.0.0.11 stays inside the sandbox and embedded DNS is unreachable, while
	// direct IP TCP/UDP traffic to serverIP still works over netgofer.
	loAddrNoLoopback, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-noloopback", "ip", "addr", "show", "dev", "lo")
	if err != nil {
		t.Fatalf("ip addr show dev lo in client-noloopback failed: %v (output: %q)", err, loAddrNoLoopback)
	}
	if !strings.Contains(loAddrNoLoopback, "127.0.0.1/8") {
		t.Errorf("client-noloopback lo addr = %q, want 127.0.0.1/8", loAddrNoLoopback)
	}
	if out, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-noloopback", "nslookup", "echo-server."); err == nil {
		t.Errorf("nslookup echo-server. in client-noloopback (--netgofer=proxy) succeeded unexpectedly with output: %q", out)
	}
	if out, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-noloopback", "getent", "hosts", "echo-server"); err == nil {
		t.Errorf("getent hosts echo-server in client-noloopback (--netgofer=proxy) succeeded unexpectedly with output: %q", out)
	}

	const wantDirectTCP = "direct-tcp-ping"
	directTCPOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-noloopback", "sh", "-c",
		`printf '%s\n' "$1" | nc -w 10 "$2" "$3"`,
		"sh", wantDirectTCP, serverIP, fmt.Sprint(tcpPort))
	if err != nil {
		t.Fatalf("direct IP TCP nc to %s:%d in client-noloopback failed: %v (output: %q)", serverIP, tcpPort, err, directTCPOut)
	}
	if strings.TrimSpace(directTCPOut) != wantDirectTCP {
		t.Errorf("client-noloopback direct TCP response = %q, want %q", strings.TrimSpace(directTCPOut), wantDirectTCP)
	}

	const wantDirectUDP = "direct-udp-ping"
	directUDPOut, err := runCompose(ctx, composeFile, projectName, "exec", "-T", "client-noloopback", "sh", "-c",
		`printf '%s\n' "$1" | nc -u -w 5 "$2" "$3"`,
		"sh", wantDirectUDP, serverIP, fmt.Sprint(udpPort))
	if err != nil {
		t.Fatalf("direct IP UDP nc to %s:%d in client-noloopback failed: %v (output: %q)", serverIP, udpPort, err, directUDPOut)
	}
	if strings.TrimSpace(directUDPOut) != wantDirectUDP {
		t.Errorf("client-noloopback direct UDP response = %q, want %q", strings.TrimSpace(directUDPOut), wantDirectUDP)
	}
}
