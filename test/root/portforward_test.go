// Copyright 2023 The gVisor Authors.
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

// Package portforward_test holds a docker test for port forward. It is separate
// from other root tests so that both hostinet and netstack can be tested in
// one Makefile target.
package portforward_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestPortForwardLocalMode(t *testing.T) {
	// TODO(b/276812243): Fix test and revive.
	t.Skip("Broken test")
	ctx := context.Background()
	server := dockerutil.MakeContainer(ctx, t)
	defer server.CleanUp(ctx)

	redisPort := 6379
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/redis",
	}); err != nil {
		t.Fatalf("failed to create redis server: %v", err)
	}

	localPort, err := getUnusedPort()
	if err != nil {
		t.Fatalf("failed to pick unused port: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pf, err := newPortForwardProcess(ctx, server, localPort, redisPort)
	if err != nil {
		t.Fatalf("failed to create port forward process: %v", err)
	}

	var g errgroup.Group
	g.Go(func() error {
		// To end this test, we kill the portforward process, which will result in a "signal: killed"
		// error. Just ignore this error.
		if err := pf.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
			return fmt.Errorf("portforward command: err: %v process error: %v out: %s", err, pf.Error(), pf.Output())
		}
		return nil
	})
	cu := cleanup.Make(pf.Kill)
	defer cu.Clean()

	client := dockerutil.MakeNativeContainer(ctx, t)
	defer client.CleanUp(ctx)

	out, err := client.Run(ctx, dockerutil.RunOpts{
		Image:       "basic/redis",
		NetworkMode: "host",
	}, "redis-cli", "--verbose", "-p", fmt.Sprintf("%d", localPort), "-i", "1", "-r", "5", "ping")

	if err != nil {
		t.Logf("portforward command: err: %v out: %s", pf.Error(), pf.Output())
		t.Fatalf("failed to run client: %v out: %s", err, out)
	}

	if !strings.Contains(out, "PONG") {
		t.Logf("portforward command: err: %v out: %s", pf.Error(), pf.Output())
		t.Fatalf("could not reach redis server: %s", out)
	}

	cu.Clean()
	if err := g.Wait(); err != nil {
		t.Fatalf("failed to kill portforward process: %v", err)
	}
}

func TestPortForwardStreamMode(t *testing.T) {
	ctx := context.Background()
	sockAddrDir, err := os.MkdirTemp("", "temp-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(sockAddrDir)
	sockAddr := path.Join(sockAddrDir, "echo.sock")

	server := dockerutil.MakeContainer(ctx, t)
	defer server.CleanUp(ctx)

	nginxPort := 80
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/nginx",
	}); err != nil {
		t.Fatalf("failed to create nginx server: %v", err)
	}

	// This is a bit crude, but we need to make sure the server is up without exposing a port to the
	// host. When the server container boots, the nginx process should run first. If we run nginx
	// again, it will fail to bind to port 80. Run exec calls until we get that failure.
	serverUpChan := make(chan struct{}, 1)
	var upOut string
	var upErr error
	reg := regexp.MustCompile(`0\.0\.0\.0:80[\s]*0\.0\.0\.0:\*[\s]*LISTEN`)
	go func() {
		for {
			time.Sleep(time.Millisecond * 500)
			upOut, upErr = server.Exec(ctx, dockerutil.ExecOpts{}, []string{"netstat", "-l"}...)
			if reg.MatchString(upOut) {
				serverUpChan <- struct{}{}
				return
			}
		}
	}()

	// If the server isn't up after 10 seconds, there is probably something wrong.
	select {
	case <-serverUpChan:
		break
	case <-time.After(time.Second * 30):
		t.Fatalf("could not verify server is up: err: %v out: %s", upErr, upOut)
	}

	socket, err := net.Listen("unix", sockAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer socket.Close()

	pf, err := newPortForwardStreamProcess(ctx, server, sockAddr, nginxPort)
	if err != nil {
		t.Fatalf("failed to create port forward process: %v", err)
	}

	if err := pf.Wait(); err != nil {
		t.Fatalf("failed to wait: %v out: %s", err, pf.Output())
	}

	conn, err := socket.Accept()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer conn.Close()

	const getMsg = "GET / HTTP/1.0\r\n\r\n"
	if n, err := io.Copy(conn, bytes.NewBufferString(getMsg)); err != nil {
		t.Fatalf("failed to copy: %v n: %d", err, n)
	}

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read: %v out: %s", err, string(buf))
	}

	const want = "Thank you for using nginx."
	if !strings.Contains(string(buf), want) {
		t.Fatalf("could not find %q in output: %s", want, string(buf))
	}
}

func getUnusedPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type portForwardProcess struct {
	cmd *exec.Cmd
	buf bytes.Buffer
}

func newPortForwardProcess(ctx context.Context, c *dockerutil.Container, localPort, containerPort int) (*portForwardProcess, error) {
	rootDir, err := c.RootDirectory()
	if err != nil {
		return nil, err
	}
	args := []string{"-root", rootDir, "port-forward", c.ID(), fmt.Sprintf("%d:%d", localPort, containerPort)}
	return startPortForwardPorcess(ctx, args)
}

func newPortForwardStreamProcess(ctx context.Context, c *dockerutil.Container, uds string, containerPort int) (*portForwardProcess, error) {
	rootDir, err := c.RootDirectory()
	if err != nil {
		return nil, err
	}
	args := []string{"-root", rootDir, "-alsologtostderr", "port-forward", "-stream", uds, c.ID(), fmt.Sprintf("%d", containerPort)}
	return startPortForwardPorcess(ctx, args)
}

func startPortForwardPorcess(ctx context.Context, args []string) (*portForwardProcess, error) {
	cmd := exec.CommandContext(ctx, specutils.ExePath, args...)
	ret := &portForwardProcess{cmd: cmd}
	ret.cmd.Stdout = &ret.buf
	ret.cmd.Stderr = &ret.buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return ret, nil
}

func (p *portForwardProcess) Close() error {
	return p.cmd.Wait()
}

func (p *portForwardProcess) Wait() error { return p.cmd.Wait() }

func (p *portForwardProcess) Kill() { p.cmd.Process.Kill() }

func (p *portForwardProcess) Output() string { return p.buf.String() }

func (p *portForwardProcess) Error() error { return p.cmd.Err }

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	if !flag.CommandLine.Parsed() {
		flag.Parse()
	}

	if !specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_DAC_OVERRIDE) {
		fmt.Println("Test requires sysadmin privileges to run. Try again with sudo.")
		os.Exit(1)
	}

	dockerutil.EnsureSupportedDockerVersion()

	// Configure exe for tests.
	path, err := dockerutil.RuntimePath()
	if err != nil {
		panic(err.Error())
	}
	specutils.ExePath = path

	os.Exit(m.Run())
}
