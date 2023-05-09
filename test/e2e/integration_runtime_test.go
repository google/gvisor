// Copyright 2022 The gVisor Authors.
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

// Package integration provides end-to-end integration tests for runsc.
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, with various runsc commands. The container is killed and
// deleted at the end.
//
// Setup instruction in test/README.md.
package integration

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
)

const (
	// defaultWait is the default wait time used for tests.
	defaultWait = time.Minute

	memInfoCmd = "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'"
)

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}

func TestRlimitNoFile(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-fdlimit")
	defer d.CleanUp(ctx)

	// Create a directory with a bunch of files.
	const nfiles = 5000
	tmpDir := testutil.TmpDir()
	for i := 0; i < nfiles; i++ {
		if _, err := ioutil.TempFile(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simutaneously and sleep a bit
	// to give time for everything to start. We should hit the FD limit and
	// fail rather than waiting the full sleep duration.
	cmd := `for file in /tmp/foo/*; do (cat > "${file}") & done && sleep 60`
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: tmpDir,
				Target: "/tmp/foo",
			},
		},
	}, "bash", "-c", cmd)
	if err == nil {
		t.Fatalf("docker run didn't fail: %s", got)
	} else if strings.Contains(err.Error(), "Unknown runtime specified") {
		t.Fatalf("docker failed because -fdlimit runtime was not installed")
	}
}

func TestDentryCacheLimit(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-dcache")
	defer d.CleanUp(ctx)

	// Create a directory with a bunch of files.
	const nfiles = 5000
	tmpDir := testutil.TmpDir()
	for i := 0; i < nfiles; i++ {
		if _, err := ioutil.TempFile(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simutaneously and sleep a bit
	// to give time for everything to start. We shouldn't hit the FD limit
	// because the dentry cache is small.
	cmd := `for file in /tmp/foo/*; do (cat > "${file}") & done && sleep 10`
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: tmpDir,
				Target: "/tmp/foo",
			},
		},
	}, "bash", "-c", cmd)
	if err != nil {
		t.Fatalf("docker failed: %v, %s", err, got)
	}
}

// NOTE(gvisor.dev/issue/8126): Regression test.
func TestHostSocketConnect(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-host-uds")
	defer d.CleanUp(ctx)

	tmpDir := testutil.TmpDir()
	tmpDirFD, err := unix.Open(tmpDir, unix.O_PATH, 0)
	if err != nil {
		t.Fatalf("open error: %v", err)
	}
	defer unix.Close(tmpDirFD)
	// Use /proc/self/fd to generate path to avoid EINVAL on large path.
	l, err := net.Listen("unix", filepath.Join("/proc/self/fd", strconv.Itoa(tmpDirFD), "test.sock"))
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("accept error: %v", err)
			return
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var buf [5]byte
		if _, err := conn.Read(buf[:]); err != nil {
			t.Errorf("read error: %v", err)
			return
		}

		if want := "Hello"; string(buf[:]) != want {
			t.Errorf("expected %s, got %v", want, string(buf[:]))
		}
	}()

	opts := dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		WorkDir: "/root",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: filepath.Join(tmpDir, "test.sock"),
				Target: "/test.sock",
			},
		},
	}
	if _, err := d.Run(ctx, opts, "./host_connect", "/test.sock"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	wg.Wait()
}

func TestOverlayNameTooLong(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-overlay")
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}
	longName := strings.Repeat("a", unix.NAME_MAX+1)
	if got, err := d.Run(ctx, opts, "bash", "-c", fmt.Sprintf("stat %s || true", longName)); err != nil {
		t.Fatalf("docker run failed: %v", err)
	} else if want := "File name too long"; !strings.Contains(got, want) {
		t.Errorf("container output %q does not contain %q", got, want)
	}
}

// Tests that the overlay backing host file inside the container's rootfs is
// hidden from the application.
func TestOverlayRootfsWhiteout(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-overlay")
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}
	if got, err := d.Run(ctx, opts, "bash", "-c", fmt.Sprintf("ls -al / | grep %q || true", boot.SelfOverlayFilestorePrefix)); err != nil {
		t.Fatalf("docker run failed: %s, %v", got, err)
	} else if got != "" {
		t.Errorf("root directory contains a file/directory whose name contains %q: output = %q", boot.SelfOverlayFilestorePrefix, got)
	}
}

// TODO(b/271612187): Once S/R support is added for file-backed overlays, move
// this test to integration_test.go so it can run with the default runsc
// configuration which uses file-backed overlay.
func TestCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Pause/resume is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-no-overlay")
	defer d.CleanUp(ctx)

	// Start the container.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/python",
		Ports: []int{port}, // See Dockerfile.
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Create a snapshot.
	if err := d.Checkpoint(ctx, "test"); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := d.WaitTimeout(ctx, defaultWait); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	// TODO(b/143498576): Remove Poll after github.com/moby/moby/issues/38963 is fixed.
	if err := testutil.Poll(func() error { return d.Restore(ctx, "test") }, defaultWait); err != nil {
		t.Fatalf("docker restore failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client := http.Client{Timeout: defaultWait}
	if err := testutil.HTTPRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}
