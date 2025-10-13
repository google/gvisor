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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// defaultWait is the default wait time used for tests.
	defaultWait = time.Minute
	// nonRootUID and nonRootGID correspond to the uid/gid defined in images/basic/integrationtest/Dockerfile.
	nonRootUID = 1338
	nonRootGID = 1337
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
		if _, err := os.CreateTemp(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simultaneously and sleep a bit
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
		if _, err := os.CreateTemp(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simultaneously and sleep a bit
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

func checkPeerCreds(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	file, err := unixConn.File()
	if err != nil {
		return fmt.Errorf("file error: %v", err)
	}
	defer file.Close()
	cred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return fmt.Errorf("getsockopt error: %v", err)
	}
	if cred.Uid != nonRootUID || cred.Gid != nonRootGID {
		return fmt.Errorf("expected uid/gid %d/%d, got %d/%d", nonRootUID, nonRootGID, cred.Uid, cred.Gid)
	}
	return nil
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
	socketPath := filepath.Join("/proc/self/fd", strconv.Itoa(tmpDirFD), "test.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer l.Close()
	// Change the socket's permission so that "nonroot" can connect to it.
	if err := os.Chmod(socketPath, 0777); err != nil {
		t.Errorf("chmod error: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("accept error: %v", err)
			return
		}
		if err := checkPeerCreds(conn); err != nil {
			t.Errorf("peer creds check failed: %v", err)
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
		WorkDir: "/home/nonroot",
		User:    "nonroot",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: filepath.Join(tmpDir, "test.sock"),
				Target: "/home/nonroot/test.sock",
			},
		},
	}
	if _, err := d.Run(ctx, opts, "./host_connect", "./test.sock"); err != nil {
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
	if got, err := d.Run(ctx, opts, "bash", "-c", fmt.Sprintf("ls -al / | grep %q || true", fsutil.SelfFilestorePrefix)); err != nil {
		t.Fatalf("docker run failed: %s, %v", got, err)
	} else if got != "" {
		t.Errorf("root directory contains a file/directory whose name contains %q: output = %q", fsutil.SelfFilestorePrefix, got)
	}
}

func TestOverlayCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()
	if !dockerutil.IsRestoreSupported() {
		t.Skip("Restore is not supported.")
	}

	dir, err := os.MkdirTemp(testutil.TmpDir(), "submount")
	if err != nil {
		t.Fatalf("MkdirTemp(): %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-overlay")
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/submount",
			},
		},
	}
	if err := d.Spawn(ctx, opts, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Create files in rootfs and submount.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo rootfs > /file"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo submount > /submount/file"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	// Check that the file was not created on host.
	if _, err := os.Stat(filepath.Join(dir, "file")); err == nil || !os.IsNotExist(err) {
		t.Fatalf("file was created on host, expected err = ENOENT, got %v", err)
	}

	// Create a snapshot.
	const ckptName = "test"
	if err := d.Checkpoint(ctx, ckptName); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := d.WaitTimeout(ctx, defaultWait); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	// Restore the snapshot.
	d.RestoreInTest(ctx, t, ckptName)

	// Make sure the files are restored in the overlay.
	if got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/file"); err != nil || got != "rootfs\n" {
		t.Errorf("cat /file returned: output = %q, err = %v", got, err)
	}
	if got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/submount/file"); err != nil || got != "submount\n" {
		t.Errorf("cat /submount/file returned: output = %q, err = %v", got, err)
	}
}
