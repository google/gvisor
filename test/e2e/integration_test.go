// Copyright 2018 The gVisor Authors.
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
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// defaultWait is the default wait time used for tests.
const defaultWait = time.Minute

// httpRequestSucceeds sends a request to a given url and checks that the status is OK.
func httpRequestSucceeds(client http.Client, server string, port int) error {
	url := fmt.Sprintf("http://%s:%d", server, port)
	// Ensure that content is being served.
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		return fmt.Errorf("wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
	return nil
}

// TestLifeCycle tests a basic Create/Start/Stop docker container life cycle.
func TestLifeCycle(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 80
	if err := d.Create(ctx, dockerutil.RunOpts{
		Image: "basic/nginx",
		Ports: []int{port},
	}); err != nil {
		t.Fatalf("docker create failed: %v", err)
	}
	if err := d.Start(ctx); err != nil {
		t.Fatalf("docker start failed: %v", err)
	}

	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Errorf("http request failed: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("docker stop failed: %v", err)
	}
	if err := d.Remove(ctx); err != nil {
		t.Fatalf("docker rm failed: %v", err)
	}
}

func TestPauseResume(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/python",
		Ports: []int{port}, // See Dockerfile.
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
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

	// Check that container is working.
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}

	if err := d.Pause(ctx); err != nil {
		t.Fatalf("docker pause failed: %v", err)
	}

	// Check if container is paused.
	client = http.Client{Timeout: 10 * time.Millisecond} // Don't wait a minute.
	switch _, err := client.Get(fmt.Sprintf("http://%s:%d", ip.String(), port)); v := err.(type) {
	case nil:
		t.Errorf("http req expected to fail but it succeeded")
	case net.Error:
		if !v.Timeout() {
			t.Errorf("http req got error %v, wanted timeout", v)
		}
	default:
		t.Errorf("http req got unexpected error %v", v)
	}

	if err := d.Unpause(ctx); err != nil {
		t.Fatalf("docker unpause failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client = http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}

func TestCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Pause/resume is not supported.")
	}

	// TODO(gvisor.dev/issue/3373): Remove after implementing.
	if usingVFS2, err := dockerutil.UsingVFS2(); usingVFS2 {
		t.Skip("CheckpointRestore not implemented in VFS2.")
	} else if err != nil {
		t.Fatalf("failed to read config for runtime %s: %v", dockerutil.Runtime(), err)
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
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
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}

// Create client and server that talk to each other using the local IP.
func TestConnectToSelf(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Creates server that replies "server" and exists. Sleeps at the end because
	// 'docker exec' gets killed if the init process exists before it can finish.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}, "/bin/sh", "-c", "echo server | nc -l -p 8080 && sleep 1"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Finds IP address for host.
	ip, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "cat /etc/hosts | grep ${HOSTNAME} | awk '{print $1}'")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	ip = strings.TrimRight(ip, "\n")

	// Runs client that sends "client" to the server and exits.
	reply, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", fmt.Sprintf("echo client | nc %s 8080", ip))
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// Ensure both client and server got the message from each other.
	if want := "server\n"; reply != want {
		t.Errorf("Error on server, want: %q, got: %q", want, reply)
	}
	if _, err := d.WaitForOutput(ctx, "^client\n$", defaultWait); err != nil {
		t.Fatalf("docker.WaitForOutput(client) timeout: %v", err)
	}
}

func TestMemLimit(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	allocMemoryKb := 50 * 1024
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image:  "basic/alpine",
		Memory: allocMemoryKb * 1024, // In bytes.
	}, "sh", "-c", "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Remove warning message that swap isn't present.
	if strings.HasPrefix(out, "WARNING") {
		lines := strings.Split(out, "\n")
		if len(lines) != 3 {
			t.Fatalf("invalid output: %s", out)
		}
		out = lines[1]
	}

	// Ensure the memory matches what we want.
	got, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if want := uint64(allocMemoryKb); got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

func TestNumCPU(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Read how many cores are in the container.
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image:      "basic/alpine",
		CpusetCpus: "0",
	}, "sh", "-c", "cat /proc/cpuinfo | grep 'processor.*:' | wc -l")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Ensure it matches what we want.
	got, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if want := 1; got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

// TestJobControl tests that job control characters are handled properly.
func TestJobControl(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container with an attached PTY.
	p, err := d.SpawnProcess(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sh", "-c", "sleep 100 | cat")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	// Give shell a few seconds to start executing the sleep.
	time.Sleep(2 * time.Second)

	if _, err := p.Write(time.Second, []byte{0x03}); err != nil {
		t.Fatalf("error exit: %v", err)
	}

	if err := d.WaitTimeout(ctx, 3*time.Second); err != nil {
		t.Fatalf("WaitTimeout failed: %v", err)
	}

	want := 130
	got, err := p.WaitExitStatus(ctx)
	if err != nil {
		t.Fatalf("wait for exit failed with: %v", err)
	} else if got != want {
		t.Fatalf("got: %d want: %d", got, want)
	}
}

// TestWorkingDirCreation checks that working dir is created if it doesn't exit.
func TestWorkingDirCreation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		workingDir string
	}{
		{name: "root", workingDir: "/foo"},
		{name: "tmp", workingDir: "/tmp/foo"},
	} {
		for _, readonly := range []bool{true, false} {
			name := tc.name
			if readonly {
				name += "-readonly"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				d := dockerutil.MakeContainer(ctx, t)
				defer d.CleanUp(ctx)

				opts := dockerutil.RunOpts{
					Image:    "basic/alpine",
					WorkDir:  tc.workingDir,
					ReadOnly: readonly,
				}
				got, err := d.Run(ctx, opts, "sh", "-c", "echo ${PWD}")
				if err != nil {
					t.Fatalf("docker run failed: %v", err)
				}
				if want := tc.workingDir + "\n"; want != got {
					t.Errorf("invalid working dir, want: %q, got: %q", want, got)
				}
			})
		}
	}
}

// TestTmpFile checks that files inside '/tmp' are not overridden.
func TestTmpFile(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{Image: "basic/tmpfile"}
	got, err := d.Run(ctx, opts, "cat", "/tmp/foo/file.txt")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want := "123\n"; want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// TestTmpMount checks that mounts inside '/tmp' are not overridden.
func TestTmpMount(t *testing.T) {
	ctx := context.Background()
	dir, err := ioutil.TempDir(testutil.TmpDir(), "tmp-mount")
	if err != nil {
		t.Fatalf("TempDir(): %v", err)
	}
	want := "123"
	if err := ioutil.WriteFile(filepath.Join(dir, "file.txt"), []byte("123"), 0666); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/tmp/foo",
			},
		},
	}
	got, err := d.Run(ctx, opts, "cat", "/tmp/foo/file.txt")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// TestHostOverlayfsCopyUp tests that the --overlayfs-stale-read option causes
// runsc to hide the incoherence of FDs opened before and after overlayfs
// copy-up on the host.
func TestHostOverlayfsCopyUp(t *testing.T) {
	runIntegrationTest(t, nil, "./test_copy_up")
}

// TestHostOverlayfsRewindDir tests that rewinddir() "causes the directory
// stream to refer to the current state of the corresponding directory, as a
// call to opendir() would have done" as required by POSIX, when the directory
// in question is host overlayfs.
//
// This test specifically targets host overlayfs because, per POSIX, "if a file
// is removed from or added to the directory after the most recent call to
// opendir() or rewinddir(), whether a subsequent call to readdir() returns an
// entry for that file is unspecified"; the host filesystems used by other
// automated tests yield newly-added files from readdir() even if the fsgofer
// does not explicitly rewinddir(), but overlayfs does not.
func TestHostOverlayfsRewindDir(t *testing.T) {
	runIntegrationTest(t, nil, "./test_rewinddir")
}

// Basic test for linkat(2). Syscall tests requires CAP_DAC_READ_SEARCH and it
// cannot use tricks like userns as root. For this reason, run a basic link test
// to ensure some coverage.
func TestLink(t *testing.T) {
	runIntegrationTest(t, nil, "./link_test")
}

// This test ensures we can run ping without errors.
func TestPing4Loopback(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		// TODO(gvisor.dev/issue/5011): support ICMP sockets in hostnet and enable
		// this test.
		t.Skip("hostnet only supports TCP/UDP sockets, so ping is not supported.")
	}

	runIntegrationTest(t, nil, "./ping4.sh")
}

// This test ensures we can enable ipv6 on loopback and run ping6 without
// errors.
func TestPing6Loopback(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		// TODO(gvisor.dev/issue/5011): support ICMP sockets in hostnet and enable
		// this test.
		t.Skip("hostnet only supports TCP/UDP sockets, so ping6 is not supported.")
	}

	// The CAP_NET_ADMIN capability is required to use the `ip` utility, which
	// we use to enable ipv6 on loopback.
	//
	// By default, ipv6 loopback is not enabled by runsc, because docker does
	// not assign an ipv6 address to the test container.
	runIntegrationTest(t, []string{"NET_ADMIN"}, "./ping6.sh")
}

// This test checks that the owner of the sticky directory can delete files
// inside it belonging to other users. It also checks that the owner of a file
// can always delete its file when the file is inside a sticky directory owned
// by another user.
func TestStickyDir(t *testing.T) {
	if vfs2Used, err := dockerutil.UsingVFS2(); err != nil {
		t.Fatalf("failed to read config for runtime %s: %v", dockerutil.Runtime(), err)
	} else if !vfs2Used {
		t.Skip("sticky bit test fails on VFS1.")
	}

	runIntegrationTest(t, nil, "./test_sticky")
}

func runIntegrationTest(t *testing.T, capAdd []string, args ...string) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if got, err := d.Run(ctx, dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		WorkDir: "/root",
		CapAdd:  capAdd,
	}, args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	} else if got != "" {
		t.Errorf("test failed:\n%s", got)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
